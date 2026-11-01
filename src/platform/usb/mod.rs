mod backend;
mod descriptors;
mod kis;
use crate::{
    device::{DeviceInfo, Mode},
    usb::RecoveryTransport,
};
use anyhow::{Context, Result, bail};
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
use backend::BulkInput;
use backend::BulkOutput;
pub(crate) use backend::UsbInterface;
pub(crate) use descriptors::{mux_interface, recovery_interface};
pub(crate) use kis::Kis;
use nusb::{
    Device, MaybeFuture,
    transfer::{ControlIn, ControlOut, ControlType, Recipient},
};
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
use std::sync::atomic::AtomicBool;
use std::time::Duration;

pub(crate) const APPLE_VENDOR: u16 = 0x05ac;
pub(crate) const MUX_INTERFACE: (u8, u8, u8) = (0xff, 0xfe, 2);
const TIMEOUT: Duration = Duration::from_secs(10);

fn recovery_devices() -> Result<impl Iterator<Item = (nusb::DeviceInfo, Mode)>> {
    Ok(nusb::list_devices()
        .wait()
        .context("enumerating USB devices")?
        .filter(|usb| usb.vendor_id() == APPLE_VENDOR)
        .filter_map(|usb| {
            let mode = if usb.product_id() == 0x1881 {
                Some(Mode::Dfu)
            } else {
                Mode::from_pid(usb.product_id())
            };
            mode.map(|mode| (usb, mode))
        }))
}

fn serial_number(device: &Device) -> Result<String> {
    let index = device
        .device_descriptor()
        .serial_number_string_index()
        .context("device has no serial descriptor")?;
    Ok(device
        .get_string_descriptor(index, 0x0409, TIMEOUT)
        .wait()?)
}

/// A disappearing neighbour must not prevent opening the requested ECID.
fn find_ecid<T, R>(
    ecid: u64,
    devices: impl Iterator<Item = (Option<u64>, T)>,
    mut read: impl FnMut(T) -> Result<(u64, R)>,
) -> Result<R> {
    let mut target_error = None;
    let mut errors = Vec::new();
    for (cached, device) in devices {
        if cached.is_some_and(|cached| cached != ecid) {
            continue;
        }
        match read(device) {
            Ok((actual, device)) if actual == ecid => return Ok(device),
            Ok(_) => {}
            Err(error) => {
                crate::log!(Warning, "usb:detect", "Reading candidate: {error:#}");
                errors.push(format!("{error:#}"));
                if cached == Some(ecid) {
                    target_error = Some(error);
                }
            }
        }
    }
    if let Some(error) = target_error {
        return Err(error).with_context(|| format!("opening ECID {ecid:016x}"));
    }
    let error = anyhow::anyhow!("no Apple DFU/recovery device with ECID {ecid:016x}");
    if errors.is_empty() {
        Err(error)
    } else {
        Err(error.context(format!("unreadable USB candidates: {}", errors.join("; "))))
    }
}

fn collect_devices<T>(devices: impl Iterator<Item = Result<T>>) -> Result<Vec<T>> {
    let mut found = Vec::new();
    let mut errors = Vec::new();
    for device in devices {
        match device {
            Ok(device) => found.push(device),
            Err(error) => {
                crate::log!(Warning, "usb:detect", "Reading candidate: {error:#}");
                errors.push(format!("{error:#}"));
            }
        }
    }
    if found.is_empty() && !errors.is_empty() {
        bail!("could not read Apple USB devices: {}", errors.join("; "));
    }
    Ok(found)
}

pub struct RecoveryUsb {
    #[cfg(not(windows))]
    device: Device,
    connection: RecoveryConnection,
    pub info: DeviceInfo,
    topology: nusb::DeviceInfo,
}

enum RecoveryConnection {
    #[cfg(target_os = "macos")]
    Closed,
    Standard {
        interface: UsbInterface,
        bulk: Option<BulkOutput>,
    },
    Kis(kis::Kis),
}

fn control_kind(kind: u8) -> Result<(ControlType, Recipient)> {
    let ty = match (kind >> 5) & 3 {
        0 => ControlType::Standard,
        1 => ControlType::Class,
        2 => ControlType::Vendor,
        _ => bail!("reserved USB request type"),
    };
    let recipient = match kind & 31 {
        0 => Recipient::Device,
        1 => Recipient::Interface,
        2 => Recipient::Endpoint,
        3 => Recipient::Other,
        _ => bail!("invalid USB recipient"),
    };
    Ok((ty, recipient))
}

impl RecoveryUsb {
    pub(crate) fn topology(&self) -> &nusb::DeviceInfo {
        &self.topology
    }

    pub(crate) fn wait_at_port(previous: &nusb::DeviceInfo, hardware: (u32, u32)) -> Result<Self> {
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        let mut last_error = anyhow::anyhow!("SoC DFU has not appeared on the original USB port");
        loop {
            let devices = match recovery_devices() {
                Ok(devices) => Some(devices),
                Err(error) => {
                    last_error = error;
                    None
                }
            };
            for (candidate, mode) in devices.into_iter().flatten() {
                if mode != Mode::Dfu
                    || candidate.bus_id() != previous.bus_id()
                    || candidate.port_chain() != previous.port_chain()
                {
                    continue;
                }
                let opened = Self::open_candidate(candidate, mode);
                match opened {
                    Ok(usb) => {
                        anyhow::ensure!(
                            usb.info.hardware_ids() == hardware
                                && usb.topology.bus_id() == previous.bus_id()
                                && usb.topology.port_chain() == previous.port_chain(),
                            "USB device changed while reconnecting after Port DFU"
                        );
                        return Ok(usb);
                    }
                    Err(error) => last_error = error,
                }
            }
            if std::time::Instant::now() >= deadline {
                return Err(last_error);
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    #[cfg(windows)]
    pub fn check_reset_access(&self) -> Result<()> {
        if let RecoveryConnection::Standard { interface, .. } = &self.connection {
            interface.check_reset_access(&self.topology)?;
        }
        Ok(())
    }
    pub fn open(ecid: u64) -> Result<Self> {
        let devices = recovery_devices()?.map(|(usb, mode)| {
            let cached = (usb.product_id() != 0x1881)
                .then(|| usb.serial_number())
                .flatten()
                .and_then(|serial| DeviceInfo::parse(serial, mode).ok())
                .map(|info| info.ecid);
            (cached, (usb, mode))
        });
        find_ecid(ecid, devices, |(usb, mode)| {
            let connection = Self::open_candidate(usb, mode)?;
            Ok((connection.info.ecid, connection))
        })
    }

    fn interface(&self) -> Result<&UsbInterface> {
        match &self.connection {
            RecoveryConnection::Standard { interface, .. } => Ok(interface),
            RecoveryConnection::Kis(_) => bail!("KIS has no iBoot control interface"),
            #[cfg(target_os = "macos")]
            RecoveryConnection::Closed => bail!("USB connection closed for reset"),
        }
    }

    fn open_candidate(usb: nusb::DeviceInfo, mode: Mode) -> Result<Self> {
        let device = usb
            .open()
            .wait()
            .context("opening Apple USB device; check permissions and driver")?;
        if usb.product_id() == 0x1881 {
            let mut kis = kis::Kis::open(&device, &usb)?;
            let info = kis.info()?;
            return Ok(Self {
                #[cfg(not(windows))]
                device,
                connection: RecoveryConnection::Kis(kis),
                info,
                topology: usb,
            });
        }
        let mut info = DeviceInfo::parse(&serial_number(&device)?, mode)?;
        let selected = if info.mode == Mode::Recovery {
            recovery_interface(device.active_configuration()?)?
        } else {
            (0, 0)
        };
        let interface = UsbInterface::claim(&device, &usb, selected.0)
            .context("claiming Apple USB interface; another process or driver may own it")?;
        interface.set_alt_setting(selected.1)?;
        let bulk = if info.mode == Mode::Recovery {
            Some(interface.bulk_out(0x04)?)
        } else {
            None
        };
        let nonces = device
            .get_string_descriptor(std::num::NonZeroU8::MIN, 0x0409, TIMEOUT)
            .wait()?;
        info.set_nonces(&nonces)?;
        Ok(Self {
            #[cfg(not(windows))]
            device,
            connection: RecoveryConnection::Standard { interface, bulk },
            info,
            topology: usb,
        })
    }
}

impl RecoveryTransport for RecoveryUsb {
    fn upload_dfu(&mut self, data: &[u8], finish: bool) -> Result<bool> {
        if let RecoveryConnection::Kis(kis) = &mut self.connection {
            kis.upload(data, finish)?;
            return Ok(true);
        }
        Ok(false)
    }
    fn control_in(
        &mut self,
        kind: u8,
        request: u8,
        value: u16,
        index: u16,
        length: u16,
    ) -> Result<Vec<u8>> {
        crate::log!(
            Trace,
            "usb:control",
            "IN type={kind:#04x}, req={request:#04x}, value={value:#06x}, index={index:#06x}, len={length}"
        );
        let (control_type, recipient) = control_kind(kind)?;
        let bytes = self.interface()?.control_in(
            ControlIn {
                control_type,
                recipient,
                request,
                value,
                index,
                length,
            },
            TIMEOUT,
        )?;
        crate::logging::bytes(
            "usb:control",
            format_args!("IN request={request:#04x}"),
            &bytes,
        );
        Ok(bytes)
    }
    fn control_out(
        &mut self,
        kind: u8,
        request: u8,
        value: u16,
        index: u16,
        data: &[u8],
    ) -> Result<()> {
        crate::log!(
            Trace,
            "usb:control",
            "OUT type={kind:#04x}, req={request:#04x}, value={value:#06x}, index={index:#06x}, len={}",
            data.len()
        );
        crate::logging::bytes(
            "usb:control",
            format_args!("OUT request={request:#04x}, value={value:#06x}"),
            data,
        );
        let (control_type, recipient) = control_kind(kind)?;
        self.interface()?.control_out(
            ControlOut {
                control_type,
                recipient,
                request,
                value,
                index,
                data,
            },
            TIMEOUT,
        )?;
        Ok(())
    }
    fn bulk_out(&mut self, data: &[u8]) -> Result<()> {
        let RecoveryConnection::Standard { bulk, .. } = &mut self.connection else {
            bail!("KIS has no Recovery bulk endpoint")
        };
        let ep = bulk
            .as_mut()
            .context("device has no recovery bulk endpoint")?;
        ep.write(data)
    }
    fn reset(&mut self) -> Result<()> {
        #[cfg(windows)]
        {
            match self.interface()? {
                UsbInterface::Native(_) => {
                    crate::platform::windows::reset::cycle_port(&self.topology)
                }
                UsbInterface::Apple(apple) => apple.reset(),
            }
        }
        #[cfg(not(windows))]
        {
            // IOKit requires every interface and endpoint handle to be dropped
            // before a device-wide reset. This connection ends at the reset;
            // the boot stage opens the re-enumerated device separately.
            #[cfg(target_os = "macos")]
            drop(std::mem::replace(
                &mut self.connection,
                RecoveryConnection::Closed,
            ));
            self.device.reset().wait().context("USB reset")
        }
    }
}

pub fn detect() -> Result<Vec<DeviceInfo>> {
    crate::log!(Trace, "usb:detect", "Scanning for Apple USB devices");
    let out = collect_devices(recovery_devices()?.map(|(usb, mode)| {
        if usb.product_id() == 0x1881 {
            return Ok(RecoveryUsb::open_candidate(usb, mode)?.info);
        }
        let serial = if let Some(s) = usb.serial_number() {
            s.to_owned()
        } else {
            let d = usb.open().wait().context("reading DFU serial descriptor")?;
            serial_number(&d)?
        };
        let info = DeviceInfo::parse(&serial, mode)?;
        crate::log!(
            Trace,
            "usb:detect",
            "ECID={:016x}; CPID={:04x}; BDID={:02x}; mode={:?}",
            info.ecid,
            info.chip_id,
            info.board_id,
            info.mode
        );
        Ok(info)
    }))?;
    crate::log!(Trace, "usb:detect", "Found={}", out.len());
    Ok(out)
}

#[cfg(test)]
#[path = "../../../tests/unit/platform/usb/enumeration.rs"]
mod enumeration_tests;

/// USB mux interface, selected by the vendor-specific ff/fe/02 interface triple.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) struct MuxUsb {
    _device: Device,
    _interface: UsbInterface,
    input: BulkInput,
    output: BulkOutput,
    packet_size: usize,
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
impl MuxUsb {
    pub(crate) fn candidates() -> Result<Vec<nusb::DeviceInfo>> {
        Ok(nusb::list_devices()
            .wait()?
            .filter(|d| {
                d.vendor_id() == APPLE_VENDOR
                    && Mode::from_pid(d.product_id()).is_none()
                    && d.product_id() != 0x1881
            })
            .collect())
    }

    pub(crate) fn open(info: &nusb::DeviceInfo) -> Result<Self> {
        let device = info.open().wait()?;
        let active = device
            .active_configuration()
            .ok()
            .map(|c| c.configuration_value());
        let selected = mux_interface(&device)?;
        if active != Some(selected.configuration) {
            device.set_configuration(selected.configuration).wait().context("selecting USB multiplex configuration (Windows requires an active WinUSB configuration)")?;
        }
        let interface = UsbInterface::claim(&device, info, selected.number).context("claiming USB multiplex interface; stop usbmuxd/Apple Mobile Device Service if it owns this interface")?;
        interface.set_alt_setting(selected.alternate)?;
        let input = interface.bulk_in(selected.input)?;
        let output = interface.bulk_out(selected.output)?;
        crate::log!(
            Debug,
            "usb:mux",
            "{:?}; {}; interface={}, IN={:#04x}, OUT={:#04x}, max_packet={}",
            info.speed(),
            interface.transport(),
            selected.number,
            selected.input,
            selected.output,
            selected.packet_size
        );
        Ok(Self {
            input,
            output,
            _device: device,
            _interface: interface,
            packet_size: selected.packet_size,
        })
    }

    pub(crate) fn write_packet(&mut self, data: &[u8]) -> Result<()> {
        self.output.write(data)?;
        if data.len().is_multiple_of(self.packet_size) {
            self.output.write(&[])?;
        }
        Ok(())
    }

    pub(crate) fn write_packets(
        &mut self,
        packets: &[Vec<u8>],
        cancelled: &AtomicBool,
    ) -> Result<()> {
        // Keep each mux packet in its own USB request, including the existing
        // zero-length terminator when it ends on a physical packet boundary.
        let mut transfers = Vec::with_capacity(packets.len() * 2);
        for packet in packets {
            transfers.push(packet.as_slice());
            if packet.len().is_multiple_of(self.packet_size) {
                transfers.push(&[]);
            }
        }
        self.output.write_batch(&transfers, cancelled)
    }

    pub(crate) fn read_packet(&mut self) -> Result<Vec<u8>> {
        self.input.read()
    }

    pub(crate) fn input_ready(&self) -> Option<crate::mux::InputReady> {
        self.input.input_ready()
    }
}

pub fn is_device_removal(error: &anyhow::Error) -> bool {
    error.chain().any(|e| {
        #[cfg(windows)]
        if e.downcast_ref::<std::io::Error>().is_some_and(|error| {
            use windows_sys::Win32::Foundation::{
                ERROR_DEV_NOT_EXIST, ERROR_DEVICE_NOT_CONNECTED, ERROR_NO_SUCH_DEVICE,
            };
            error.raw_os_error().is_some_and(|code| {
                [
                    ERROR_DEVICE_NOT_CONNECTED,
                    ERROR_DEV_NOT_EXIST,
                    ERROR_NO_SUCH_DEVICE,
                ]
                .contains(&(code as u32))
            })
        }) {
            return true;
        }
        e.downcast_ref::<nusb::transfer::TransferError>()
            == Some(&nusb::transfer::TransferError::Disconnected)
            || e.downcast_ref::<nusb::Error>()
                .is_some_and(|e| e.kind() == nusb::ErrorKind::Disconnected)
    })
}
