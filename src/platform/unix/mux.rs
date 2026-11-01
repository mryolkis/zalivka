//! Plist usbmuxd protocol v1 over the system Unix socket.
//! Wire reference: libimobiledevice/libusbmuxd, usbmuxd-proto.h.
use crate::wire;
use anyhow::{Context, Result, ensure};
use plist::Value;
use std::{
    collections::VecDeque,
    io::{self, Cursor, Read, Write},
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU16, Ordering},
    },
    time::{Duration, Instant},
};

const SOCKET: &str = "/var/run/usbmuxd";
const MAX_MESSAGE: usize = 1024 * 1024;
const TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Clone)]
pub(crate) struct Session(Arc<Shared>);

struct Shared {
    path: PathBuf,
    device_id: u32,
    cancelled: AtomicBool,
    next_channel: AtomicU16,
}

pub(crate) fn candidates() -> Result<Vec<Session>> {
    candidates_at(Path::new(SOCKET))
}

fn candidates_at(path: &Path) -> Result<Vec<Session>> {
    Ok(device_ids(path)?
        .into_iter()
        .map(|device_id| {
            Session(Arc::new(Shared {
                path: path.to_owned(),
                device_id,
                cancelled: AtomicBool::new(false),
                next_channel: AtomicU16::new(1),
            }))
        })
        .collect())
}

fn list_devices(path: &Path) -> Result<Vec<Value>> {
    let shared = Arc::new(Shared {
        path: path.to_owned(),
        device_id: 0,
        cancelled: AtomicBool::new(false),
        next_channel: AtomicU16::new(1),
    });
    let mut stream = Stream::open(shared, 0, Instant::now() + Duration::from_secs(10))?;
    let response = request(&mut stream, "ListDevices", [])?;
    let devices = wire::get(&response, &["DeviceList"])?
        .as_array()
        .context("usbmuxd DeviceList is not an array")?;
    // Apple's daemon can also advertise paired network devices.
    devices
        .iter()
        .filter_map(
            |device| match wire::string(device, &["Properties", "ConnectionType"]) {
                Ok("USB") => Some(Ok(device.clone())),
                Ok(_) => None,
                Err(error) => Some(Err(error)),
            },
        )
        .collect()
}

fn device_ids(path: &Path) -> Result<Vec<u32>> {
    list_devices(path)?
        .iter()
        .map(|device| {
            Ok(u32::try_from(wire::number(wire::get(
                device,
                &["DeviceID"],
            )?)?)?)
        })
        .collect()
}

pub(crate) fn check_device(info: &nusb::DeviceInfo) -> Result<()> {
    let devices = list_devices(Path::new(SOCKET))?;
    let present = devices.iter().any(|device| {
        wire::get(device, &["Properties", "ProductID"])
            .and_then(wire::number)
            .ok()
            == Some(u64::from(info.product_id()))
            && info.serial_number().is_none_or(|serial| {
                wire::string(device, &["Properties", "SerialNumber"]).is_ok_and(|s| {
                    s.replace('-', "")
                        .eq_ignore_ascii_case(&serial.replace('-', ""))
                })
            })
    });
    ensure!(
        present,
        "USB device is not registered with system usbmuxd; check the service and update Zalivka's udev rules"
    );
    Ok(())
}

impl Session {
    pub(crate) fn connect(&self, destination: u16, deadline: Instant) -> Result<Stream> {
        ensure!(destination != 0, "zero service port");
        let mut stream = Stream::open(self.0.clone(), destination, deadline)?;
        let response = request(
            &mut stream,
            "Connect",
            [
                ("DeviceID", Value::from(self.0.device_id)),
                // The plist integer contains the port in network byte order.
                ("PortNumber", Value::from(destination.to_be())),
            ],
        )?;
        ensure!(
            wire::string(&response, &["MessageType"])? == "Result",
            "invalid usbmuxd Connect response"
        );
        let code = wire::number(wire::get(&response, &["Number"])?)?;
        if code != 0 {
            return Err(io::Error::new(
                match code {
                    2 => io::ErrorKind::NotFound,
                    3 => io::ErrorKind::ConnectionRefused,
                    _ => io::ErrorKind::Other,
                },
                format!(
                    "usbmuxd Connect to device {}, port {destination} failed: result {code}",
                    self.0.device_id
                ),
            )
            .into());
        }
        // After Result=0, the very next byte belongs to the service. Do not
        // buffer ahead while parsing the daemon's response.
        stream.deadline = None;
        crate::log!(
            Debug,
            "usbmuxd",
            "Device {}: connected port {destination}",
            self.0.device_id
        );
        Ok(stream)
    }

    pub(crate) fn cancel(&self) {
        self.0.cancelled.store(true, Ordering::Release);
    }

    pub(crate) fn disconnected(&self) -> bool {
        // A service EOF, failed plist or daemon outage is not proof of removal.
        device_ids(&self.0.path).is_ok_and(|ids| !ids.contains(&self.0.device_id))
    }
}

fn request<const N: usize>(
    stream: &mut Stream,
    kind: &str,
    fields: [(&str, Value); N],
) -> Result<Value> {
    let mut message = wire::dict([
        ("MessageType", kind.into()),
        (
            "ClientVersionString",
            format!("zalivka-{}", env!("CARGO_PKG_VERSION")).into(),
        ),
        ("ProgName", "zalivka".into()),
        ("kLibUSBMuxVersion", 3u64.into()),
    ]);
    message
        .as_dictionary_mut()
        .unwrap()
        .extend(fields.into_iter().map(|(k, v)| (k.to_owned(), v)));
    let mut payload = Vec::new();
    plist::to_writer_xml(&mut payload, &message)?;
    let mut packet = Vec::with_capacity(16 + payload.len());
    for value in [(16 + payload.len()) as u32, 1, 8, 1] {
        packet.extend_from_slice(&value.to_le_bytes());
    }
    packet.extend_from_slice(&payload);
    stream
        .write_all(&packet)
        .context("sending usbmuxd request")?;
    let mut header = [0; 16];
    stream
        .read_exact(&mut header)
        .context("reading usbmuxd header")?;
    let [length, version, message, tag] =
        std::array::from_fn(|i| u32::from_le_bytes(header[i * 4..i * 4 + 4].try_into().unwrap()));
    ensure!(
        (16..=MAX_MESSAGE).contains(&(length as usize)),
        "invalid usbmuxd message length {length}"
    );
    ensure!(
        version == 1 && message == 8 && tag == 1,
        "invalid usbmuxd response header"
    );
    let mut payload = vec![0; length as usize - 16];
    stream
        .read_exact(&mut payload)
        .context("reading usbmuxd plist")?;
    Value::from_reader(Cursor::new(payload)).context("decoding usbmuxd plist")
}

pub(crate) struct Stream {
    socket: UnixStream,
    shared: Arc<Shared>,
    pending: Mutex<VecDeque<u8>>,
    source: u16,
    destination: u16,
    read_timeout: Duration,
    deadline: Option<Instant>,
    log_source: &'static str,
    received: u64,
    written: u64,
}

impl Stream {
    fn open(shared: Arc<Shared>, destination: u16, deadline: Instant) -> Result<Self> {
        check(&shared, deadline)?;
        let socket = UnixStream::connect(&shared.path).map_err(|error| {
            // connect_retry retries a device's Result=3, not a stopped daemon.
            if error.kind() == io::ErrorKind::ConnectionRefused {
                io::Error::new(io::ErrorKind::NotConnected, error)
            } else {
                error
            }
        }).with_context(|| format!(
            "connecting to system usbmuxd at {}; Linux: install/start usbmuxd and update Zalivka's udev rules; macOS: system usbmuxd must be available",
            shared.path.display()
        ))?;
        socket.set_nonblocking(true)?;
        let source = shared.next_channel.fetch_add(1, Ordering::Relaxed);
        Ok(Self {
            socket,
            shared,
            pending: Mutex::new(VecDeque::new()),
            source,
            destination,
            read_timeout: TIMEOUT,
            deadline: Some(deadline),
            log_source: "usbmux:io",
            received: 0,
            written: 0,
        })
    }

    pub(crate) fn has_pending_input(&self) -> Result<bool> {
        self.poll_input().map_err(Into::into)
    }

    fn poll_input(&self) -> io::Result<bool> {
        check(&self.shared, Instant::now() + TIMEOUT)?;
        let mut pending = self
            .pending
            .lock()
            .map_err(|_| io::Error::other("usbmuxd input lock poisoned"))?;
        if pending.is_empty() {
            let mut buffer = [0; 8192];
            match (&self.socket).read(&mut buffer) {
                Ok(n) => pending.extend(&buffer[..n]),
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(!pending.is_empty())
    }

    pub(crate) fn set_read_timeout(&mut self, timeout: Duration) {
        self.read_timeout = timeout;
    }
    pub(crate) fn read_timeout(&self) -> Duration {
        self.read_timeout
    }
    pub(crate) fn set_log_source(&mut self, source: &'static str) {
        self.log_source = source;
    }
    pub(crate) fn local_port(&self) -> u16 {
        self.source
    }

    fn write_data(&mut self, data: &[u8], stop_on_input: bool) -> io::Result<Option<usize>> {
        if data.is_empty() {
            return Ok(Some(0));
        }
        let deadline = self.deadline.unwrap_or_else(|| Instant::now() + TIMEOUT);
        loop {
            check(&self.shared, deadline)?;
            if stop_on_input && self.poll_input()? {
                return Ok(None);
            }
            match self.socket.write(&data[..data.len().min(256 * 1024)]) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "usbmuxd socket closed",
                    ));
                }
                Ok(n) => {
                    crate::logging::bytes(
                        self.log_source,
                        format_args!(
                            "{} -> {} TX offset={}",
                            self.source, self.destination, self.written
                        ),
                        &data[..n],
                    );
                    self.written += n as u64;
                    return Ok(Some(n));
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(1))
                }
                Err(error) => return Err(error),
            }
        }
    }

    pub(crate) fn write_until_input(&mut self, data: &[u8]) -> io::Result<Option<usize>> {
        let result = self.write_data(data, true);
        if result.is_err() {
            self.shared.cancelled.store(true, Ordering::Release);
        }
        result
    }
}

fn check(shared: &Shared, deadline: Instant) -> io::Result<()> {
    if shared.cancelled.load(Ordering::Acquire) {
        return Err(io::Error::other("USB mux session cancelled"));
    }
    if Instant::now() >= deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "usbmuxd I/O timed out",
        ));
    }
    Ok(())
}

impl Read for Stream {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        let deadline = self
            .deadline
            .unwrap_or_else(|| Instant::now() + self.read_timeout);
        let n = loop {
            check(&self.shared, deadline)?;
            let pending = self
                .pending
                .get_mut()
                .map_err(|_| io::Error::other("usbmuxd input lock poisoned"))?;
            if !pending.is_empty() {
                break pending.read(out)?;
            }
            match self.socket.read(out) {
                Ok(n) => break n,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(1))
                }
                Err(error) => return Err(error),
            }
        };
        crate::logging::bytes(
            self.log_source,
            format_args!(
                "{} -> {} RX offset={}",
                self.destination, self.source, self.received
            ),
            &out[..n],
        );
        self.received += n as u64;
        Ok(n)
    }
}

impl Write for Stream {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let result = self.write_data(data, false).map(|n| n.unwrap_or_default());
        if result.is_err() {
            self.shared.cancelled.store(true, Ordering::Release);
        }
        result
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/platform/unix/mux.rs"]
mod tests;
