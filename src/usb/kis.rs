//! Apple Debug USB carries ROM DFU through KIS portals, not DFU control requests.
//! Wire reference: libimobiledevice/libirecovery src/libirecovery.c.
use super::TIMEOUT;
use crate::device::{DeviceInfo, Mode};
use anyhow::{Context, Result, bail, ensure};
use nusb::{
    MaybeFuture,
    transfer::{Buffer, Bulk, In, Out},
};

const KIS_HEADER: usize = 12;
const KIS_ACK: usize = 20;
const KIS_INFO: usize = 788;
const KIS_CHUNK: usize = 0x4000;
const PORTAL_MAIN: u8 = 1;
const PORTAL_TARGET: u8 = 0x10;

pub(crate) struct Portal {
    output: nusb::Endpoint<Bulk, Out>,
    input: nusb::Endpoint<Bulk, In>,
}

impl Portal {
    fn exchange(&mut self, request: &[u8], length: usize) -> Result<Vec<u8>> {
        let sent = self
            .output
            .transfer_blocking(request.to_vec().into(), TIMEOUT);
        sent.status?;
        ensure!(sent.actual_len == request.len(), "short KIS USB write");
        let capacity = length.next_multiple_of(self.input.max_packet_size());
        let received = self.input.transfer_blocking(Buffer::new(capacity), TIMEOUT);
        received.status?;
        ensure!(received.actual_len <= length, "oversized KIS reply");
        Ok(received.buffer[..received.actual_len].to_vec())
    }
}

pub(crate) enum Kis {
    Native(Box<[Portal; 2]>),
    #[cfg(windows)]
    Apple(crate::windows::apple::AppleUsb),
}

impl Kis {
    pub(crate) fn open(device: &nusb::Device, info: &nusb::DeviceInfo) -> Result<Self> {
        let interface = match device.claim_interface(0).wait() {
            Ok(interface) => interface,
            Err(error) => {
                #[cfg(windows)]
                if let Some(apple) = crate::windows::apple::AppleUsb::open_kis(info)? {
                    return Ok(Self::Apple(apple));
                }
                return Err(error).context(
                    "claiming KIS interface; compatible Apple KIS or WinUSB driver required",
                );
            }
        };
        let _ = info;
        let mut kis = Self::Native(Box::new([
            Portal {
                output: interface.endpoint(1)?,
                input: interface.endpoint(0x81)?,
            },
            Portal {
                output: interface.endpoint(3)?,
                input: interface.endpoint(0x83)?,
            },
        ]));
        kis.write32(PORTAL_MAIN, 0x0a, 0x21)?;
        kis.write32(PORTAL_MAIN, 0x14, 1)?;
        Ok(kis)
    }

    fn exchange(
        &mut self,
        portal: u8,
        index: u16,
        args: &[u32],
        data: &[u8],
        words: u16,
        reply_len: usize,
    ) -> Result<Vec<u8>> {
        let request = packet(portal, index, args, data, words)?;
        match self {
            Self::Native(portals) => match portal {
                PORTAL_MAIN => portals[0].exchange(&request, reply_len),
                PORTAL_TARGET => portals[1].exchange(&request, reply_len),
                _ => bail!("unsupported KIS portal"),
            },
            #[cfg(windows)]
            Self::Apple(_) => bail!("raw KIS portals require WinUSB"),
        }
    }

    fn write32(&mut self, portal: u8, index: u16, value: u32) -> Result<()> {
        let reply = self.exchange(portal, index, &[value], &[], 1, KIS_ACK)?;
        check_reply(&reply)?;
        ensure!(
            u32_at(&reply, 12)? == 4,
            "KIS register write was not acknowledged"
        );
        Ok(())
    }

    pub(crate) fn info(&mut self) -> Result<DeviceInfo> {
        #[cfg(windows)]
        if let Self::Apple(apple) = self {
            return apple.kis_info();
        }
        let reply = self.exchange(PORTAL_TARGET, 0x100, &[], &[], 0xc0, KIS_INFO)?;
        device_info(&reply)
    }

    pub(crate) fn upload(&mut self, data: &[u8], finish: bool) -> Result<()> {
        ensure!(
            !data.is_empty() && u32::try_from(data.len()).is_ok(),
            "invalid KIS image size"
        );
        let mut progress =
            crate::progress::Progress::new("USB KIS transfer", Some(data.len() as u64), 0);
        for (index, chunk) in data.chunks(KIS_CHUNK).enumerate() {
            let address = index as u64 * KIS_CHUNK as u64;
            match self {
                #[cfg(windows)]
                Self::Apple(apple) => apple.kis_upload_chunk(address, chunk)?,
                _ => {
                    let reply = self.exchange(
                        PORTAL_TARGET,
                        0x0d,
                        &[address as u32, (address >> 32) as u32, chunk.len() as u32],
                        chunk,
                        0,
                        KIS_ACK,
                    )?;
                    check_reply(&reply)?;
                }
            }
            progress.advance(chunk.len() as u64);
        }
        progress.finish();
        if finish {
            match self {
                #[cfg(windows)]
                Self::Apple(apple) => apple.kis_boot(data.len() as u32)?,
                _ => self.write32(PORTAL_TARGET, 0x103, data.len() as u32)?,
            }
        }
        Ok(())
    }
}

/// One 12-byte KIS request header followed by arguments and inline data.
fn packet(portal: u8, index: u16, args: &[u32], data: &[u8], words: u16) -> Result<Vec<u8>> {
    ensure!(
        matches!(portal, PORTAL_MAIN | PORTAL_TARGET)
            && index < 1024
            && words < 16384
            && args.len() <= 255,
        "invalid KIS request header"
    );
    let length = u32::try_from(args.len() * 4 + data.len())?;
    let mut bytes = Vec::with_capacity(KIS_HEADER + length as usize);
    bytes.extend([
        0,
        0,
        0xa0,
        portal,
        args.len() as u8,
        index as u8,
        ((index >> 8) as u8 & 3) | ((words << 2) as u8 & 0xfc),
        (words >> 6) as u8,
    ]);
    bytes.extend(length.to_le_bytes());
    for arg in args {
        bytes.extend(arg.to_le_bytes());
    }
    bytes.extend(data);
    Ok(bytes)
}

fn u32_at(bytes: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .context("truncated KIS field")?
            .try_into()?,
    ))
}

fn check_reply(reply: &[u8]) -> Result<()> {
    ensure!(reply.len() == KIS_ACK, "invalid KIS acknowledgement length");
    let status = u32_at(reply, 16)?;
    ensure!(status == 0, "KIS request rejected with status {status:#x}");
    Ok(())
}

fn device_info(reply: &[u8]) -> Result<DeviceInfo> {
    ensure!(reply.len() == KIS_INFO, "invalid KIS device info length");
    ensure!(u32_at(reply, 784)? == 0, "KIS device info request rejected");
    let body = &reply[KIS_HEADER..KIS_INFO - 8];
    ensure!(
        body[64..66] == [18, 1] && body[72..74] == [0xac, 5],
        "invalid KIS USB device descriptor"
    );
    let pid = u16::from_le_bytes([body[74], body[75]]);
    let mode = Mode::from_pid(pid).context("KIS reported an unknown device mode")?;
    ensure!(
        mode == Mode::Dfu,
        "KIS firmware upload requires ROM DFU mode"
    );
    let serial = string(body, usize::from(body[80]))?;
    let nonces = string(body, u32_at(body, 24)? as usize)?;
    let mut info = DeviceInfo::parse(&serial, mode)?;
    info.set_nonces(&nonces)?;
    Ok(info)
}

/// Read one USB string descriptor from the KIS info body.
fn string(body: &[u8], word_offset: usize) -> Result<String> {
    let offset = word_offset
        .checked_mul(4)
        .context("KIS string offset overflow")?;
    let prefix = body
        .get(offset..offset + 2)
        .context("KIS string outside device info")?;
    // KIS lengths count the UTF-16 bytes following the two-byte header.
    let length = usize::from(prefix[0]);
    ensure!(
        prefix[1] == 3 && length > 0 && length.is_multiple_of(2),
        "invalid KIS string descriptor"
    );
    let bytes = body
        .get(offset + 2..offset + 2 + length)
        .context("truncated KIS string")?;
    let units = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .collect::<Vec<_>>();
    String::from_utf16(&units).context("invalid KIS UTF-16")
}

#[cfg(test)]
#[path = "../../tests/unit/usb/kis.rs"]
mod tests;
