//! Apple USB transports and the portable recovery protocol contract.
use anyhow::Result;

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) use crate::platform::usb::MuxUsb;
pub use crate::platform::usb::{DeviceEvents, RecoveryUsb, detect};

pub trait RecoveryTransport {
    fn control_in(
        &mut self,
        kind: u8,
        request: u8,
        value: u16,
        index: u16,
        length: u16,
    ) -> Result<Vec<u8>>;
    fn control_out(
        &mut self,
        kind: u8,
        request: u8,
        value: u16,
        index: u16,
        data: &[u8],
    ) -> Result<()>;
    fn bulk_out(&mut self, data: &[u8]) -> Result<()>;
    /// Complete every packet in order before returning. A backend may queue
    /// transfers, but must cancel and drain them on failure without replaying.
    fn bulk_out_batch(&mut self, packets: &[&[u8]]) -> Result<()> {
        for packet in packets {
            self.bulk_out(packet)?;
        }
        Ok(())
    }
    fn reset(&mut self) -> Result<()>;
    /// A transport can implement ROM DFU without USB DFU control requests.
    /// Return true only after completing the complete transfer.
    fn upload_dfu(&mut self, _data: &[u8], _finish: bool) -> Result<bool> {
        Ok(false)
    }
}
