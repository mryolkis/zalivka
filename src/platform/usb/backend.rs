//! Native nusb and AppleUsbFilter endpoints, ordered bursts and pending reads.
use super::TIMEOUT;
#[cfg(windows)]
use crate::platform::windows::{
    apple::{AppleUsb, BulkReader},
    reset,
};
#[cfg(windows)]
use anyhow::bail;
use anyhow::{Context, Result, ensure};
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
use nusb::transfer::In;
use nusb::{
    Device, Interface, MaybeFuture,
    transfer::{Buffer, Bulk, ControlIn, ControlOut, Out},
};
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
use std::{
    sync::Arc,
    task::{Context as TaskContext, Poll, Waker},
};
use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

#[cfg(any(not(any(target_os = "linux", target_os = "macos")), test))]
#[path = "completion.rs"]
mod completion;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
use completion::CompletionReady;

/// Use the normal OS USB backend first, then Apple's installed Windows filter.
pub(crate) enum UsbInterface {
    Native(Interface),
    #[cfg(windows)]
    Apple(AppleUsb),
}

impl UsbInterface {
    pub(crate) fn claim(device: &Device, _info: &nusb::DeviceInfo, number: u8) -> Result<Self> {
        match device.claim_interface(number).wait() {
            Ok(interface) => Ok(Self::Native(interface)),
            Err(error) => {
                #[cfg(windows)]
                match AppleUsb::open(_info, number) {
                    Ok(Some(apple)) => return Ok(Self::Apple(apple)),
                    Ok(None) => {}
                    Err(apple) => {
                        return Err(apple).with_context(|| {
                            format!("WinUSB failed ({error}); Apple USB fallback failed")
                        });
                    }
                }
                Err(error).with_context(|| format!("claiming USB interface {number}"))
            }
        }
    }

    pub(crate) fn transport(&self) -> &'static str {
        match self {
            Self::Native(_) => {
                if cfg!(windows) {
                    "winusb"
                } else if cfg!(target_os = "macos") {
                    "iokit"
                } else {
                    "usbfs"
                }
            }
            #[cfg(windows)]
            Self::Apple(_) => "apple_usb",
        }
    }

    #[cfg(windows)]
    pub(crate) fn check_reset_access(&self, info: &nusb::DeviceInfo) -> Result<()> {
        match self {
            Self::Native(_) => reset::check_access(info),
            // Reset uses the same already-open Apple handle as control transfers.
            Self::Apple(_) => Ok(()),
        }
    }

    pub(super) fn set_alt_setting(&self, alt: u8) -> Result<()> {
        if alt == 0 {
            return Ok(());
        }
        match self {
            Self::Native(i) => i.set_alt_setting(alt).wait().map_err(Into::into),
            #[cfg(windows)]
            Self::Apple(_) => bail!(
                "Apple USB driver does not expose alternate setting {alt}; use a compatible WinUSB driver for this interface"
            ),
        }
    }

    pub(crate) fn control_in(&self, request: ControlIn, timeout: Duration) -> Result<Vec<u8>> {
        match self {
            Self::Native(i) => i.control_in(request, timeout).wait().map_err(Into::into),
            #[cfg(windows)]
            Self::Apple(i) => i.control_in(request, timeout),
        }
    }

    pub(super) fn control_out(&self, request: ControlOut<'_>, timeout: Duration) -> Result<()> {
        match self {
            Self::Native(i) => i.control_out(request, timeout).wait().map_err(Into::into),
            #[cfg(windows)]
            Self::Apple(i) => i.control_out(request, timeout),
        }
    }

    pub(super) fn bulk_out(&self, address: u8) -> Result<BulkOutput> {
        match self {
            Self::Native(i) => Ok(BulkOutput::Native {
                endpoint: i.endpoint(address)?,
                buffers: Vec::new(),
            }),
            #[cfg(windows)]
            Self::Apple(i) => Ok(BulkOutput::Apple(i.clone(), i.pipe(address)?)),
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    pub(super) fn bulk_in(&self, address: u8) -> Result<BulkInput> {
        match self {
            Self::Native(i) => Ok(BulkInput::Native {
                endpoint: i.endpoint(address)?,
                ready: Arc::new(CompletionReady::default()),
            }),
            #[cfg(windows)]
            Self::Apple(i) => Ok(BulkInput::Apple(BulkReader::new(
                i.clone(),
                i.pipe(address)?,
            )?)),
        }
    }
}

pub(super) enum BulkOutput {
    Native {
        endpoint: nusb::Endpoint<Bulk, Out>,
        buffers: Vec<Buffer>,
    },
    #[cfg(windows)]
    Apple(AppleUsb, u8),
}

impl BulkOutput {
    pub(super) fn write_batch(
        &mut self,
        packets: &[&[u8]],
        cancelled: Option<&AtomicBool>,
    ) -> Result<()> {
        match self {
            Self::Native { endpoint, buffers } => {
                let result = (|| {
                    let deadline = Instant::now() + TIMEOUT;
                    // Bound both outstanding requests and retained allocations.
                    for burst in packets.chunks(8) {
                        for packet in burst {
                            ensure!(
                                !cancelled.is_some_and(|c| c.load(Ordering::Acquire)),
                                "USB mux session cancelled"
                            );
                            let buffer =
                                fill_buffer(buffers.pop(), packet, |len| endpoint.allocate(len));
                            endpoint.submit(buffer);
                        }
                        for packet in burst {
                            ensure!(
                                !cancelled.is_some_and(|c| c.load(Ordering::Acquire)),
                                "USB mux session cancelled"
                            );
                            let sent = endpoint
                                .wait_next_complete(
                                    deadline.saturating_duration_since(Instant::now()),
                                )
                                .context("USB bulk write burst timed out")?;
                            buffers.push(sent.buffer);
                            sent.status?;
                            ensure!(sent.actual_len == packet.len(), "short USB bulk write");
                        }
                    }
                    Ok(())
                })();
                if result.is_err() {
                    // Retain all buffers until the cancelled requests complete.
                    cancel_and_drain(endpoint);
                }
                result
            }
            #[cfg(windows)]
            Self::Apple(device, pipe) => {
                // AppleUsbFilter 538 dispatches OUT IOCTLs in parallel and
                // calls synchronous WinUsb_WritePipe from each handler. More
                // than one pending IOCTL can reorder mux/TCP frames before
                // WinUSB sees them. Complete each request before the next;
                // the shared mux batch and ready-ACK processing still apply.
                for packet in packets {
                    ensure!(
                        !cancelled.is_some_and(|c| c.load(Ordering::Acquire)),
                        "USB mux session cancelled"
                    );
                    device.bulk_out(*pipe, packet, TIMEOUT)?;
                }
                Ok(())
            }
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(super) enum BulkInput {
    Native {
        endpoint: nusb::Endpoint<Bulk, In>,
        ready: Arc<CompletionReady>,
    },
    #[cfg(windows)]
    Apple(BulkReader),
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
impl BulkInput {
    pub(super) fn input_ready(&self) -> Option<crate::mux::InputReady> {
        match self {
            Self::Native { ready, .. } => {
                let ready = ready.clone();
                Some(crate::mux::InputReady::new(move |timeout| {
                    Ok(ready.wait(timeout))
                }))
            }
            #[cfg(windows)]
            Self::Apple(reader) => reader.input_ready(),
        }
    }

    pub(super) fn read(&mut self) -> Result<Vec<u8>> {
        match self {
            Self::Native { endpoint, ready } => {
                // Keep input queued while mux workers process earlier packets.
                while endpoint.pending() < 4 {
                    endpoint.submit(endpoint.allocate(65536));
                }
                ready.clear();
                let waker = Waker::from(ready.clone());
                let mut cx = TaskContext::from_waker(&waker);
                let Poll::Ready(mut completion) = endpoint.poll_next_complete(&mut cx) else {
                    return Ok(Vec::new());
                };
                match completion.status {
                    // Windows may cancel IN when its submitting service worker
                    // exits. Preserve any partial input and rearm on this worker.
                    Ok(()) | Err(nusb::transfer::TransferError::Cancelled) => {}
                    Err(error) => return Err(error.into()),
                }
                let data = completion.buffer[..completion.actual_len].to_vec();
                completion.buffer.clear();
                endpoint.submit(completion.buffer);
                // Poll again before waiting: the next queued request may already
                // be complete and has not yet registered its own waker.
                ready.signal();
                Ok(data)
            }
            #[cfg(windows)]
            Self::Apple(reader) => reader.read(),
        }
    }
}

/// Cancellation is asynchronous: retire every request before releasing its buffer.
fn cancel_and_drain(endpoint: &mut nusb::Endpoint<Bulk, Out>) {
    endpoint.cancel_all();
    while endpoint.pending() != 0 {
        let _ = endpoint.wait_next_complete(Duration::from_secs(1));
    }
}

fn fill_buffer(
    buffer: Option<Buffer>,
    data: &[u8],
    allocate: impl FnOnce(usize) -> Buffer,
) -> Buffer {
    let mut buffer = buffer
        .filter(|buffer| buffer.capacity() >= data.len())
        .unwrap_or_else(|| allocate(data.len()));
    buffer.clear();
    buffer.extend_from_slice(data);
    buffer
}

#[cfg(test)]
#[path = "../../../tests/unit/platform/usb/backend.rs"]
mod tests;
