//! USB inventory notifications without an async runtime or a watcher thread.
use futures_core::Stream;
use nusb::hotplug::HotplugWatch;
use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Wake, Waker},
    thread::{self, Thread},
    time::{Duration, Instant},
};

/// Subscribe before scanning devices to avoid missing a concurrent connection.
/// Notifications are hints: opening a Windows interface may still need retries.
pub struct DeviceEvents(Option<HotplugWatch>);

impl DeviceEvents {
    /// Fall back to timed retries if the host cannot provide notifications.
    pub fn new() -> Self {
        Self(
            nusb::watch_devices()
                .inspect_err(|error| {
                    crate::log!(
                        Warning,
                        "usb:watch",
                        "USB notifications unavailable: {error:#}"
                    );
                })
                .ok(),
        )
    }

    pub fn available(&self) -> bool {
        self.0.is_some()
    }

    /// Drain queued notifications and wake the caller when another one arrives.
    pub fn poll(&mut self, waker: &Waker) -> bool {
        self.0
            .as_mut()
            .is_some_and(|watch| poll_changes(watch, waker))
    }

    /// Wait for a change or the retry timeout, tolerating spurious wakeups.
    pub fn wait(&mut self, timeout: Duration) {
        let waker = Waker::from(Arc::new(ThreadWake(thread::current())));
        let deadline = Instant::now() + timeout;
        while !self.poll(&waker) {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            thread::park_timeout(remaining);
        }
    }
}

impl Default for DeviceEvents {
    fn default() -> Self {
        Self::new()
    }
}

fn poll_changes(stream: &mut (impl Stream + Unpin), waker: &Waker) -> bool {
    let mut cx = Context::from_waker(waker);
    let mut changed = false;
    // Bound work during a hotplug storm so the GUI and retry deadlines progress.
    for _ in 0..64 {
        match Pin::new(&mut *stream).poll_next(&mut cx) {
            std::task::Poll::Ready(Some(_)) => changed = true,
            _ => return changed,
        }
    }
    waker.wake_by_ref();
    changed
}

struct ThreadWake(Thread);

impl Wake for ThreadWake {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.unpark();
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/platform/usb/events.rs"]
mod tests;
