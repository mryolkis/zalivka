//! Share nusb wakeups with mux workers without holding the USB link lock.
use std::{
    sync::{Arc, Condvar, Mutex},
    task::Wake,
    time::Duration,
};

#[derive(Default)]
pub(in crate::platform::usb) struct CompletionReady {
    ready: Mutex<bool>,
    changed: Condvar,
}

impl CompletionReady {
    pub(super) fn clear(&self) {
        *self.ready.lock().unwrap_or_else(|e| e.into_inner()) = false;
    }

    pub(super) fn signal(&self) {
        *self.ready.lock().unwrap_or_else(|e| e.into_inner()) = true;
        self.changed.notify_all();
    }

    pub(super) fn wait(&self, timeout: Duration) -> bool {
        let ready = self.ready.lock().unwrap_or_else(|e| e.into_inner());
        let (ready, _) = self
            .changed
            .wait_timeout_while(ready, timeout, |ready| !*ready)
            .unwrap_or_else(|e| e.into_inner());
        *ready
    }
}

impl Wake for CompletionReady {
    fn wake(self: Arc<Self>) {
        self.signal();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.signal();
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/platform/usb/completion.rs"]
mod tests;
