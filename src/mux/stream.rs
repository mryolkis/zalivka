//! Per-service reads, bounded writes, ACK waiting and transfer accounting.
use super::{ACK, MAX_PAYLOAD, RST, Session, State, WRITE_BATCH, yield_link};
use anyhow::Result;
use std::{
    io::{Read, Write},
    sync::atomic::Ordering,
    time::{Duration, Instant},
};

const ACK_AFTER_BYTES: usize = 16_384;
const WRITE_TIMEOUT: Duration = Duration::from_secs(300);
const WINDOW_POLL_LIMIT: usize = 64;

#[derive(Default)]
struct WriteProfile {
    bytes: u64,
    calls: u64,
    errors: u64,
    elapsed: Duration,
    usb_out: Duration,
    window_stalls: u64,
    event_waits: u64,
    event_wakeups: u64,
}

impl WriteProfile {
    fn record(&mut self, started: Instant, failed: bool) {
        self.elapsed += started.elapsed();
        self.calls += 1;
        self.errors += u64::from(failed);
    }
}

pub struct MuxStream {
    session: Session,
    source: u16,
    destination: u16,
    read_timeout: Duration,
    log_source: &'static str,
    received: u64,
    profile: WriteProfile,
}

impl MuxStream {
    pub(super) fn new(session: Session, source: u16, destination: u16) -> Self {
        Self {
            session,
            source,
            destination,
            read_timeout: Duration::from_secs(300),
            log_source: "usbmux:io",
            received: 0,
            profile: WriteProfile::default(),
        }
    }

    pub fn has_pending_input(&self) -> Result<bool> {
        let link = self.session.lock()?;
        Ok(link
            .channels
            .get(&self.source)
            .is_some_and(|channel| !channel.input.is_empty()))
    }

    pub fn set_read_timeout(&mut self, timeout: Duration) {
        crate::log!(
            Trace,
            "usbmux:io",
            "{} -> {}: read timeout={timeout:?}",
            self.source,
            self.destination
        );
        self.read_timeout = timeout;
    }

    pub(crate) fn set_log_source(&mut self, source: &'static str) {
        self.log_source = source;
    }

    pub(crate) fn local_port(&self) -> u16 {
        self.source
    }

    pub fn read_timeout(&self) -> Duration {
        self.read_timeout
    }

    /// A write() remains one packet so its error cannot discard a partial
    /// success. write_all() may send a bounded batch under one lock: its API
    /// already reports an error after a partially written buffer.
    fn write_packets(
        &mut self,
        data: &[u8],
        limit: usize,
        stop_on_input: bool,
    ) -> std::io::Result<Option<usize>> {
        if data.is_empty() {
            return Ok(Some(0));
        }
        let deadline = Instant::now() + WRITE_TIMEOUT;
        let mut pending_polls = 0;
        loop {
            let mut link = self.session.lock()?;
            if link.cancelled.load(Ordering::Acquire) {
                return Err(std::io::Error::other("USB mux session cancelled"));
            }
            let window = {
                let channel = link
                    .channels
                    .get_mut(&self.source)
                    .ok_or_else(|| std::io::Error::other("mux channel closed"))?;
                channel.firmware_transfer = crate::logging::firmware_transfer_active();
                if channel.state == State::Closed {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "device closed service",
                    ));
                }
                let outstanding = channel.seq.wrapping_sub(channel.peer_ack);
                Window {
                    available: channel.window.saturating_sub(outstanding) as usize,
                    outstanding,
                    has_input: !channel.input.is_empty(),
                    seq: channel.seq,
                    peer_ack: channel.peer_ack,
                    size: channel.window,
                }
            };
            if stop_on_input && window.available == 0 && window.has_input {
                return Ok(None);
            }
            if window.available == 0 && pending_polls == 0 {
                crate::log!(
                    Trace,
                    "usbmux:tcp",
                    "{} -> {}: waiting for window; seq={}, ack={}, window={}",
                    self.source,
                    self.destination,
                    window.seq,
                    window.peer_ack,
                    window.size
                );
            }
            // The available window may be based on an old ACK while newer ACKs
            // are already queued. Drain ready input before sizing a USB burst,
            // so a stale window does not reduce it to one synchronous packet.
            // Never wait for more space when some is available: small windows
            // and peers delaying their next ACK must still make progress.
            if window.available != 0
                && window.available < data.len().min(limit)
                && window.outstanding != 0
                && pending_polls < WINDOW_POLL_LIMIT
            {
                pending_polls += 1;
                if link.pump().map_err(std::io::Error::other)? {
                    drop(link);
                    std::thread::yield_now();
                    continue;
                }
            }
            if window.available != 0 {
                let n = data.len().min(window.available).min(limit);
                // Keep intermediate batches on packet boundaries. A short tail
                // here would create another USB transfer at every window edge.
                // Small windows and the caller's final tail still go out now.
                let n = if n < data.len() && n >= MAX_PAYLOAD {
                    n / MAX_PAYLOAD * MAX_PAYLOAD
                } else {
                    n
                };
                let usb_before = link.usb_write_time;
                crate::logging::bytes(
                    self.log_source,
                    format_args!(
                        "{} -> {} TX offset={}",
                        self.source, self.destination, self.profile.bytes
                    ),
                    &data[..n],
                );
                let sent = link.send_data(self.source, &data[..n]);
                self.profile.usb_out += link.usb_write_time - usb_before;
                if let Err(error) = sent {
                    crate::log!(
                        Trace,
                        "usbmux:io",
                        "{} -> {}: write failed: {error:#}",
                        self.source,
                        self.destination
                    );
                    return Err(std::io::Error::other(error));
                }
                self.profile.bytes += n as u64;
                return Ok(Some(n));
            }
            if Instant::now() >= deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "mux send window timeout",
                ));
            }
            self.profile.window_stalls += 1;
            let progressed = link.pump().map_err(std::io::Error::other)?;
            let ready = if progressed {
                None
            } else {
                link.usb.input_ready()
            };
            drop(link);
            if let Some(ready) = ready {
                self.profile.event_waits += 1;
                let waited = ready.wait(Duration::from_millis(1));
                if let Ok(true) = waited {
                    self.profile.event_wakeups += 1;
                }
                // Other channels still get a chance to acquire the link. Idle
                // readers retain their existing backoff against starvation.
                std::thread::yield_now();
                waited.map(|_| ()).map_err(std::io::Error::other)?;
            } else {
                yield_link(progressed);
            }
        }
    }

    /// Yield a blocked file write to its incoming key request. Some(n) counts
    /// bytes committed once; None means input is ready and no bytes were sent.
    pub(crate) fn write_until_input(&mut self, data: &[u8]) -> std::io::Result<Option<usize>> {
        let started = Instant::now();
        let result = self.write_packets(data, WRITE_BATCH, true);
        self.profile.record(started, result.is_err());
        result
    }
}

/// The channel values needed to decide how much a write may send.
struct Window {
    available: usize,
    outstanding: u32,
    has_input: bool,
    seq: u32,
    peer_ack: u32,
    size: u32,
}

impl Read for MuxStream {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        let deadline = Instant::now() + self.read_timeout;
        loop {
            let mut link = self.session.lock()?;
            if link.cancelled.load(Ordering::Acquire) {
                return Err(std::io::Error::other("USB mux session cancelled"));
            }
            let channel = link
                .channels
                .get_mut(&self.source)
                .ok_or_else(|| std::io::Error::other("mux channel closed"))?;
            channel.firmware_transfer = crate::logging::firmware_transfer_active();
            if !channel.input.is_empty() {
                let n = channel.input.read(out)?;
                crate::logging::bytes(
                    self.log_source,
                    format_args!(
                        "{} -> {} RX offset={}",
                        self.destination, self.source, self.received
                    ),
                    &out[..n],
                );
                self.received += n as u64;
                channel.consumed += n;
                if channel.consumed >= ACK_AFTER_BYTES {
                    channel.consumed = 0;
                    // The bytes are already in the caller's buffer. Report
                    // that success; a failed ACK cancels the next operation.
                    let _ = link.send_tcp(self.source, ACK, &[]);
                }
                return Ok(n);
            }
            let closed = channel.state == State::Closed;
            if closed {
                crate::log!(
                    Trace,
                    "usbmux:io",
                    "{} -> {}: EOF",
                    self.destination,
                    self.source
                );
                return Ok(0);
            }
            if Instant::now() >= deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "mux read timeout",
                ));
            }
            let progressed = link.pump().map_err(std::io::Error::other)?;
            drop(link);
            yield_link(progressed);
        }
    }
}

impl Write for MuxStream {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let started = Instant::now();
        let sent = self
            .write_packets(data, MAX_PAYLOAD, false)
            .map(|sent| sent.unwrap_or_default());
        self.profile.record(started, sent.is_err());
        sent
    }

    fn write_all(&mut self, mut data: &[u8]) -> std::io::Result<()> {
        let started = Instant::now();
        let result = (|| {
            while !data.is_empty() {
                let sent = self
                    .write_packets(data, WRITE_BATCH, false)?
                    .unwrap_or_default();
                data = &data[sent..];
            }
            Ok(())
        })();
        self.profile.record(started, result.is_err());
        result
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for MuxStream {
    fn drop(&mut self) {
        crate::log!(
            Trace,
            "usbmux:io",
            "{} -> {}: closing",
            self.source,
            self.destination
        );
        if let Ok(mut link) = self.session.lock()
            && link.channels.contains_key(&self.source)
        {
            let _ = link.send_tcp(self.source, RST, &[]);
            link.channels.remove(&self.source);
        }
        if self.profile.bytes >= 1024 * 1024 || self.profile.errors != 0 {
            let profile = &self.profile;
            crate::log!(
                Trace,
                "usbmux:stats",
                "Profile {} -> {}: bytes={}, calls={}, errors={}, elapsed={:.3}s, usb={:.3}s, stalls={}, event_waits={}, wakeups={}",
                self.source,
                self.destination,
                profile.bytes,
                profile.calls,
                profile.errors,
                profile.elapsed.as_secs_f64(),
                profile.usb_out.as_secs_f64(),
                profile.window_stalls,
                profile.event_waits,
                profile.event_wakeups
            );
        }
    }
}

#[cfg(test)]
#[path = "../../tests/unit/mux/stream.rs"]
mod tests;
