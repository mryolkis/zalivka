//! Service streams: system usbmuxd on Linux/macOS, direct USB on Windows.
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::platform::unix::mux as daemon;
mod direct;

use anyhow::{Result, ensure};
use std::{
    io::{self, Read, Write},
    time::{Duration, Instant},
};

pub use crate::platform::usb::is_device_removal;
pub(crate) use direct::MAX_PAYLOAD;
pub use direct::{InputReady, Packet, PacketTransport, decode_packet};

#[derive(Clone)]
pub struct Session(Backend);

#[derive(Clone)]
enum Backend {
    Direct(direct::Session),
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    System(daemon::Session),
}

impl Session {
    pub fn new(usb: impl PacketTransport + 'static) -> Result<Self> {
        Ok(Self(Backend::Direct(direct::Session::new(usb)?)))
    }

    pub(crate) fn candidates() -> Result<Vec<Result<Self>>> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        return daemon::candidates().map(|sessions| {
            sessions
                .into_iter()
                .map(|s| Ok(Self::from_system(s)))
                .collect()
        });
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        crate::usb::MuxUsb::candidates().map(|devices| {
            devices
                .iter()
                .map(|candidate| Self::new(crate::usb::MuxUsb::open(candidate)?))
                .collect()
        })
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(crate) fn from_system(session: daemon::Session) -> Self {
        Self(Backend::System(session))
    }

    pub fn connect(&self, destination: u16) -> Result<MuxStream> {
        self.connect_until(destination, Instant::now() + Duration::from_secs(30))
    }

    /// Services may start listening after their data request. Retry only explicit
    /// refusals; transport and framing errors must not hide an uncertain request.
    pub fn connect_retry(&self, destination: u16, timeout: Duration) -> Result<MuxStream> {
        let deadline = Instant::now() + timeout;
        loop {
            ensure!(Instant::now() < deadline, "service connection timed out");
            let attempt = deadline.min(Instant::now() + Duration::from_secs(30));
            match self.connect_until(destination, attempt) {
                Ok(stream) => return Ok(stream),
                Err(error)
                    if error
                        .downcast_ref::<io::Error>()
                        .is_some_and(|e| e.kind() == io::ErrorKind::ConnectionRefused) =>
                {
                    if Instant::now() >= deadline {
                        return Err(error);
                    }
                    std::thread::sleep(
                        Duration::from_millis(100)
                            .min(deadline.saturating_duration_since(Instant::now())),
                    );
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn connect_until(&self, destination: u16, deadline: Instant) -> Result<MuxStream> {
        Ok(MuxStream(match &self.0 {
            Backend::Direct(session) => {
                Stream::Direct(session.connect_until(destination, deadline)?)
            }
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            Backend::System(session) => Stream::System(session.connect(destination, deadline)?),
        }))
    }

    pub fn cancel(&self) {
        match &self.0 {
            Backend::Direct(session) => session.cancel(),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            Backend::System(session) => session.cancel(),
        }
    }

    /// A closed service alone does not confirm physical device removal.
    pub fn disconnected(&self) -> bool {
        match &self.0 {
            Backend::Direct(session) => session.disconnected(),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            Backend::System(session) => session.disconnected(),
        }
    }
}

pub struct MuxStream(Stream);

enum Stream {
    Direct(direct::MuxStream),
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    System(daemon::Stream),
}

macro_rules! dispatch {
    ($self:ident, $stream:ident => $call:expr) => {
        match &mut $self.0 {
            Stream::Direct($stream) => $call,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            Stream::System($stream) => $call,
        }
    };
}

impl MuxStream {
    pub fn has_pending_input(&self) -> Result<bool> {
        match &self.0 {
            Stream::Direct(s) => s.has_pending_input(),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            Stream::System(s) => s.has_pending_input(),
        }
    }

    pub fn set_read_timeout(&mut self, timeout: Duration) {
        dispatch!(self, s => s.set_read_timeout(timeout))
    }

    pub fn read_timeout(&self) -> Duration {
        match &self.0 {
            Stream::Direct(s) => s.read_timeout(),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            Stream::System(s) => s.read_timeout(),
        }
    }

    pub(crate) fn set_log_source(&mut self, source: &'static str) {
        dispatch!(self, s => s.set_log_source(source))
    }

    pub(crate) fn local_port(&self) -> u16 {
        match &self.0 {
            Stream::Direct(s) => s.local_port(),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            Stream::System(s) => s.local_port(),
        }
    }

    pub(crate) fn write_until_input(&mut self, data: &[u8]) -> io::Result<Option<usize>> {
        dispatch!(self, s => s.write_until_input(data))
    }
}

impl Read for MuxStream {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        dispatch!(self, s => s.read(out))
    }
}

impl Write for MuxStream {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        dispatch!(self, s => s.write(data))
    }

    fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
        dispatch!(self, s => s.write_all(data))
    }

    fn flush(&mut self) -> io::Result<()> {
        dispatch!(self, s => s.flush())
    }
}
