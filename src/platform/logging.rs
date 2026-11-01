//! Forward elevated Windows helper logs to the unprivileged application.
use crate::logging::Record;
use std::{io, sync::OnceLock};

static ELEVATED: OnceLock<std::sync::Mutex<std::fs::File>> = OnceLock::new();

/// Only a local named pipe can receive elevated logs, never an arbitrary file.
pub fn connect_elevated(id: uuid::Uuid) -> io::Result<()> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::SECURITY_IDENTIFICATION;
    let pipe = std::fs::OpenOptions::new()
        .write(true)
        // The unprivileged log reader must not impersonate the elevated writer.
        .security_qos_flags(SECURITY_IDENTIFICATION)
        .open(format!(r"\\.\pipe\zalivka-elevated-{id}"))?;
    ELEVATED
        .set(std::sync::Mutex::new(pipe))
        .map_err(|_| io::Error::other("elevated logging is already connected"))
}

pub(crate) fn write_elevated(record: &Record) -> bool {
    if let Some(pipe) = ELEVATED.get() {
        let mut pipe = pipe.lock().unwrap_or_else(|error| error.into_inner());
        if record.write_json(&mut *pipe).is_ok() {
            return true;
        }
    }
    false
}
