//! Bounded metadata reads and portable free-space checks for firmware files.
use anyhow::{Context, Result, ensure};
use std::{
    io::Read,
    path::{Path, PathBuf},
};

pub(crate) fn read_limited(reader: impl Read, limit: u64, error: &str) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    reader
        .take(limit.saturating_add(1))
        .read_to_end(&mut data)?;
    ensure!(data.len() as u64 <= limit, "{error}");
    Ok(data)
}

pub fn available(path: &Path) -> Result<u64> {
    let path = path.canonicalize().context("locating storage volume")?;
    fs4::available_space(path).context("checking available storage")
}

pub fn require(path: &Path, bytes: u64) -> Result<()> {
    let free = available(path)?;
    ensure!(
        free >= bytes,
        "insufficient disk space: need {bytes} bytes, available {free} on {}",
        path.display()
    );
    Ok(())
}

pub use crate::platform::{app_directory, config_directory};

/// Create the existing application log directory without changing its location.
pub fn log_directory() -> Result<PathBuf> {
    let directory = app_directory()?.join("logs");
    std::fs::create_dir_all(&directory)?;
    Ok(directory)
}

/// Replace a small settings file only after the complete new value is written.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let directory = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(directory)?;
    let mut saved = tempfile::NamedTempFile::new_in(directory)?;
    saved.write_all(bytes)?;
    saved.persist(path).context("saving settings")?;
    Ok(())
}

#[cfg(test)]
#[path = "../tests/unit/storage.rs"]
mod tests;
