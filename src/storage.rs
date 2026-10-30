//! Bounded metadata reads and portable application/configuration locations.
use anyhow::{Context, Result, ensure};
use std::{
    io::Read,
    path::{Path, PathBuf},
};

/// Read at most `limit` bytes, reporting the caller's message when it overflows.
///
/// One byte past the limit is consumed so the error is detected without
/// trusting the reader's reported length.
pub(crate) fn read_limited(mut reader: impl Read, limit: u64, error: &str) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    reader
        .by_ref()
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

/// An environment directory, accepted only when absolute.
fn environment(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
}

/// The user cache root, falling back to a directory in the working directory.
fn cache_root() -> Result<PathBuf> {
    let root = if cfg!(windows) {
        environment("LOCALAPPDATA")
            .or_else(|| environment("USERPROFILE").map(|path| path.join("AppData").join("Local")))
    } else {
        environment("XDG_CACHE_HOME")
            .or_else(|| environment("HOME").map(|path| path.join(".cache")))
    };
    match root {
        Some(path) => Ok(path),
        None => Ok(std::env::current_dir()?.join(".cache")),
    }
}

/// Root shared by firmware cache, diagnostic logs and USB driver backups.
pub fn app_directory() -> Result<PathBuf> {
    Ok(cache_root()?.join("zalivka"))
}

/// Create the application log directory without relocating it.
pub fn log_directory() -> Result<PathBuf> {
    let directory = app_directory()?.join("logs");
    std::fs::create_dir_all(&directory)?;
    Ok(directory)
}

pub fn config_directory() -> Result<PathBuf> {
    let root = if cfg!(windows) {
        environment("LOCALAPPDATA")
            .or_else(|| environment("USERPROFILE").map(|path| path.join("AppData/Local")))
    } else {
        environment("XDG_CONFIG_HOME")
            .or_else(|| environment("HOME").map(|path| path.join(".config")))
    };
    Ok(root
        .context("could not locate the settings folder")?
        .join("zalivka"))
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
