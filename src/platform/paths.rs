//! Application cache and settings directories, retaining each host's conventions.
use anyhow::{Context, Result};
use std::path::PathBuf;

pub(crate) fn available_space(path: &std::path::Path) -> std::io::Result<u64> {
    #[cfg(windows)]
    {
        super::windows::available_space(path)
    }
    #[cfg(not(windows))]
    {
        let stat = rustix::fs::statvfs(path)?;
        Ok(stat.f_frsize.saturating_mul(stat.f_bavail))
    }
}

fn absolute_env(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
}

/// Root shared by firmware cache, diagnostic logs and USB driver backups.
pub fn app_directory() -> Result<PathBuf> {
    let root = if cfg!(windows) {
        absolute_env("LOCALAPPDATA")
            .or_else(|| absolute_env("USERPROFILE").map(|path| path.join("AppData").join("Local")))
    } else {
        absolute_env("XDG_CACHE_HOME")
            .or_else(|| absolute_env("HOME").map(|path| path.join(".cache")))
    };
    let root = root.map_or_else(
        || std::env::current_dir().map(|path| path.join(".cache")),
        Ok,
    )?;
    Ok(root.join("zalivka"))
}

pub fn config_directory() -> Result<PathBuf> {
    let root = if cfg!(windows) {
        absolute_env("LOCALAPPDATA")
            .or_else(|| absolute_env("USERPROFILE").map(|path| path.join("AppData/Local")))
    } else {
        absolute_env("XDG_CONFIG_HOME")
            .or_else(|| absolute_env("HOME").map(|path| path.join(".config")))
    };
    Ok(root
        .context("could not locate the settings folder")?
        .join("zalivka"))
}
