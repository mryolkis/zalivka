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

fn base_directory(xdg: &str, fallback: &str) -> Option<PathBuf> {
    let (configured, home, fallback) = if cfg!(windows) {
        ("LOCALAPPDATA", "USERPROFILE", "AppData/Local")
    } else {
        (xdg, "HOME", fallback)
    };
    absolute_env(configured).or_else(|| absolute_env(home).map(|path| path.join(fallback)))
}

/// Root shared by firmware cache, diagnostic logs and USB driver backups.
pub fn app_directory() -> Result<PathBuf> {
    let root = base_directory("XDG_CACHE_HOME", ".cache").map_or_else(
        || std::env::current_dir().map(|path| path.join(".cache")),
        Ok,
    )?;
    Ok(root.join("zalivka"))
}

pub fn config_directory() -> Result<PathBuf> {
    Ok(base_directory("XDG_CONFIG_HOME", ".config")
        .context("could not locate the settings folder")?
        .join("zalivka"))
}
