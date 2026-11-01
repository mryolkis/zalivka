//! Console, fonts and opening folders through the host desktop.
use anyhow::{Context, Result};
use std::{
    path::Path,
    process::{Command, Stdio},
};

/// Reuse the caller's terminal for CLI commands in a Windows GUI build.
#[allow(unsafe_code)]
pub fn attach_parent_console() {
    #[cfg(windows)]
    unsafe {
        windows_sys::Win32::System::Console::AttachConsole(
            windows_sys::Win32::System::Console::ATTACH_PARENT_PROCESS,
        );
    }
}

pub fn system_font() -> Option<Vec<u8>> {
    #[cfg(windows)]
    {
        let windows = std::env::var_os("WINDIR")?;
        std::fs::read(std::path::PathBuf::from(windows).join("Fonts/segoeui.ttf")).ok()
    }
    #[cfg(not(windows))]
    None
}

pub fn open_directory(directory: &Path) -> Result<()> {
    #[cfg(windows)]
    let opener = "explorer.exe";
    #[cfg(target_os = "macos")]
    let opener = "open";
    #[cfg(not(any(windows, target_os = "macos")))]
    let opener = "xdg-open";
    let mut child = Command::new(opener)
        .arg(directory)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("opening firmware directory")?;
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(())
}
