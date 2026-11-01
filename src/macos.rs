//! Enter DFU on a target Mac through the host's Apple USB-C controller.
#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
mod hpm;
mod protocol;

#[cfg(target_os = "macos")]
use anyhow::{Context, Result, ensure};

/// Reboot the Mac connected to the host DFU port, then confirm USB DFU appears.
/// The GUI remains unprivileged; macOS authorizes only the short-lived helper.
#[cfg(target_os = "macos")]
pub fn enter_dfu() -> Result<()> {
    ensure!(
        cfg!(target_arch = "aarch64"),
        "Automatic DFU entry requires an Apple silicon host and target"
    );
    ensure!(
        !crate::usb::detect()?
            .iter()
            .any(|device| device.mode.can_restore()),
        "A Mac is already in DFU mode"
    );
    if hpm::is_root() {
        hpm::enter_dfu()?;
    } else {
        let executable = std::env::current_exe().context("locating the Zalivka executable")?;
        let output = std::process::Command::new("/usr/bin/osascript")
            .args(["-e", ELEVATION_SCRIPT, "--"])
            .arg(executable)
            .stdin(std::process::Stdio::null())
            .output()
            .context("requesting macOS administrator authorization")?;
        for line in String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter(|line| !line.is_empty())
        {
            crate::log!(Info, "dfu", "{line}");
        }
        ensure!(
            output.status.success(),
            "macOS DFU helper failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    crate::progress::Event::Checkpoint {
        name: "Waiting for DFU".into(),
        complete: false,
    }
    .emit();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let mut last_error = None;
    loop {
        match crate::usb::detect() {
            Ok(devices) => {
                if let Some(device) = devices.iter().find(|device| device.mode.can_restore()) {
                    crate::log!(Info, "dfu", "DFU confirmed: ECID {:016x}", device.ecid);
                    return Ok(());
                }
            }
            Err(error) => last_error = Some(error),
        }
        if std::time::Instant::now() >= deadline {
            return Err(last_error.unwrap_or_else(|| anyhow::anyhow!("The target did not appear in DFU mode after the USB-C command; check the cable and DFU ports")));
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
}

#[cfg(target_os = "macos")]
const ELEVATION_SCRIPT: &str = r#"on run argv
    do shell script (quoted form of (item 1 of argv) & " enter-dfu-helper 2>&1") with administrator privileges
end run"#;

/// Internal executable entry point used by the macOS authorization prompt.
#[cfg(target_os = "macos")]
pub fn run_dfu_helper() -> Result<()> {
    ensure!(
        cfg!(target_arch = "aarch64"),
        "Automatic DFU entry requires an Apple silicon host and target"
    );
    ensure!(
        hpm::is_root(),
        "The DFU helper requires macOS administrator authorization"
    );
    hpm::enter_dfu()
}
