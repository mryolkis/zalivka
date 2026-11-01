//! Enter DFU on a target Mac through the host's Apple USB-C controller.
mod elevation;
#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
mod hpm;
mod protocol;
#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
pub(crate) mod proxy;

#[cfg(target_os = "macos")]
use anyhow::{Result, ensure};

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
        elevation::run()?;
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

/// Internal entry point for the temporary authorizer and privileged DFU worker.
#[cfg(target_os = "macos")]
pub fn run_dfu_helper(prompt: Option<&str>) -> Result<()> {
    ensure!(
        cfg!(target_arch = "aarch64"),
        "Automatic DFU entry requires an Apple silicon host and target"
    );
    if !hpm::is_root() {
        return elevation::authorize(
            prompt.unwrap_or("Zalivka: Enter DFU mode"),
            std::io::stdout().lock(),
        );
    }
    elevation::report(hpm::enter_dfu, std::io::stdout().lock())
}
