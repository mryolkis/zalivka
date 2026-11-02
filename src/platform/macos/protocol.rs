// SPDX-License-Identifier: Apache-2.0
// Adapted from macvdmtool (Asahi Linux Contributors, 2021) and
// ThunderboltPatcher (osy86, 2019). See licenses/macvdmtool-APACHE-2.0.txt.
//! Apple USB-PD command sequence, independent of the IOKit interface.
use anyhow::{Context, Result, ensure};

pub(super) trait Controller {
    fn read(&mut self, register: u8) -> Result<Vec<u8>>;
    fn command(&mut self, command: [u8; 4], args: &[u8]) -> Result<u8>;
}

fn command(controller: &mut impl Controller, name: [u8; 4], args: &[u8]) -> Result<()> {
    let status = controller.command(name, args)?;
    ensure!(
        status == 0,
        "HPM command {} returned {status:#x}",
        String::from_utf8_lossy(&name)
    );
    Ok(())
}

pub(super) fn enter_dfu(
    controller: &mut impl Controller,
    key: [u8; 4],
    wait_for_dfu: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let connection = controller.read(0x3f)?;
    ensure!(
        connection.first().is_some_and(|state| state & 1 != 0),
        "No USB-C connection on the host DFU port; connect the two Macs directly through their DFU ports"
    );
    let mode = controller.read(0x03)?;
    let already_debug = mode.starts_with(b"DBMa");
    let mut entered_debug = false;
    let result = (|| {
        if !already_debug {
            if controller.command(*b"LOCK", &key)? != 0 {
                command(controller, *b"Gaid", &[])
                    .context("resetting the USB-C controller to unlock it")?;
                command(controller, *b"LOCK", &key).context("unlocking the USB-C controller")?;
            }
            // Even a failed command can have changed the hardware state.
            entered_debug = true;
            command(controller, *b"DBMa", &[1]).context("entering USB-C debug mode")?;
            ensure!(
                controller.read(0x03)?.starts_with(b"DBMa"),
                "USB-C controller did not enter debug mode"
            );
        }
        let previous = controller.read(0x4d)?;
        let counter = *previous.first().context("empty USB-PD receive status")?;
        // SOP target, three little-endian VDM words: Apple vendor header,
        // DFU reboot command, and DFU mode argument.
        let mut args = vec![0x33];
        for word in [0x05ac8012u32, 0x106, 0x80010000] {
            args.extend_from_slice(&word.to_le_bytes());
        }
        // Never replay the reboot VDM after a timeout or uncertain write.
        command(controller, *b"VDMs", &args).context("requesting target DFU mode")?;
        for _ in 0..16 {
            let reply = controller.read(0x4d)?;
            if reply.first().is_some_and(|value| *value != counter) {
                let header = reply.get(1..5).context("truncated USB-PD VDM reply")?;
                ensure!(
                    u32::from_le_bytes(header.try_into()?) == 0x05ac8052,
                    "The connected device did not acknowledge the DFU command; automatic DFU requires an Apple silicon target"
                );
                crate::log!(
                    Info,
                    "dfu",
                    "USB-C DFU command acknowledged; waiting for USB DFU"
                );
                // Keep DBMa active through the target reboot. Restoring the
                // controller mode on the ACK can interrupt USB-C negotiation
                // before the target has actually entered DFU.
                return wait_for_dfu();
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        anyhow::bail!("No reply to the DFU command; check the USB-C cable and DFU ports")
    })();
    let cleanup = if entered_debug {
        command(controller, *b"DBMa", &[0]).context("leaving USB-C debug mode")
    } else {
        Ok(())
    };
    match (result, cleanup) {
        (Err(error), Err(cleanup)) => {
            Err(error.context(format!("USB-C cleanup also failed: {cleanup:#}")))
        }
        (Err(error), _) => Err(error),
        (Ok(()), cleanup) => cleanup,
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/platform/macos/protocol.rs"]
mod tests;
