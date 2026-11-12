//! Restore-service connection and identity checks.
use super::RESTORED_PORT;
use crate::{
    device::DeviceInfo,
    mux::{MuxStream, Session},
    wire,
};
use anyhow::{Context, Result, ensure};
use plist::Value;
use std::{
    io::{Read, Write},
    time::{Duration, Instant},
};

/// Query an existing service without booting firmware or starting a restore.
pub fn query_value(stream: &mut (impl Read + Write), key: &str) -> Result<Value> {
    wire::send(
        stream,
        &wire::dict([
            ("Request", "QueryValue".into()),
            ("QueryKey", key.into()),
            ("Label", "zalivka".into()),
        ]),
    )?;
    wire::receive(stream).with_context(|| format!("reading {key}"))
}

pub(super) fn confirm_restore_service<T>(
    bootx_error: Option<anyhow::Error>,
    connect: impl FnOnce() -> Result<T>,
) -> Result<T> {
    if let Some(error) = &bootx_error {
        crate::log!(Debug, "restore:usb", "bootx: {error:#}");
    }
    match connect() {
        Ok(service) => {
            if bootx_error.is_some() {
                crate::log!(Debug, "restore:usb", "Restore service available");
            }
            Ok(service)
        }
        Err(error) => match bootx_error {
            Some(bootx) => Err(bootx.context(format!(
                "restore service not confirmed after bootx ({error:#}); re-enter DFU before retrying"
            ))),
            None => Err(error),
        },
    }
}

pub(super) fn wait_restored(device: &DeviceInfo) -> Result<(Session, MuxStream, u64)> {
    wait_restored_ecid(device.ecid, Some(device), Duration::from_secs(180))
}

pub(super) fn wait_restored_ecid(
    ecid: u64,
    expected: Option<&DeviceInfo>,
    timeout: Duration,
) -> Result<(Session, MuxStream, u64)> {
    crate::log!(Info, "restore", "Waiting for the Mac restore service");
    let mut events = crate::usb::DeviceEvents::new();
    let deadline = Instant::now() + timeout;
    let mut last_error = None;
    let mut reported_error = None;
    let mut last_inventory = None;
    let mut next_inventory = Instant::now();
    loop {
        if Instant::now() >= next_inventory {
            match super::diagnostics::usb_snapshot() {
                Ok(inventory) if last_inventory.as_ref() != Some(&inventory) => {
                    super::diagnostics::describe(
                        "waiting-usb",
                        &inventory,
                        crate::logging::Level::Debug,
                        crate::logging::publish,
                    );
                    last_inventory = Some(inventory);
                }
                Err(error) => crate::log!(Debug, "restore:usb", "Reading USB inventory: {error:#}"),
                _ => {}
            }
            next_inventory = Instant::now() + Duration::from_secs(5);
        }
        // Enumeration can fail during re-enumeration or daemon startup. Preserve
        // that diagnostic and retry within the same restore-service deadline.
        let candidates = match Session::candidates() {
            Ok(candidates) => candidates,
            Err(error) => vec![Err(error)],
        };
        for candidate in candidates {
            let result = (|| -> Result<_> {
                let session = candidate?;
                let mut stream = session.connect(RESTORED_PORT)?;
                stream.set_read_timeout(Duration::from_secs(10));
                wire::send(
                    &mut stream,
                    &wire::dict([("Request", "QueryType".into()), ("Label", "zalivka".into())]),
                )?;
                let query = wire::receive(&mut stream)?;
                ensure!(
                    wire::string(&query, &["Type"])? == "com.apple.mobile.restored",
                    "not the restored service"
                );
                let version = wire::number(wire::get(&query, &["RestoreProtocolVersion"])?)?;
                let hardware = query_value(&mut stream, "HardwareInfo")?;
                let hw = wire::get(&hardware, &["HardwareInfo"])?;
                ensure!(
                    wire::number(wire::get(hw, &["UniqueChipID"])?)? == ecid,
                    "restore service ECID mismatch"
                );
                if let Some(device) = expected {
                    ensure!(
                        wire::number(wire::get(hw, &["ChipID"])?)? == u64::from(device.chip_id),
                        "restore service chip mismatch"
                    );
                    ensure!(
                        wire::number(wire::get(hw, &["BoardID"])?)? == u64::from(device.board_id),
                        "restore service board mismatch"
                    );
                }
                super::diagnostics::describe(
                    "restore-service",
                    &query,
                    crate::logging::Level::Debug,
                    crate::logging::publish,
                );
                super::diagnostics::describe(
                    "HardwareInfo",
                    hw,
                    crate::logging::Level::Debug,
                    crate::logging::publish,
                );
                stream.set_read_timeout(Duration::from_secs(300));
                Ok((session, stream, version))
            })();
            match result {
                Ok(result) => return Ok(result),
                Err(error) => {
                    let message = format!("{error:#}");
                    if reported_error.as_ref() != Some(&message) {
                        crate::log!(Debug, "restore:usb", "Connecting: {message}");
                        reported_error = Some(message);
                    }
                    last_error = Some(error);
                }
            }
        }
        if Instant::now() >= deadline {
            return Err(last_error
                .unwrap_or_else(|| anyhow::anyhow!("no USB multiplex device found"))
                .context(format!(
                    "restore service did not appear for ECID {:016x}",
                    ecid
                )));
        }
        let timeout =
            Duration::from_secs(1).min(deadline.saturating_duration_since(Instant::now()));
        events.wait(timeout);
    }
}
