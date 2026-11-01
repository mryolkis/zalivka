//! Native authorization for the portable binary and the DFU helper's result pipe.
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    sync::{Arc, Mutex},
};

#[cfg(target_os = "macos")]
pub(super) fn run() -> Result<()> {
    use security_framework::authorization::{Authorization, AuthorizationItemSetBuilder, Flags};
    use std::os::unix::ffi::OsStrExt;

    let executable = std::env::current_exe().context("locating the Zalivka executable")?;
    let rights = AuthorizationItemSetBuilder::new()
        .add_data("system.privilege.admin", executable.as_os_str().as_bytes())?
        .build();
    let environment = AuthorizationItemSetBuilder::new()
        .add_string(
            "prompt",
            format!("Zalivka: {}", crate::localization::text("Enter DFU mode")),
        )?
        .build();
    let authorization = Authorization::new(
        Some(rights),
        Some(environment),
        Flags::INTERACTION_ALLOWED | Flags::EXTEND_RIGHTS | Flags::PREAUTHORIZE,
    )
    .map_err(authorization_error)?;

    // AuthorizationExecuteWithPrivileges is deprecated, but supports our standalone
    // executable. SMAppService requires an app bundle and a registered launch daemon.
    // Pass only the fixed helper command; no shell interprets the executable path.
    let pipe = authorization.execute_with_privileges_piped(
        &executable,
        ["enter-dfu-helper"],
        Flags::DEFAULTS,
    );
    let result = pipe.map_err(authorization_error).and_then(receive);
    authorization.destroy_rights();
    result
}

#[cfg(target_os = "macos")]
fn authorization_error(error: security_framework::base::Error) -> anyhow::Error {
    match error.code() {
        -60006 => anyhow::anyhow!("macOS administrator authentication was cancelled"),
        -60005 => anyhow::anyhow!("macOS administrator authorization was denied"),
        _ => anyhow::Error::new(error).context("requesting macOS administrator authorization"),
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Report {
    logs: Vec<crate::logging::Record>,
    result: std::result::Result<(), String>,
}

pub(super) fn report(task: impl FnOnce() -> Result<()>, mut output: impl Write) -> Result<()> {
    let logs = Arc::new(Mutex::new(Vec::new()));
    let captured = logs.clone();
    let context = crate::progress::Context::new(move |event| {
        if let crate::progress::Event::Log(record) = event {
            captured.lock().unwrap().push(record);
        }
    });
    let result = context.run(task);
    let report = Report {
        logs: std::mem::take(&mut *logs.lock().unwrap()),
        result: result.as_ref().map(|_| ()).map_err(|e| format!("{e:#}")),
    };
    serde_json::to_writer(&mut output, &report).context("writing macOS DFU helper result")?;
    output.flush().context("flushing macOS DFU helper result")?;
    result
}

fn receive(input: impl Read) -> Result<()> {
    // A successful launch or EOF does not prove that the hardware command ran.
    let data =
        crate::storage::read_limited(input, 1024 * 1024, "macOS DFU helper result is too large")
            .context("reading macOS DFU helper result")?;
    let report: Report = serde_json::from_slice(&data)
        .context("The macOS DFU helper exited without a complete result")?;
    for mut record in report.logs {
        record.normalize();
        crate::logging::publish(record);
    }
    report
        .result
        .map_err(anyhow::Error::msg)
        .context("macOS DFU helper failed")
}

#[cfg(test)]
#[path = "../../../tests/unit/platform/macos/elevation.rs"]
mod tests;
