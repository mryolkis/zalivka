//! Native authorization from a temporary copy outside macOS protected folders.
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
#[cfg(any(target_os = "macos", all(test, unix)))]
use std::process::{Command, Stdio};
use std::{
    io::{Read, Write},
    path::Path,
    process::Output,
    sync::{Arc, Mutex},
};

#[cfg(target_os = "macos")]
pub(super) fn run() -> Result<()> {
    let executable = std::env::current_exe().context("locating the Zalivka executable")?;
    // authd reads the requesting process's executable, so staging only the root
    // helper is insufficient. Request authorization from the temporary copy too.
    // Use /private/tmp explicitly: TMPDIR can point into a protected folder.
    run_at(
        &executable,
        Path::new("/private/tmp"),
        &format!("Zalivka: {}", crate::localization::text("Enter DFU mode")),
    )
}

#[cfg(any(target_os = "macos", all(test, unix)))]
fn run_at(executable: &Path, parent: &Path, prompt: &str) -> Result<()> {
    let directory = stage_helper(executable, parent)?;
    let output = Command::new(directory.path().join("zalivka"))
        .args(["enter-dfu-helper", "--prompt"])
        .arg(prompt)
        .stdin(Stdio::null())
        .output()
        .context("starting the macOS DFU authorization helper")?;
    receive_output(output)
}

fn stage_helper(executable: &Path, parent: &Path) -> Result<tempfile::TempDir> {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    let mut builder = tempfile::Builder::new();
    builder.prefix("zalivka-dfu-");
    #[cfg(unix)]
    builder.permissions(std::fs::Permissions::from_mode(0o700));
    let directory = builder
        .tempdir_in(parent)
        .context("creating the temporary macOS DFU helper directory")?;
    let path = directory.path().join("zalivka");
    std::fs::copy(executable, &path).context("copying the macOS DFU authorization helper")?;
    #[cfg(unix)]
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
        .context("setting macOS DFU helper permissions")?;
    Ok(directory)
}

fn receive_output(output: Output) -> Result<()> {
    if !output.status.success() {
        let diagnostic = String::from_utf8_lossy(&output.stderr);
        bail!(
            "macOS DFU authorization helper failed ({}): {}",
            output.status,
            diagnostic.trim()
        );
    }
    receive(output.stdout.as_slice())
}

#[cfg(target_os = "macos")]
pub(super) fn authorize(prompt: &str, output: impl Write) -> Result<()> {
    use security_framework::authorization::{Authorization, AuthorizationItemSetBuilder, Flags};

    let executable = std::env::current_exe().context("locating the macOS DFU helper")?;
    let rights = AuthorizationItemSetBuilder::new()
        .add_right("system.privilege.admin")?
        .build();
    let environment = AuthorizationItemSetBuilder::new()
        .add_string("prompt", prompt)?
        .build();
    let authorization = Authorization::new(
        Some(rights),
        Some(environment),
        Flags::INTERACTION_ALLOWED | Flags::EXTEND_RIGHTS | Flags::PREAUTHORIZE,
    )
    .map_err(|error| {
        anyhow::Error::new(error)
            .context(authorization_message("AuthorizationCreate", error.code()))
    })?;
    // Only this fixed command is elevated; paths and arguments never enter a shell.
    let result = authorization
        .execute_with_privileges_piped(&executable, ["enter-dfu-helper"], Flags::DEFAULTS)
        .map_err(|error| {
            anyhow::Error::new(error).context(authorization_message(
                "AuthorizationExecuteWithPrivileges",
                error.code(),
            ))
        })
        .and_then(|input| forward_report(input, output));
    authorization.destroy_rights();
    result
}

fn authorization_message(operation: &str, code: i32) -> String {
    let reason = match code {
        -60006 => "macOS administrator authentication was cancelled",
        -60005 => "macOS administrator authorization was denied",
        -60007 => "macOS administrator authentication requires an interactive login session",
        _ => "requesting macOS administrator authorization",
    };
    format!("{reason}: {operation} returned OSStatus {code}")
}

fn forward_report(input: impl Read, mut output: impl Write) -> Result<()> {
    let data =
        crate::storage::read_limited(input, 1024 * 1024, "macOS DFU helper result is too large")
            .context("reading the privileged macOS DFU helper result")?;
    output
        .write_all(&data)
        .context("forwarding the macOS DFU helper result")?;
    output
        .flush()
        .context("flushing the macOS DFU helper result")
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
    // The process exit status describes report delivery; the parent must check
    // the reported operation result before treating DFU entry as successful.
    Ok(())
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
