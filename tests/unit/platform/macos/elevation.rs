use super::*;

#[test]
fn helper_reports_success_and_preserves_log_level_and_source() {
    let mut data = Vec::new();
    report(
        || {
            crate::log!(Warning, "dfu", "Controller diagnostic");
            Ok(())
        },
        &mut data,
    )
    .unwrap();

    let logs = Arc::new(Mutex::new(Vec::new()));
    let captured = logs.clone();
    crate::progress::Context::new(move |event| {
        if let crate::progress::Event::Log(record) = event {
            captured.lock().unwrap().push(record);
        }
    })
    .run(|| receive(data.as_slice()))
    .unwrap();
    let logs = logs.lock().unwrap();
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].level, crate::logging::Level::Warning);
    assert_eq!(logs[0].source, "dfu");
    assert_eq!(logs[0].message, "Controller diagnostic");
}

#[test]
fn helper_failure_preserves_the_error_chain() {
    let mut data = Vec::new();
    report(
        || Err(anyhow::anyhow!("IOKit refused access")).context("opening Apple USB-C controller"),
        &mut data,
    )
    .unwrap();
    let error = format!("{:#}", receive(data.as_slice()).unwrap_err());
    assert!(error.contains("macOS DFU helper failed"));
    assert!(error.contains("opening Apple USB-C controller: IOKit refused access"));
}

#[test]
fn temporary_helper_preserves_contents_and_is_removed_after_use_or_copy_failure() {
    let source = tempfile::tempdir().unwrap();
    let executable = source.path().join("Заливка ' $HOME `id` $(id); app");
    let bytes = b"executable contents including its embedded code signature";
    std::fs::write(&executable, bytes).unwrap();
    let parent = tempfile::tempdir().unwrap();
    let path;
    {
        let directory = stage_helper(&executable, parent.path()).unwrap();
        path = directory.path().to_owned();
        let copied = path.join("zalivka");
        assert_eq!(std::fs::read(&copied).unwrap(), bytes);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(copied).unwrap().permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
    }
    assert!(!path.exists());
    assert_eq!(std::fs::read(&executable).unwrap(), bytes);
    assert!(stage_helper(&source.path().join("missing"), parent.path()).is_err());
    assert_eq!(std::fs::read_dir(parent.path()).unwrap().count(), 0);
}

#[cfg(unix)]
#[test]
fn staged_process_receives_literal_arguments_and_is_cleaned_up_on_success_and_failure() {
    let source = tempfile::tempdir().unwrap();
    let executable = source.path().join("Заливка ' \" $HOME `id` $(id); app");
    let parent = tempfile::tempdir().unwrap();
    // Only this test fixture uses a shell. The production native helper is a
    // byte-for-byte executable copy launched directly with Command.
    std::fs::write(
        &executable,
        br##"#!/bin/sh
[ "$#" = 3 ] || exit 2
[ "$1" = enter-dfu-helper ] || exit 3
[ "$2" = --prompt ] || exit 4
[ "$3" = 'Zalivka: $HOME $(id); "DFU"' ] || exit 5
printf '%s' '{"logs":[],"result":{"Ok":null}}'
"##,
    )
    .unwrap();
    run_at(&executable, parent.path(), "Zalivka: $HOME $(id); \"DFU\"").unwrap();
    assert_eq!(std::fs::read_dir(parent.path()).unwrap().count(), 0);

    for script in [
        "#!/bin/sh\nprintf '%s' 'authorization failed' >&2\nexit 1\n",
        "#!/bin/sh\nexit 0\n",
    ] {
        std::fs::write(&executable, script).unwrap();
        assert!(run_at(&executable, parent.path(), "Zalivka: DFU").is_err());
        assert_eq!(std::fs::read_dir(parent.path()).unwrap().count(), 0);
    }
}

fn process_output(success: bool, stdout: &[u8], stderr: &[u8]) -> Output {
    #[cfg(unix)]
    use std::os::unix::process::ExitStatusExt;
    #[cfg(windows)]
    use std::os::windows::process::ExitStatusExt;
    Output {
        status: std::process::ExitStatus::from_raw(if success { 0 } else { 256 }),
        stdout: stdout.to_vec(),
        stderr: stderr.to_vec(),
    }
}

#[test]
fn authorization_process_must_succeed_and_return_a_complete_helper_report() {
    let mut data = Vec::new();
    report(|| Ok(()), &mut data).unwrap();
    receive_output(process_output(true, &data, b"")).unwrap();
    let error = receive_output(process_output(
        false,
        &data,
        b"native authorization failed: -60008",
    ))
    .unwrap_err()
    .to_string();
    assert!(error.contains("macOS DFU authorization helper failed"));
    assert!(error.contains("native authorization failed: -60008"));
    assert!(receive_output(process_output(true, b"", b"")).is_err());

    data.clear();
    report(|| anyhow::bail!("USB-C controller unavailable"), &mut data).unwrap();
    let error = format!(
        "{:#}",
        receive_output(process_output(true, &data, b"")).unwrap_err()
    );
    assert!(error.contains("USB-C controller unavailable"));
}

#[test]
fn native_authorization_errors_identify_the_operation_and_status() {
    for (code, reason) in [
        (-60006, "authentication was cancelled"),
        (-60005, "authorization was denied"),
        (-60007, "requires an interactive login session"),
        (-60008, "requesting macOS administrator authorization"),
    ] {
        for operation in ["AuthorizationCreate", "AuthorizationExecuteWithPrivileges"] {
            let message = authorization_message(operation, code);
            assert!(message.contains(reason), "{message}");
            assert!(message.contains(operation), "{message}");
            assert!(message.contains(&format!("OSStatus {code}")), "{message}");
        }
    }
}

#[test]
fn authorization_relay_forwards_the_privileged_report_without_changing_it() {
    let mut data = Vec::new();
    report(|| anyhow::bail!("IOKit refused access"), &mut data).unwrap();
    let mut forwarded = Vec::new();
    forward_report(data.as_slice(), &mut forwarded).unwrap();
    assert_eq!(forwarded, data);
    assert!(
        format!("{:#}", receive(forwarded.as_slice()).unwrap_err())
            .contains("IOKit refused access")
    );

    let oversized = vec![b' '; 1024 * 1024 + 1];
    forwarded.clear();
    assert!(forward_report(oversized.as_slice(), &mut forwarded).is_err());
    assert!(forwarded.is_empty());
}

#[test]
fn missing_truncated_or_invalid_helper_results_never_count_as_success() {
    for data in [
        "",
        r#"{"logs":[],"result":{"Ok":null}"#,
        r#"{"logs":[]}"#,
        r#"{"logs":[],"result":{"Ok":null},"unexpected":true}"#,
        r#"{"logs":[],"result":{"Ok":null}} trailing"#,
    ] {
        let error = receive(data.as_bytes()).unwrap_err().to_string();
        assert!(
            error.contains("without a complete result"),
            "{data}: {error}"
        );
    }
}

#[test]
fn helper_result_read_and_write_failures_are_reported() {
    let oversized = vec![b' '; 1024 * 1024 + 1];
    assert!(format!("{:#}", receive(oversized.as_slice()).unwrap_err()).contains("too large"));

    let input = std::io::Error::other("helper pipe disconnected");
    struct FailedRead(std::io::Error);
    impl Read for FailedRead {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other(self.0.to_string()))
        }
    }
    let error = format!("{:#}", receive(FailedRead(input)).unwrap_err());
    assert!(error.contains("helper pipe disconnected"));

    struct FailedWrite;
    impl Write for FailedWrite {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("helper pipe closed"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let error = format!("{:#}", report(|| Ok(()), FailedWrite).unwrap_err());
    assert!(error.contains("helper pipe closed"));
}
