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
    let result = report(
        || Err(anyhow::anyhow!("IOKit refused access")).context("opening Apple USB-C controller"),
        &mut data,
    );
    assert!(result.is_err());
    let error = format!("{:#}", receive(data.as_slice()).unwrap_err());
    assert!(error.contains("macOS DFU helper failed"));
    assert!(error.contains("opening Apple USB-C controller: IOKit refused access"));
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
