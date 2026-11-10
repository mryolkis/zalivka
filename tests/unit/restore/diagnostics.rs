use super::*;
use std::io::Cursor;

#[test]
fn diagnostic_rendering_preserves_long_unicode_text_nested_fields_and_gzip_panics() {
    let panic = format!(
        "panic(cpu 0): {}\nbacktrace\nlast frame",
        "Ж🚀".repeat(1400)
    );
    let mut compressed = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    compressed.write_all(panic.as_bytes()).unwrap();
    let value = wire::dict([
        ("PanicLog", Value::Data(compressed.finish().unwrap())),
        (
            "Nested",
            wire::dict([("LastError", "storage initialization".into())]),
        ),
    ]);
    let mut records = vec![];
    describe("SavedDebugInfo", &value, Level::Debug, |r| records.push(r));
    let text = records
        .iter()
        .map(|r| r.message.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    for needle in [
        "panic(cpu 0)",
        "last frame",
        "Nested.LastError",
        "storage initialization",
    ] {
        assert!(text.contains(needle), "missing {needle}");
    }
    assert_eq!(text.matches("Ж🚀").count(), 1400);
    assert!(
        records
            .iter()
            .all(|r| r.message.is_char_boundary(r.message.len()))
    );
}

#[test]
fn rendering_is_bounded_and_original_binary_and_large_text_remain_in_the_plist() {
    let directory = tempfile::tempdir().unwrap();
    let mut diagnostics = Diagnostics::new(Some(directory.path().join("evidence")));
    let value = wire::dict([
        ("OpaquePanic", Value::Data(vec![0xff, 0, 0x80])),
        ("LargeLog", "x".repeat(TEXT_BUDGET + 100).into()),
    ]);
    diagnostics.capture("../../panic", &value, Level::Debug);
    let files: Vec<_> = std::fs::read_dir(directory.path().join("evidence"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(files.len(), 1);
    let saved = Value::from_file(&files[0]).unwrap();
    assert_eq!(saved, value);
    let mut records = vec![];
    describe("panic", &value, Level::Debug, |r| records.push(r));
    assert!(records.len() <= MAX_LINES + 1);
    assert!(records.last().unwrap().message.contains("limit reached"));
    assert!(records.iter().any(|r| r.message.contains("binary data;")));
}

struct Duplex {
    input: Cursor<Vec<u8>>,
    output: Vec<u8>,
}
impl Read for Duplex {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        self.input.read(b)
    }
}
impl Write for Duplex {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.output.write(b)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn saved_debug_queries_preserve_responses_and_unsupported_keys_are_nonfatal() {
    let responses = [
        wire::dict([(
            "SavedDebugInfo",
            wire::dict([
                ("PanicLog", "panic full details\nframe two".into()),
                ("USBLog", "USB reset".into()),
            ]),
        )]),
        wire::dict([("Error", "UnknownQueryKey".into())]),
    ];
    let mut input = vec![];
    for response in &responses {
        wire::send(&mut input, response).unwrap();
    }
    let mut stream = Duplex {
        input: Cursor::new(input),
        output: vec![],
    };
    let directory = tempfile::tempdir().unwrap();
    let transcript = tempfile::NamedTempFile::new().unwrap();
    let mut diagnostics = Diagnostics::new(Some(directory.path().join("evidence")));
    diagnostics
        .query_values(&mut stream, &mut Some(transcript.reopen().unwrap()))
        .unwrap();
    let mut sent = stream.output.as_slice();
    for key in ["SavedDebugInfo", "Logs"] {
        let message = wire::receive(&mut sent).unwrap();
        assert_eq!(wire::string(&message, &["Request"]).unwrap(), "QueryValue");
        assert_eq!(wire::string(&message, &["QueryKey"]).unwrap(), key);
    }
    assert!(sent.is_empty());
    let recorded: Vec<Value> = std::fs::read_to_string(transcript.path())
        .unwrap()
        .lines()
        .map(|s| serde_json::from_str(s).unwrap())
        .collect();
    assert_eq!(recorded, responses);
    assert_eq!(
        Value::from_file(directory.path().join("evidence/0001-SavedDebugInfo.plist")).unwrap(),
        *wire::get(&responses[0], &["SavedDebugInfo"]).unwrap()
    );
}

#[test]
fn evidence_write_errors_do_not_change_restore_failure_context() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("evidence");
    let mut diagnostics = Diagnostics::new(Some(path.clone()));
    std::fs::remove_dir(path).unwrap();
    diagnostics.observe(&wire::dict([
        ("MsgType", "CheckpointMsg".into()),
        ("CHECKPOINT_NAME", "wait_for_storage".into()),
        ("CHECKPOINT_COMPLETE", false.into()),
        ("CHECKPOINT_RESULT", 0u64.into()),
    ]));
    // Saving to a disappeared directory is best effort; the original error lives on.
    let error = anyhow::anyhow!("original USB EOF");
    diagnostics.failure(&error, Some(true));
    assert_eq!(error.to_string(), "original USB EOF");
    assert!(diagnostics.checkpoint.unwrap().contains("wait_for_storage"));
}
