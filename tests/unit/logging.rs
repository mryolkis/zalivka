use super::*;

#[test]
fn plist_summaries_keep_identifiers_and_sizes_without_expanding_payloads() {
    let message = crate::wire::dict([
        ("MsgType", "DataRequestMsg".into()),
        ("DataType", "FirmwareUpdaterData".into()),
        ("Payload", plist::Value::Data(vec![0xa5; 1024 * 1024])),
        ("Items", plist::Value::Array(vec![true.into(); 64])),
        (
            "Nested",
            crate::wire::dict([("Secret", "not part of the summary".into())]),
        ),
        ("Text", "Ж🚀".repeat(200).into()),
    ]);
    let summary = plist_summary(&message);
    assert!(summary.contains("DataRequestMsg"));
    assert!(summary.contains("FirmwareUpdaterData"));
    assert!(summary.contains("data[1048576 B]"));
    assert!(summary.contains("array[64]"));
    assert!(summary.contains("dict[1]"));
    assert!(summary.contains("… (1200 B)"));
    assert!(!summary.contains("not part of the summary"));
    assert!(summary.len() < 1024);
}

#[test]
fn plist_field_limit_preserves_late_protocol_identifiers_and_error_details() {
    let mut fields = plist::Dictionary::new();
    for index in 0..32 {
        fields.insert(format!("Field{index}"), plist::Value::Data(vec![0xa5; 256]));
    }
    fields.extend([
        ("MsgType".into(), "StatusMsg".into()),
        ("DataType".into(), "FirmwareUpdaterData".into()),
        ("Status".into(), 42u64.into()),
        ("Error".into(), "ticket rejected".into()),
    ]);
    let summary = plist_summary(&fields.into());
    for expected in [
        "StatusMsg",
        "FirmwareUpdaterData",
        "42",
        "ticket rejected",
        "+28 fields",
    ] {
        assert!(summary.contains(expected), "{summary}");
    }
    assert!(summary.len() < 512);
}

#[test]
fn diagnostic_overload_is_bounded_reported_and_does_not_discard_important_records() {
    use std::sync::{Arc, Mutex};
    let (entered, ready) = mpsc::channel();
    let (release, released) = mpsc::channel();
    let warnings = Arc::new(Mutex::new(Vec::new()));
    let output = warnings.clone();
    let queue = Queue::new(move |record| {
        if let Some(record) = record {
            if record.source == "block" {
                entered.send(()).unwrap();
                released.recv_timeout(Duration::from_secs(5)).unwrap();
            } else {
                output.lock().unwrap().push(record);
            }
        }
    })
    .unwrap();
    queue
        .record(Record::new(
            Level::Debug,
            "block",
            "x".repeat(MAX_QUEUED_BYTES - 128 - 5),
        ))
        .unwrap();
    ready.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(queue.budget.bytes.load(Ordering::Acquire), MAX_QUEUED_BYTES);
    queue
        .record(Record::new(Level::Trace, "test", "omitted diagnostic"))
        .unwrap();
    let error = Record::new(Level::Error, "restore", "preserve me");
    assert_eq!(queue.record(error.clone()).unwrap_err(), error);
    release.send(()).unwrap();
    queue.flush().unwrap();
    assert_eq!(queue.budget.bytes.load(Ordering::Acquire), 0);
    assert!(
        warnings
            .lock()
            .unwrap()
            .iter()
            .any(|record| record.level == Level::Warning && record.message.contains("omitted 1"))
    );
}

#[test]
fn records_keep_their_level_and_source_through_the_elevated_pipe() {
    for level in [
        Level::Trace,
        Level::Debug,
        Level::Info,
        Level::Warning,
        Level::Error,
    ] {
        let mut record = Record::new(level, "restore", "Подготовка macOS");
        record.elapsed_ms = 3_723_004;
        let mut pipe = Vec::new();
        record.write_json(&mut pipe).unwrap();
        assert_eq!(
            Record::parse_json(std::str::from_utf8(&pipe).unwrap()).unwrap(),
            record
        );
        let text = record.to_string();
        assert!(text.starts_with("01:02:03.004 "));
        assert!(text.contains(level.label()));
        assert!(text.contains("restore"));
        assert!(text.ends_with("Подготовка macOS"));
    }
}

#[test]
fn external_diagnostics_cannot_break_rows_or_inject_terminal_controls() {
    let record = Record::new(
        Level::Error,
        "usb",
        "one\r\ntwo\tthree\u{00b7}four\u{1b}[31m",
    );
    assert_eq!(record.message, "one  / two three,four\\u{1b}[31m");
    let mut output = Vec::new();
    record.write_to(&mut output).unwrap();
    let text = String::from_utf8(output).unwrap();
    assert_eq!(text.lines().count(), 1);
    assert!(!text.contains('\u{00b7}'));
    assert!(!text.contains('\u{1b}'));
}

#[test]
fn firmware_trace_suppression_is_scoped_and_preserves_parallel_fdr_and_errors() {
    use std::sync::{Arc, Mutex};
    let records = Arc::new(Mutex::new(Vec::new()));
    let output = records.clone();
    crate::progress::Context::new(move |event| {
        if let crate::progress::Event::Log(record) = event {
            output.lock().unwrap().push(record);
        }
    })
    .run(|| {
        let mut formatted = false;
        let result = (|| -> anyhow::Result<()> {
            let _transfer = firmware_transfer();
            {
                let _nested = firmware_transfer();
                assert!(!enabled(Level::Trace));
            }
            assert!(!enabled(Level::Trace));
            crate::log!(Trace, "plist", "{}", {
                formatted = true;
                "firmware payload"
            });
            crate::log!(Trace, "usbmux:io", "TX frame");
            crate::log!(Debug, "transfer", "Transfer progress");
            std::thread::spawn(crate::progress::inherit(|| {
                crate::log!(Trace, "fdr:conn", "Parallel FDR");
            }))
            .join()
            .unwrap();
            crate::log!(Error, "restore", "Transfer failed");
            anyhow::bail!("injected transfer failure")
        })();
        assert!(result.is_err());
        assert!(!formatted);
        assert!(enabled(Level::Trace));
        crate::log!(Trace, "restore", "Control tracing resumed");
    });
    let records = records.lock().unwrap();
    assert!(
        !records
            .iter()
            .any(|record| matches!(record.source.as_str(), "plist" | "usbmux:io"))
    );
    for message in [
        "Transfer progress",
        "Transfer failed",
        "Parallel FDR",
        "Control tracing resumed",
    ] {
        assert!(records.iter().any(|record| record.message == message));
    }
}

#[test]
fn queued_records_do_not_wait_for_the_sink_and_keep_owned_data_and_timestamps() {
    use std::sync::{Arc, Mutex, mpsc};
    use std::time::Duration;
    let records = Arc::new(Mutex::new(Vec::new()));
    let output = records.clone();
    let (entered_tx, entered) = mpsc::channel();
    let (release, released) = mpsc::channel();
    let released = Mutex::new(released);
    let context = crate::progress::Context::new(move |event| {
        if let crate::progress::Event::Log(record) = event {
            if record.message == "Pause sink" {
                entered_tx.send(()).unwrap();
                released.lock().unwrap().recv().unwrap();
            }
            output.lock().unwrap().push(record);
        }
    })
    .with_async_logs(|| {})
    .unwrap();
    let worker = context.clone();
    let (done_tx, done) = mpsc::channel();
    let producer = std::thread::spawn(move || {
        worker.run(|| {
            crate::log!(Info, "test", "Pause sink");
            let mut message = String::from("Queued diagnostic");
            crate::log!(Trace, "test:trace", "{message}");
            message.clear();
            let mut value = crate::wire::dict([("Data", plist::Value::Data(vec![1, 2, 3]))]);
            plist("plist", "TX binary LE", &value);
            value.as_dictionary_mut().unwrap().clear();
            {
                let _transfer = firmware_transfer();
                crate::log!(Trace, "firmware", "TX frame");
                plist("plist", "Firmware", &value);
            }
            crate::log!(Info, "test", "Final record");
            done_tx.send(elapsed_ms()).unwrap();
        })
    });
    entered.recv_timeout(Duration::from_secs(5)).unwrap();
    // The sink stays blocked until the producer has queued every record.
    let produced = done.recv_timeout(Duration::from_secs(5));
    release.send(()).unwrap();
    producer.join().unwrap();
    let produced_at = produced.expect("TRACE waited for the blocked sink");
    context.flush_logs().unwrap();
    let records = records.lock().unwrap();
    assert_eq!(records.first().unwrap().message, "Pause sink");
    assert_eq!(records.last().unwrap().message, "Final record");
    assert!(
        records
            .iter()
            .all(|record| record.elapsed_ms <= produced_at)
    );
    assert!(
        records
            .iter()
            .any(|record| record.source == "test:trace" && record.message == "Queued diagnostic")
    );
    assert!(
        records
            .iter()
            .any(|record| record.source == "plist" && record.message.contains("data[3 B]"))
    );
    assert!(
        !records
            .iter()
            .any(|record| record.source == "firmware" || record.message.starts_with("Firmware"))
    );
}

#[test]
fn background_journal_flushes_while_the_producer_is_idle() {
    use std::{sync::mpsc, time::Duration};
    let (flushed, rx) = mpsc::channel();
    let queue = Queue::new(move |record| {
        if record.is_none() {
            let _ = flushed.send(());
        }
    })
    .unwrap();
    queue
        .record(Record::new(Level::Info, "test", "Buffered record"))
        .unwrap();
    rx.recv_timeout(Duration::from_secs(5)).unwrap();
    queue.flush().unwrap();
}

#[test]
fn trace_subprocess() {
    let Ok(level) = std::env::var("ZALIVKA_TEST_TRACE_LEVEL") else {
        return;
    };
    init(match level.as_str() {
        "trace" => Level::Trace,
        "debug" => Level::Debug,
        _ => Level::Info,
    });
    let native = std::env::var_os("ZALIVKA_TEST_TRACE_NATIVE").is_some();
    let _background = (!native).then(|| background().unwrap());
    let run = || {
        let mut formatted = false;
        crate::log!(Trace, "test", "{}", {
            formatted = true;
            "trace formatting"
        });
        assert_eq!(formatted, level == "trace" || native);
        crate::log!(Debug, "test", "debug record");
        crate::log!(Info, "test", "info record");

        use crate::{
            mux::{PacketTransport, Session},
            test_mux::{tcp, version_packet},
        };
        use std::{
            collections::VecDeque,
            io::{Cursor, Read},
            sync::{Arc, Mutex, atomic::AtomicBool},
        };
        struct Usb(VecDeque<Vec<u8>>);
        impl PacketTransport for Usb {
            fn write_packet(&mut self, _: &[u8]) -> anyhow::Result<()> {
                Ok(())
            }
            fn read_packet(&mut self) -> anyhow::Result<Vec<u8>> {
                Ok(self.0.pop_front().unwrap_or_default())
            }
        }
        // Control negotiation must be visible before a connection port is known.
        let mut frame = Vec::new();
        crate::wire::send_binary_le(
            &mut frame,
            &crate::wire::dict([("ConnPort", 45678u64.into())]),
        )
        .unwrap();
        let session = Session::new(Usb(VecDeque::from([
            version_packet(),
            tcp(1082, 1, 0, 1, 0x12, &[]),
            tcp(1082, 1, 1, 1, 0x10, &frame),
        ])))
        .unwrap();
        drop(crate::fdr::Fdr::start(&session).unwrap());

        // A complete SOCKS request and binary payload arrive in one USB packet,
        // but the parser consumes them through several reads of different sizes.
        let payload: Vec<u8> = (0..400).map(|i| i as u8).collect();
        let reply: Vec<u8> = (0..333).map(|i| (255 - i % 256) as u8).collect();
        let host = b"tbsc.apple.com";
        let mut request = vec![5, 1, 0, 3, host.len() as u8];
        request.extend(host);
        request.extend(443u16.to_be_bytes());
        request.extend(&payload);
        let session = Session::new(Usb(VecDeque::from([
            version_packet(),
            tcp(45678, 1, 0, 1, 0x12, &[]),
            tcp(45678, 1, 1, 1, 0x10, &request),
        ])))
        .unwrap();
        struct Peer(Cursor<Vec<u8>>, Arc<Mutex<Vec<u8>>>);
        impl Read for Peer {
            fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
                self.0.read(out)
            }
        }
        impl Write for Peer {
            fn write(&mut self, data: &[u8]) -> io::Result<usize> {
                let n = data.len().min(13);
                self.1.lock().unwrap().extend_from_slice(&data[..n]);
                Ok(n)
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let sent = Arc::new(Mutex::new(Vec::new()));
        crate::fdr::handle_connection(
            session.connect(45678).unwrap(),
            &AtomicBool::new(false),
            |host, port| {
                assert_eq!((host, port), ("tbsc.apple.com", 443));
                Ok(Peer(Cursor::new(reply.clone()), sent.clone()))
            },
        )
        .unwrap();
        assert_eq!(*sent.lock().unwrap(), payload);
    };
    if native {
        let context = crate::progress::Context::new(|event| {
            if let crate::progress::Event::Log(record) = event {
                record.write_json(io::stdout().lock()).unwrap();
            }
        })
        .with_async_logs(|| {})
        .unwrap();
        context.run(run);
        context.flush_logs().unwrap();
    } else {
        run();
    }
}

#[test]
fn native_operations_trace_fdr_events_without_payload_dumps() {
    for native in [false, true] {
        for level in ["info", "debug", "trace"] {
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            command
                .args([
                    "--exact",
                    "logging::tests::trace_subprocess",
                    "--nocapture",
                    "--format=terse",
                ])
                .env("ZALIVKA_TEST_TRACE_LEVEL", level);
            if native {
                command.env("ZALIVKA_TEST_TRACE_NATIVE", "1");
            } else {
                command.env_remove("ZALIVKA_TEST_TRACE_NATIVE");
            }
            let output = command.output().unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            let stderr = String::from_utf8(output.stderr).unwrap();
            let stdout = String::from_utf8(output.stdout).unwrap();
            let records: Vec<_> = stdout
                .lines()
                .filter_map(|line| Record::parse_json(line).ok())
                .collect();
            if !native {
                assert_eq!(stderr.contains("TRACE"), level == "trace");
                assert_eq!(stderr.contains("DEBUG"), level != "info");
                assert!(stderr.contains("info record"));
                assert_eq!(stderr.contains("Negotiating v2"), level != "info");
                assert!(!stderr.contains(" offset="));
                assert!(!stderr.contains(" +00000000 ["));
                assert!(!stderr.contains("Methods=["));
                assert_eq!(stderr.contains("Authentication: none"), level == "trace");
                continue;
            }
            assert!(stderr.is_empty());
            assert!(records.iter().any(|r| r.message == "debug record"));
            assert!(records.iter().any(|r| r.level == Level::Trace));
            for (source, message) in [
                ("fdr:control", "Negotiating v2"),
                ("fdr:control", "Stopped"),
                ("fdr:proxy", "Connecting to tbsc.apple.com:443"),
                ("fdr:socks", "Methods: 1"),
                ("fdr:socks", "Authentication: none"),
            ] {
                assert!(
                    records
                        .iter()
                        .any(|r| r.source == source && r.message == message)
                );
            }
            assert!(!records.iter().any(|r| {
                (r.source == "usbmux:io" || r.source.starts_with("fdr:"))
                    && r.message.contains(" offset=")
            }));
            assert!(!records.iter().any(|r| {
                r.message.contains(" +00000000 [") || r.message.starts_with("Methods=[")
            }));
        }
    }
}
