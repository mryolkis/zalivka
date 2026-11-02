use super::*;
use std::{os::unix::net::UnixListener, sync::mpsc, thread};

fn listener() -> (tempfile::TempDir, UnixListener) {
    let dir = tempfile::tempdir().unwrap();
    let listener = UnixListener::bind(dir.path().join("usbmuxd")).unwrap();
    (dir, listener)
}

fn read_request(socket: &mut UnixStream, kind: &str) -> Value {
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut header = [0; 16];
    socket.read_exact(&mut header).unwrap();
    assert_eq!(&header[4..], &[1, 0, 0, 0, 8, 0, 0, 0, 1, 0, 0, 0]);
    let length = u32::from_le_bytes(header[..4].try_into().unwrap()) as usize;
    assert!((16..=MAX_MESSAGE).contains(&length));
    let mut payload = vec![0; length - 16];
    socket.read_exact(&mut payload).unwrap();
    assert!(payload.starts_with(b"<?xml"));
    let request = Value::from_reader(Cursor::new(payload)).unwrap();
    assert_eq!(wire::string(&request, &["MessageType"]).unwrap(), kind);
    assert_eq!(wire::string(&request, &["ProgName"]).unwrap(), "zalivka");
    request
}

fn packet(value: Value) -> Vec<u8> {
    let mut payload = Vec::new();
    plist::to_writer_xml(&mut payload, &value).unwrap();
    let mut packet = Vec::new();
    for word in [(16 + payload.len()) as u32, 1, 8, 1] {
        packet.extend(word.to_le_bytes());
    }
    packet.extend(payload);
    packet
}

fn result(code: u64) -> Vec<u8> {
    packet(wire::dict([
        ("MessageType", "Result".into()),
        ("Number", code.into()),
    ]))
}

fn devices(ids: &[(u32, &str)]) -> Vec<u8> {
    packet(wire::dict([(
        "DeviceList",
        Value::Array(
            ids.iter()
                .map(|&(id, kind)| {
                    wire::dict([
                        ("DeviceID", id.into()),
                        ("Properties", wire::dict([("ConnectionType", kind.into())])),
                    ])
                })
                .collect(),
        ),
    )]))
}

fn session(path: &Path) -> Session {
    Session(Arc::new(Shared {
        path: path.to_owned(),
        device_id: 42,
        cancelled: AtomicBool::new(false),
    }))
}

fn facade(session: &Session) -> crate::mux::Session {
    crate::mux::Session::from_system(session.clone())
}

#[test]
fn lists_only_usb_devices_and_reports_missing_daemon() {
    let (dir, listener) = listener();
    let server = thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        read_request(&mut socket, "ListDevices");
        socket
            .write_all(&devices(&[(42, "USB"), (99, "Network"), (43, "USB")]))
            .unwrap();
    });
    let sessions = candidates_at(&dir.path().join("usbmuxd")).unwrap();
    assert_eq!(
        sessions.iter().map(|s| s.0.device_id).collect::<Vec<_>>(),
        [42, 43]
    );
    server.join().unwrap();
    let error = format!(
        "{:#}",
        candidates_at(&dir.path().join("missing")).err().unwrap()
    );
    assert!(error.contains("system usbmuxd"));
    assert!(error.contains("check service and USB rules"));
}

#[test]
fn connect_preserves_coalesced_service_bytes_and_independent_channels() {
    let (dir, listener) = listener();
    let server = thread::spawn(move || {
        let (mut main, _) = listener.accept().unwrap();
        let request = read_request(&mut main, "Connect");
        assert_eq!(
            wire::number(wire::get(&request, &["DeviceID"]).unwrap()).unwrap(),
            42
        );
        assert_eq!(
            wire::number(wire::get(&request, &["PortNumber"]).unwrap()).unwrap(),
            u64::from(62078u16.to_be())
        );
        let mut reply = result(0);
        reply.extend(b"restored");
        // Fragment the header; coalesce its final bytes with the service data.
        main.write_all(&reply[..7]).unwrap();
        main.write_all(&reply[7..]).unwrap();
        let (mut data, _) = listener.accept().unwrap();
        let request = read_request(&mut data, "Connect");
        assert_eq!(
            wire::number(wire::get(&request, &["PortNumber"]).unwrap()).unwrap(),
            u64::from(12345u16.to_be())
        );
        data.write_all(&result(0)).unwrap();
        let mut bytes = [0; 7];
        data.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"payload");
        data.write_all(b"key-request").unwrap();
        let mut bytes = [0; 4];
        main.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"done");
    });
    let session = facade(&session(&dir.path().join("usbmuxd")));
    let mut main = session.connect(62078).unwrap();
    let mut data = session.connect(12345).unwrap();
    let mut bytes = [0; 8];
    main.read_exact(&mut bytes).unwrap();
    assert_eq!(&bytes, b"restored");
    data.write_all(b"payload").unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    while !data.has_pending_input().unwrap() {
        assert!(Instant::now() < deadline);
        thread::yield_now();
    }
    // Pending AEA input interrupts a write without consuming it or sending bytes.
    assert_eq!(data.write_until_input(b"must-not-send").unwrap(), None);
    let mut bytes = [0; 11];
    data.read_exact(&mut bytes).unwrap();
    assert_eq!(&bytes, b"key-request");
    main.write_all(b"done").unwrap();
    server.join().unwrap();
}

#[test]
fn retries_service_refusal_but_reports_other_daemon_results() {
    let (dir, listener) = listener();
    let server = thread::spawn(move || {
        for code in [3, 0, 2] {
            let (mut socket, _) = listener.accept().unwrap();
            read_request(&mut socket, "Connect");
            socket.write_all(&result(code)).unwrap();
        }
    });
    let session = facade(&session(&dir.path().join("usbmuxd")));
    session
        .connect_retry(12345, Duration::from_secs(3))
        .unwrap();
    let error = session
        .connect_retry(12345, Duration::from_secs(3))
        .err()
        .unwrap();
    assert_eq!(
        error.downcast_ref::<io::Error>().unwrap().kind(),
        io::ErrorKind::NotFound
    );
    server.join().unwrap();
}

#[test]
fn rejects_malformed_daemon_frames_before_entering_service_mode() {
    for mode in 0..5 {
        let (dir, listener) = listener();
        let server = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            read_request(&mut socket, "Connect");
            let mut reply = result(0);
            match mode {
                0 => reply[..4].copy_from_slice(&15u32.to_le_bytes()),
                1 => reply[..4].copy_from_slice(&((MAX_MESSAGE + 1) as u32).to_le_bytes()),
                2 => reply[4..8].copy_from_slice(&2u32.to_le_bytes()),
                3 => reply[12..16].copy_from_slice(&2u32.to_le_bytes()),
                4 => reply.truncate(reply.len() - 5),
                _ => unreachable!(),
            }
            socket.write_all(&reply).unwrap();
        });
        assert!(
            facade(&session(&dir.path().join("usbmuxd")))
                .connect(12345)
                .is_err()
        );
        server.join().unwrap();
    }
}

#[test]
fn read_timeout_can_resume_and_cancel_wakes_all_service_readers() {
    let (dir, listener) = listener();
    let (ready_tx, ready_rx) = mpsc::channel();
    let (stop_tx, stop_rx) = mpsc::channel();
    let server = thread::spawn(move || {
        let mut sockets = Vec::new();
        for _ in 0..2 {
            let (mut socket, _) = listener.accept().unwrap();
            read_request(&mut socket, "Connect");
            socket.write_all(&result(0)).unwrap();
            sockets.push(socket);
        }
        ready_tx.send(()).unwrap();
        stop_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    });
    let session = facade(&session(&dir.path().join("usbmuxd")));
    let mut a = session.connect(12345).unwrap();
    let mut b = session.connect(23456).unwrap();
    ready_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    a.set_read_timeout(Duration::from_millis(10));
    assert_eq!(
        a.read(&mut [0]).unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    a.set_read_timeout(Duration::from_secs(300));
    assert_eq!(a.read_timeout(), Duration::from_secs(300));
    let reader_a = thread::spawn(move || a.read(&mut [0]));
    let reader_b = thread::spawn(move || b.read(&mut [0]));
    let started = Instant::now();
    session.cancel();
    assert!(
        reader_a
            .join()
            .unwrap()
            .unwrap_err()
            .to_string()
            .contains("cancelled")
    );
    assert!(
        reader_b
            .join()
            .unwrap()
            .unwrap_err()
            .to_string()
            .contains("cancelled")
    );
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(session.connect(34567).is_err());
    stop_tx.send(()).unwrap();
    server.join().unwrap();
}

#[test]
fn service_eof_and_daemon_outage_do_not_confirm_device_removal() {
    let (dir, listener) = listener();
    let server = thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        read_request(&mut socket, "Connect");
        socket.write_all(&result(0)).unwrap();
        drop(socket);
        for ids in [&[(42, "USB")][..], &[][..]] {
            let (mut socket, _) = listener.accept().unwrap();
            read_request(&mut socket, "ListDevices");
            socket.write_all(&devices(ids)).unwrap();
        }
    });
    let session = facade(&session(&dir.path().join("usbmuxd")));
    let mut stream = session.connect(12345).unwrap();
    assert_eq!(stream.read(&mut [0]).unwrap(), 0);
    assert_eq!(
        stream
            .has_pending_input()
            .unwrap_err()
            .downcast_ref::<io::Error>()
            .unwrap()
            .kind(),
        io::ErrorKind::UnexpectedEof
    );
    assert!(!session.disconnected());
    assert!(session.disconnected());
    server.join().unwrap();
    assert!(!session.disconnected());
}

#[test]
fn pending_key_request_interrupts_a_full_socket_and_cancel_wakes_blocked_writer() {
    let (dir, listener) = listener();
    let (key_tx, key_rx) = mpsc::channel();
    let (stop_tx, stop_rx) = mpsc::channel();
    let server = thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        read_request(&mut socket, "Connect");
        socket.write_all(&result(0)).unwrap();
        key_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        // The device requests a key while it has stopped accepting image data.
        socket.write_all(b"K").unwrap();
        stop_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    });
    let session = session(&dir.path().join("usbmuxd"));
    let mut stream = session
        .connect(12345, Instant::now() + Duration::from_secs(3))
        .unwrap();
    let bytes = vec![0xa5; 64 * 1024];
    let mut queued = 0;
    loop {
        match stream.socket.write(&bytes) {
            Ok(n) => queued += n,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(error) => panic!("filling socket: {error}"),
        }
        assert!(queued < 16 * 1024 * 1024);
    }
    assert!(queued > 0);
    // Also fill any tail too small for the preceding large write.
    loop {
        match stream.socket.write(b"x") {
            Ok(1) => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            other => panic!("filling socket tail: {other:?}"),
        }
    }
    key_tx.send(()).unwrap();
    assert_eq!(stream.write_until_input(b"next image bytes").unwrap(), None);
    let mut key = [0];
    stream.read_exact(&mut key).unwrap();
    assert_eq!(&key, b"K");
    let writer = thread::spawn(move || stream.write_all(b"blocked"));
    let started = Instant::now();
    session.cancel();
    assert!(
        writer
            .join()
            .unwrap()
            .unwrap_err()
            .to_string()
            .contains("cancelled")
    );
    assert!(started.elapsed() < Duration::from_secs(1));
    stop_tx.send(()).unwrap();
    server.join().unwrap();
}

#[test]
fn cancel_interrupts_an_unanswered_connect_request() {
    let (dir, listener) = listener();
    let (ready_tx, ready_rx) = mpsc::channel();
    let (stop_tx, stop_rx) = mpsc::channel();
    let server = thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        read_request(&mut socket, "Connect");
        ready_tx.send(()).unwrap();
        stop_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    });
    let session = facade(&session(&dir.path().join("usbmuxd")));
    let worker_session = session.clone();
    let worker = thread::spawn(move || worker_session.connect(12345).err().unwrap());
    ready_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    let started = Instant::now();
    session.cancel();
    assert!(format!("{:#}", worker.join().unwrap()).contains("cancelled"));
    assert!(started.elapsed() < Duration::from_secs(1));
    stop_tx.send(()).unwrap();
    server.join().unwrap();
}

#[test]
fn stopped_daemon_is_not_retried_as_a_service_refusal() {
    let (dir, listener) = listener();
    drop(listener);
    let session = facade(&session(&dir.path().join("usbmuxd")));
    let started = Instant::now();
    let error = session
        .connect_retry(12345, Duration::from_secs(3))
        .err()
        .unwrap();
    assert_eq!(
        error.downcast_ref::<io::Error>().unwrap().kind(),
        io::ErrorKind::NotConnected
    );
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[test]
fn full_socket_write_observes_deadline() {
    let (dir, listener) = listener();
    let (stop_tx, stop_rx) = mpsc::channel();
    let server = thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        read_request(&mut socket, "Connect");
        socket.write_all(&result(0)).unwrap();
        // Leave image data unread so the writer must wait for socket space.
        stop_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    });
    let session = session(&dir.path().join("usbmuxd"));
    let mut stream = session
        .connect(12345, Instant::now() + Duration::from_secs(3))
        .unwrap();
    rustix::net::sockopt::set_socket_send_buffer_size(&stream.socket, 8192).unwrap();
    let payload = vec![0xa5; 1024 * 1024];
    stream.deadline = Some(Instant::now() + Duration::from_millis(100));
    let started = Instant::now();
    let error = stream.write_all(&payload).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(stream.writes.waits > 0);
    assert!(started.elapsed() < Duration::from_secs(1));
    stop_tx.send(()).unwrap();
    server.join().unwrap();
}

#[test]
#[ignore = "local socket benchmark; no USB devices or firmware writes"]
fn small_socket_buffer_throughput() {
    let payload: Vec<u8> = (0..8 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
    let expected = payload.clone();
    let (dir, listener) = listener();
    let server = thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        read_request(&mut socket, "Connect");
        rustix::net::sockopt::set_socket_recv_buffer_size(&socket, 8192).unwrap();
        socket.write_all(&result(0)).unwrap();
        let mut received = vec![0; expected.len()];
        socket.read_exact(&mut received).unwrap();
        assert_eq!(received, expected);
    });
    let session = session(&dir.path().join("usbmuxd"));
    let mut stream = session
        .connect(12345, Instant::now() + Duration::from_secs(3))
        .unwrap();
    rustix::net::sockopt::set_socket_send_buffer_size(&stream.socket, 8192).unwrap();
    let started = Instant::now();
    stream.write_all(&payload).unwrap();
    server.join().unwrap();
    let seconds = started.elapsed().as_secs_f64();
    println!(
        "USBMUXD_BENCH bytes={} seconds={seconds:.3} MiB/s={:.1}; payload verified; no USB",
        payload.len(),
        payload.len() as f64 / 1048576.0 / seconds
    );
}
