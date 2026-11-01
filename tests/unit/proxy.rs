use super::*;
use crate::platform::proxy::{environment_proxy, from_windows_list, routes_from_strings};
use std::io::{self, Read, Write};

#[test]
fn tunnel_destination_selects_the_same_environment_and_windows_proxy() {
    let read = |name: &str| match name {
        "HTTP_PROXY" => Some("http://web:8080".to_owned()),
        "HTTPS_PROXY" => Some("http://secure:3128".to_owned()),
        _ => None,
    };
    for (port, expected) in [(80, "web"), (443, "secure"), (5223, "secure")] {
        let uri = target_uri("example.apple.com", port).unwrap();
        assert_eq!(uri.host(), Some("example.apple.com"));
        assert_eq!(uri.port_u16(), Some(port));
        assert_eq!(
            environment_proxy(&uri, read).unwrap().unwrap().host(),
            expected
        );
        assert_eq!(
            from_windows_list(&uri, "http=web:8080;https=secure:3128", "")
                .unwrap()
                .unwrap()
                .host(),
            expected
        );
    }
}

#[test]
fn fdr_direct_connection_retains_short_read_timeout() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let uri = format!("https://{}/", listener.local_addr().unwrap())
        .parse()
        .unwrap();
    let mut tunnel = connect_via(&uri, None).unwrap();
    let (mut stream, _) = listener.accept().unwrap();
    let mut byte = [0];
    assert_eq!(
        tunnel.read(&mut byte).unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    stream.write_all(b"x").unwrap();
    tunnel.read_exact(&mut byte).unwrap();
    assert_eq!(byte, *b"x");
}

#[test]
fn tunnel_hosts_cannot_change_authority_path_or_port() {
    for host in [
        "",
        "apple.com/other",
        "apple.com?x",
        "apple.com#fragment",
        "user@apple.com",
        "apple.com:80",
        "apple.com:443/path",
        "host\r\nInjected: x",
    ] {
        assert!(target_uri(host, 443).is_err(), "{host:?}");
    }
    assert!(target_uri("apple.com", 0).is_err());
    for host in ["apple.com", "127.0.0.1", "[::1]"] {
        assert_eq!(
            target_uri(host, 443).unwrap().authority().unwrap().as_str(),
            format!("{host}:443")
        );
    }
}

#[test]
fn pac_failover_only_retries_connection_failures_and_never_invents_direct() {
    let proxies = || {
        vec![
            Some(Proxy::new("http://one.example:1").unwrap()),
            Some(Proxy::new("http://two.example:2").unwrap()),
        ]
    };
    let mut calls = Vec::new();
    let result = try_routes(proxies(), |proxy| {
        let proxy = proxy.unwrap();
        calls.push(proxy.host().to_owned());
        if proxy.port() == 1 {
            Err(ConnectFailure(anyhow::anyhow!("connection refused")).into())
        } else {
            Ok(7)
        }
    })
    .unwrap();
    assert_eq!(result, 7);
    assert_eq!(calls, ["one.example", "two.example"]);
    calls.clear();
    let error = try_routes(proxies(), |proxy| {
        calls.push(proxy.unwrap().host().to_owned());
        Err::<(), _>(anyhow::anyhow!("POST already sent; response lost"))
    })
    .unwrap_err();
    assert_eq!(calls, ["one.example"]);
    assert!(error.to_string().contains("POST already sent"));
    let mut count = 0;
    assert!(
        try_routes(proxies(), |proxy| {
            assert!(proxy.is_some());
            count += 1;
            Err::<(), _>(ConnectFailure(anyhow::anyhow!("offline")).into())
        })
        .is_err()
    );
    assert_eq!(count, 2);
}

#[test]
fn fdr_uses_the_next_pac_proxy_without_resolving_or_inspecting_the_target() {
    use std::{net::TcpListener, thread, time::Duration};
    let offline = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = offline.local_addr().unwrap();
    drop(offline);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let available = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            stream.read_exact(&mut byte).unwrap();
            header.push(byte[0]);
            assert!(header.len() < 4096);
        }
        assert!(header.starts_with(b"CONNECT fdr.does-not-resolve.invalid:443 "));
        stream
            .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .unwrap();
        let mut bytes = [0; 4];
        stream.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"PING");
        stream.write_all(b"PONG").unwrap();
    });
    let routes = routes_from_strings(vec![
        format!("http://{address}"),
        format!("http://{available}"),
    ])
    .unwrap();
    let uri = target_uri("fdr.does-not-resolve.invalid", 443).unwrap();
    let mut stream = try_routes(routes, |proxy| connect_via(&uri, proxy)).unwrap();
    stream.write_all(b"PING").unwrap();
    let mut bytes = [0; 4];
    stream.read_exact(&mut bytes).unwrap();
    assert_eq!(&bytes, b"PONG");
    server.join().unwrap();
}
