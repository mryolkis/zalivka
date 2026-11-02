use super::assets::*;
use super::download::{download_from, firmware_request, retryable_download};
use super::request::*;
use super::*;
use crate::{
    test_net::{accept, read_header},
    wire,
};
use plist::Value;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::path::Path;
use std::{net::TcpListener, thread};

// Local fixtures must not depend on the developer's Windows/PAC/env policy.
fn send_http(agent: &ureq::Agent, request: &Request<Vec<u8>>) -> Result<Response<ureq::Body>> {
    send_http_via(agent, request, None)
}

mod assets;
mod download;
mod request;
mod transport;

#[test]
fn pac_download_preserves_http_follows_relative_redirects_and_removes_utf8_bom() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let script = "function FindProxyForURL(url, host) { return 'DIRECT'; }";
    let server = thread::spawn(move || {
        for path in ["/proxy.pac", "/actual.pac"] {
            let mut stream = accept(&listener);
            assert!(read_header(&mut stream).starts_with(&format!("GET {path} HTTP/1.1")));
            if path == "/proxy.pac" {
                stream.write_all(b"HTTP/1.1 302 Found\r\nLocation: actual.pac\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
            } else {
                write!(stream, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n\u{feff}{script}", script.len() + 3).unwrap();
            }
        }
    });
    assert_eq!(
        proxy_script(&format!("http://{address}/proxy.pac")).unwrap(),
        script
    );
    server.join().unwrap();
}

#[test]
fn pac_download_rejects_credentials_non_http_urls_and_oversized_scripts() {
    for address in [
        "file:///tmp/proxy.pac",
        "ftp://pac.example/proxy.pac",
        "http://user:password@pac.example/proxy.pac",
    ] {
        assert!(proxy_script(address).is_err(), "{address}");
    }
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let mut stream = accept(&listener);
        read_header(&mut stream);
        let _ = stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1048577\r\nConnection: close\r\n\r\n");
        let _ = stream.write_all(&vec![b'x'; 1048577]);
    });
    assert!(
        proxy_script(&format!("http://{address}/proxy.pac"))
            .unwrap_err()
            .to_string()
            .contains("1 MiB")
    );
    server.join().unwrap();
}
