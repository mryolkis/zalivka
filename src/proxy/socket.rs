//! Blocking TCP tunnels for FDR, including HTTP, HTTPS and SOCKS proxies.
use anyhow::{Context, Result, bail, ensure};
use rustls::{ClientConfig, ClientConnection, StreamOwned, pki_types::ServerName};
use std::{
    io::{self, Read, Write},
    net::{IpAddr, TcpStream, ToSocketAddrs},
    sync::Arc,
    time::{Duration, Instant},
};
use ureq::{Proxy, ProxyProtocol};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(3);
const TUNNEL_READ_TIMEOUT: Duration = Duration::from_millis(100);
const SOCKS4_CONNECT: u8 = 90;
const MAX_SOCKS_CREDENTIAL: usize = 255;

pub(crate) enum Stream {
    Tcp(TcpStream),
    Tls(Box<StreamOwned<ClientConnection, TcpStream>>),
}

impl Stream {
    fn tcp(&self) -> &TcpStream {
        match self {
            Self::Tcp(stream) => stream,
            Self::Tls(stream) => &stream.sock,
        }
    }
}

impl Read for Stream {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        match self {
            Self::Tcp(stream) => stream.read(out),
            Self::Tls(stream) => stream.read(out),
        }
        .map_err(|error| {
            // Unix reports an expired SO_RCVTIMEO as WouldBlock. Keep the
            // blocking tunnel's read timeout consistent across platforms.
            if error.kind() == io::ErrorKind::WouldBlock {
                io::Error::new(io::ErrorKind::TimedOut, error)
            } else {
                error
            }
        })
    }
}

impl Write for Stream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.write(bytes),
            Self::Tls(stream) => stream.write(bytes),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.flush(),
            Self::Tls(stream) => stream.flush(),
        }
    }
}

fn socket_host(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host)
}

fn tcp_connect(host: &str, port: u16, timeout: Duration) -> Result<TcpStream> {
    let deadline = Instant::now() + timeout;
    let host = socket_host(host);
    let addresses = (host, port)
        .to_socket_addrs()
        .context("resolving upstream proxy or destination")?;
    let mut error = None;
    for address in addresses {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match TcpStream::connect_timeout(&address, remaining.min(ATTEMPT_TIMEOUT)) {
            Ok(stream) => {
                stream.set_read_timeout(Some(timeout))?;
                stream.set_write_timeout(Some(timeout))?;
                stream.set_nodelay(true)?;
                return Ok(stream);
            }
            Err(failure) => error = Some(failure),
        }
    }
    Err(error
        .unwrap_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "upstream connection timed out"))
        .into())
}

pub(crate) fn connect_blocking(host: &str, port: u16, proxy: Option<Proxy>) -> Result<Stream> {
    let stream = open(host, port, proxy, CONNECT_TIMEOUT)?;
    stream.tcp().set_read_timeout(Some(TUNNEL_READ_TIMEOUT))?;
    Ok(stream)
}

fn open(host: &str, port: u16, proxy: Option<Proxy>, timeout: Duration) -> Result<Stream> {
    super::target_uri(host, port)?;
    let mut stream = match proxy {
        Some(proxy) => {
            crate::log!(
                Debug,
                "proxy:connect",
                "{host}:{port} via {:?} {}:{}",
                proxy.protocol(),
                proxy.host(),
                proxy.port()
            );
            let mut stream = proxy_stream(&proxy, timeout)?;
            match proxy.protocol() {
                ProxyProtocol::Http | ProxyProtocol::Https => {
                    http_connect(&mut stream, host, port, &proxy, timeout)?
                }
                ProxyProtocol::Socks4
                | ProxyProtocol::Socks4A
                | ProxyProtocol::Socks5
                | ProxyProtocol::Socks5h => socks_connect(&mut stream, host, port, &proxy)?,
                _ => bail!("unsupported proxy protocol"),
            }
            stream
        }
        None => {
            crate::log!(Debug, "proxy:connect", "{host}:{port} direct");
            Stream::Tcp(tcp_connect(host, port, timeout)?)
        }
    };
    stream.flush()?;
    Ok(stream)
}

fn proxy_stream(proxy: &Proxy, timeout: Duration) -> Result<Stream> {
    let tcp =
        tcp_connect(proxy.host(), proxy.port(), timeout).context("connecting configured proxy")?;
    if proxy.protocol() == ProxyProtocol::Https {
        tls_transport(tcp, proxy.host(), crate::tls::config(None)?)
    } else {
        Ok(Stream::Tcp(tcp))
    }
}

impl super::connect::Connection for Stream {
    fn timeout(&mut self, remaining: Duration) -> Result<()> {
        self.tcp().set_read_timeout(Some(remaining))?;
        self.tcp().set_write_timeout(Some(remaining))?;
        Ok(())
    }
}

fn tls_transport(tcp: TcpStream, host: &str, config: Arc<ClientConfig>) -> Result<Stream> {
    let host = socket_host(host);
    let name = ServerName::try_from(host.to_owned()).context("invalid HTTPS proxy hostname")?;
    let mut tls = StreamOwned::new(ClientConnection::new(config, name)?, tcp);
    while tls.conn.is_handshaking() {
        tls.conn.complete_io(&mut tls.sock)?;
    }
    Ok(Stream::Tls(Box::new(tls)))
}

fn http_connect(
    stream: &mut Stream,
    host: &str,
    port: u16,
    proxy: &Proxy,
    timeout: Duration,
) -> Result<()> {
    super::connect::connect(stream, (host, port), proxy, timeout, |remaining| {
        proxy_stream(proxy, remaining)
    })
}

/// Open a SOCKS4/4a or SOCKS5/5h tunnel to `host:port`.
fn socks_connect(stream: &mut Stream, host: &str, port: u16, proxy: &Proxy) -> Result<()> {
    let target = socks_target(proxy, host, port)?;
    if matches!(
        proxy.protocol(),
        ProxyProtocol::Socks4 | ProxyProtocol::Socks4A
    ) {
        socks4_connect(stream, host, port, proxy, target)
    } else {
        socks5_connect(stream, host, port, proxy, target)
    }
}

/// Resolve the SOCKS destination: a proxy-side name, or a local literal address.
fn socks_target(proxy: &Proxy, host: &str, port: u16) -> Result<Option<IpAddr>> {
    let host = socket_host(host);
    if !proxy.resolve_target() {
        return Ok(host.parse::<IpAddr>().ok());
    }
    Ok(Some(
        (host, port)
            .to_socket_addrs()?
            .find(|address| proxy.protocol() != ProxyProtocol::Socks4 || address.is_ipv4())
            .context("no address for SOCKS target")?
            .ip(),
    ))
}

fn socks4_connect(
    stream: &mut Stream,
    host: &str,
    port: u16,
    proxy: &Proxy,
    target: Option<IpAddr>,
) -> Result<()> {
    let host = socket_host(host);
    ensure!(
        !proxy.username().unwrap_or("").contains('\0'),
        "invalid SOCKS4 user ID"
    );
    let mut request = vec![4, 1];
    request.extend(port.to_be_bytes());
    match target {
        Some(IpAddr::V4(ip)) => request.extend(ip.octets()),
        Some(IpAddr::V6(_)) => bail!("SOCKS4 cannot connect to IPv6"),
        None => request.extend([0, 0, 0, 1]),
    }
    request.extend(proxy.username().unwrap_or("").bytes());
    request.push(0);
    if target.is_none() {
        request.extend(host.bytes());
        request.push(0);
    }
    stream.write_all(&request)?;
    let mut reply = [0; 8];
    stream.read_exact(&mut reply)?;
    ensure!(
        reply[0] == 0 && reply[1] == SOCKS4_CONNECT,
        "SOCKS4 proxy refused connection"
    );
    Ok(())
}

fn socks5_connect(
    stream: &mut Stream,
    host: &str,
    port: u16,
    proxy: &Proxy,
    target: Option<IpAddr>,
) -> Result<()> {
    socks5_authenticate(stream, proxy)?;
    let host = socket_host(host);
    let mut request = vec![5, 1, 0];
    match target {
        Some(IpAddr::V4(ip)) => {
            request.push(1);
            request.extend(ip.octets());
        }
        Some(IpAddr::V6(ip)) => {
            request.push(4);
            request.extend(ip.octets());
        }
        None => {
            ensure!(host.len() <= 255, "SOCKS hostname exceeds 255 bytes");
            request.extend([3, host.len() as u8]);
            request.extend(host.bytes());
        }
    }
    request.extend(port.to_be_bytes());
    stream.write_all(&request)?;
    let mut reply = [0; 4];
    stream.read_exact(&mut reply)?;
    ensure!(reply[..3] == [5, 0, 0], "SOCKS5 proxy refused connection");
    let length = match reply[3] {
        1 => 4,
        4 => 16,
        3 => {
            let mut length = [0];
            stream.read_exact(&mut length)?;
            usize::from(length[0])
        }
        _ => bail!("invalid SOCKS5 reply address"),
    };
    // Discard the bound address and port; the tunnel is established.
    let mut address = vec![0; length + 2];
    stream.read_exact(&mut address)?;
    Ok(())
}

/// Negotiate no authentication, or username/password when credentials exist.
fn socks5_authenticate(stream: &mut Stream, proxy: &Proxy) -> Result<()> {
    let authenticated = proxy.username().is_some() || proxy.password().is_some();
    stream.write_all(if authenticated {
        &[5, 1, 2]
    } else {
        &[5, 1, 0]
    })?;
    let mut reply = [0; 2];
    stream.read_exact(&mut reply)?;
    ensure!(
        reply == [5, if authenticated { 2 } else { 0 }],
        "SOCKS5 proxy rejected authentication method"
    );
    if !authenticated {
        return Ok(());
    }
    let user = proxy.username().unwrap_or("").as_bytes();
    let pass = proxy.password().unwrap_or("").as_bytes();
    ensure!(
        user.len() <= MAX_SOCKS_CREDENTIAL && pass.len() <= MAX_SOCKS_CREDENTIAL,
        "SOCKS5 credentials exceed 255 bytes"
    );
    let mut auth = vec![1, user.len() as u8];
    auth.extend(user);
    auth.push(pass.len() as u8);
    auth.extend(pass);
    stream.write_all(&auth)?;
    stream.read_exact(&mut reply)?;
    ensure!(reply == [1, 0], "SOCKS5 proxy authentication failed");
    Ok(())
}

#[cfg(test)]
#[path = "../../tests/unit/proxy/socket.rs"]
mod tests;
