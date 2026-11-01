//! Shared proxy policy for HTTP requests and the opaque restoreOS FDR tunnel.
use anyhow::{Context, Result, ensure};
use ureq::unversioned::transport::{
    ConnectionDetails, Connector, DefaultConnector, RustlsConnector, SocksConnector, TcpConnector,
    Transport,
};
use ureq::{Proxy, http::Uri};

mod connect;
pub(crate) mod socket;

pub(crate) use crate::platform::proxy::for_url;

/// This marker is produced only before HTTP request bytes can reach a server.
/// PAC failover must never replay a partially sent POST or response.
#[derive(Debug)]
pub(crate) struct ConnectFailure(pub(crate) anyhow::Error);
impl std::fmt::Display for ConnectFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("connecting proxy route")
    }
}
impl std::error::Error for ConnectFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}

pub(crate) fn try_routes<T>(
    routes: Vec<Option<Proxy>>,
    mut connect: impl FnMut(Option<Proxy>) -> Result<T>,
) -> Result<T> {
    ensure!(
        !routes.is_empty(),
        "proxy resolver returned no routes; direct fallback is disabled"
    );
    let mut routes = routes.into_iter().peekable();
    while let Some(proxy) = routes.next() {
        crate::progress::check_cancelled()?;
        match connect(proxy) {
            Ok(value) => return Ok(value),
            Err(error)
                if routes.peek().is_some() && error.chain().any(|e| e.is::<ConnectFailure>()) =>
            {
                crate::log!(
                    Warning,
                    "proxy",
                    "Connection failed: {error:#}; trying the next configured proxy route"
                );
            }
            Err(error) => return Err(error),
        }
    }
    unreachable!()
}

/// Keep the HTTPS proxy's trust roots separate from Apple's private TSS PKI.
#[derive(Debug)]
pub(crate) struct HttpConnector {
    tls: RustlsConnector,
    proxy_config: ureq::config::Config,
    tss: bool,
}

impl HttpConnector {
    pub(crate) fn new(proxy_config: ureq::config::Config) -> Self {
        Self {
            tls: RustlsConnector::default(),
            proxy_config,
            tss: false,
        }
    }

    pub(crate) fn for_tss(proxy_config: ureq::config::Config) -> Self {
        Self {
            tss: true,
            ..Self::new(proxy_config)
        }
    }
}

impl Connector for HttpConnector {
    type Out = Box<dyn Transport>;

    fn connect(
        &self,
        details: &ConnectionDetails,
        chained: Option<()>,
    ) -> Result<Option<Self::Out>, ureq::Error> {
        self.connect_route(details, chained).map_err(|error| {
            let error = match error {
                ureq::Error::Other(error) => anyhow::Error::from_boxed(error),
                error => error.into(),
            };
            ureq::Error::Other(ConnectFailure(error).into())
        })
    }
}

impl HttpConnector {
    fn connect_route(
        &self,
        details: &ConnectionDetails,
        chained: Option<()>,
    ) -> Result<Option<Box<dyn Transport>>, ureq::Error> {
        let transport = if chained.is_none()
            && let Some(proxy) = details.config.proxy()
            && matches!(
                proxy.protocol(),
                ureq::ProxyProtocol::Http | ureq::ProxyProtocol::Https
            )
            && !proxy.is_no_proxy(details.uri)
        {
            self.connect_http(details, proxy)?
        } else {
            ().chain(SocksConnector::default())
                .chain(TcpConnector::default())
                .connect(details, chained)?
                .ok_or(ureq::Error::ConnectionFailed)?
                .boxed()
        };
        // Every route arrives here with a transport to the destination. TLS to
        // an HTTPS proxy belongs to the tunnel, not to the destination server.
        if self.tss && details.needs_tls() {
            return crate::net::tls::connect_tss(details, transport).map(Some);
        }
        Ok(self
            .tls
            .connect(details, Some(transport))?
            .map(Transport::boxed))
    }
}

impl HttpConnector {
    fn connect_http(
        &self,
        details: &ConnectionDetails,
        proxy: &Proxy,
    ) -> Result<Box<dyn Transport>, ureq::Error> {
        use std::time::Duration;
        use ureq::unversioned::transport::TransportAdapter;
        let timeout = details
            .timeout
            .not_zero()
            .map(|duration| *duration)
            .unwrap_or(Duration::from_secs(30));
        let make = |remaining: Duration| -> anyhow::Result<_> {
            let timeout = ureq::unversioned::transport::NextTimeout {
                after: remaining.into(),
                ..details.timeout
            };
            let addrs = details
                .resolver
                .resolve(proxy.uri(), &self.proxy_config, timeout)?;
            let proxy_details = ConnectionDetails {
                uri: proxy.uri(),
                addrs,
                config: &self.proxy_config,
                request_level: true,
                resolver: details.resolver,
                now: details.now,
                timeout,
                current_time: details.current_time.clone(),
                run_connector: details.run_connector.clone(),
                register_shutdown: details.register_shutdown.clone(),
            };
            let transport = DefaultConnector::default()
                .connect(&proxy_details, None)?
                .context("connecting configured HTTP proxy")?;
            Ok(TransportAdapter::new(
                transport,
                details.current_time.clone(),
            ))
        };
        (|| -> anyhow::Result<_> {
            let mut stream = make(timeout)?;
            let host = details
                .uri
                .host()
                .context("HTTP proxy target has no hostname")?;
            let port = details
                .uri
                .port_u16()
                .unwrap_or(if details.needs_tls() { 443 } else { 80 });
            connect::connect(&mut stream, (host, port), proxy, timeout, make)?;
            Ok(TunnelTransport(stream.into_inner()).boxed())
        })()
        .map_err(|error| ureq::Error::Other(error.into()))
    }
}

impl<T: Transport> connect::Connection for ureq::unversioned::transport::TransportAdapter<T> {
    fn timeout(&mut self, remaining: std::time::Duration) -> anyhow::Result<()> {
        self.set_timeout(ureq::unversioned::transport::NextTimeout {
            after: remaining.into(),
            reason: ureq::Timeout::Connect,
            ..Default::default()
        });
        Ok(())
    }
}

#[derive(Debug)]
struct TunnelTransport(Box<dyn Transport>);
impl Transport for TunnelTransport {
    fn buffers(&mut self) -> &mut dyn ureq::unversioned::transport::Buffers {
        self.0.buffers()
    }
    fn transmit_output(
        &mut self,
        amount: usize,
        timeout: ureq::unversioned::transport::NextTimeout,
    ) -> Result<(), ureq::Error> {
        self.0.transmit_output(amount, timeout)
    }
    fn await_input(
        &mut self,
        timeout: ureq::unversioned::transport::NextTimeout,
    ) -> Result<bool, ureq::Error> {
        self.0.await_input(timeout)
    }
    fn is_open(&mut self) -> bool {
        self.0.is_open()
    }
    // TLS, if any, currently terminates at the proxy rather than the target.
    fn is_tls(&self) -> bool {
        false
    }
}

pub(crate) fn connect(host: &str, port: u16) -> Result<socket::Stream> {
    let uri = target_uri(host, port)?;
    try_routes(for_url(&uri)?, |proxy| connect_via(&uri, proxy))
}

/// A tunnel exposes the destination port, but no HTTP path or target TLS session.
fn target_uri(host: &str, port: u16) -> Result<Uri> {
    ensure!(port != 0 && !host.is_empty(), "invalid tunnel destination");
    let authority = format!("{host}:{port}");
    let uri: Uri = format!(
        "{}://{host}:{port}/",
        if port == 80 { "http" } else { "https" }
    )
    .parse()?;
    ensure!(
        uri.authority()
            .is_some_and(|value| value.as_str() == authority)
            && uri.host() == Some(host)
            && uri.port_u16() == Some(port)
            && !authority.contains('@')
            && uri.path() == "/"
            && uri.query().is_none(),
        "invalid tunnel hostname"
    );
    Ok(uri)
}

fn connect_via(uri: &Uri, proxy: Option<Proxy>) -> Result<socket::Stream> {
    let host = uri.host().context("tunnel destination has no host")?;
    let port = uri
        .port_u16()
        .unwrap_or(if uri.scheme_str() == Some("http") {
            80
        } else {
            443
        });
    // The destination's TLS remains opaque to the proxy tunnel.
    socket::connect_blocking(host, port, proxy).map_err(|error| ConnectFailure(error).into())
}

#[cfg(test)]
#[path = "../tests/unit/proxy.rs"]
mod tests;
