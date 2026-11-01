//! System proxy selection, environment overrides and native proxy-list formats.
#[cfg(any(target_os = "linux", test))]
use anyhow::ensure;
use anyhow::{Context, Result};
use ureq::{Proxy, http::Uri};

pub(crate) fn for_url(uri: &Uri) -> Result<Vec<Option<Proxy>>> {
    crate::progress::check_cancelled()?;
    #[cfg(windows)]
    if let Some(proxy) = crate::platform::windows::proxy::for_url(uri)? {
        return Ok(vec![proxy]);
    }
    // An explicitly configured environment proxy overrides desktop settings.
    // NO_PROXY is an explicit DIRECT decision, not an absent configuration.
    if proxy_variables(uri)
        .iter()
        .any(|name| std::env::var(name).is_ok_and(|v| !v.trim().is_empty()))
    {
        return Ok(vec![environment_proxy(uri, |name| {
            std::env::var(name).ok()
        })?]);
    }
    #[cfg(target_os = "linux")]
    return super::linux::proxy::for_url(uri);
    #[cfg(target_os = "macos")]
    return super::macos::proxy::for_url(uri);
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    Ok(vec![None])
}

fn proxy_variables(uri: &Uri) -> [&'static str; 4] {
    if uri.scheme_str() == Some("http") {
        ["HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"]
    } else {
        ["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"]
    }
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn routes_from_strings(values: Vec<String>) -> Result<Vec<Option<Proxy>>> {
    ensure!(
        !values.is_empty() && values.len() <= 32,
        "invalid system proxy route list; direct fallback is disabled"
    );
    let mut routes = Vec::new();
    for value in values {
        if value == "direct://" {
            routes.push(None);
        } else if let Some(address) = value.strip_prefix("socks://") {
            // An unspecified SOCKS version means v5, then v4 (remote DNS).
            for scheme in ["socks5h", "socks4a"] {
                routes.push(Some(Proxy::new(&format!("{scheme}://{address}"))?));
            }
        } else if let Some(address) = value.strip_prefix("socks5://") {
            // Native/PAC SOCKS5 routes resolve the destination at the proxy.
            // Preserve that behavior; explicit env socks5:// still means local DNS.
            routes.push(Some(Proxy::new(&format!("socks5h://{address}"))?));
        } else {
            routes.push(Some(
                Proxy::new(&value).context("invalid system proxy URI")?,
            ));
        }
    }
    Ok(routes)
}

pub(crate) fn environment_proxy(
    uri: &Uri,
    read: impl Fn(&str) -> Option<String>,
) -> Result<Option<Proxy>> {
    let names = proxy_variables(uri);
    let Some((name, address)) = names.iter().find_map(|name| {
        read(name)
            .filter(|v| !v.trim().is_empty())
            .map(|value| (name, value))
    }) else {
        return Ok(None);
    };
    let proxy = Proxy::new(address.trim())
        .with_context(|| format!("invalid {name}; direct fallback is disabled"))?;
    let mut builder = Proxy::builder(proxy.protocol())
        .host(proxy.host())
        .port(proxy.port())
        .resolve_target(proxy.resolve_target());
    if let Some(user) = proxy.username() {
        builder = builder.username(user);
    }
    if let Some(password) = proxy.password() {
        builder = builder.password(password);
    }
    if let Some(bypass) = read("NO_PROXY")
        .filter(|value| !value.trim().is_empty())
        .or_else(|| read("no_proxy"))
    {
        for pattern in bypass
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            builder = builder.no_proxy(pattern);
        }
    }
    let proxy = builder.build()?;
    Ok((!proxy.is_no_proxy(uri)).then_some(proxy))
}

/// Windows proxy lists distinguish the destination scheme (https=) from the
/// proxy transport (http://). A SOCKS entry is the fallback for other schemes.
#[cfg(any(windows, test))]
pub(crate) fn from_windows_list(uri: &Uri, list: &str, bypass: &str) -> Result<Option<Proxy>> {
    if windows_bypass(uri, bypass) {
        return Ok(None);
    }
    let entries = list
        .split(|c: char| c == ';' || c.is_whitespace())
        .filter(|entry| !entry.is_empty());
    let scheme = uri
        .scheme_str()
        .context("proxy destination has no scheme")?;
    let selected = entries
        .clone()
        .find_map(|entry| {
            let (key, value) = entry.split_once('=')?;
            key.eq_ignore_ascii_case(scheme).then_some((value, false))
        })
        .or_else(|| {
            entries
                .clone()
                .find(|entry| !entry.contains('='))
                .map(|entry| (entry, false))
        })
        .or_else(|| {
            entries.clone().find_map(|entry| {
                let (key, value) = entry.split_once('=')?;
                key.eq_ignore_ascii_case("socks").then_some((value, true))
            })
        });
    let Some((server, socks)) = selected else {
        return Ok(None);
    };
    if server.eq_ignore_ascii_case("DIRECT") {
        return Ok(None);
    }
    let server = if server.contains("://") {
        server.to_owned()
    } else {
        format!("{}://{server}", if socks { "socks4a" } else { "http" })
    };
    Ok(Some(
        Proxy::new(&server).context("invalid Windows proxy address")?,
    ))
}

#[cfg(any(windows, test))]
fn windows_bypass(uri: &Uri, bypass: &str) -> bool {
    let host = uri.host().unwrap_or("").to_ascii_lowercase();
    let port = uri
        .port_u16()
        .unwrap_or(if uri.scheme_str() == Some("https") {
            443
        } else {
            80
        });
    let address = format!("{host}:{port}");
    bypass
        .split(|c: char| c == ';' || c.is_whitespace())
        .any(|pattern| {
            let pattern = pattern.to_ascii_lowercase();
            if pattern == "<local>" {
                return !host.contains(['.', ':']);
            }
            let pattern = if let Some((scheme, pattern)) = pattern.split_once("://") {
                if Some(scheme) != uri.scheme_str() {
                    return false;
                }
                pattern
            } else {
                &pattern
            };
            !pattern.is_empty()
                && (wildcard(pattern.as_bytes(), host.as_bytes())
                    || wildcard(pattern.as_bytes(), address.as_bytes()))
        })
}

#[cfg(any(windows, test))]
fn wildcard(pattern: &[u8], text: &[u8]) -> bool {
    let (mut p, mut t, mut star) = (0, 0, None);
    while t < text.len() {
        if p < pattern.len() && (pattern[p] == b'?' || pattern[p] == text[t]) {
            p += 1;
            t += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star = Some((p, t));
            p += 1;
        } else if let Some((s, last)) = star {
            t = last + 1;
            star = Some((s, t));
            p = s + 1;
        } else {
            return false;
        }
    }
    pattern[p..].iter().all(|b| *b == b'*')
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) use super::unix::negotiate::Negotiate;
#[cfg(windows)]
pub(crate) use super::windows::negotiate::Negotiate;

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
pub(crate) struct Negotiate;

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
impl Negotiate {
    pub(crate) fn new(_scheme: &str, _host: &str) -> Result<Self> {
        anyhow::bail!("integrated proxy authentication is unavailable on this platform")
    }

    pub(crate) fn step(&mut self, _challenge: Option<&str>) -> Result<String> {
        anyhow::bail!("integrated proxy authentication is unavailable on this platform")
    }
}

#[cfg(test)]
#[path = "../../tests/unit/platform/proxy.rs"]
mod tests;
