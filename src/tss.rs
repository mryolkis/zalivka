//! Apple TSS transport and response validation.
mod request;
use crate::{img4, net, wire};
use anyhow::{Context, Result, ensure};
use plist::Value;
pub use request::{apply_rules, local_policy_request, recovery_request, request};
pub(crate) use request::{host_fields, updater_fields};

const TSS_URL: &str = "https://gs.apple.com/TSS/controller?action=2";

pub fn send(request: &Value) -> Result<Value> {
    let response = send_raw(request)?;
    validate_ticket(request, &response)?;
    Ok(response)
}

pub fn send_for_identity(request: &Value, identity: &crate::ipsw::Identity) -> Result<Value> {
    let response = send_raw(request)?;
    validate_ticket_for_identity(request, &response, identity)?;
    Ok(response)
}

/// Check hardware and requested measurements before using an AP ticket.
pub fn validate_ticket<'a>(request: &Value, response: &'a Value) -> Result<&'a [u8]> {
    validate_measurements(request, response, None)
}

pub fn validate_ticket_for_identity<'a>(
    request: &Value,
    response: &'a Value,
    identity: &crate::ipsw::Identity,
) -> Result<&'a [u8]> {
    validate_measurements(request, response, Some(identity))
}

fn validate_measurements<'a>(
    request: &Value,
    response: &'a Value,
    identity: Option<&crate::ipsw::Identity>,
) -> Result<&'a [u8]> {
    let ticket = ticket(response)?;
    let manifest = img4::Manifest::parse(ticket)?;
    manifest.check_hardware(request)?;
    let digests = manifest.digests()?;
    for (name, entry) in wire::dictionary(request)? {
        let Some(entry) = entry.as_dictionary() else {
            continue;
        };
        if entry.get("Trusted").and_then(Value::as_boolean) != Some(true) {
            continue;
        }
        let expected = entry
            .get("Digest")
            .and_then(Value::as_data)
            .with_context(|| format!("missing signing Digest for {name}"))?;
        let tag = if name == "Ap,LocalPolicy" {
            Some(*b"lpol")
        } else {
            let explicit = identity
                .map(|id| id.payload_type(name))
                .transpose()?
                .flatten();
            explicit.or_else(|| {
                (name.len() == 4
                    && name
                        .bytes()
                        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit()))
                .then(|| name.as_bytes().try_into().expect("four ASCII bytes"))
            })
        };
        if expected.is_empty() {
            let tag = tag.with_context(|| {
                format!("cannot resolve server-generated {name} measurement type")
            })?;
            ensure!(
                digests.contains_key(&tag),
                "Apple ticket is missing the server-generated {name} digest; refusing to boot"
            );
        } else {
            ensure!(
                [20, 32, 48].contains(&expected.len()),
                "unsupported signing Digest for {name}"
            );
            let matches = tag.map_or_else(
                || digests.values().any(|actual| *actual == expected),
                |tag| digests.get(&tag).is_some_and(|actual| *actual == expected),
            );
            ensure!(
                matches,
                "Apple ticket digest mismatch or missing measurement for {name}; refusing to boot"
            );
        }
    }
    Ok(ticket)
}

pub fn send_raw(request: &Value) -> Result<Value> {
    crate::logging::plist("tss", "Request", request);
    let body = wire::xml(request)?;
    let request = ureq::http::Request::post(TSS_URL)
        .header("Content-Type", "text/xml")
        .body(body)?;
    let mut response =
        net::send_http(&net::tss_agent(), &request).context("Apple TSS request failed")?;
    ensure!(
        response.status().is_success(),
        "Apple TSS returned {}",
        response.status()
    );
    let data = crate::storage::read_limited(
        response.body_mut().as_reader(),
        16 * 1024 * 1024,
        "TSS response too large",
    )?;
    crate::log!(Trace, "tss", "RX: {} B", data.len());
    parse_response(&data)
}

pub fn parse_response(data: &[u8]) -> Result<Value> {
    let text = std::str::from_utf8(data).context("TSS response is not UTF-8")?;
    let response = text.split_once("&REQUEST_STRING=");
    let header = response.map_or(text, |(header, _)| header);
    let mut status = header
        .split('&')
        .filter_map(|field| field.strip_prefix("STATUS="));
    ensure!(
        status.next() == Some("0") && status.next().is_none(),
        "Apple refused personalization: {header}"
    );
    let (_, plist) = response.context("TSS response has no REQUEST_STRING")?;
    let value = wire::decode_plist(plist.as_bytes()).context("invalid TSS plist")?;
    Ok(value)
}

pub fn ticket(response: &Value) -> Result<&[u8]> {
    wire::get(response, &["ApImg4Ticket"])?
        .as_data()
        .filter(|d| !d.is_empty())
        .context("Apple returned no ApImg4Ticket")
}
