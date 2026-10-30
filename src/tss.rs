//! Apple TSS transport and response validation.
//!
//! Requests are ordinary XML plists. Apple answers with a form-encoded status
//! header followed by `&REQUEST_STRING=` and the signed plist; the whole
//! response must be validated before any ticket can boot a device.
mod request;
pub use request::{apply_rules, local_policy_request, recovery_request, request};
pub(crate) use request::{host_fields, updater_fields};

use crate::{img4, net, wire};
use anyhow::{Context, Result, ensure};
use plist::Value;

const TSS_URL: &str = "https://gs.apple.com/TSS/controller?action=2";
const MAX_RESPONSE: u64 = 16 * 1024 * 1024;

pub fn send(request: &Value) -> Result<Value> {
    let response = send_raw(request)?;
    validate_ticket(request, &response)?;
    Ok(response)
}

/// Check server-generated measurements before using the ticket to boot a device.
pub fn validate_ticket<'a>(request: &Value, response: &'a Value) -> Result<&'a [u8]> {
    let ticket = ticket(response)?;
    for (name, entry) in wire::dictionary(request)? {
        let Some(entry) = entry.as_dictionary() else {
            continue;
        };
        let trusted = entry.get("Trusted").and_then(Value::as_boolean) == Some(true);
        let server_measured = entry
            .get("Digest")
            .and_then(Value::as_data)
            .is_some_and(|digest| digest.is_empty());
        if name.len() != 4 || !name.is_ascii() || !trusted || !server_measured {
            continue;
        }
        let object: &[u8; 4] = name.as_bytes().try_into()?;
        let digest = img4::manifest_data(ticket, object, b"DGST")
            .with_context(|| format!("validating server-generated {name} measurement"))?;
        ensure!(
            digest.is_some_and(|digest| !digest.is_empty()),
            "Apple ticket is missing the server-generated {name} digest; refusing to boot"
        );
    }
    Ok(ticket)
}

pub fn send_raw(request: &Value) -> Result<Value> {
    crate::logging::plist("tss", "Request", request);
    let request = ureq::http::Request::post(TSS_URL)
        .header("Content-Type", "text/xml")
        .body(wire::xml(request)?)?;
    let mut response =
        net::send_http(&net::tss_agent(), &request).context("Apple TSS request failed")?;
    ensure!(
        response.status().is_success(),
        "Apple TSS returned {}",
        response.status()
    );
    let data = crate::storage::read_limited(
        response.body_mut().as_reader(),
        MAX_RESPONSE,
        "TSS response too large",
    )?;
    crate::logging::bytes("tss", format_args!("RX"), &data);
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
    wire::decode_plist(plist.as_bytes()).context("invalid TSS plist")
}

pub fn ticket(response: &Value) -> Result<&[u8]> {
    wire::get(response, &["ApImg4Ticket"])?
        .as_data()
        .filter(|ticket| !ticket.is_empty())
        .context("Apple returned no ApImg4Ticket")
}
