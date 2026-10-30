//! Apple's local Canary self-test; synthetic fields never enter TSS.
use crate::wire;
use anyhow::{Context, Result, ensure};
use plist::Value;

/// Canary is Apple's local protocol self-test, enabled by the V3 capability.
/// These deliberately synthetic Test,Ticket fields never enter TSS or IMG4.
/// Confirmed in 26A434 libauthinstall __Canary{GetTags,CopyFirmware,LocalSign}.
pub fn canary_response(arguments: &Value) -> Result<Option<Value>> {
    if wire::string(arguments, &["MessageArgUpdaterName"]).ok() != Some("Canary") {
        return Ok(None);
    }
    ensure!(
        wire::string(arguments, &["MessageArgType"])? == "FirmwareResponseData",
        "invalid Canary message type"
    );
    let info = wire::dictionary(wire::get(arguments, &["MessageArgInfo"])?)?;
    let query = query_mode(info, arguments)?;
    if let Some(tags) = wire::dictionary(arguments)?.get("DeviceGeneratedTags") {
        validate_tags(wire::dictionary(tags)?, query)?;
    }
    let test = Value::Data(vec![if query { 1 } else { 2 }; 4]);
    Ok(Some(wire::dict([
        (
            "Test,Ticket,1",
            wire::dict([("Test,Ticket,1", test.clone())]),
        ),
        ("Test,Ticket,2", test),
        (
            "FirmwareData",
            wire::dict([
                ("FirmwareEntry1", "PlaceholderData".into()),
                ("FirmwareEntry2", "PlaceholderData".into()),
            ]),
        ),
    ])))
}

/// QueryLoop0 may be in MessageArgInfo or in a generated request; both must agree.
fn query_mode(info: &plist::Dictionary, arguments: &Value) -> Result<bool> {
    let mut query = info.get("QueryLoop0");
    if let Some(generated) = wire::dictionary(arguments)?.get("DeviceGeneratedRequest")
        && let Some(value) = wire::dictionary(generated)?.get("QueryLoop0")
    {
        ensure!(
            query.is_none_or(|previous| previous == value),
            "conflicting Canary QueryLoop0"
        );
        query = Some(value);
    }
    query
        .and_then(Value::as_boolean)
        .context("Canary QueryLoop0 must be boolean")
}

fn validate_tags(tags: &plist::Dictionary, query: bool) -> Result<()> {
    let names = super::request::tags(
        tags.get("ResponseTags")
            .context("missing Canary ResponseTags")?,
    )?;
    ensure!(
        names
            .iter()
            .copied()
            .filter(|name| *name != "FirmwareData")
            .eq(["Test,Ticket,1", "Test,Ticket,2"]),
        "unrecognized Canary response tags"
    );
    if let Some(build) = tags.get("BuildIdentityTags") {
        ensure!(
            build
                .as_array()
                .is_some_and(|tags| tags.len() == 1 && tags[0].as_string() == Some("TestFirmware")),
            "unrecognized Canary build tags"
        );
    }
    if let Some(instance) = tags.get("LoopInstance") {
        ensure!(
            instance.as_string() == Some(if query { "InstanceA" } else { "InstanceB" }),
            "invalid Canary LoopInstance"
        );
    }
    Ok(())
}
