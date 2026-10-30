//! Filesystem transfer, boot objects and manifest-selected image collections.
use crate::{
    asr,
    ipsw::{Identity, Ipsw},
    mux::MuxStream,
    wire,
};
use anyhow::{Context, Result, ensure};
use plist::{Dictionary, Value};
use std::{collections::HashSet, io::Write};

const BOOTABILITY_BUNDLES: [&str; 2] = ["BootabilityBundle/", "BootabilityBundleV2/"];
const BOOTABILITY_RESTORE: &str = "Restore/Bootability/";
const BOOTABILITY_TRUSTCACHE: &str = "Restore/Firmware/Bootability.dmg.trustcache";
const TRAILER: &str = "TRAILER!!!";

pub(super) fn serve_asr(ipsw: &mut Ipsw, id: &Identity, stream: &mut MuxStream) -> Result<()> {
    let mut image = ipsw.image(id.path("OS")?)?;
    let length = image.size();
    asr::transfer(stream, &mut image, length)
}

/// Stream selected Bootability files as one odc CPIO archive.
pub(super) fn bootability(ipsw: &mut Ipsw, out: &mut impl Write) -> Result<()> {
    let _trace = crate::logging::firmware_transfer();
    let mut entries = Vec::new();
    let mut names = HashSet::new();
    for path in ipsw.files()? {
        let Some(name) = bootability_name(&path) else {
            continue;
        };
        ensure!(
            name.trim_end_matches('/') != TRAILER
                && names.insert(name.trim_end_matches('/').to_owned()),
            "duplicate or reserved Bootability entry {name}"
        );
        let mode = ipsw.unix_mode(&path)?;
        let size = ipsw.size(&path)?;
        let mut header = Vec::new();
        cpio_header(&mut header, name, mode, size)?;
        entries.push((header, path, size));
    }
    ensure!(!entries.is_empty(), "IPSW has no BootabilityBundle");
    for (header, path, size) in entries {
        out.write_all(&header)?;
        ensure!(
            ipsw.stream(&path, out)? == size,
            "truncated Bootability entry"
        );
    }
    cpio_header(out, TRAILER, 0, 0)
}

/// The CPIO name for a BootabilityBundle entry, without the bundle prefix.
fn bootability_name(path: &str) -> Option<&str> {
    let relative = BOOTABILITY_BUNDLES
        .iter()
        .find_map(|prefix| path.strip_prefix(prefix))?;
    let name = match relative {
        _ if relative.starts_with(BOOTABILITY_RESTORE) => {
            relative.strip_prefix(BOOTABILITY_RESTORE)?
        }
        BOOTABILITY_TRUSTCACHE => "Bootability.trustcache",
        _ => return None,
    };
    (!name.is_empty()).then_some(name)
}

pub fn cpio_header(out: &mut impl Write, name: &str, mode: u32, size: u64) -> Result<()> {
    crate::ipsw::validate_path(name).context("unsafe CPIO entry name")?;
    ensure!(
        name.len() < 0o777777 && size <= 0o77777777777 && mode <= 0o777777,
        "CPIO entry exceeds odc field sizes"
    );
    let header = format!(
        "070707{0:06o}{0:06o}{mode:06o}{0:06o}{0:06o}{1:06o}{0:06o}{0:011o}{namesize:06o}{size:011o}",
        0,
        1,
        namesize = name.len() + 1
    );
    ensure!(
        header.len() == 76 && !name.contains('\0'),
        "invalid CPIO header"
    );
    out.write_all(header.as_bytes())?;
    out.write_all(name.as_bytes())?;
    out.write_all(&[0])?;
    Ok(())
}

pub(super) fn boot_object_path(id: &Identity, name: &str, message: &Value) -> Result<String> {
    let path = match name {
        "__RestoreVersion__" => "RestoreVersion.plist".into(),
        "__SystemVersion__" => "SystemVersion.plist".into(),
        "__GlobalManifest__" => global_manifest_path(id, message)?,
        component => id.path(component)?.into(),
    };
    crate::ipsw::validate_path(&path)?;
    Ok(path)
}

/// Locate the AP ticket selected by the requested variant and optional affixes.
fn global_manifest_path(id: &Identity, message: &Value) -> Result<String> {
    let variant = match wire::optional(message, &["Arguments", "Variant"])? {
        Some(value) => value
            .as_string()
            .filter(|value| !value.is_empty())
            .context("invalid Arguments.Variant")?,
        None => wire::string(&id.value, &["Info", "MacOSVariant"])?,
    };
    let class = wire::string(&id.value, &["Info", "DeviceClass"])?;
    // These optional fields select an AP ticket without a suffix when
    // omitted. A present value with the wrong type is still an error.
    let prefix = wire::optional(message, &["Arguments", "GlobalManifestPrefix"])?
        .map(|value| {
            value
                .as_string()
                .context("invalid Arguments.GlobalManifestPrefix")
        })
        .transpose()?
        .unwrap_or("apticket");
    let suffix = wire::optional(message, &["Arguments", "GlobalManifestSuffix"])?
        .map(|value| {
            value
                .as_string()
                .context("invalid Arguments.GlobalManifestSuffix")
        })
        .transpose()?
        .unwrap_or("");
    Ok(format!(
        "Firmware/Manifests/restore/{variant}/{prefix}.{class}{suffix}.im4m"
    ))
}

pub(super) fn image_data(
    ipsw: &mut Ipsw,
    id: &Identity,
    ticket: &Value,
    kind: &str,
    message: &Value,
) -> Result<Value> {
    let (list, image_type, key) = match kind {
        "FUDData" => ("FUDImageList", "IsFUDFirmware", "FUDImageData"),
        "EANData" => ("EANImageList", "IsEarlyAccessFirmware", "EANData"),
        _ => (
            "ImageList",
            wire::string(message, &["Arguments", "ImageType"])?,
            "ImageData",
        ),
    };
    let want_list = wire::flag(message, &["Arguments", list])?;
    let image_name = wire::optional(message, &["Arguments", "ImageName"])?
        .map(|value| {
            value
                .as_string()
                .filter(|value| !value.is_empty())
                .context("invalid Arguments.ImageName")
        })
        .transpose()?;
    let mut names = Vec::new();
    for (name, entry) in id.manifest()? {
        if wire::flag(entry, &["Info", image_type])? {
            names.push(name.as_str());
        }
    }
    if want_list {
        return Ok(wire::dict([(
            list,
            Value::Array(names.into_iter().map(Value::from).collect()),
        )]));
    }
    if let Some(name) = image_name {
        ensure!(
            names.contains(&name),
            "requested image does not match {image_type}"
        );
        return Ok(wire::dict([
            (key, Value::Data(ipsw.personalized(id, name, ticket)?)),
            ("ImageName", name.into()),
        ]));
    }
    Ok(wire::dict([(
        key,
        Value::Dictionary(personalized_images(ipsw, id, ticket, names.into_iter())?),
    )]))
}

pub(super) fn personalized_images<'a>(
    ipsw: &mut Ipsw,
    id: &Identity,
    ticket: &Value,
    names: impl Iterator<Item = &'a str>,
) -> Result<Dictionary> {
    names
        .map(|name| {
            Ok((
                name.to_owned(),
                Value::Data(ipsw.personalized(id, name, ticket)?),
            ))
        })
        .collect()
}

/// NOR images: every primary/secondary boot firmware image except LLB and the
/// restore SEP, with the primary iBoot image first.
pub(super) fn nor_data(
    ipsw: &mut Ipsw,
    id: &Identity,
    ticket: &Value,
    message: &Value,
) -> Result<Value> {
    let llb = id.require_component_type(b"illb")?;
    let restore_sep = id.component_by_type(b"rsep")?;
    let iboot = id.component_by_type(b"ibot")?;
    let mut names = Vec::new();
    for (name, entry) in id.manifest()? {
        let primary = wire::flag(entry, &["Info", "IsFirmwarePayload"])?;
        let secondary = wire::flag(entry, &["Info", "IsSecondaryFirmwarePayload"])?;
        let loaded = wire::flag(entry, &["Info", "IsLoadedByiBoot"])?;
        if (primary || (secondary && loaded)) && name != llb && Some(name.as_str()) != restore_sep {
            names.push(name.as_str());
        }
    }
    names.sort_by_key(|name| Some(*name) != iboot);
    let flash_v1 = wire::optional(message, &["Arguments", "FlashVersion1"])?.is_some();
    let images = if flash_v1 {
        Value::Dictionary(personalized_images(ipsw, id, ticket, names.into_iter())?)
    } else {
        Value::Array(
            names
                .into_iter()
                .map(|name| ipsw.personalized(id, name, ticket).map(Value::Data))
                .collect::<Result<_>>()?,
        )
    };
    let mut fields = Dictionary::new();
    fields.insert(
        "LlbImageData".into(),
        Value::Data(ipsw.personalized(id, llb, ticket)?),
    );
    fields.insert("NorImageData".into(), images);
    for (tag, key) in [(b"rsep", "RestoreSEPImageData"), (b"sepi", "SEPImageData")] {
        if let Some(name) = id.component_by_type(tag)? {
            fields.insert(
                key.into(),
                Value::Data(ipsw.personalized(id, name, ticket)?),
            );
        }
    }
    Ok(Value::Dictionary(fields))
}
