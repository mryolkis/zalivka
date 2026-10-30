use super::data_type::DataType;
use crate::{
    ipsw::{Behavior, Identity},
    wire,
};
use anyhow::{Context, Result};
use plist::{Dictionary, Value};

/// Protocol vocabulary required by the restored service. `false` marks a
/// required entry; it is not an on/off switch.
const REQUIRED_DATA_TYPES: &[&str] = &[
    "DataType",
    "SystemImageData",
    "SystemImageRootHash",
    "SystemImageCanonicalMetadata",
    "ProvisioningData",
    "FDRTrustData",
    "FDRMemoryCommit",
    "NORData",
    "FUDData",
    "EANData",
    "RootData",
    "OverlayRootDataCount",
    "KernelCache",
    "RootTicket",
    "BuildIdentityDict",
    "BuildIdentityDictV2",
    "BasebandBootData",
    "BasebandStackData",
    "BasebandData",
    "DiagData",
    "BasebandUpdaterOutputData",
    "GrapeFWData",
    "HPMFWData",
    "SsoServiceTicket",
    "S3EOverride",
    "USBCOverride",
    "USBCFWData",
    "OpalFWData",
    "StockholmPostflight",
    "FirmwareUpdaterData",
    "FirmwareUpdaterDataV2",
    "FileData",
    "FileDataDone",
    "RecoveryOSOverlayRootDataCount",
    "SourceBootObjectV3",
    "SourceBootObjectV4",
    "RecoveryOSLocalPolicy",
    "PersonalizedBootObjectV3",
    "BootabilityBundle",
    "BootabilityBundleV2",
    "MessageUseStreamedImageFile",
];

/// Message names and whether each is optional.
const MESSAGE_TYPES: &[(&str, bool)] = &[
    ("MsgType", false),
    ("DataRequestMsg", false),
    ("AsyncDataRequestMsg", true),
    ("ProgressMsg", false),
    ("StatusMsg", false),
    ("CheckpointMsg", true),
    ("PreviousRestoreLogMsg", false),
    ("BBUpdateStatusMsg", false),
    ("ProvisioningInfo", false),
    ("ProvisioningAck", false),
    ("ProvisioningStatusMsg", false),
    ("ReceivedFinalStatusMsg", false),
    ("AsyncWait", true),
    ("RestoreProtocol", true),
    ("RestoreAttestation", true),
    ("RestoredCrash", true),
];

pub fn supported_data_types() -> Value {
    let mut types = DataType::async_types();
    // Legacy required message names must also be present.
    for name in REQUIRED_DATA_TYPES {
        types.insert((*name).into(), false.into());
    }
    // A capability marker enabling Canary's self-test, not a V3 data envelope.
    types.insert("FirmwareUpdaterDataV3".into(), true.into());
    Value::Dictionary(types)
}

pub fn options(id: &Identity) -> Result<Value> {
    let update = id.behavior()? == Behavior::Update;
    // The booleans mark optionality, not an on/off switch.
    let mut fields = Dictionary::from_iter([
        ("SupportedDataTypes", supported_data_types()),
        (
            "SupportedMessageTypes",
            wire::dict(
                MESSAGE_TYPES
                    .iter()
                    .map(|(name, optional)| (*name, (*optional).into())),
            ),
        ),
        (
            "SupportedAsyncDataTypes",
            Value::Dictionary(DataType::async_types()),
        ),
        (
            "SupportedHostProtocols",
            Value::Array(vec!["MuxSocket".into()]),
        ),
        (
            "AuthInstallRestoreBehavior",
            if update { "Update" } else { "Erase" }.into(),
        ),
        ("CreateFilesystemPartitions", (!update).into()),
        ("FormatForAPFS", (!update).into()),
        ("AutoBootDelay", 0u64.into()),
        ("BootImageType", "User".into()),
        ("SystemImageType", "User".into()),
        ("DFUFileType", "RELEASE".into()),
    ]);
    insert_flags(
        &mut fields,
        &[
            "FlashNOR",
            "SystemImage",
            "ShouldRestoreSystemImage",
            "PersonalizedDuringPreflight",
        ],
        true,
    );
    insert_flags(
        &mut fields,
        &[
            "RootToInstall",
            "InstallDiags",
            "UpdateBaseband",
            "SkipPreflightPersonalization",
        ],
        false,
    );
    if id.is_macos()? {
        macos_options(&mut fields, id)?;
    }
    if let Some(value) = wire::optional(&id.value, &["Info", "SystemPartitionPadding"])? {
        for (size, padding) in wire::dictionary(value).context("invalid SystemPartitionPadding")? {
            size.parse::<u64>()
                .with_context(|| format!("invalid SystemPartitionPadding key {size}"))?;
            wire::number(padding)
                .with_context(|| format!("invalid SystemPartitionPadding.{size}"))?;
        }
        fields.insert("SystemPartitionPadding".into(), value.clone());
    }
    Ok(Value::Dictionary(fields))
}

fn insert_flags(fields: &mut Dictionary, keys: &[&str], value: bool) {
    for key in keys {
        fields.insert((*key).into(), value.into());
    }
}

fn macos_options(fields: &mut Dictionary, id: &Identity) -> Result<()> {
    insert_flags(
        fields,
        &[
            "AddSystemPartitionPadding",
            "DisableUserAuthentication",
            "FitSystemPartitionToContent",
            "InstallRecoveryOS",
            "MacOSSwapPerformed",
            "MacOSVariantPresent",
            "RecoveryOSUnpack",
        ],
        true,
    );
    insert_flags(
        fields,
        &[
            "AllowUntetheredRestore",
            "AuthInstallEnableSso",
            "FormatForLwVM",
        ],
        false,
    );
    fields.insert(
        "AuthInstallRecoveryOSVariant".into(),
        id.info("MacOSVariant")?.clone(),
    );
    if let Some(value) = wire::optional(&id.value, &["Info", "recoveryOSPartitionSize"])? {
        wire::number(value).context("invalid recoveryOSPartitionSize")?;
        fields.insert("recoveryOSPartitionSize".into(), value.clone());
    }
    if let Some(value) = wire::optional(&id.value, &["Info", "MinimumSystemPartition"])? {
        wire::number(value).context("invalid MinimumSystemPartition")?;
        fields.insert("SystemPartitionSize".into(), value.clone());
    }
    Ok(())
}

pub fn boot_arguments(id: &Identity) -> Result<&'static str> {
    Ok(if id.behavior()? == Behavior::Update {
        "setenvnp boot-args rd=md0 -progress -restore"
    } else {
        "setenvnp boot-args rd=md0 nand-enable-reformat=1 -progress -restore"
    })
}
