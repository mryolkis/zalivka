use super::*;

#[test]
fn tss_requests_bind_hardware_nonce_and_component_digests() {
    let d = device_info();
    let id = identity();
    let request = tss::request(&d, &id).unwrap();
    assert_eq!(
        wire::number(wire::get(&request, &["ApECID"]).unwrap()).unwrap(),
        d.ecid
    );
    assert_eq!(
        wire::get(&request, &["ApNonce"])
            .unwrap()
            .as_data()
            .unwrap(),
        d.ap_nonce
    );
    assert!(wire::get(&request, &["iBSS", "Info"]).is_err());
    assert!(crate::test_support::boolean(&request, &["iBSS", "ESEC"]));
    assert_eq!(
        wire::get(&request, &["iBSS", "Digest"]).unwrap(),
        wire::get(&id.value, &["Manifest", "iBSS", "Digest"]).unwrap()
    );
    let local = tss::local_policy_request(&d, &ticket(), None).unwrap();
    assert_eq!(
        wire::get(&local, &["Ap,NextStageIM4MHash"])
            .unwrap()
            .as_data()
            .unwrap(),
        Sha384::digest(ticket()).as_slice()
    );
    let mut no_nonce = d;
    no_nonce.ap_nonce.clear();
    assert!(tss::request(&no_nonce, &id).is_err());
}

#[test]
fn ftab_components_are_reserved_for_updater_signing() {
    let id = identity();
    let names = [
        "Timer,RTKitOS,1",
        "Timer,RTKitOS,2",
        "Timer,RestoreRTKitOS,1",
        "Timer,RestoreRTKitOS,2",
        "FutureController,Firmware",
    ];
    let mut entry = id.manifest().unwrap()["iBSS"].clone();
    let info = entry
        .as_dictionary_mut()
        .unwrap()
        .get_mut("Info")
        .unwrap()
        .as_dictionary_mut()
        .unwrap();
    info.insert("Path".into(), "Firmware/controller/ftab.bin".into());
    info.remove("Img4PayloadType");
    for build in [tss::request, tss::recovery_request] {
        let expected = build(&device_info(), &id).unwrap();
        for flag in [
            None,
            Some(Value::Boolean(false)),
            Some(Value::Boolean(true)),
        ] {
            let mut id = id.clone();
            let mut entry = entry.clone();
            if let Some(flag) = &flag {
                entry
                    .as_dictionary_mut()
                    .unwrap()
                    .get_mut("Info")
                    .unwrap()
                    .as_dictionary_mut()
                    .unwrap()
                    .insert("IsFTAB".into(), flag.clone());
            }
            for name in names {
                manifest_mut(&mut id).insert(name.into(), entry.clone());
            }
            let request = build(&device_info(), &id).unwrap();
            if flag == Some(true.into()) {
                assert_eq!(request, expected);
            } else {
                for name in names {
                    assert!(wire::get(&request, &[name]).is_ok(), "{name}");
                }
            }
        }
    }
}

#[test]
fn signing_requires_device_security_metadata_and_never_defaults_to_production() {
    let mut device = device_info();
    for (fuse, production, security) in [
        (0, false, false),
        (1, false, true),
        (2, true, false),
        (3, true, true),
    ] {
        device.chip_fuse_mode = Some(fuse);
        let request = tss::request(&device, &identity()).unwrap();
        assert_eq!(
            wire::get(&request, &["ApProductionMode"]).unwrap(),
            &Value::Boolean(production)
        );
        assert_eq!(
            wire::get(&request, &["ApSecurityMode"]).unwrap(),
            &Value::Boolean(security)
        );
    }
    device.chip_fuse_mode = None;
    assert!(tss::request(&device, &identity()).is_err());
    device.chip_fuse_mode = Some(3);
    device.security_domain = None;
    let request = tss::request(&device, &identity()).unwrap();
    assert_eq!(
        wire::number(wire::get(&request, &["ApSecurityDomain"]).unwrap()).unwrap(),
        1
    );
    device.security_domain = Some(2);
    assert!(tss::request(&device, &identity()).is_err());
    let mut id = identity();
    manifest_mut(&mut id)
        .get_mut("iBSS")
        .unwrap()
        .as_dictionary_mut()
        .unwrap()
        .get_mut("Info")
        .unwrap()
        .as_dictionary_mut()
        .unwrap()
        .remove("Personalize");
    assert!(wire::get(&tss::request(&device_info(), &id).unwrap(), &["iBSS"]).is_ok());
}

#[test]
fn component_signing_uses_declared_trust_rules_and_actions() {
    for rules in [
        Value::Array(vec![]),
        Value::Array(vec![wire::dict([
            ("Conditions", wire::dict([] as [(&str, Value); 0])),
            (
                "Actions",
                wire::dict([
                    ("ESEC", false.into()),
                    ("FutureAction", Value::Data(vec![1, 2])),
                ]),
            ),
        ])]),
    ] {
        let mut id = identity();
        let entry = wire::dict([
            ("Trusted", true.into()),
            ("Digest", Value::Data(vec![])),
            (
                "Info",
                wire::dict([
                    ("Personalize", true.into()),
                    ("RestoreRequestRules", rules.clone()),
                ]),
            ),
        ]);
        manifest_mut(&mut id).insert("NewComponent".into(), entry);
        for build in [tss::request, tss::recovery_request] {
            let request = build(&device_info(), &id).unwrap();
            assert!(wire::get(&request, &["NewComponent", "Info"]).is_err());
            assert!(wire::get(&request, &["NewComponent", "EPRO"]).is_err());
            assert_eq!(
                wire::get(&request, &["NewComponent", "ESEC"]).is_ok(),
                !rules.as_array().unwrap().is_empty()
            );
        }
        manifest_mut(&mut id)["NewComponent"]
            .as_dictionary_mut()
            .unwrap()
            .remove("Digest");
        assert_eq!(
            wire::get(
                &tss::request(&device_info(), &id).unwrap(),
                &["NewComponent", "Digest"]
            )
            .unwrap(),
            &Value::Data(vec![])
        );
    }
}

#[test]
fn fileless_measurements_are_signed_even_with_personalize_false() {
    let manifest: Value =
        serde_json::from_str(include_str!("../fixtures/j313-26A434-fdr.json")).unwrap();
    for renamed in [false, true] {
        let mut id = identity();
        for (index, (name, value)) in manifest.as_dictionary().unwrap().iter().enumerate() {
            let name = if renamed {
                format!("new{index}")
            } else {
                name.clone()
            };
            manifest_mut(&mut id).insert(name, value.clone());
        }
        let original = id.value.clone();
        for build in [tss::request, tss::recovery_request] {
            let request = build(&device_info(), &id).unwrap();
            for (index, (name, _)) in manifest.as_dictionary().unwrap().iter().enumerate() {
                let name = if renamed {
                    format!("new{index}")
                } else {
                    name.clone()
                };
                assert_eq!(
                    wire::get(&request, &[&name]).unwrap(),
                    &wire::dict([
                        ("Trusted", true.into()),
                        ("EPRO", true.into()),
                        ("ESEC", true.into()),
                        ("Digest", Value::Data(vec![])),
                    ])
                );
            }
        }
        assert_eq!(id.value, original);
    }
}

#[test]
fn trusted_file_hashes_are_never_replaced_with_server_measurement_markers() {
    for digest in [None, Some(Value::Data(vec![])), Some("invalid".into())] {
        let mut id = identity();
        let entry = manifest_mut(&mut id)["iBSS"].as_dictionary_mut().unwrap();
        entry.remove("Digest");
        if let Some(digest) = digest {
            entry.insert("Digest".into(), digest);
        }
        entry["Info"]
            .as_dictionary_mut()
            .unwrap()
            .insert("Personalize".into(), false.into());
        for build in [tss::request, tss::recovery_request] {
            let error = build(&device_info(), &id).unwrap_err();
            assert!(format!("{error:#}").contains("iBSS"), "{error:#}");
        }
    }
    let mut id = identity();
    manifest_mut(&mut id).insert(
        "newa".into(),
        wire::dict([
            ("Trusted", true.into()),
            ("Info", wire::dict([("Personalize", false.into())])),
        ]),
    );
    assert!(tss::request(&device_info(), &id).is_err());
}

pub(super) fn measurement_property(name: &[u8; 4], value: &[u8]) -> Vec<u8> {
    use asn1_rs::{Class, Header, Length, Tag, ToDer};
    let mut body = img4::element(0x16, name);
    body.extend_from_slice(value);
    let body = img4::element(0x30, &body);
    let header = Header::new(
        Class::Private,
        true,
        Tag(u32::from_be_bytes(*name)),
        Length::Definite(body.len()),
    );
    let mut encoded = Vec::new();
    header.write_der_header(&mut encoded).unwrap();
    encoded.extend(body);
    encoded
}

pub(super) fn measurement_ticket(objects: &[u8]) -> Value {
    let mut fields = img4::element(0x16, b"IM4M");
    fields.extend(img4::element(0x02, &[0]));
    fields.extend(img4::element(
        0x31,
        &measurement_property(b"MANB", &img4::element(0x31, objects)),
    ));
    fields.extend(img4::element(0x04, b"synthetic-signature"));
    fields.extend(img4::element(0x30, &[]));
    wire::dict([("ApImg4Ticket", Value::Data(img4::element(0x30, &fields)))])
}

#[test]
fn server_generated_measurements_must_be_present_and_nonempty_in_the_returned_ticket() {
    let request = wire::dict([(
        "newa",
        wire::dict([("Trusted", true.into()), ("Digest", Value::Data(vec![]))]),
    )]);
    let digest = measurement_property(b"DGST", &img4::element(0x04, &[0xab; 32]));
    let object = measurement_property(b"newa", &img4::element(0x31, &digest));
    let valid = measurement_ticket(&object);
    assert_eq!(
        tss::validate_ticket(&request, &valid).unwrap(),
        tss::ticket(&valid).unwrap()
    );
    for objects in [
        vec![],
        measurement_property(b"newb", &img4::element(0x31, &digest)),
        measurement_property(b"newa", &img4::element(0x31, &[])),
        measurement_property(
            b"newa",
            &img4::element(
                0x31,
                &measurement_property(b"DGST", &img4::element(0x04, &[])),
            ),
        ),
        measurement_property(
            b"newa",
            &img4::element(
                0x31,
                &measurement_property(b"DGST", &img4::element(0x01, &[0xff])),
            ),
        ),
        measurement_property(
            b"newa",
            &img4::element(0x31, &[digest.clone(), digest].concat()),
        ),
        [object.clone(), object].concat(),
    ] {
        let error = tss::validate_ticket(&request, &measurement_ticket(&objects)).unwrap_err();
        assert!(format!("{error:#}").contains("newa"), "{error:#}");
    }
    for malformed in [
        b"invalid".to_vec(),
        tss::ticket(&valid).unwrap()[..12].to_vec(),
    ] {
        assert!(
            tss::validate_ticket(
                &request,
                &wire::dict([("ApImg4Ticket", Value::Data(malformed))])
            )
            .is_err()
        );
    }
}

#[test]
fn signing_rejects_malformed_metadata_instead_of_skipping_components() {
    for entry in [
        true.into(),
        wire::dict([("Info", "invalid".into())]),
        wire::dict([("Info", wire::dict([("Personalize", "yes".into())]))]),
        wire::dict([
            ("Info", wire::dict([] as [(&str, Value); 0])),
            ("Trusted", "true".into()),
        ]),
        wire::dict([
            ("Trusted", true.into()),
            ("Info", wire::dict([("RestoreRequestRules", false.into())])),
        ]),
    ] {
        let mut id = identity();
        manifest_mut(&mut id).insert("Extra".into(), entry);
        for build in [tss::request, tss::recovery_request] {
            let error = build(&device_info(), &id).unwrap_err();
            assert!(format!("{error:#}").contains("Extra"), "{error:#}");
        }
    }
    let mut id = identity();
    manifest_mut(&mut id).insert("SigningOnly".into(), wire::dict([("Trusted", true.into())]));
    for build in [tss::request, tss::recovery_request] {
        let error = build(&device_info(), &id).unwrap_err();
        assert!(format!("{error:#}").contains("SigningOnly"));
    }
}

#[test]
fn trusted_signing_measurements_without_info_keep_their_declared_digest() {
    let entry = wire::dict([
        ("Trusted", true.into()),
        ("Digest", Value::Data(vec![0x36; 48])),
    ]);
    let mut id = identity();
    manifest_mut(&mut id).insert("FutureMeasurement".into(), entry.clone());
    for build in [tss::request, tss::recovery_request] {
        let request = build(&device_info(), &id).unwrap();
        assert_eq!(wire::get(&request, &["FutureMeasurement"]).unwrap(), &entry);
    }
}

#[test]
fn local_policy_rejects_missing_empty_or_nondata_hashes() {
    let valid = wire::dict([
        ("Ap,NextStageIM4MHash", Value::Data(vec![5; 48])),
        ("Ap,RecoveryOSPolicyNonceHash", Value::Data(vec![6; 48])),
        (
            "Ap,VolumeUUID",
            "00112233-4455-6677-8899-aabbccddeeff".into(),
        ),
    ]);
    for name in ["Ap,NextStageIM4MHash", "Ap,RecoveryOSPolicyNonceHash"] {
        for invalid in [
            None,
            Some(Value::Data(vec![])),
            Some("hash".into()),
            Some(false.into()),
        ] {
            let mut args = valid.clone();
            let fields = args.as_dictionary_mut().unwrap();
            fields.remove(name);
            if let Some(value) = invalid {
                fields.insert(name.into(), value);
            }
            let error =
                tss::local_policy_request(&device_info(), &ticket(), Some(&args)).unwrap_err();
            assert!(format!("{error:#}").contains(name), "{error:#}");
        }
    }
}

#[test]
fn component_rules_use_device_parameters_independently_of_manifest_order() {
    let first = wire::dict([
        ("Trusted", true.into()),
        ("Info", wire::dict([("Personalize", true.into())])),
        ("Digest", Value::Data(vec![])),
    ]);
    for build in [tss::request, tss::recovery_request] {
        let mut id = identity();
        manifest_mut(&mut id).insert("First".into(), first.clone());
        let prepared = wire::get(&build(&device_info(), &id).unwrap(), &["First"])
            .unwrap()
            .clone();
        let second = wire::dict([
            ("Trusted", true.into()),
            ("Digest", Value::Data(vec![])),
            (
                "Info",
                wire::dict([
                    ("Personalize", true.into()),
                    (
                        "RestoreRequestRules",
                        Value::Array(vec![wire::dict([
                            ("Conditions", wire::dict([("First", prepared)])),
                            ("Actions", wire::dict([("ESEC", false.into())])),
                        ])]),
                    ),
                ]),
            ),
        ]);
        manifest_mut(&mut id).insert("Second".into(), second.clone());
        let forward = build(&device_info(), &id).unwrap();
        let entries = manifest_mut(&mut id);
        entries.remove("First");
        entries.remove("Second");
        entries.insert("Second".into(), second);
        entries.insert("First".into(), first.clone());
        let reverse = build(&device_info(), &id).unwrap();
        assert_eq!(
            wire::get(&forward, &["Second"]).unwrap(),
            wire::get(&reverse, &["Second"]).unwrap()
        );
        assert!(wire::get(&forward, &["Second", "ESEC"]).is_err());
    }
}

#[test]
fn local_policy_volume_uuid_preserves_byte_order_and_rejects_misplaced_hyphens() {
    for (valid, uuid) in [
        (true, "00112233-4455-6677-8899-aabbccddeeff"),
        (true, "00112233-4455-6677-8899-AABBCCDDEEFF"),
        (true, "00112233445566778899aabbccddeeff"),
        (false, "-00112233445566778899aabbccddeeff"),
        (false, "00112233445566778899aabbccddeeff-"),
        (false, "0011223344556677-8899aabbccddeeff"),
        (false, "00112233--4455-6677-8899-aabbccddeeff"),
        (false, "00112233-4455-6677-8899-aabbccddeezz"),
        (false, "00112233-4455-6677-8899-aabbccddee"),
    ] {
        let args = wire::dict([
            ("Ap,NextStageIM4MHash", Value::Data(vec![5; 48])),
            ("Ap,RecoveryOSPolicyNonceHash", Value::Data(vec![6; 48])),
            ("Ap,VolumeUUID", uuid.into()),
        ]);
        let policy = tss::local_policy_request(&device_info(), &ticket(), Some(&args));
        if valid {
            let policy = policy.unwrap();
            assert_eq!(
                wire::get(&policy, &["Ap,VolumeUUID"])
                    .unwrap()
                    .as_data()
                    .unwrap(),
                &[
                    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                    0xdd, 0xee, 0xff
                ],
                "{uuid}"
            );
        } else {
            assert!(policy.is_err(), "accepted {uuid:?}");
        }
    }
}

#[test]
fn local_policy_omits_firmware_metadata_without_changing_firmware_requests() {
    let mut id = identity();
    let metadata = [
        "Ap,OSLongVersion",
        "Ap,OSReleaseType",
        "Ap,ProductMarketingVersion",
        "Ap,ProductType",
        "Ap,SDKPlatform",
        "Ap,Target",
        "Ap,TargetType",
        "Ap,Timestamp",
        "PearlCertificationRootPub",
        "NeRDEpoch",
        "AllowNeRDBoot",
        "PermitNeRDPivot",
    ];
    for key in metadata {
        id.value
            .as_dictionary_mut()
            .unwrap()
            .insert(key.into(), "firmware-only fixture".into());
    }
    id.value
        .as_dictionary_mut()
        .unwrap()
        .get_mut("Info")
        .unwrap()
        .as_dictionary_mut()
        .unwrap()
        .insert("RequiresUIDMode".into(), true.into());
    id.value
        .as_dictionary_mut()
        .unwrap()
        .insert("UID_MODE".into(), false.into());
    id.value
        .as_dictionary_mut()
        .unwrap()
        .insert("Ap,SikaFuse".into(), 0u64.into());
    let device = device_info();
    let firmware = tss::request(&device, &id).unwrap();
    let recovery = tss::recovery_request(&device, &id).unwrap();
    for request in [&firmware, &recovery] {
        for key in metadata {
            assert_eq!(
                wire::get(request, &[key]).unwrap(),
                wire::get(&id.value, &[key]).unwrap()
            );
        }
        assert!(wire::get(request, &["UniqueBuildID"]).is_ok());
        assert!(wire::get(request, &["SepNonce"]).is_ok());
        assert!(wire::get(request, &["UID_MODE"]).is_ok());
    }

    let args = wire::dict([
        ("Ap,NextStageIM4MHash", Value::Data(vec![5; 48])),
        ("Ap,RecoveryOSPolicyNonceHash", Value::Data(vec![6; 48])),
        (
            "Ap,VolumeUUID",
            "00112233-4455-6677-8899-aabbccddeeff".into(),
        ),
    ]);
    for args in [None, Some(&args)] {
        let policy = tss::local_policy_request(&device, &ticket(), args).unwrap();
        let mut expected = vec![
            "@HostPlatformInfo",
            "@VersionInfo",
            "@ApImg4Ticket",
            "ApECID",
            "ApChipID",
            "ApBoardID",
            "ApSecurityDomain",
            "ApProductionMode",
            "ApSecurityMode",
            "Ap,LocalBoot",
            "Ap,LocalPolicy",
            "Ap,NextStageIM4MHash",
        ];
        if args.is_some() {
            expected.extend(["Ap,RecoveryOSPolicyNonceHash", "Ap,VolumeUUID"]);
        } else {
            expected.push("ApNonce");
            assert_eq!(
                wire::get(&policy, &["ApNonce"]).unwrap().as_data().unwrap(),
                device.ap_nonce
            );
        }
        expected.sort_unstable();
        let mut actual: Vec<&str> = wire::dictionary(&policy)
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        actual.sort_unstable();
        assert_eq!(actual, expected);
        for key in [
            "ApECID",
            "ApChipID",
            "ApBoardID",
            "ApSecurityDomain",
            "ApProductionMode",
            "ApSecurityMode",
        ] {
            assert_eq!(
                wire::get(&policy, &[key]).unwrap(),
                wire::get(&firmware, &[key]).unwrap()
            );
        }
        assert_eq!(
            crate::test_support::boolean(&policy, &["Ap,LocalBoot"]),
            args.is_some()
        );
    }
}

#[test]
fn tss_restore_rules_apply_only_when_conditions_match() {
    let mut entry = plist::Dictionary::new();
    let parameters = wire::dict([("ApProductionMode", true.into())]);
    let rules = Value::Array(vec![
        wire::dict([
            (
                "Conditions",
                wire::dict([
                    ("ApRawProductionMode", true.into()),
                    ("ApRequiresImage4", true.into()),
                ]),
            ),
            ("Actions", wire::dict([("EPRO", true.into())])),
        ]),
        wire::dict([
            (
                "Conditions",
                wire::dict([("UnknownCondition", true.into())]),
            ),
            ("Actions", wire::dict([("ESEC", false.into())])),
        ]),
    ]);
    tss::apply_rules(&mut entry, &rules, parameters.as_dictionary().unwrap()).unwrap();
    assert_eq!(entry.get("EPRO"), Some(&true.into()));
    assert!(!entry.contains_key("ESEC"));
}

#[test]
fn tss_never_accepts_rejection_or_malformed_success() {
    assert!(tss::parse_response(b"STATUS=94&MESSAGE=not eligible").is_err());
    assert!(tss::parse_response(b"STATUS=9&MESSAGE=FAIL&REQUEST_STRING=<plist/>").is_err());
    assert!(tss::parse_response(b"STATUS=0&MESSAGE=SUCCESS&REQUEST_STRING=bad").is_err());
    let response = wire::dict([("ApImg4Ticket", Value::Data(ticket()))]);
    let bytes = [
        b"STATUS=0&MESSAGE=SUCCESS&REQUEST_STRING=".as_slice(),
        &wire::xml(&response).unwrap(),
    ]
    .concat();
    assert_eq!(tss::parse_response(&bytes).unwrap(), response);
    for header in [
        "STATUS=94&STATUS=0",
        "STATUS=0&STATUS=94",
        "STATUS=0&STATUS=0",
        "MESSAGE=SUCCESS",
    ] {
        let bytes = [
            format!("{header}&REQUEST_STRING=").into_bytes(),
            wire::xml(&response).unwrap(),
        ]
        .concat();
        assert!(tss::parse_response(&bytes).is_err(), "{header}");
    }
}

#[test]
fn unmatched_signing_rules_still_require_well_formed_actions() {
    for actions in [None, Some(true.into())] {
        let mut rule = wire::dict([(
            "Conditions",
            wire::dict([("UnavailableParameter", true.into())]),
        )]);
        if let Some(actions) = actions {
            rule.as_dictionary_mut()
                .unwrap()
                .insert("Actions".into(), actions);
        }
        let mut entry = plist::Dictionary::new();
        assert!(
            tss::apply_rules(
                &mut entry,
                &Value::Array(vec![rule]),
                &plist::Dictionary::new()
            )
            .is_err()
        );
        assert!(entry.is_empty());
    }
}
#[test]
fn signing_rules_validate_the_resulting_trust_and_digest() {
    for (trusted, digest) in [
        ("yes".into(), Value::Data(vec![1; 48])),
        (true.into(), Value::Data(vec![])),
        (true.into(), Value::Data(vec![1; 17])),
    ] {
        let mut id = identity();
        let entry = manifest_mut(&mut id)
            .get_mut("iBSS")
            .unwrap()
            .as_dictionary_mut()
            .unwrap();
        entry.insert("Trusted".into(), false.into());
        entry
            .get_mut("Info")
            .unwrap()
            .as_dictionary_mut()
            .unwrap()
            .insert(
                "RestoreRequestRules".into(),
                Value::Array(vec![wire::dict([
                    ("Conditions", wire::dict([] as [(&str, Value); 0])),
                    (
                        "Actions",
                        wire::dict([("Trusted", trusted), ("Digest", digest)]),
                    ),
                ])]),
            );
        assert!(tss::request(&device_info(), &id).is_err());
    }
}

#[test]
fn manifest_components_cannot_replace_device_signing_fields() {
    for name in ["ApNonce", "ApECID", "@ApImg4Ticket", "@FutureTicket"] {
        let mut id = identity();
        let entry = manifest_mut(&mut id)["iBSS"].clone();
        manifest_mut(&mut id).insert(name.into(), entry);
        assert!(tss::request(&device_info(), &id).is_err(), "{name}");
    }
}

#[test]
fn signing_rejects_an_identity_for_other_hardware_or_security_domain() {
    for key in ["ApChipID", "ApBoardID", "ApSecurityDomain"] {
        let mut id = identity();
        id.value
            .as_dictionary_mut()
            .unwrap()
            .insert(key.into(), 0xffffu64.into());
        for request in [tss::request, tss::recovery_request] {
            assert!(request(&device_info(), &id).is_err(), "{key}");
        }
    }
}

pub(super) fn hardware_properties(chip: u64, board: u64, domain: u64) -> Vec<u8> {
    use asn1_rs::ToDer;
    let mut props = Vec::new();
    for (name, number) in [(b"CHIP", chip), (b"BORD", board), (b"SDOM", domain)] {
        props.extend(measurement_property(name, &number.to_der_vec().unwrap()));
    }
    measurement_property(b"MANP", &img4::element(0x31, &props))
}

#[test]
fn tickets_are_bound_to_the_selected_identity_hardware_and_requested_digests() {
    use asn1_rs::ToDer;
    let id = identity();
    let request = tss::request(&device_info(), &id).unwrap();
    let mut hardware = Vec::new();
    for (name, key) in [
        (b"CHIP", "ApChipID"),
        (b"BORD", "ApBoardID"),
        (b"SDOM", "ApSecurityDomain"),
        (b"ECID", "ApECID"),
    ] {
        hardware.extend(measurement_property(
            name,
            &wire::number(wire::get(&request, &[key]).unwrap())
                .unwrap()
                .to_der_vec()
                .unwrap(),
        ));
    }
    let build = |omit: bool, corrupt: bool, wrong_type: bool, wrong_hardware: bool| {
        let mut props = hardware.clone();
        if wrong_hardware {
            props = measurement_property(b"CHIP", &1u64.to_der_vec().unwrap());
        }
        let mut objects = measurement_property(b"MANP", &img4::element(0x31, &props));
        for (name, entry) in id.manifest().unwrap() {
            if omit && name == "iBSS" {
                continue;
            }
            let mut tag = id.payload_type(name).unwrap().unwrap();
            if wrong_type && name == "iBSS" {
                tag = *b"fake";
            }
            let mut digest = wire::get(entry, &["Digest"])
                .unwrap()
                .as_data()
                .unwrap()
                .to_vec();
            if corrupt && name == "iBSS" {
                digest[0] ^= 1;
            }
            let digest = measurement_property(b"DGST", &img4::element(4, &digest));
            objects.extend(measurement_property(&tag, &img4::element(0x31, &digest)));
        }
        measurement_ticket(&objects)
    };
    let response = build(false, false, false, false);
    tss::validate_ticket_for_identity(&request, &response, &id).unwrap();
    for (omit, corrupt, wrong_type, wrong_hardware) in [
        (true, false, false, false),
        (false, true, false, false),
        (false, false, true, false),
        (false, false, false, true),
    ] {
        assert!(
            tss::validate_ticket_for_identity(
                &request,
                &build(omit, corrupt, wrong_type, wrong_hardware),
                &id
            )
            .is_err()
        );
    }
}

#[test]
fn local_policy_and_fileless_measurements_use_their_actual_img4_types() {
    let digest = vec![0xab; 48];
    let request = wire::dict([(
        "Ap,LocalPolicy",
        wire::dict([
            ("Trusted", true.into()),
            ("Digest", Value::Data(digest.clone())),
        ]),
    )]);
    let fields = measurement_property(b"DGST", &img4::element(4, &digest));
    let valid = measurement_ticket(&measurement_property(
        b"lpol",
        &img4::element(0x31, &fields),
    ));
    tss::validate_ticket(&request, &valid).unwrap();
    let wrong = measurement_ticket(&measurement_property(
        b"fake",
        &img4::element(0x31, &fields),
    ));
    assert!(tss::validate_ticket(&request, &wrong).is_err());
}

#[test]
fn selected_identity_retains_fourcc_names_for_fileless_server_generated_measurements() {
    let mut id = identity();
    manifest_mut(&mut id).insert(
        "newa".into(),
        wire::dict([("Trusted", true.into()), ("Digest", Value::Data(vec![]))]),
    );
    let request = wire::dict([(
        "newa",
        wire::dict([("Trusted", true.into()), ("Digest", Value::Data(vec![]))]),
    )]);
    let fields = measurement_property(b"DGST", &img4::element(4, &[0x15; 32]));
    let response = measurement_ticket(&measurement_property(
        b"newa",
        &img4::element(0x31, &fields),
    ));
    tss::validate_ticket_for_identity(&request, &response, &id).unwrap();
}

#[test]
fn raw_measurements_resolve_from_global_manifests_without_component_name_tables() {
    for (name, tag) in [
        ("BaseSystem", *b"bsys"),
        ("OS", *b"rosi"),
        ("FutureFilesystem", *b"nx42"),
        ("RenamedFilesystem", *b"disk"),
    ] {
        let bytes = b"raw image without an IM4P header";
        let digest = Sha384::digest(bytes).to_vec();
        let mut entry = component_entry("disk.dmg.aea", bytes);
        entry.as_dictionary_mut().unwrap()["Info"]
            .as_dictionary_mut()
            .unwrap()
            .remove("Img4PayloadType");
        let mut id = identity();
        manifest_mut(&mut id).insert(name.into(), entry);
        let original = id.value.clone();
        let response = |tag: &[u8; 4], digest: &[u8]| {
            let fields = measurement_property(b"DGST", &img4::element(4, digest));
            let mut objects = hardware_properties(0x8103, 10, 1);
            objects.extend(measurement_property(tag, &img4::element(0x31, &fields)));
            measurement_ticket(&objects)
        };
        let global = response(&tag, &digest);
        let file = fixture_files(
            Some(id.clone()),
            false,
            &[
                ("disk.dmg.aea", bytes),
                (
                    "Firmware/Manifests/restore/macOS Customer/apticket.j313ap.im4m",
                    tss::ticket(&global).unwrap(),
                ),
            ],
        );
        let mut ipsw = Ipsw::open(file.path()).unwrap();
        ipsw.validate_identity(&mut id).unwrap();
        assert_eq!(id.value, original);
        assert_eq!(id.payload_type(name).unwrap(), None);
        let request = wire::dict([(
            name,
            wire::dict([
                ("Trusted", true.into()),
                ("Digest", Value::Data(digest.clone())),
            ]),
        )]);
        tss::validate_ticket_for_identity(&request, &global, &id.clone()).unwrap();
        // A personalized response cannot serve as its own reference.
        assert!(tss::validate_ticket(&request, &global).is_err());
        for invalid in [
            response(&tag, &[0xcd; 48]),
            response(b"ibss", &digest),
            measurement_ticket(&[]),
        ] {
            assert!(
                tss::validate_ticket_for_identity(&request, &invalid, &id).is_err(),
                "{name}"
            );
        }
        // An explicit manifest type still takes precedence over inference.
        manifest_mut(&mut id)[name].as_dictionary_mut().unwrap()["Info"]
            .as_dictionary_mut()
            .unwrap()
            .insert("Img4PayloadType".into(), "next".into());
        tss::validate_ticket_for_identity(&request, &response(b"next", &digest), &id).unwrap();
        assert!(tss::validate_ticket_for_identity(&request, &global, &id).is_err());
    }
}

#[test]
fn raw_measurement_inference_requires_the_selected_global_ap_manifest() {
    let bytes = b"raw disk";
    let digest = Sha384::digest(bytes).to_vec();
    let mut entry = component_entry("raw.dmg", bytes);
    entry.as_dictionary_mut().unwrap()["Info"]
        .as_dictionary_mut()
        .unwrap()
        .remove("Img4PayloadType");
    let mut id = identity();
    manifest_mut(&mut id).insert("FutureFilesystem".into(), entry);
    let fields = measurement_property(b"DGST", &img4::element(4, &digest));
    let object = measurement_property(b"nx42", &img4::element(0x31, &fields));
    let mut objects = hardware_properties(0x8103, 10, 1);
    objects.extend(&object);
    let response = measurement_ticket(&objects);
    let request = wire::dict([(
        "FutureFilesystem",
        wire::dict([("Trusted", true.into()), ("Digest", Value::Data(digest))]),
    )]);
    for path in [
        "unrelated.im4m",
        "Firmware/Manifests/restore/macOS Customer/apticket.other.im4m",
        "Firmware/Manifests/restore/Other Variant/apticket.j313ap.im4m",
        "Firmware/Manifests/restore/cryptex1/macOS Customer/apticket.j313ap.im4m",
    ] {
        let file = fixture_files(
            Some(id.clone()),
            false,
            &[("raw.dmg", bytes), (path, tss::ticket(&response).unwrap())],
        );
        let mut ipsw = Ipsw::open(file.path()).unwrap();
        let mut selected = id.clone();
        ipsw.validate_identity(&mut selected).unwrap();
        assert!(
            tss::validate_ticket_for_identity(&request, &response, &selected).is_err(),
            "{path}"
        );
    }
    for invalid in [
        [hardware_properties(0x8103, 11, 1), object.clone()].concat(),
        [hardware_properties(0x8103, 10, 2), object.clone()].concat(),
        [hardware_properties(0x8104, 10, 1), object.clone()].concat(),
        object,
        [
            objects,
            measurement_property(b"dupe", &img4::element(0x31, &fields)),
        ]
        .concat(),
    ] {
        let global = measurement_ticket(&invalid);
        let file = fixture_files(
            Some(id.clone()),
            false,
            &[
                ("raw.dmg", bytes),
                (
                    "Firmware/Manifests/restore/macOS Customer/apticket.j313ap.im4m",
                    tss::ticket(&global).unwrap(),
                ),
            ],
        );
        let mut ipsw = Ipsw::open(file.path()).unwrap();
        assert!(ipsw.validate_identity(&mut id.clone()).is_err());
    }
}

#[test]
fn unresolved_component_names_cannot_match_another_tss_measurement() {
    let digest = vec![0xab; 48];
    let entry = wire::dict([
        ("Trusted", true.into()),
        ("Digest", Value::Data(digest.clone())),
    ]);
    let request = wire::dict([("UnmappedComponent", entry.clone())]);
    let fields = measurement_property(b"DGST", &img4::element(4, &digest));
    let response = measurement_ticket(&measurement_property(
        b"ibss",
        &img4::element(0x31, &fields),
    ));
    let mut id = identity();
    manifest_mut(&mut id).insert("UnmappedComponent".into(), entry);
    for result in [
        tss::validate_ticket(&request, &response),
        tss::validate_ticket_for_identity(&request, &response, &id),
    ] {
        let error = result.unwrap_err().to_string();
        assert!(
            error.contains("cannot resolve UnmappedComponent"),
            "{error}"
        );
    }
}
