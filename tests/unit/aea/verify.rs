use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use std::io::{self, Cursor};

fn vectors() -> serde_json::Value {
    serde_json::from_str(include_str!("../../fixtures/aea-verification.json")).unwrap()
}

fn options(value: &serde_json::Value) -> Options {
    Options {
        key: Some(
            hex::decode(value["key"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
        ),
        ..Default::default()
    }
}

#[test]
fn independent_c_codec_and_python_crypto_vectors_verify_across_clusters() {
    let value = vectors();
    let expected = STANDARD
        .decode(value["plaintext"].as_str().unwrap())
        .unwrap();
    for vector in value["vectors"].as_array().unwrap() {
        let bytes = STANDARD
            .decode(vector["archive"].as_str().unwrap())
            .unwrap();
        let mut output = Vec::new();
        let report = verify(
            &mut bytes.as_slice(),
            bytes.len() as u64,
            &options(&value),
            |data| {
                output.extend_from_slice(data);
                Ok(())
            },
        )
        .unwrap();
        assert!(report.integrity_verified, "{vector}");
        assert_eq!(report.plaintext_bytes, expected.len() as u64);
        assert!(report.clusters > 1);
        if vector["compression"] == "unsupported" {
            assert!(!report.content_verified);
            assert!(report.skipped_reason.unwrap().contains("compression"));
        } else {
            assert!(report.content_verified, "{vector}");
            assert_eq!(output, expected, "{}", vector["compression"]);
            assert!(report.skipped_reason.is_none());
        }
    }
}

#[test]
fn every_aea_authentication_layer_and_plaintext_checksum_are_enforced() {
    let value = vectors();
    let bytes = STANDARD
        .decode(value["vectors"][1]["archive"].as_str().unwrap())
        .unwrap();
    for offset in [12, 44, 76, 124, 156, 236, 268, 300, bytes.len() - 1] {
        let mut corrupt = bytes.clone();
        corrupt[offset] ^= 1;
        assert!(
            verify(
                &mut corrupt.as_slice(),
                corrupt.len() as u64,
                &options(&value),
                |_| Ok(())
            )
            .is_err(),
            "offset {offset}"
        );
    }
    let mut wrong_key = options(&value);
    wrong_key.key.as_mut().unwrap()[0] ^= 1;
    assert!(
        verify(
            &mut bytes.as_slice(),
            bytes.len() as u64,
            &wrong_key,
            |_| Ok(())
        )
        .is_err()
    );
    let bad = STANDARD
        .decode(value["bad_checksum"].as_str().unwrap())
        .unwrap();
    let error = verify(
        &mut bad.as_slice(),
        bad.len() as u64,
        &options(&value),
        |_| Ok(()),
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("checksum mismatch"));
    for size in [0, 4, 11, 155, 156, 200, bytes.len() - 1] {
        assert!(
            verify(
                &mut &bytes[..size],
                bytes.len() as u64,
                &options(&value),
                |_| Ok(())
            )
            .is_err(),
            "size {size}"
        );
    }
    assert!(
        verify(
            &mut bytes.as_slice(),
            bytes.len() as u64 + 1,
            &options(&value),
            |_| Ok(())
        )
        .is_err()
    );
}

#[test]
fn offline_mode_reports_missing_keys_without_claiming_authenticated_content() {
    let value = vectors();
    let bytes = STANDARD
        .decode(value["vectors"][0]["archive"].as_str().unwrap())
        .unwrap();
    let report = verify(
        &mut bytes.as_slice(),
        bytes.len() as u64,
        &Options::default(),
        |_| panic!("no key means no plaintext"),
    )
    .unwrap();
    assert!(!report.integrity_verified && !report.content_verified);
    assert!(report.skipped_reason.unwrap().contains("offline"));
}

#[test]
fn fragmented_reads_and_callback_failures_preserve_errors() {
    struct Fragmented(Cursor<Vec<u8>>);
    impl Read for Fragmented {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            let size = out.len().min(3);
            self.0.read(&mut out[..size])
        }
    }
    let value = vectors();
    let bytes = STANDARD
        .decode(value["vectors"][1]["archive"].as_str().unwrap())
        .unwrap();
    let mut reader = Fragmented(Cursor::new(bytes.clone()));
    assert!(
        verify(
            &mut reader,
            bytes.len() as u64,
            &options(&value),
            |_| Ok(())
        )
        .unwrap()
        .content_verified
    );
    let error = verify(
        &mut bytes.as_slice(),
        bytes.len() as u64,
        &options(&value),
        |_| anyhow::bail!("consumer failed"),
    )
    .unwrap_err();
    assert!(error.to_string().contains("consumer failed"));
}

#[test]
fn real_apple_fcs_and_first_lzfse_segment_match_the_reference_tools() {
    let bytes = include_bytes!("../../fixtures/ipsw-verification/aea-first-segment.bin");
    let expected: serde_json::Value = serde_json::from_str(include_str!(
        "../../fixtures/ipsw-verification/aea-first-segment.json"
    ))
    .unwrap();
    let key = hex::decode(expected["archive_key"].as_str().unwrap()).unwrap();
    let public = match PublicFcs::from_prefix(bytes).unwrap() {
        Prefix::Public(public) => public,
        _ => panic!("real Apple public FCS metadata"),
    };
    let pem = include_bytes!("../../fixtures/ipsw-verification/public-fcs.pem");
    assert_eq!(public.unwrap_key(pem).unwrap().as_slice(), key);
    let opts = Options {
        private_key: Some(pem.to_vec()),
        ..Default::default()
    };
    let mut outputs = Vec::new();
    // The checked-in fixture deliberately ends after the first genuine segment.
    // It must verify that segment and then reject the incomplete archive.
    let result = verify(
        &mut bytes.as_slice(),
        expected["encrypted_size"].as_u64().unwrap(),
        &opts,
        |plaintext| {
            outputs.push((plaintext.len(), hex::encode(Sha256::digest(plaintext))));
            Ok(())
        },
    );
    assert!(result.is_err());
    assert_eq!(outputs.len(), 1);
    assert_eq!(
        outputs[0].0,
        expected["plaintext_segment_bytes"].as_u64().unwrap() as usize
    );
    assert_eq!(
        outputs[0].1,
        expected["plaintext_segment_sha256"].as_str().unwrap()
    );
}

#[test]
fn murmur_64_bit_seed_matches_go_reference_for_blocks_and_every_tail_length() {
    let values: Vec<u64> = serde_json::from_str(include_str!(
        "../../fixtures/ipsw-verification/murmur64-reference.json"
    ))
    .unwrap();
    for (length, expected) in values.into_iter().enumerate() {
        let data = (0..length).map(|n| n as u8).collect::<Vec<_>>();
        assert_eq!(murmur64(&data), expected, "length {length}");
    }
}

#[test]
fn authenticated_aea_headers_cannot_request_unbounded_allocations() {
    let value = vectors();
    let bytes = STANDARD
        .decode(value["vectors"][0]["archive"].as_str().unwrap())
        .unwrap();
    let opts = options(&value);
    for (offset, number, expected) in [
        (16, 0u32, "segment size"),
        (16, 64 * 1024 * 1024 + 1, "segment size"),
        (20, 0, "segments per cluster"),
        (20, 4097, "segments per cluster"),
    ] {
        let mut bad = bytes.clone();
        let (main, mut root) = root_header(
            opts.key.as_ref().unwrap(),
            bad[12..44].try_into().unwrap(),
            &[],
            bad[44..156].try_into().unwrap(),
        )
        .unwrap();
        root[offset..offset + 4].copy_from_slice(&number.to_le_bytes());
        let material = derive::<80>(&main, None, b"AEA_RHEK").unwrap();
        decrypt(&mut root, &material).unwrap();
        bad[76..124].copy_from_slice(&root);
        let mut mac = Hmac::<Sha256>::new_from_slice(&material[..32]).unwrap();
        mac.update(&bad[124..156]);
        mac.update(&bad[76..124]);
        mac.update(&32u64.to_le_bytes());
        bad[44..76].copy_from_slice(&mac.finalize().into_bytes());
        let error = verify(&mut bad.as_slice(), bad.len() as u64, &opts, |_| Ok(())).unwrap_err();
        assert!(error.to_string().contains(expected), "{error:#}");
    }
}
