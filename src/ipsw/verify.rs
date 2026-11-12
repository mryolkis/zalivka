//! Collect manifest requirements, stream ZIP entries and report verified digests.
use super::{
    Ipsw, component_digest, component_path,
    digest::{DigestInput, verify_component_digest},
    stream::read_chunk,
};
use crate::{aea, checksum::hasher, firmware, img4, wire};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use std::{
    collections::{HashMap, HashSet, hash_map::Entry},
    io::{Read, Seek, SeekFrom, Write},
};

#[derive(Debug, Serialize)]
pub struct Verification {
    pub entries: usize,
    pub uncompressed_bytes: u64,
    pub manifest_digests: usize,
    pub archive_checksum_verified: bool,
    pub aea_content_digests_not_checked: Vec<String>,
    pub files: Vec<FileVerification>,
    pub components: Vec<ComponentVerification>,
    pub im4m_manifests: Vec<ManifestVerification>,
    pub apple_signature_verified: bool,
}

#[derive(Debug, Serialize)]
pub struct FileVerification {
    pub path: String,
    pub bytes: u64,
    pub manifest_digests: usize,
    pub crc_only: bool,
    pub skipped_checks: Vec<String>,
    pub aea: Option<aea::Verification>,
}

#[derive(Debug, Serialize)]
pub struct ComponentVerification {
    pub identity_index: usize,
    pub component: String,
    pub path: String,
    pub algorithm: Option<&'static str>,
    pub digest_verified: bool,
    pub skipped_reason: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ManifestVerification {
    pub path: String,
    pub identity_indexes: Vec<usize>,
    /// Minimum number verified across matching identities.
    pub verified_digests: usize,
    /// Types unmapped in at least one matching identity.
    pub unmapped_payload_types: Vec<String>,
    pub signature_verified: bool,
    pub skipped_reason: Option<String>,
}

#[derive(Hash, PartialEq, Eq)]
struct ComponentDigest {
    tag: Option<[u8; 4]>,
    expected: Vec<u8>,
}

/// Each component keeps its own declared digest input when paths are shared.
#[derive(Default)]
struct EntryDigests {
    components: HashSet<ComponentDigest>,
}

#[derive(Default)]
struct EntryVerification {
    digests: usize,
    aea: Option<aea::Verification>,
    payload_type: Option<[u8; 4]>,
}

impl Ipsw {
    fn manifest_digests(&self) -> Result<HashMap<String, EntryDigests>> {
        let mut entries: HashMap<String, EntryDigests> = HashMap::new();
        for (_, value) in self.identity_values() {
            for (name, entry) in wire::dictionary(wire::get(value, &["Manifest"])?)? {
                let tag = img4::component_tag(name, Some(entry))?;
                let digest = component_digest(entry)
                    .with_context(|| format!("checking manifest component {name}"))?;
                let Some(path) = component_path(entry)
                    .with_context(|| format!("invalid manifest component {name}"))?
                else {
                    continue;
                };
                ensure!(self.contains(path), "missing manifest component {path}");
                let requirements = entries.entry(path.into()).or_default();
                if let Some(digest) = digest {
                    requirements.components.insert(ComponentDigest {
                        tag,
                        expected: digest.to_vec(),
                    });
                }
            }
        }
        Ok(entries)
    }

    /// Exhaust every ZIP stream (including CRC validation) with bounded memory.
    pub fn verify_all_with_options(&mut self, options: &aea::Options) -> Result<Verification> {
        let requirements = self.manifest_digests()?;
        let no_digests = EntryDigests::default();
        let mut report = Verification {
            entries: self.archive.len(),
            uncompressed_bytes: 0,
            manifest_digests: 0,
            archive_checksum_verified: false,
            aea_content_digests_not_checked: vec![],
            files: vec![],
            components: vec![],
            im4m_manifests: vec![],
            apple_signature_verified: false,
        };
        let mut types = HashMap::new();
        let mut tickets = Vec::new();
        let mut buffer = vec![0; 2 * 1024 * 1024];
        for index in 0..self.archive.len() {
            crate::progress::check_cancelled()?;
            let mut entry = self.archive.by_index(index)?;
            let name = entry.name()?.into_owned();
            let length = entry.size();
            let requirements_for_file = requirements.get(&name).unwrap_or(&no_digests);
            let verified = requirements_for_file.verify_with_options(
                &mut entry,
                &name,
                length,
                &mut buffer,
                options,
            )?;
            report.manifest_digests += verified.digests;
            report.uncompressed_bytes = report
                .uncompressed_bytes
                .checked_add(length)
                .context("IPSW size overflow")?;
            if !requirements_for_file.components.is_empty()
                && verified
                    .aea
                    .as_ref()
                    .is_some_and(|aea| !aea.content_verified)
            {
                report.aea_content_digests_not_checked.push(name.clone());
            }
            types.insert(name.clone(), verified.payload_type);
            if name.starts_with("Firmware/Manifests/restore/") && name.ends_with(".im4m") {
                tickets.push(name.clone());
            }
            let mut skipped_checks = Vec::new();
            if requirements_for_file.components.is_empty() {
                skipped_checks.push(
                    if requirements.contains_key(&name) {
                        "BuildManifest declares no digest"
                    } else {
                        "file is not referenced by BuildManifest"
                    }
                    .into(),
                );
            }
            if let Some(reason) = verified
                .aea
                .as_ref()
                .and_then(|aea| aea.skipped_reason.clone())
            {
                skipped_checks.push(reason);
            }
            report.files.push(FileVerification {
                path: name.clone(),
                bytes: length,
                manifest_digests: verified.digests,
                crc_only: verified.digests == 0
                    && !verified
                        .aea
                        .as_ref()
                        .is_some_and(|aea| aea.integrity_verified),
                skipped_checks,
                aea: verified.aea,
            });
            crate::log!(
                Debug,
                "ipsw:verify",
                "{}/{}: {} ({} MiB)",
                index + 1,
                report.entries,
                name,
                length / 1048576,
            );
        }
        for (index, identity) in self.identity_values() {
            for (name, entry) in wire::dictionary(wire::get(identity, &["Manifest"])?)? {
                let Some(path) = component_path(entry)? else {
                    continue;
                };
                let digest = component_digest(entry)?;
                let deferred = report
                    .aea_content_digests_not_checked
                    .iter()
                    .any(|file| file == path);
                report.components.push(ComponentVerification {
                    identity_index: index,
                    component: name.clone(),
                    path: path.into(),
                    algorithm: digest.map(|digest| match digest.len() {
                        20 => "sha1",
                        32 => "sha256",
                        _ => "sha384",
                    }),
                    digest_verified: digest.is_some() && !deferred,
                    skipped_reason: if digest.is_none() {
                        Some("BuildManifest declares no digest".into())
                    } else if deferred {
                        Some("AEA plaintext digest not checked; see file report".into())
                    } else {
                        None
                    },
                });
            }
        }
        for path in tickets {
            report
                .im4m_manifests
                .push(self.verify_embedded_manifest(&path, &types)?);
        }
        Ok(report)
    }

    fn verify_embedded_manifest(
        &mut self,
        path: &str,
        types: &HashMap<String, Option<[u8; 4]>>,
    ) -> Result<ManifestVerification> {
        let bytes = self.read_limited(path, 16 * 1024 * 1024)?;
        let ticket = img4::Manifest::parse(&bytes)
            .with_context(|| format!("parsing embedded IM4M {path}"))?;
        let chip = ticket
            .number(b"CHIP")?
            .context("embedded IM4M has no CHIP")?;
        let board = ticket
            .number(b"BORD")?
            .context("embedded IM4M has no BORD")?;
        let digests = ticket.digests()?;
        let mut report = ManifestVerification {
            path: path.into(),
            identity_indexes: vec![],
            verified_digests: 0,
            unmapped_payload_types: vec![],
            signature_verified: false,
            skipped_reason: None,
        };
        let basename = path.rsplit('/').next().context("invalid IM4M path")?;
        let variant = path.rsplit('/').nth(1).context("invalid IM4M variant")?;
        let mut candidates = 0;
        let mut matching_hardware = 0;
        let mut mapped = false;
        for (index, value) in self.identity_values() {
            let class = wire::string(value, &["Info", "DeviceClass"])?;
            let declared_variant =
                wire::optional(value, &["Info", "MacOSVariant"])?.and_then(plist::Value::as_string);
            if !basename.starts_with(&format!("apticket.{class}."))
                || declared_variant.is_some_and(|expected| expected != variant)
            {
                continue;
            }
            candidates += 1;
            if wire::number(wire::get(value, &["ApChipID"])?)? != chip
                || wire::number(wire::get(value, &["ApBoardID"])?)? != board
            {
                continue;
            }
            if ticket.check_hardware(value).is_err() {
                continue;
            }
            matching_hardware += 1;
            let mut identity = super::Identity::new(index, value.clone());
            identity.file_types = types.clone();
            let mut checked = 0;
            let mut unknown = Vec::new();
            let mut mismatch = false;
            for (tag, actual) in &digests {
                let mut expected = Vec::new();
                for (name, entry) in identity.manifest()? {
                    if identity.payload_type(name)? == Some(*tag)
                        && let Some(digest) = component_digest(entry)?
                    {
                        expected.push(digest);
                    }
                }
                if expected.is_empty() {
                    unknown.push(String::from_utf8_lossy(tag).into_owned());
                } else if expected.contains(actual) {
                    mapped = true;
                    checked += 1;
                } else {
                    mapped = true;
                    mismatch = true;
                    break;
                }
            }
            if !mismatch && checked > 0 {
                report.verified_digests = if report.identity_indexes.is_empty() {
                    checked
                } else {
                    report.verified_digests.min(checked)
                };
                report.identity_indexes.push(index);
                report.unmapped_payload_types.extend(unknown);
                report.unmapped_payload_types.sort_unstable();
                report.unmapped_payload_types.dedup();
            }
        }
        if candidates == 0 {
            report.skipped_reason =
                Some("embedded IM4M path does not select a supported identity".into());
        } else {
            ensure!(
                matching_hardware > 0,
                "embedded IM4M hardware mismatch: {path}"
            );
            if digests.is_empty() {
                report.skipped_reason = Some("embedded IM4M contains no component digests".into());
            } else if report.identity_indexes.is_empty() {
                // Distinguish an unsupported namespace from a known digest mismatch.
                ensure!(!mapped, "embedded IM4M digest mismatch: {path}");
                report.unmapped_payload_types = digests
                    .keys()
                    .map(|tag| String::from_utf8_lossy(tag).into_owned())
                    .collect();
                report.skipped_reason =
                    Some("embedded IM4M namespace has no mapped manifest digests".into());
            }
        }
        Ok(report)
    }
}

struct ProgressReader<R> {
    inner: R,
    progress: crate::progress::Progress,
}

impl<R: Read> Read for ProgressReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        crate::progress::check_cancelled()?;
        let size = self.inner.read(buffer)?;
        self.progress.advance(size as u64);
        Ok(size)
    }
}

impl EntryDigests {
    #[cfg(test)]
    fn verify(
        &self,
        reader: &mut impl Read,
        name: &str,
        length: u64,
        buffer: &mut [u8],
    ) -> Result<EntryVerification> {
        self.verify_with_options(reader, name, length, buffer, &aea::Options::default())
    }

    fn verify_with_options(
        &self,
        reader: &mut impl Read,
        name: &str,
        length: u64,
        buffer: &mut [u8],
        options: &aea::Options,
    ) -> Result<EntryVerification> {
        let mut progress =
            crate::progress::Progress::new(format!("Verifying {name}"), Some(length), 0);
        let mut n =
            read_chunk(reader, buffer).with_context(|| format!("checking ZIP entry {name}"))?;
        if buffer[..n].starts_with(b"AEA1") {
            let inner = std::io::Cursor::new(&buffer[..n]).chain(reader);
            let mut measured = ProgressReader { inner, progress };
            let mut hashes = HashMap::new();
            for component in &self.components {
                if let Entry::Vacant(slot) = hashes.entry(component.expected.len()) {
                    slot.insert(
                        hasher(component.expected.len()).context("unsupported AEA digest")?,
                    );
                }
            }
            let report = aea::verify(&mut measured, length, options, |data| {
                for hash in hashes.values_mut() {
                    hash.update(data);
                }
                Ok(())
            })
            .with_context(|| format!("checking AEA entry {name}"))?;
            // Missing keys and unsupported profiles still require reading to
            // EOF, so ZIP CRC and length checks cover the entire stored entry.
            std::io::copy(&mut measured, &mut std::io::sink())
                .with_context(|| format!("checking ZIP entry {name}"))?;
            ensure!(
                measured.progress.completed() == length,
                "truncated ZIP entry {name}"
            );
            if report.content_verified {
                let actual: HashMap<_, _> = hashes
                    .into_iter()
                    .map(|(size, hash)| (size, hash.finalize()))
                    .collect();
                for component in &self.components {
                    ensure!(
                        actual[&component.expected.len()].as_ref() == component.expected.as_slice(),
                        "AEA plaintext manifest digest mismatch: {name}"
                    );
                }
            }
            measured.progress.finish();
            return Ok(EntryVerification {
                digests: if report.content_verified {
                    self.components.len()
                } else {
                    0
                },
                aea: Some(report),
                payload_type: None,
            });
        }
        let mut bundle =
            (!self.components.is_empty() && firmware::plist_prefix(&buffer[..n])).then(Vec::new);
        ensure!(
            bundle.is_none() || length <= firmware::MAX_PLIST_BUNDLE,
            "plist payload bundle exceeds memory limit: {name}"
        );
        // ZIP readers cannot seek into deflated entries. Retain only firmware
        // containers on disk so nested indexes can be read at any file offset.
        let mut container = if firmware::container_prefix(&buffer[..n]) {
            crate::storage::require(&std::env::temp_dir(), length)?;
            Some(tempfile::tempfile()?)
        } else {
            None
        };
        let mut inputs = vec![DigestInput::File];
        let checks = self
            .components
            .iter()
            .map(|component| (component, DigestInput::retag(&buffer[..n], component.tag)))
            .collect::<Vec<_>>();
        let mut hashes = HashMap::new();
        for (component, tag) in &checks {
            for input in inputs.iter().copied().chain(*tag) {
                if let Entry::Vacant(slot) = hashes.entry((component.expected.len(), input)) {
                    slot.insert(
                        hasher(component.expected.len())
                            .context("unsupported manifest digest size")?,
                    );
                }
            }
        }
        let mut verified = EntryVerification {
            payload_type: img4::payload_type(&buffer[..n]),
            ..Default::default()
        };
        while n != 0 {
            if let Some(file) = &mut container {
                file.write_all(&buffer[..n])?;
            }
            if let Some(bytes) = &mut bundle {
                ensure!(
                    bytes.len() as u64 + n as u64 <= firmware::MAX_PLIST_BUNDLE,
                    "plist payload bundle exceeds memory limit: {name}"
                );
                bytes.extend_from_slice(&buffer[..n]);
            }
            for ((_, input), hash) in &mut hashes {
                input.update(hash.as_mut(), &buffer[..n], progress.completed());
            }
            progress.advance(n as u64);
            n = read_chunk(reader, buffer).with_context(|| format!("checking ZIP entry {name}"))?;
        }
        ensure!(progress.completed() == length, "truncated ZIP entry {name}");
        if let Some(file) = &mut container {
            for range in firmware::payload_ranges_from(file, length)? {
                let input = DigestInput::Payload(range.start, range.end);
                inputs.push(input);
                for (component, _) in &checks {
                    if let Entry::Vacant(slot) = hashes.entry((component.expected.len(), input)) {
                        let mut hash = hasher(component.expected.len())
                            .context("unsupported manifest digest size")?;
                        file.seek(SeekFrom::Start(range.start))?;
                        let mut remaining = range.end - range.start;
                        while remaining > 0 {
                            let size = remaining.min(buffer.len() as u64) as usize;
                            let n = read_chunk(file, &mut buffer[..size])?;
                            ensure!(n != 0, "truncated firmware payload in {name}");
                            hash.update(&buffer[..n]);
                            remaining -= n as u64;
                        }
                        slot.insert(hash);
                    }
                }
            }
        }
        let actual: HashMap<_, _> = hashes
            .into_iter()
            .map(|(key, hash)| (key, hash.finalize()))
            .collect();
        // Verify all payload records even when an outer-file digest matches.
        let bundle_digests = bundle
            .as_ref()
            .map(|bytes| firmware::verify_plist_bundle(bytes))
            .transpose()
            .with_context(|| format!("checking payload bundle {name}"))?
            .unwrap_or_default();
        for (component, tag) in checks {
            let digest = verify_component_digest(inputs.iter().copied().chain(tag), |input| {
                Ok(actual
                    .get(&(component.expected.len(), input))
                    .is_some_and(|hash| hash.as_ref() == component.expected.as_slice()))
            });
            if let Err(error) = digest {
                ensure!(
                    bundle_digests.contains(component.expected.as_slice()),
                    "manifest digest mismatch: {name}: {error}"
                );
            }
            verified.digests += 1;
        }
        progress.finish();
        Ok(verified)
    }
}

#[cfg(test)]
#[path = "../../tests/unit/ipsw/verify.rs"]
mod tests;
