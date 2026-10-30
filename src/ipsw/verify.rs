//! Collect manifest requirements, stream ZIP entries and report verified digests.
//!
//! Verification never extracts the archive: each entry is read once with a
//! bounded buffer while every declared digest input is hashed together. Nested
//! container indexes are retained on disk so payload records can be hashed at
//! their actual offsets; plist payload bundles stay in memory only when small.
use super::{
    Ipsw, component_digest, component_path,
    containers::{
        MAX_PLIST_BUNDLE, container_prefix, payload_ranges_from, plist_prefix, verify_plist_bundle,
    },
    digest::{DigestInput, verify_component_digest},
    stream::read_chunk,
};
use crate::{checksum::hasher, img4, wire};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use sha2::digest::DynDigest;
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
    bytes: u64,
    digests: usize,
    aea_deferred: bool,
}

type Hash = Box<dyn DynDigest>;
type Hashes = HashMap<(usize, DigestInput), Hash>;

impl Ipsw {
    fn manifest_digests(&self) -> Result<HashMap<String, EntryDigests>> {
        let mut entries: HashMap<String, EntryDigests> = HashMap::new();
        for (_, identity) in self.identity_values() {
            for (name, entry) in wire::dictionary(wire::get(identity, &["Manifest"])?)? {
                let tag = img4::component_tag(name, Some(entry))?;
                let digest = component_digest(entry)
                    .with_context(|| format!("checking manifest component {name}"))?;
                let Some(path) = component_path(entry)
                    .with_context(|| format!("invalid manifest component {name}"))?
                else {
                    continue;
                };
                ensure!(self.contains(path), "missing manifest component {path}");
                if let Some(digest) = digest {
                    entries
                        .entry(path.into())
                        .or_default()
                        .components
                        .insert(ComponentDigest {
                            tag,
                            expected: digest.to_vec(),
                        });
                }
            }
        }
        Ok(entries)
    }

    /// Exhaust every ZIP stream (including CRC validation) with bounded memory.
    pub fn verify_all(&mut self) -> Result<Verification> {
        let requirements = self.manifest_digests()?;
        let no_digests = EntryDigests::default();
        let mut report = Verification {
            entries: self.archive.len(),
            uncompressed_bytes: 0,
            manifest_digests: 0,
            archive_checksum_verified: false,
            aea_content_digests_not_checked: vec![],
        };
        let mut buffer = vec![0; 2 * 1024 * 1024];
        for index in 0..self.archive.len() {
            crate::progress::check_cancelled()?;
            let mut entry = self.archive.by_index(index)?;
            let name = entry.name()?.into_owned();
            let length = entry.size();
            let verified = requirements.get(&name).unwrap_or(&no_digests).verify(
                &mut entry,
                &name,
                length,
                &mut buffer,
            )?;
            report.manifest_digests += verified.digests;
            report.uncompressed_bytes = report
                .uncompressed_bytes
                .checked_add(verified.bytes)
                .context("IPSW size overflow")?;
            if verified.aea_deferred {
                report.aea_content_digests_not_checked.push(name.clone());
            }
            crate::log!(
                Debug,
                "ipsw:verify",
                "{}/{}: {} ({} MiB)",
                index + 1,
                report.entries,
                name,
                verified.bytes / 1048576,
            );
        }
        Ok(report)
    }
}

/// Return the hash for `input`, creating it only on first use at this size.
fn hash_for(hashes: &mut Hashes, length: usize, input: DigestInput) -> Result<&mut Hash> {
    Ok(match hashes.entry((length, input)) {
        Entry::Occupied(entry) => entry.into_mut(),
        Entry::Vacant(entry) => {
            entry.insert(hasher(length).context("unsupported manifest digest size")?)
        }
    })
}

impl EntryDigests {
    fn verify(
        &self,
        reader: &mut impl Read,
        name: &str,
        length: u64,
        buffer: &mut [u8],
    ) -> Result<EntryVerification> {
        let mut progress =
            crate::progress::Progress::new(format!("Verifying {name}"), Some(length), 0);
        let mut read =
            read_chunk(reader, buffer).with_context(|| format!("checking ZIP entry {name}"))?;
        let aea = buffer[..read].starts_with(b"AEA1");
        let mut bundle =
            (!self.components.is_empty() && plist_prefix(&buffer[..read])).then(Vec::new);
        ensure!(
            bundle.is_none() || length <= MAX_PLIST_BUNDLE,
            "plist payload bundle exceeds memory limit: {name}"
        );
        // ZIP readers cannot seek into deflated entries. Retain only firmware
        // containers on disk so nested indexes can be read at any file offset.
        let mut container = if container_prefix(&buffer[..read]) {
            crate::storage::require(&std::env::temp_dir(), length)?;
            Some(tempfile::tempfile()?)
        } else {
            None
        };
        let mut inputs = vec![DigestInput::File];
        // AEA manifest digests describe decrypted content, not the ZIP bytes.
        let checks = self
            .components
            .iter()
            .filter(|_| !aea)
            .map(|component| {
                (
                    component,
                    DigestInput::retag(&buffer[..read], component.tag),
                )
            })
            .collect::<Vec<_>>();
        let mut hashes = Hashes::new();
        for (component, tag) in &checks {
            for input in inputs.iter().copied().chain(*tag) {
                hash_for(&mut hashes, component.expected.len(), input)?;
            }
        }
        let mut verified = EntryVerification {
            aea_deferred: aea && !self.components.is_empty(),
            ..Default::default()
        };
        while read != 0 {
            if let Some(file) = &mut container {
                file.write_all(&buffer[..read])?;
            }
            if let Some(bytes) = &mut bundle {
                ensure!(
                    bytes.len() as u64 + read as u64 <= MAX_PLIST_BUNDLE,
                    "plist payload bundle exceeds memory limit: {name}"
                );
                bytes.extend_from_slice(&buffer[..read]);
            }
            for ((_, input), hash) in &mut hashes {
                input.update(hash.as_mut(), &buffer[..read], verified.bytes);
            }
            verified.bytes += read as u64;
            progress.advance(read as u64);
            read =
                read_chunk(reader, buffer).with_context(|| format!("checking ZIP entry {name}"))?;
        }
        ensure!(verified.bytes == length, "truncated ZIP entry {name}");
        if let Some(file) = &mut container {
            let lengths = checks
                .iter()
                .map(|(component, _)| component.expected.len())
                .collect::<HashSet<_>>();
            for range in payload_ranges_from(file, length)? {
                let input = DigestInput::Payload(range.start, range.end);
                inputs.push(input);
                for length in &lengths {
                    let mut hash = hasher(*length).context("unsupported manifest digest size")?;
                    file.seek(SeekFrom::Start(range.start))?;
                    let mut remaining = range.end - range.start;
                    while remaining > 0 {
                        let size = remaining.min(buffer.len() as u64) as usize;
                        let read = read_chunk(file, &mut buffer[..size])?;
                        ensure!(read != 0, "truncated firmware payload in {name}");
                        hash.update(&buffer[..read]);
                        remaining -= read as u64;
                    }
                    hashes.insert((*length, input), hash);
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
            .map(|bytes| verify_plist_bundle(bytes))
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
