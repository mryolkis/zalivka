//! Component digest inputs shared by in-memory reads and archive streaming.
//!
//! A BuildManifest digest may describe the whole file, the same file with the
//! IM4P type replaced, or one payload record inside an FTAB/UARP container. The
//! verifier tries only the inputs declared for that component.
use super::containers;
use crate::{checksum::hasher, img4};
use anyhow::{Context, Result, bail, ensure};
use sha2::digest::DynDigest;

#[derive(Clone, Copy, Hash, PartialEq, Eq)]
pub(super) enum DigestInput {
    File,
    Retag([u8; 4]),
    Payload(u64, u64),
}

impl DigestInput {
    pub(super) fn variants(prefix: &[u8], length: u64, tag: Option<[u8; 4]>) -> Result<Vec<Self>> {
        let mut inputs = vec![Self::File];
        inputs.extend(Self::retag(prefix, tag));
        inputs.extend(
            containers::payload_ranges(prefix, length)?
                .into_iter()
                .map(|range| Self::Payload(range.start, range.end)),
        );
        Ok(inputs)
    }

    /// Replacing the IM4P type is a digest input for some components.
    pub(super) fn retag(prefix: &[u8], tag: Option<[u8; 4]>) -> Option<Self> {
        img4::type_offset(prefix).and(tag).map(Self::Retag)
    }

    pub(super) fn update(self, hash: &mut dyn DynDigest, data: &[u8], position: u64) {
        match self {
            Self::Retag(tag) if position == 0 => {
                let Some(offset) = img4::type_offset(data) else {
                    hash.update(data);
                    return;
                };
                hash.update(&data[..offset]);
                hash.update(&tag);
                hash.update(&data[offset + 4..]);
            }
            Self::Payload(start, end) => {
                let start = start.max(position);
                let end = end.min(position + data.len() as u64);
                if start < end {
                    hash.update(&data[(start - position) as usize..(end - position) as usize]);
                }
            }
            _ => hash.update(data),
        }
    }

    pub(super) fn matches(self, data: &[u8], expected: &[u8]) -> Result<bool> {
        let mut hash = hasher(expected.len())
            .with_context(|| format!("unsupported component digest size {}", expected.len()))?;
        self.update(hash.as_mut(), data, 0);
        Ok(hash.finalize().as_ref() == expected)
    }
}

/// Succeed when any input declared for this component matches.
pub(super) fn verify_component_digest(
    inputs: impl IntoIterator<Item = DigestInput>,
    mut matches: impl FnMut(DigestInput) -> Result<bool>,
) -> Result<()> {
    for input in inputs {
        if matches(input)? {
            return Ok(());
        }
    }
    bail!("digest verification failed")
}

pub fn verify_digest(data: &[u8], expected: &[u8]) -> Result<()> {
    ensure!(
        DigestInput::File.matches(data, expected)?,
        "digest verification failed"
    );
    Ok(())
}
