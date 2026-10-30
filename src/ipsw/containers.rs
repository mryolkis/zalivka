//! Firmware container parsing and payload digest validation.
//!
//! BuildManifest digests sometimes describe records inside a container rather
//! than the whole file. Two on-disk formats appear in Mac IPSWs:
//! - FTAB: a 48-byte header followed by 16-byte `tag/offset/size/padding` rows.
//! - UARP: a 44-byte header pointing at 40-byte rows with a payload range.
//!
//! UARP may wrap an FTAB recursively, so discovery is depth-limited. Only
//! indexes are read here; payload bytes are streamed by the caller.
use anyhow::{Context, Result, ensure};
use plist::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    io::{Cursor, Read, Seek, SeekFrom},
    ops::Range,
};

pub(crate) const MAX_PLIST_BUNDLE: u64 = 32 * 1024 * 1024;

const FTAB_HEADER: u64 = 48;
const FTAB_ROW: u64 = 16;
const UARP_HEADER: u64 = 44;
const UARP_ROW_LEN: usize = 40;
const MAX_ENTRIES: usize = 65_536;
const MAX_UARP_INDEX: usize = 1024 * 1024;
const MAX_DEPTH: usize = 4;
const MAX_BUNDLE_DEPTH: usize = 32;

/// True when the bytes begin with a plist document (binary, XML or BOM/space prefixed).
pub(crate) fn plist_prefix(bytes: &[u8]) -> bool {
    let bytes = bytes
        .strip_prefix(b"\xef\xbb\xbf")
        .unwrap_or(bytes)
        .trim_ascii_start();
    bytes.starts_with(b"bplist00") || bytes.starts_with(b"<?xml") || bytes.starts_with(b"<plist")
}

/// True when the bytes begin with an FTAB or UARP container.
pub(crate) fn container_prefix(prefix: &[u8]) -> bool {
    prefix.get(36..40) == Some(b"ftab") || uarp_magic(prefix)
}

fn uarp_magic(prefix: &[u8]) -> bool {
    matches!(prefix.get(..8), Some([0, 0, 0, 2 | 3, 0, 0, 0, 44]))
}

/// UARP header fields; `None` unless the complete header is available.
fn uarp_header(prefix: &[u8]) -> Option<(u64, usize)> {
    if !uarp_magic(prefix) {
        return None;
    }
    let start = prefix.get(36..40)?.try_into().ok()?;
    let size = prefix.get(40..44)?.try_into().ok()?;
    Some((
        u64::from(u32::from_be_bytes(start)),
        u32::from_be_bytes(size) as usize,
    ))
}

/// Verify every payload record once and return the digests of verified records.
/// Callers can match several manifest requirements without parsing the bundle again.
pub(crate) fn verify_plist_bundle(bytes: &[u8]) -> Result<HashSet<Vec<u8>>> {
    if !plist_prefix(bytes) {
        return Ok(HashSet::new());
    }
    ensure!(
        bytes.len() as u64 <= MAX_PLIST_BUNDLE,
        "plist payload bundle exceeds memory limit"
    );
    let value = crate::wire::decode_plist(bytes).context("reading plist payload bundle")?;
    let mut digests = HashSet::new();
    verify_plist_node(&value, 0, &mut digests)?;
    Ok(digests)
}

/// Walk dictionaries and arrays, verifying every object that carries both a
/// `Payload` and a `Digest`. Metadata without a payload is not evidence.
fn verify_plist_node(value: &Value, depth: usize, digests: &mut HashSet<Vec<u8>>) -> Result<()> {
    ensure!(
        depth <= MAX_BUNDLE_DEPTH,
        "plist payload bundle nested too deeply"
    );
    if let Some(fields) = value.as_dictionary() {
        if let Some(payload) = fields.get("Payload") {
            let payload = payload.as_data().context("invalid bundle Payload")?;
            let digest = fields
                .get("Digest")
                .and_then(Value::as_data)
                .context("bundle payload has no data Digest")?;
            verify_bundle_payload(payload, digest)?;
            digests.insert(digest.to_vec());
        }
        for (name, child) in fields {
            if name != "Payload" {
                verify_plist_node(child, depth + 1, digests)
                    .with_context(|| format!("checking bundle field {name}"))?;
            }
        }
    } else if let Some(values) = value.as_array() {
        for child in values {
            verify_plist_node(child, depth + 1, digests)?;
        }
    }
    Ok(())
}

fn verify_bundle_payload(payload: &[u8], digest: &[u8]) -> Result<()> {
    if crate::ipsw::verify_digest(payload, digest).is_ok() {
        return Ok(());
    }
    // DP855 flash-image format: two big-endian lengths, code and data banks.
    // These offsets define the format, not a model/controller selection table.
    if payload.len() == 0xf000 && digest.len() == 32 {
        let code = u32::from_be_bytes(payload[..4].try_into()?) as usize;
        let data = u32::from_be_bytes(payload[4..8].try_into()?) as usize;
        if (1..=0x8000).contains(&code) && (1..=0x6000).contains(&data) {
            let mut hash = Sha256::new();
            hash.update(&payload[..8]);
            hash.update(&payload[0x1000..0x1000 + code]);
            hash.update(&payload[0x9000..0x9000 + data]);
            if hash.finalize().as_slice() == digest {
                return Ok(());
            }
        }
    }
    anyhow::bail!("bundle payload digest mismatch or unsupported digest format")
}

struct FtabEntry {
    tag: [u8; 4],
    range: Range<u64>,
}

/// Validate the complete index before either hashing ranges or copying payloads.
/// Payload bytes may be absent from a streaming prefix.
fn ftab_index(bytes: &[u8], length: u64) -> Result<Vec<FtabEntry>> {
    ensure!(
        bytes.len() as u64 >= FTAB_HEADER && &bytes[36..40] == b"ftab",
        "invalid FTAB header"
    );
    let count = u32::from_le_bytes(bytes[40..44].try_into()?) as usize;
    ensure!(count <= MAX_ENTRIES, "too many FTAB entries");
    let end = FTAB_HEADER + count as u64 * FTAB_ROW;
    ensure!(end <= length, "FTAB index outside file");
    let rows = bytes
        .get(FTAB_HEADER as usize..end as usize)
        .context("truncated FTAB index")?;
    let mut entries = Vec::with_capacity(count);
    let mut tags = HashSet::new();
    for row in rows.as_chunks::<16>().0 {
        let tag = row[..4].try_into()?;
        let offset = u64::from(u32::from_le_bytes(row[4..8].try_into()?));
        let size = u64::from(u32::from_le_bytes(row[8..12].try_into()?));
        ensure!(
            offset >= end && offset + size <= length && tags.insert(tag),
            "invalid or duplicate FTAB entry"
        );
        entries.push(FtabEntry {
            tag,
            range: offset..offset + size,
        });
    }
    let mut ranges: Vec<_> = entries.iter().map(|entry| &entry.range).collect();
    ranges.sort_unstable_by_key(|range| (range.start, range.end));
    ensure!(
        ranges.windows(2).all(|pair| pair[0].end <= pair[1].start),
        "overlapping FTAB entries"
    );
    Ok(entries)
}

/// Byte ranges hashed by BuildManifest inside FTAB and UARP containers.
/// Only the index must be present in `prefix`; payloads can be streamed later.
pub fn payload_ranges(prefix: &[u8], length: u64) -> Result<Vec<Range<u64>>> {
    ensure!(
        prefix.len() as u64 <= length,
        "firmware prefix exceeds file length"
    );
    payload_ranges_inner(&mut Cursor::new(prefix), 0, length, prefix.len() as u64, 0)
}

/// Read only bounded indexes at their actual offsets, including late children.
pub(crate) fn payload_ranges_from(
    reader: &mut (impl Read + Seek),
    length: u64,
) -> Result<Vec<Range<u64>>> {
    payload_ranges_inner(reader, 0, length, length, 0)
}

fn read_index(reader: &mut (impl Read + Seek), offset: u64, size: usize) -> Result<Vec<u8>> {
    reader.seek(SeekFrom::Start(offset))?;
    let mut bytes = vec![0; size];
    reader
        .read_exact(&mut bytes)
        .context("truncated firmware index")?;
    Ok(bytes)
}

/// Discover payload ranges relative to `base`. `available` bounds what the
/// reader can actually supply (the prefix length for streaming callers).
fn payload_ranges_inner(
    reader: &mut (impl Read + Seek),
    base: u64,
    length: u64,
    available: u64,
    depth: usize,
) -> Result<Vec<Range<u64>>> {
    ensure!(depth <= MAX_DEPTH, "firmware containers nested too deeply");
    let header_size = length.min(available.saturating_sub(base)).min(FTAB_HEADER) as usize;
    let prefix = read_index(reader, base, header_size)?;

    if prefix.get(36..40) == Some(b"ftab") {
        ensure!(prefix.len() as u64 >= FTAB_HEADER, "truncated FTAB header");
        let count = u32::from_le_bytes(prefix[40..44].try_into()?) as usize;
        ensure!(count <= MAX_ENTRIES, "too many FTAB entries");
        let end = FTAB_HEADER + count as u64 * FTAB_ROW;
        ensure!(end <= length, "FTAB index outside file");
        let entries = ftab_index(&read_index(reader, base, end as usize)?, length)?
            .into_iter()
            // Centauri's 2ftb describes device memory, not a nested on-disk
            // container. Its bytes are hashable, but its offsets are not ours.
            .map(|entry| (entry.range, entry.tag != *b"2ftb"))
            .collect::<Vec<_>>();
        return descend(reader, base, available, depth, entries);
    }

    if !uarp_magic(&prefix) {
        return Ok(Vec::new());
    }
    ensure!(prefix.len() as u64 >= UARP_HEADER, "truncated UARP header");
    let (start, size) = uarp_header(&prefix).expect("UARP magic was checked");
    let end = start + size as u64;
    ensure!(
        start >= UARP_HEADER && end <= length && size <= MAX_UARP_INDEX,
        "invalid UARP index"
    );
    ensure!(base + end <= available, "truncated firmware index");
    let ranges = uarp_index(&read_index(reader, base + start, size)?, end, length)?;
    descend(
        reader,
        base,
        available,
        depth,
        ranges.into_iter().map(|r| (r, true)).collect(),
    )
}

/// Concatenate entry ranges and recursively discover nested containers.
fn descend(
    reader: &mut (impl Read + Seek),
    base: u64,
    available: u64,
    depth: usize,
    entries: Vec<(Range<u64>, bool)>,
) -> Result<Vec<Range<u64>>> {
    let mut ranges: Vec<_> = entries.iter().map(|(range, _)| range.clone()).collect();
    // RT15 UARP v3 wraps an FTAB in its FIRM payload. Its manifest digests
    // describe rkos/cphy entries inside that table, plus the separate RRKO.
    for (range, descend) in entries {
        if descend && base + range.start < available {
            for child in payload_ranges_inner(
                reader,
                base + range.start,
                range.end - range.start,
                available,
                depth + 1,
            )? {
                ensure!(
                    ranges.len() < MAX_ENTRIES,
                    "too many nested firmware payloads"
                );
                ranges.push(range.start + child.start..range.start + child.end);
            }
        }
    }
    Ok(ranges)
}

/// Read UARP's index independently of recursive payload discovery.
fn uarp_index(rows: &[u8], index_end: u64, length: u64) -> Result<Vec<Range<u64>>> {
    let mut position = 0;
    let mut ranges = Vec::new();
    while position < rows.len() {
        let row = &rows[position..];
        ensure!(row.len() >= UARP_ROW_LEN, "truncated UARP row");
        let size = u32::from_be_bytes(row[..4].try_into()?) as usize;
        ensure!(
            size >= UARP_ROW_LEN && size <= row.len(),
            "invalid UARP row length"
        );
        let offset = u64::from(u32::from_be_bytes(row[32..36].try_into()?));
        let payload = u64::from(u32::from_be_bytes(row[36..40].try_into()?));
        ensure!(
            offset >= index_end && offset + payload <= length,
            "UARP payload outside file"
        );
        ranges.push(offset..offset + payload);
        position += size;
    }
    let mut ordered: Vec<_> = ranges.iter().collect();
    ordered.sort_unstable_by_key(|range| (range.start, range.end));
    ensure!(
        ordered.windows(2).all(|pair| pair[0].end <= pair[1].start),
        "overlapping UARP payloads"
    );
    Ok(ranges)
}

#[cfg(test)]
#[path = "../../tests/unit/ipsw/containers.rs"]
mod tests;
