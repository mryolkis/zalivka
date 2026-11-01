//! Bounded AEA profile 1 authentication and plaintext measurement.
use super::{MAX_AUTH, Prefix, PublicFcs};
use anyhow::{Context, Result, ensure};
use ctr::cipher::{KeyIvInit, StreamCipher};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io::Read;

#[derive(Default)]
pub struct Options {
    pub key: Option<[u8; 32]>,
    pub private_key: Option<Vec<u8>>,
    pub online: bool,
}

#[derive(Debug, Default, Serialize)]
pub struct Verification {
    pub integrity_verified: bool,
    pub content_verified: bool,
    pub plaintext_bytes: u64,
    pub clusters: usize,
    pub segments: usize,
    pub compression: Option<String>,
    pub skipped_reason: Option<String>,
}

fn derive<const N: usize>(key: &[u8], salt: Option<&[u8]>, info: &[u8]) -> Result<[u8; N]> {
    let mut output = [0; N];
    Hkdf::<Sha256>::new(salt, key)
        .expand(info, &mut output)
        .map_err(|_| anyhow::anyhow!("AEA key derivation failed"))?;
    Ok(output)
}

fn authenticate(key: &[u8], expected: &[u8], data: &[u8], salt: &[u8]) -> Result<()> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key)?;
    mac.update(salt);
    mac.update(data);
    mac.update(&(salt.len() as u64).to_le_bytes());
    mac.verify_slice(expected)
        .map_err(|_| anyhow::anyhow!("AEA HMAC mismatch"))
}

fn decrypt(data: &mut [u8], material: &[u8; 80]) -> Result<()> {
    let mut cipher =
        ctr::Ctr128BE::<aes::Aes256>::new_from_slices(&material[32..64], &material[64..])?;
    cipher
        .try_apply_keystream(data)
        .map_err(|_| anyhow::anyhow!("AEA AES counter overflow"))?;
    Ok(())
}

pub(super) fn root_header(
    key: &[u8; 32],
    salt: &[u8; 32],
    auth: &[u8],
    root: &[u8; 112],
) -> Result<([u8; 32], [u8; 48])> {
    let main = derive::<32>(key, Some(salt), b"AEA_AMK\x01\0\0\0")?;
    let material = derive::<80>(&main, None, b"AEA_RHEK")?;
    let mut bound = root[80..].to_vec();
    bound.extend_from_slice(auth);
    authenticate(&material[..32], &root[..32], &root[32..80], &bound)
        .context("AEA root header authentication failed")?;
    let mut header: [u8; 48] = root[32..80].try_into()?;
    decrypt(&mut header, &material)?;
    Ok((main, header))
}

fn u32le(data: &[u8]) -> u32 {
    u32::from_le_bytes(data[..4].try_into().expect("fixed header field"))
}
fn u64le(data: &[u8]) -> u64 {
    u64::from_le_bytes(data[..8].try_into().expect("fixed header field"))
}

/// Authenticate all encrypted blocks even if a compression method is unknown.
/// The callback receives plaintext only after its segment has been checked.
pub fn verify(
    reader: &mut impl Read,
    length: u64,
    options: &Options,
    mut plaintext: impl FnMut(&[u8]) -> Result<()>,
) -> Result<Verification> {
    let mut header = [0; 12];
    reader
        .read_exact(&mut header)
        .context("truncated AEA header")?;
    ensure!(&header[..4] == b"AEA1", "invalid AEA magic");
    let auth_size = u32le(&header[8..]) as usize;
    ensure!(
        auth_size <= MAX_AUTH,
        "AEA authentication metadata exceeds 1 MiB"
    );
    let prefix_size = 12 + auth_size + 144;
    ensure!(length >= prefix_size as u64, "truncated AEA prefix");
    let mut prefix = header.to_vec();
    prefix.resize(prefix_size, 0);
    reader
        .read_exact(&mut prefix[12..])
        .context("truncated AEA prefix")?;
    let mut report = Verification::default();
    if u32le(&header[4..]) != 1 {
        report.skipped_reason = Some(format!(
            "unsupported AEA profile {:#x}",
            u32le(&header[4..])
        ));
        return Ok(report);
    }
    let public = PublicFcs::from_prefix(&prefix)?;
    let key = if let Some(key) = options.key {
        Some(key)
    } else if let Prefix::Public(public) = public {
        if let Some(pem) = &options.private_key {
            Some(public.unwrap_key(pem)?)
        } else if options.online {
            Some(public.fetch_key()?)
        } else {
            None
        }
    } else {
        None
    };
    let Some(key) = key else {
        report.skipped_reason = Some(if options.online || options.private_key.is_some() {
            "no supported public FCS key metadata; supply --aea-key"
        } else { "AEA key unavailable in offline mode; supply --aea-key, --aea-private-key or --online" }.into());
        return Ok(report);
    };
    let end = 12 + auth_size;
    let (main, root) = root_header(
        &key,
        prefix[end..end + 32].try_into()?,
        &prefix[12..end],
        prefix[end + 32..].try_into()?,
    )?;
    let file_size = u64le(&root);
    ensure!(u64le(&root[8..]) == length, "AEA encrypted size mismatch");
    let segment_size = u32le(&root[16..]) as usize;
    let segment_count = u32le(&root[20..]) as usize;
    ensure!(
        (1..=64 * 1024 * 1024).contains(&segment_size),
        "AEA segment size exceeds limit"
    );
    ensure!(
        (1..=4096).contains(&segment_count),
        "AEA segments per cluster exceeds limit"
    );
    let compression = root[24];
    let checksum = root[25];
    let checksum_size = match checksum {
        0 => 0,
        1 => 8,
        2 => 32,
        _ => anyhow::bail!("unsupported AEA checksum {checksum}"),
    };
    report.compression = Some(
        match compression {
            b'-' => "none",
            b'e' => "lzfse",
            b'f' => "lzvn",
            b'b' => "lzbitmap",
            b'z' => "zlib",
            b'4' => "lz4",
            _ => "unsupported",
        }
        .into(),
    );
    let mut cluster_mac = prefix[end + 112..end + 144].to_vec();
    let mut consumed = prefix_size as u64;
    let mut decoded = 0u64;
    let mut complete = true;
    let mut scratch = Vec::new();
    let mut output = Vec::new();
    while decoded < file_size {
        crate::progress::check_cancelled()?;
        let cluster_index = u32::try_from(report.clusters).context("too many AEA clusters")?;
        let cluster_key = derive::<32>(
            &main,
            None,
            &[b"AEA_CK".as_slice(), &cluster_index.to_le_bytes()].concat(),
        )?;
        let material = derive::<80>(&cluster_key, None, b"AEA_CHEK")?;
        let header_size = (8 + checksum_size) * segment_count;
        let mut headers = vec![0; header_size];
        let mut salt = vec![0; 32 + 32 * segment_count];
        ensure!(
            consumed + (header_size + salt.len()) as u64 <= length,
            "truncated AEA cluster header"
        );
        reader.read_exact(&mut headers)?;
        reader.read_exact(&mut salt)?;
        consumed += (header_size + salt.len()) as u64;
        authenticate(&material[..32], &cluster_mac, &headers, &salt)
            .with_context(|| format!("AEA cluster {cluster_index}"))?;
        decrypt(&mut headers, &material)?;
        for (index, header) in headers.chunks_exact(8 + checksum_size).enumerate() {
            crate::progress::check_cancelled()?;
            let raw_size = u32le(header) as usize;
            let compressed_size = u32le(&header[4..]) as usize;
            if raw_size == 0 {
                ensure!(
                    compressed_size == 0 && decoded == file_size,
                    "invalid empty AEA segment"
                );
                continue;
            }
            ensure!(
                raw_size <= segment_size
                    && raw_size as u64 == (file_size - decoded).min(segment_size as u64),
                "invalid AEA plaintext segment size"
            );
            ensure!(
                compressed_size > 0
                    && compressed_size <= segment_size
                    && consumed + compressed_size as u64 <= length,
                "invalid AEA encrypted segment size"
            );
            scratch.resize(compressed_size, 0);
            reader.read_exact(&mut scratch)?;
            consumed += compressed_size as u64;
            let material = derive::<80>(
                &cluster_key,
                None,
                &[b"AEA_SK".as_slice(), &(index as u32).to_le_bytes()].concat(),
            )?;
            authenticate(
                &material[..32],
                &salt[32 + 32 * index..64 + 32 * index],
                &scratch,
                &[],
            )
            .with_context(|| format!("AEA cluster {cluster_index} segment {index}"))?;
            decrypt(&mut scratch, &material)?;
            output.clear();
            if decompress(compression, &scratch, raw_size, &mut output)? {
                match checksum {
                    2 => ensure!(
                        Sha256::digest(&output).as_slice() == &header[8..],
                        "AEA SHA-256 checksum mismatch"
                    ),
                    1 => ensure!(
                        murmur64(&output).to_le_bytes() == header[8..],
                        "AEA Murmur checksum mismatch"
                    ),
                    _ => {}
                }
                plaintext(&output)?;
            } else {
                complete = false;
                report.skipped_reason = Some(format!(
                    "unsupported AEA compression {compression:#x}; plaintext digests not checked"
                ));
            }
            decoded += raw_size as u64;
            report.segments += 1;
        }
        cluster_mac.copy_from_slice(&salt[..32]);
        report.clusters += 1;
    }
    if consumed < length {
        let material = derive::<80>(&main, None, b"AEA_PAK")?;
        let mut mac = Hmac::<Sha256>::new_from_slice(&material[..32])?;
        let mut buffer = [0; 64 * 1024];
        while consumed < length {
            crate::progress::check_cancelled()?;
            let n = ((length - consumed).min(buffer.len() as u64)) as usize;
            reader.read_exact(&mut buffer[..n])?;
            mac.update(&buffer[..n]);
            consumed += n as u64;
        }
        mac.verify_slice(&cluster_mac)
            .map_err(|_| anyhow::anyhow!("AEA padding HMAC mismatch"))?;
    }
    report.integrity_verified = true;
    report.content_verified = complete;
    report.plaintext_bytes = decoded;
    Ok(report)
}

fn decompress(compression: u8, data: &[u8], expected: usize, output: &mut Vec<u8>) -> Result<bool> {
    if data.len() == expected {
        output.extend_from_slice(data);
    } else {
        match compression {
            b'e' | b'f' => {
                let wrapped;
                let input = if compression == b'f' {
                    wrapped = [
                        b"bvxn".as_slice(),
                        &(expected as u32).to_le_bytes(),
                        &(data.len() as u32).to_le_bytes(),
                        data,
                        b"bvx$",
                    ]
                    .concat();
                    wrapped.as_slice()
                } else {
                    data
                };
                let mut decoder = lzfse_rust::LzfseRingDecoder::default();
                let mut reader = decoder.reader_bytes(input);
                reader
                    .by_ref()
                    .take(expected as u64 + 1)
                    .read_to_end(output)?;
            }
            b'b' => {
                zbitmap::decompress(data, output, expected)?;
            }
            b'z' => {
                flate2::read::ZlibDecoder::new(data)
                    .take(expected as u64 + 1)
                    .read_to_end(output)?;
            }
            b'4' => {
                output.resize(expected, 0);
                let size = lz4_flex::block::decompress_into(data, output)?;
                ensure!(size == expected, "AEA LZ4 size mismatch");
            }
            b'-' => anyhow::bail!("compressed segment with AEA compression disabled"),
            _ => return Ok(false),
        }
    }
    ensure!(output.len() == expected, "AEA decompressed size mismatch");
    Ok(true)
}

// AEA uses MurmurHash3 x64's first word with a 64-bit seed (not the
// common 32-bit seeded variant). All arithmetic is modulo 2^64.
fn murmur64(data: &[u8]) -> u64 {
    const C1: u64 = 0x87c37b91114253d5;
    const C2: u64 = 0x4cf5ad432745937f;
    let mut h1 = 0xe2236fdc26a5f6d2u64;
    let mut h2 = h1;
    let mix1 = |k: u64| k.wrapping_mul(C1).rotate_left(31).wrapping_mul(C2);
    let mix2 = |k: u64| k.wrapping_mul(C2).rotate_left(33).wrapping_mul(C1);
    let (chunks, tail) = data.as_chunks::<16>();
    for chunk in chunks {
        h1 ^= mix1(u64le(chunk));
        h1 = h1
            .rotate_left(27)
            .wrapping_add(h2)
            .wrapping_mul(5)
            .wrapping_add(0x52dce729);
        h2 ^= mix2(u64le(&chunk[8..]));
        h2 = h2
            .rotate_left(31)
            .wrapping_add(h1)
            .wrapping_mul(5)
            .wrapping_add(0x38495ab5);
    }
    let mut k1 = [0; 8];
    let mut k2 = [0; 8];
    let split = tail.len().min(8);
    k1[..split].copy_from_slice(&tail[..split]);
    k2[..tail.len() - split].copy_from_slice(&tail[split..]);
    h1 ^= mix1(u64le(&k1));
    h2 ^= mix2(u64le(&k2));
    h1 ^= data.len() as u64;
    h2 ^= data.len() as u64;
    h1 = h1.wrapping_add(h2);
    h2 = h2.wrapping_add(h1);
    fn fmix(mut x: u64) -> u64 {
        x ^= x >> 33;
        x = x.wrapping_mul(0xff51afd7ed558ccd);
        x ^= x >> 33;
        x = x.wrapping_mul(0xc4ceb9fe1a85ec53);
        x ^ (x >> 33)
    }
    fmix(h1).wrapping_add(fmix(h2))
}

#[cfg(test)]
#[path = "../../tests/unit/aea/verify.rs"]
mod tests;
