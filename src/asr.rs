//! Apple Software Restore image transfer, including validation reads and SHA-1 chunks.
use crate::wire;
use anyhow::{Context, Result, bail, ensure};
use plist::Value;
use sha1::{Digest, Sha1};
use std::io::{BufReader, Read, Seek, SeekFrom, Write};

const CHUNK: usize = 131_072;
const BATCH_CHUNKS: usize = 4;
const CHECKSUM_BYTES: usize = 20;
const MAX_VALIDATION_REQUESTS: u64 = 100_000;
const MAX_OOB: u64 = 64 * 1024 * 1024;

fn info(stream: &mut impl Write, length: u64, checksum: bool) -> Result<()> {
    let mut fields = plist::Dictionary::from_iter([
        ("Version", 1u64.into()),
        ("Stream ID", 1u64.into()),
        ("FEC Slice Stride", 40u64.into()),
        ("Packet Payload Size", 1450u64.into()),
        ("Packets Per FEC", 25u64.into()),
        (
            "Payload",
            wire::dict([("Port", 1u64.into()), ("Size", length.into())]),
        ),
    ]);
    if checksum {
        fields.insert("Checksum Chunk Size".into(), (CHUNK as u64).into());
    }
    stream.write_all(&wire::xml(&Value::Dictionary(fields))?)?;
    stream.flush()?;
    Ok(())
}

pub fn transfer(
    stream: &mut (impl Read + Write),
    image: &mut (impl Read + Seek),
    length: u64,
) -> Result<()> {
    let _trace = crate::logging::firmware_transfer();
    let mut stream = BufReader::new(stream);
    let initiate = wire::receive_xml(&mut stream)?;
    ensure!(
        wire::string(&initiate, &["Command"])? == "Initiate",
        "ASR did not send Initiate"
    );
    let mut checksum = checksum_mode(&initiate, false)?;
    info(stream.get_mut(), length, checksum)?;

    let mut requests = 0u64;
    loop {
        let message = wire::receive_xml(&mut stream)?;
        match wire::string(&message, &["Command"])? {
            "Initiate" => {
                checksum = checksum_mode(&message, checksum)?;
                info(stream.get_mut(), length, checksum)?;
            }
            "OOBData" => {
                requests += 1;
                ensure!(
                    requests <= MAX_VALIDATION_REQUESTS,
                    "too many ASR validation requests"
                );
                let offset = wire::number(wire::get(&message, &["OOB Offset"])?)?;
                let count = wire::number(wire::get(&message, &["OOB Length"])?)?;
                ensure!(
                    count <= MAX_OOB && offset.checked_add(count).is_some_and(|end| end <= length),
                    "ASR OOB read is outside image"
                );
                image.seek(SeekFrom::Start(offset))?;
                let copied = std::io::copy(&mut image.take(count), stream.get_mut())?;
                ensure!(copied == count, "truncated ASR validation data");
                stream.get_mut().flush()?;
            }
            "Payload" => break,
            command => bail!("unsupported ASR command {command}"),
        }
    }

    image.seek(SeekFrom::Start(0))?;
    // Keep the negotiated checksum boundaries, but fill several blocks before
    // writing so USB packets can span ASR block boundaries.
    let stride = CHUNK + if checksum { CHECKSUM_BYTES } else { 0 };
    let mut buffer = vec![0; BATCH_CHUNKS * stride];
    let mut total = 0;
    let mut progress = crate::progress::Progress::new("ASR filesystem transfer", Some(length), 0);
    while total < length {
        let mut payload = 0;
        let mut sent = 0;
        for block in buffer.chunks_mut(stride) {
            let n = (length - total - payload).min(CHUNK as u64) as usize;
            if n == 0 {
                break;
            }
            image
                .read_exact(&mut block[..n])
                .context("reading filesystem image")?;
            if checksum {
                let digest = Sha1::digest(&block[..n]);
                block[n..n + CHECKSUM_BYTES].copy_from_slice(&digest);
                sent += n + CHECKSUM_BYTES;
            } else {
                sent += n;
            }
            payload += n as u64;
        }
        stream.get_mut().write_all(&buffer[..sent])?;
        total += payload;
        progress.advance(payload);
    }
    stream.get_mut().flush()?;
    progress.finish();
    Ok(())
}

fn checksum_mode(message: &Value, previous: bool) -> Result<bool> {
    match wire::dictionary(message)?.get("Checksum Chunks") {
        Some(value) => value.as_boolean().context("invalid ASR checksum mode"),
        None => Ok(previous),
    }
}
