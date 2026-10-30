//! Bounded image cursors and read-ahead for compressed ZIP entries.
//!
//! The archive reader is shared with the USB writer but must never hold a
//! multi-gigabyte image in memory. A single reader thread decompresses one block
//! ahead; the calling thread performs the writes (and therefore owns any mux/AEA
//! exchange ordering).
use anyhow::{Context, Result, ensure};
use std::{
    fs::File,
    io::{self, BufReader, Read, Seek, SeekFrom, Write},
    sync::mpsc,
    thread,
};

pub(super) const STREAM_CHUNK: usize = 256 * 1024;

/// Overlap decompression with writes. The queue, reader and writer hold at most
/// three blocks.
pub(super) fn copy_prefetched(mut input: impl Read + Send, out: &mut impl Write) -> Result<u64> {
    thread::scope(|scope| {
        let (sender, receiver) = mpsc::sync_channel(1);
        let reader = thread::Builder::new()
            .name("ipsw-read-ahead".into())
            .spawn_scoped(
                scope,
                crate::progress::inherit(move || -> io::Result<u64> {
                    let mut total = 0;
                    loop {
                        let mut block = vec![0; STREAM_CHUNK];
                        let filled = read_chunk(&mut input, &mut block)?;
                        if filled == 0 {
                            return Ok(total);
                        }
                        block.truncate(filled);
                        total += filled as u64;
                        sender.send(block).map_err(|_| {
                            io::Error::new(io::ErrorKind::BrokenPipe, "IPSW stream consumer closed")
                        })?;
                    }
                }),
            )
            .context("starting IPSW reader")?;
        let mut write_error = None;
        for block in &receiver {
            if let Err(error) = out.write_all(&block) {
                write_error = Some(error);
                break;
            }
        }
        // Unblock a reader waiting on a full queue before joining after an
        // output failure, and preserve that original failure over queue closure.
        drop(receiver);
        let read = reader
            .join()
            .map_err(|_| anyhow::anyhow!("IPSW reader panicked"));
        if let Some(error) = write_error {
            return Err(error.into());
        }
        // EOF (including ZIP CRC validation) must succeed before the caller can
        // signal FileDataDone, even if every payload block was written.
        Ok(read??)
    })
}

/// Fill a bounded block across short reads and interruptions, respecting cancellation.
pub(super) fn read_chunk(reader: &mut impl Read, buffer: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buffer.len() {
        crate::progress::check_cancelled()?;
        match reader.read(&mut buffer[filled..]) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(filled)
}

/// A bounded, CRC-checked cursor over a stored ZIP entry or a prepared image.
pub struct ImageReader {
    file: File,
    start: u64,
    size: u64,
    position: u64,
    expected_crc: u32,
    /// `None` once a seek made sequential CRC validation impossible.
    crc: Option<crc32fast::Hasher>,
}

impl ImageReader {
    pub(super) fn new(mut file: File, start: u64, size: u64, expected_crc: u32) -> Result<Self> {
        let backing_size = file.metadata()?.len();
        ensure!(
            start
                .checked_add(size)
                .is_some_and(|end| end <= backing_size),
            "filesystem image extends beyond its backing file"
        );
        file.seek(SeekFrom::Start(start))?;
        Ok(Self {
            file,
            start,
            size,
            position: 0,
            expected_crc,
            crc: Some(crc32fast::Hasher::new()),
        })
    }

    pub(super) fn copy_to(self, out: &mut impl Write) -> Result<u64> {
        // FileData consumes 8-KiB frames; keep filesystem reads much larger,
        // especially when the archive lives across the Windows filesystem bridge.
        Ok(std::io::copy(
            &mut BufReader::with_capacity(STREAM_CHUNK, self),
            out,
        )?)
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    fn remaining(&self) -> usize {
        (self.size - self.position).min(usize::MAX as u64) as usize
    }
}

impl Read for ImageReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let limit = buffer.len().min(self.remaining());
        let read = self.file.read(&mut buffer[..limit])?;
        if read == 0 && limit != 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated filesystem image",
            ));
        }
        self.position += read as u64;
        if let Some(crc) = &mut self.crc {
            crc.update(&buffer[..read]);
            if self.position == self.size && crc.clone().finalize() != self.expected_crc {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "filesystem image CRC mismatch",
                ));
            }
        }
        Ok(read)
    }
}

impl Seek for ImageReader {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let target = match from {
            SeekFrom::Start(position) => i128::from(position),
            SeekFrom::Current(delta) => i128::from(self.position) + i128::from(delta),
            SeekFrom::End(delta) => i128::from(self.size) + i128::from(delta),
        };
        if target < 0 || target > i128::from(self.size) {
            return Err(io::Error::other("image seek out of bounds"));
        }
        let target = target as u64;
        self.file.seek(SeekFrom::Start(self.start + target))?;
        if target == 0 {
            self.crc = Some(crc32fast::Hasher::new());
        } else if target != self.position {
            // Bytes skipped by the seek cannot be hashed; never claim a CRC.
            self.crc = None;
        }
        self.position = target;
        Ok(target)
    }
}
