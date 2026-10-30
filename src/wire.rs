//! Property-list framing used by restored and FDR.
//!
//! Restored prefixes each plist with a big-endian byte length. FDR uses the same
//! binary-plist body with a little-endian length. ASR instead sends unframed XML
//! whose root element ends the message. All paths share the same depth, size and
//! canonical-form checks; nothing here trusts a length supplied by the device.
use anyhow::{Context, Result, bail, ensure};
use plist::{Dictionary, Value};
use quick_xml::{Reader, Writer, events::Event};
use serde::de::Error as _;
use std::io::{BufRead, Read, Write};

/// Upper bound for one plist message, in bytes, on both directions.
pub const MAX_PLIST: usize = 64 * 1024 * 1024;
const MAX_PLIST_DEPTH: usize = 128;
const MAX_XML_DEPTH: usize = 256;
const LENGTH_BYTES: usize = 4;

/// Decode XML, binary or ASCII with a depth limit applied while streaming.
pub(crate) fn decode_plist(bytes: &[u8]) -> Result<Value> {
    use plist::stream::{Event as PlistEvent, Reader as PlistReader};
    let mut depth = 0usize;
    let events = PlistReader::new(std::io::Cursor::new(bytes)).map(|event| {
        let event = event?;
        match &event {
            PlistEvent::StartArray(_) | PlistEvent::StartDictionary(_) => {
                depth += 1;
                if depth > MAX_PLIST_DEPTH {
                    return Err(plist::Error::custom("plist nested too deeply"));
                }
            }
            PlistEvent::EndCollection => {
                depth = depth
                    .checked_sub(1)
                    .ok_or_else(|| plist::Error::custom("unbalanced plist collections"))?;
            }
            _ => {}
        }
        Ok(event)
    });
    Value::from_events(events).map_err(Into::into)
}

pub fn dict(items: impl IntoIterator<Item = (impl Into<String>, Value)>) -> Value {
    Value::Dictionary(
        items
            .into_iter()
            .map(|(key, value)| (key.into(), value))
            .collect(),
    )
}

pub(crate) fn copy_keys(target: &mut Dictionary, source: &Dictionary, keys: &[&str]) {
    target.extend(keys.iter().filter_map(|key| {
        source
            .get(key)
            .map(|value| ((*key).to_owned(), value.clone()))
    }));
}

/// Look up a required value.
pub fn get<'a>(value: &'a Value, path: &[&str]) -> Result<&'a Value> {
    walk(value, path)?.with_context(|| format!("missing plist key {}", path.join(".")))
}

/// Look up an optional value. A missing key is `None`; a present value with the
/// wrong shape is still an error, so callers cannot silently treat it as absent.
pub fn optional<'a>(value: &'a Value, path: &[&str]) -> Result<Option<&'a Value>> {
    walk(value, path)
}

fn walk<'a>(mut value: &'a Value, path: &[&str]) -> Result<Option<&'a Value>> {
    for key in path {
        let fields = value.as_dictionary().with_context(|| {
            format!("expected plist dictionary while reading {}", path.join("."))
        })?;
        let Some(next) = fields.get(key) else {
            return Ok(None);
        };
        value = next;
    }
    Ok(Some(value))
}

pub fn optional_boolean(value: &Value, path: &[&str]) -> Result<Option<bool>> {
    optional(value, path)?
        .map(|value| {
            value
                .as_boolean()
                .with_context(|| format!("expected plist boolean at {}", path.join(".")))
        })
        .transpose()
}

pub fn string<'a>(value: &'a Value, path: &[&str]) -> Result<&'a str> {
    get(value, path)?
        .as_string()
        .context("expected plist string")
}

/// A data request can name its payload through `DataType`, through a direct
/// `MsgType`, or through a data-request envelope wrapping `DataType`.
pub(crate) fn data_type(message: &Value) -> Result<&str> {
    let fields = dictionary(message)?;
    let name = optional_string(fields.get("DataType"), "DataType")?;
    let envelope = optional_string(fields.get("MsgType"), "MsgType")?;
    match (name, envelope) {
        (Some(name), Some("DataRequestMsg" | "AsyncDataRequestMsg") | None) => Ok(name),
        (Some(name), Some(kind)) => {
            ensure!(
                name == kind,
                "conflicting DataType {name} and MsgType {kind}"
            );
            Ok(name)
        }
        (None, Some("DataRequestMsg" | "AsyncDataRequestMsg")) => {
            bail!("data request has no DataType")
        }
        (None, Some(kind)) => Ok(kind),
        (None, None) => bail!("data request has no DataType or MsgType"),
    }
}

fn optional_string<'a>(value: Option<&'a Value>, name: &str) -> Result<Option<&'a str>> {
    value
        .map(|value| value.as_string().with_context(|| format!("invalid {name}")))
        .transpose()
}

/// A missing or zero service port means the caller's protocol default.
pub fn data_port(message: &Value, default: u16) -> Result<u16> {
    let port = dictionary(message)?
        .get("DataPort")
        .map(|value| -> Result<u16> { Ok(u16::try_from(number(value)?)?) })
        .transpose()?;
    Ok(port.filter(|port| *port != 0).unwrap_or(default))
}

pub fn number(value: &Value) -> Result<u64> {
    if let Some(number) = value.as_unsigned_integer() {
        return Ok(number);
    }
    let text = value.as_string().context("expected plist integer")?;
    let (digits, radix) = match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(hex) => (hex, 16),
        None => (text, 10),
    };
    let digit = match radix {
        16 => |byte: u8| byte.is_ascii_hexdigit(),
        _ => |byte: u8| byte.is_ascii_digit(),
    };
    ensure!(
        !digits.is_empty() && digits.bytes().all(digit),
        "invalid unsigned plist integer"
    );
    u64::from_str_radix(digits, radix).context("plist integer overflow")
}

pub fn xml(value: &Value) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    value.to_writer_xml(LimitedWriter {
        bytes: &mut out,
        remaining: MAX_PLIST,
    })?;
    Ok(out)
}

pub fn send(output: &mut impl Write, value: &Value) -> Result<()> {
    crate::logging::plist("plist", "TX XML", value);
    write_frame(output, value, Endian::Big, Encoding::Xml)
}

pub fn send_binary(output: &mut impl Write, value: &Value) -> Result<()> {
    crate::logging::plist("plist", "TX binary BE", value);
    write_frame(output, value, Endian::Big, Encoding::Binary)
}

/// FDR uses the restored binary-plist body with a little-endian frame length.
pub(crate) fn send_binary_le(output: &mut impl Write, value: &Value) -> Result<()> {
    crate::logging::plist("plist", "TX binary LE", value);
    write_frame(output, value, Endian::Little, Encoding::Binary)
}

/// Append a complete frame to an existing batch. Offsets inside a binary plist
/// stay relative to its own writer, never to the enclosing batch.
pub(crate) fn append_binary(bytes: &mut Vec<u8>, value: &impl serde::Serialize) -> Result<()> {
    append_frame(bytes, u32::to_be_bytes, |out| {
        plist::to_writer_binary(out, value)
    })
}

#[derive(Clone, Copy)]
enum Endian {
    Big,
    Little,
}

#[derive(Clone, Copy)]
enum Encoding {
    Xml,
    Binary,
}

impl Endian {
    fn prefix(self) -> fn(u32) -> [u8; 4] {
        match self {
            Self::Big => u32::to_be_bytes,
            Self::Little => u32::to_le_bytes,
        }
    }
}

fn write_frame(
    output: &mut impl Write,
    value: &Value,
    endian: Endian,
    encoding: Encoding,
) -> Result<()> {
    let mut bytes = Vec::new();
    append_frame(&mut bytes, endian.prefix(), |out| match encoding {
        Encoding::Xml => value.to_writer_xml(out),
        Encoding::Binary => plist::to_writer_binary(out, value),
    })?;
    crate::log!(Trace, "plist", "TX frame={} B", bytes.len());
    // One call keeps the length and body in a single USB transfer.
    output.write_all(&bytes)?;
    output.flush()?;
    Ok(())
}

fn append_frame(
    bytes: &mut Vec<u8>,
    length_prefix: fn(u32) -> [u8; 4],
    encode: impl FnOnce(&mut LimitedWriter<'_>) -> std::result::Result<(), plist::Error>,
) -> Result<()> {
    let start = bytes.len();
    bytes.extend_from_slice(&[0; LENGTH_BYTES]);
    let result = (|| {
        encode(&mut LimitedWriter {
            bytes,
            remaining: MAX_PLIST,
        })?;
        let length = bytes.len() - start - LENGTH_BYTES;
        ensure!(length <= MAX_PLIST, "outgoing plist too large");
        bytes[start..start + LENGTH_BYTES].copy_from_slice(&length_prefix(length as u32));
        Ok(())
    })();
    if result.is_err() {
        bytes.truncate(start);
    }
    result
}

/// Enforce the frame limit while encoding, before a value can grow the output
/// allocation past the protocol's bound.
struct LimitedWriter<'a> {
    bytes: &'a mut Vec<u8>,
    remaining: usize,
}

impl Write for LimitedWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.remaining {
            return Err(std::io::Error::other("outgoing plist too large"));
        }
        self.bytes.extend_from_slice(bytes);
        self.remaining -= bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Read a message only when at least one byte is already available. A timeout
/// before the first byte means "nothing yet"; a timeout mid-frame is an error.
pub fn try_receive(input: &mut impl Read) -> Result<Option<Value>> {
    let mut length = [0; LENGTH_BYTES];
    match input.read_exact(&mut length[..1]) {
        Err(error) if error.kind() == std::io::ErrorKind::TimedOut => return Ok(None),
        result => result.context("service disconnected during optional message read")?,
    }
    input.read_exact(&mut length[1..])?;
    receive_body(input, u32::from_be_bytes(length)).map(Some)
}

pub fn receive(input: &mut impl Read) -> Result<Value> {
    let mut length = [0; LENGTH_BYTES];
    input
        .read_exact(&mut length)
        .context("reading plist length")?;
    receive_body(input, u32::from_be_bytes(length))
}

pub(crate) fn receive_body(input: &mut impl Read, length: u32) -> Result<Value> {
    let length = length as usize;
    ensure!(
        (1..=MAX_PLIST).contains(&length),
        "invalid plist frame length {length}"
    );
    let mut body = vec![0; length];
    input.read_exact(&mut body).context("reading plist body")?;
    let value = decode_plist(&body)?;
    crate::log!(Trace, "plist", "RX frame={length} B");
    crate::logging::plist("plist", "RX", &value);
    Ok(value)
}

/// ASR sends unframed XML. Keep the caller's buffer across messages so read-ahead
/// remains available for the next plist or raw payload.
pub fn receive_xml(input: &mut impl BufRead) -> Result<Value> {
    let mut reader = Reader::from_reader(input.take(MAX_PLIST as u64));
    let mut writer = Writer::new(Vec::new());
    let mut buffer = Vec::new();
    let mut depth = 0usize;
    loop {
        let event = reader
            .read_event_into(&mut buffer)
            .context("reading ASR XML")?;
        match &event {
            Event::Start(tag) => {
                ensure!(
                    depth != 0 || tag.name().as_ref() == "plist",
                    "ASR XML root is not plist"
                );
                depth += 1;
                ensure!(depth <= MAX_XML_DEPTH, "ASR XML nested too deeply");
            }
            Event::End(_) => {
                depth = depth
                    .checked_sub(1)
                    .context("unexpected ASR XML closing tag")?;
            }
            Event::Empty(tag) if depth == 0 => {
                ensure!(tag.name().as_ref() == "plist", "ASR XML root is not plist");
            }
            Event::Eof => bail!("truncated ASR XML or message exceeds {MAX_PLIST} bytes"),
            _ => {}
        }
        let complete = depth == 0 && matches!(event, Event::End(_) | Event::Empty(_));
        writer.write_event(event)?;
        if complete {
            let value = Value::from_reader_xml(writer.into_inner().as_slice())
                .context("decoding ASR plist")?;
            crate::logging::plist("asr:plist", "RX", &value);
            return Ok(value);
        }
        buffer.clear();
    }
}

pub fn dictionary(value: &Value) -> Result<&Dictionary> {
    value.as_dictionary().context("expected plist dictionary")
}

#[cfg(test)]
#[path = "../tests/unit/wire.rs"]
mod tests;
