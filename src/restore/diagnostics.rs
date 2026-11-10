//! Read-only restore evidence. Diagnostic failures must never replace a restore error.
use super::{connection, events::record_message};
use crate::{
    logging::{Level, Record},
    mux::MuxStream,
    wire,
};
use anyhow::{Context, Result};
use nusb::MaybeFuture;
use plist::Value;
use std::{
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const TEXT_BUDGET: usize = 2 * 1024 * 1024;
const MAX_LINES: usize = 8192;

pub(super) struct Diagnostics {
    directory: Option<PathBuf>,
    sequence: u64,
    messages: u64,
    last_message: Instant,
    checkpoint: Option<String>,
    operation: Option<String>,
    request: Option<String>,
}

impl Diagnostics {
    pub(super) fn new(directory: Option<PathBuf>) -> Self {
        let directory = directory.and_then(|path| match std::fs::create_dir(&path) {
            Ok(()) => {
                crate::log!(
                    Info,
                    "diagnostics",
                    "Evidence directory: {}",
                    path.display()
                );
                Some(path)
            }
            Err(error) => {
                crate::log!(
                    Warning,
                    "diagnostics",
                    "Cannot create {}: {error}; continuing without evidence files",
                    path.display()
                );
                None
            }
        });
        Self {
            directory,
            sequence: 0,
            messages: 0,
            last_message: Instant::now(),
            checkpoint: None,
            operation: None,
            request: None,
        }
    }

    pub(super) fn capture(&mut self, name: &str, value: &Value, level: Level) {
        self.sequence += 1;
        if let Some(directory) = &self.directory {
            // Names are generated here, never taken from a device-supplied path.
            let name: String = name
                .chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric() || c == '-' {
                        c
                    } else {
                        '_'
                    }
                })
                .take(100)
                .collect();
            let path = directory.join(format!("{:04}-{name}.plist", self.sequence));
            let result = (|| -> Result<()> {
                let mut file = File::options().write(true).create_new(true).open(&path)?;
                plist::to_writer_xml(&mut file, value)?;
                file.flush()?;
                Ok(())
            })();
            if let Err(error) = result {
                crate::log!(
                    Warning,
                    "diagnostics",
                    "Saving {}: {error:#}",
                    path.display()
                );
            } else {
                crate::log!(Debug, "diagnostics", "Saved {}", path.display());
            }
        }
        describe(name, value, level, crate::logging::publish);
    }

    pub(super) fn host(&mut self) {
        let mut fields = plist::Dictionary::from_iter([
            ("Version", Value::from(crate::VERSION)),
            ("HostOS", std::env::consts::OS.into()),
            ("HostArchitecture", std::env::consts::ARCH.into()),
            ("Compiler", env!("ZALIVKA_COMPILER").into()),
            ("BuildTarget", env!("ZALIVKA_TARGET").into()),
            ("BuildProfile", env!("ZALIVKA_PROFILE").into()),
            (
                "UnixTimeSeconds",
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
                    .into(),
            ),
        ]);
        fields.insert(
            "RestoreTransport".into(),
            if cfg!(any(target_os = "linux", target_os = "macos")) {
                "system usbmuxd"
            } else {
                "direct USB mux"
            }
            .into(),
        );
        #[cfg(target_os = "macos")]
        if let Ok(bytes) = std::fs::read("/System/Library/CoreServices/SystemVersion.plist")
            && let Ok(version) = wire::decode_plist(&bytes)
        {
            fields.insert("SystemVersion".into(), version);
        }
        #[cfg(target_os = "linux")]
        if let Ok(version) = std::fs::read_to_string("/etc/os-release") {
            fields.insert("SystemVersion".into(), version.into());
        }
        self.capture("host", &fields.into(), Level::Debug);
        self.usb("initial-usb");
    }

    pub(super) fn usb(&mut self, name: &str) {
        match usb_snapshot() {
            Ok(value) => self.capture(name, &value, Level::Debug),
            Err(error) => crate::log!(Debug, "diagnostics", "USB inventory unavailable: {error:#}"),
        }
    }

    /// Query only before StartRestore. A failed read leaves framing uncertain:
    /// the caller must reconnect, never continue parsing this stream.
    pub(super) fn query(
        &mut self,
        main: &mut MuxStream,
        transcript: &mut Option<File>,
    ) -> Result<()> {
        let previous = main.read_timeout();
        main.set_read_timeout(Duration::from_secs(3));
        let result = self.query_values(main, transcript);
        main.set_read_timeout(previous);
        result
    }

    fn query_values(
        &mut self,
        main: &mut (impl Read + Write),
        transcript: &mut Option<File>,
    ) -> Result<()> {
        for key in ["SavedDebugInfo", "Logs"] {
            let response = connection::query_value(main, key)?;
            if let Some(warning) = record_message(transcript, &response) {
                crate::logging::publish(warning);
            }
            if let Some(value) = response.as_dictionary().and_then(|d| d.get(key)) {
                self.capture(key, value, Level::Debug);
                if key == "SavedDebugInfo"
                    && value
                        .as_dictionary()
                        .is_some_and(|d| !d.contains_key("PanicLog"))
                {
                    crate::log!(
                        Debug,
                        "diagnostics",
                        "SavedDebugInfo did not include a PanicLog; this does not rule out a panic"
                    );
                }
            } else {
                self.capture(&format!("{key}-response"), &response, Level::Debug);
                crate::log!(
                    Debug,
                    "diagnostics",
                    "{key} is unavailable or unsupported on this restore environment"
                );
            }
        }
        Ok(())
    }

    pub(super) fn observe(&mut self, message: &Value) {
        self.messages += 1;
        self.last_message = Instant::now();
        match wire::string(message, &["MsgType"]).unwrap_or("") {
            "CheckpointMsg" => {
                self.checkpoint = Some(format!(
                    "{}; complete={}; result={}",
                    wire::string(message, &["CHECKPOINT_NAME"]).unwrap_or("unknown"),
                    wire::get(message, &["CHECKPOINT_COMPLETE"])
                        .map(|v| format!("{v:?}"))
                        .unwrap_or_default(),
                    wire::get(message, &["CHECKPOINT_RESULT"])
                        .map(|v| format!("{v:?}"))
                        .unwrap_or_default()
                ));
            }
            "ProgressMsg" => {
                self.operation = Some(format!(
                    "operation={:?}; progress={:?}",
                    wire::get(message, &["Operation"]).ok(),
                    wire::get(message, &["Progress"]).ok()
                ))
            }
            "DataRequestMsg" | "AsyncDataRequestMsg" => {
                self.request = Some(format!(
                    "{}; port={:?}",
                    wire::string(message, &["DataType"]).unwrap_or("unknown"),
                    wire::get(message, &["DataPort"]).ok()
                ))
            }
            "PreviousRestoreLogMsg" | "CrashLog" | "RestoredCrash" | "StatusMsg" => {
                let kind = wire::string(message, &["MsgType"]).unwrap();
                let level = if matches!(kind, "RestoredCrash" | "CrashLog") {
                    Level::Warning
                } else {
                    Level::Debug
                };
                self.capture(kind, message, level);
            }
            _ => {}
        }
    }

    pub(super) fn failure(&mut self, error: &anyhow::Error, removed: Option<bool>) {
        let value = wire::dict([
            ("Error", format!("{error:#}").into()),
            ("MessagesReceived", self.messages.into()),
            (
                "SecondsSinceLastMessage",
                self.last_message.elapsed().as_secs_f64().into(),
            ),
            (
                "LastCheckpoint",
                self.checkpoint.as_deref().unwrap_or("none").into(),
            ),
            (
                "LastOperation",
                self.operation.as_deref().unwrap_or("none").into(),
            ),
            (
                "LastDataRequest",
                self.request.as_deref().unwrap_or("none").into(),
            ),
            (
                "DeviceRemovalConfirmed",
                removed
                    .map_or_else(|| "unknown".to_owned(), |v| v.to_string())
                    .into(),
            ),
        ]);
        self.capture("failure-context", &value, Level::Warning);
        self.usb("failure-usb");
        crate::log!(
            Debug,
            "diagnostics",
            "A target panic may only be available as SavedDebugInfo.PanicLog after the restore environment boots again"
        );
    }
}

/// Enumerate cached descriptors only: never open, claim, reset or probe devices.
pub(super) fn usb_snapshot() -> Result<Value> {
    let mut devices: Vec<_> = nusb::list_devices()
        .wait()?
        .filter(|d| d.vendor_id() == 0x05ac)
        .collect();
    devices.sort_by(|a, b| {
        (a.bus_id(), a.port_chain(), a.device_address()).cmp(&(
            b.bus_id(),
            b.port_chain(),
            b.device_address(),
        ))
    });
    let devices = devices
        .into_iter()
        .map(|d| {
            wire::dict([
                ("ProductID", format!("{:04x}", d.product_id()).into()),
                ("Bus", d.bus_id().into()),
                (
                    "PortChain",
                    Value::Array(
                        d.port_chain()
                            .iter()
                            .map(|p| u64::from(*p).into())
                            .collect(),
                    ),
                ),
                ("Address", u64::from(d.device_address()).into()),
                ("Product", d.product_string().unwrap_or("").into()),
                ("Serial", d.serial_number().unwrap_or("").into()),
                ("Speed", format!("{:?}", d.speed()).into()),
                ("USBVersion", format!("{:04x}", d.usb_version()).into()),
                (
                    "Interfaces",
                    Value::Array(
                        d.interfaces()
                            .map(|i| {
                                format!(
                                    "{}: {:02x}/{:02x}/{:02x}",
                                    i.interface_number(),
                                    i.class(),
                                    i.subclass(),
                                    i.protocol()
                                )
                                .into()
                            })
                            .collect(),
                    ),
                ),
            ])
        })
        .collect();
    let mut fields = plist::Dictionary::from_iter([("AppleUSBDevices", Value::Array(devices))]);
    fields.insert("InventoryScope".into(), "All observed Apple USB devices; entries are not automatically attributed to the target ECID".into());
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    match crate::platform::unix::mux::diagnostic_devices() {
        Ok(value) => {
            fields.insert("UsbmuxdDevices".into(), value);
        }
        Err(error) => {
            fields.insert("UsbmuxdError".into(), format!("{error:#}").into());
        }
    }
    Ok(fields.into())
}

/// Preserve complete text lines and nested fields, while bounding rendering work.
/// The original plist is saved separately, including any binary panic payload.
pub(super) fn describe(name: &str, value: &Value, level: Level, mut output: impl FnMut(Record)) {
    struct Render<'a, F> {
        bytes: usize,
        lines: usize,
        omitted: bool,
        level: Level,
        output: &'a mut F,
    }
    impl<F: FnMut(Record)> Render<'_, F> {
        fn line(&mut self, path: &str, text: &str) {
            for line in text.split('\n') {
                let mut rest = line.trim_end_matches('\r');
                loop {
                    let end = rest.char_indices().nth(2048).map_or(rest.len(), |(i, _)| i);
                    let chunk = &rest[..end];
                    if self.lines >= MAX_LINES
                        || self.bytes.saturating_add(path.len() + chunk.len()) > TEXT_BUDGET
                    {
                        self.omitted = true;
                        return;
                    }
                    (self.output)(Record::new(
                        self.level,
                        "diagnostics",
                        format!("{path}: {chunk}"),
                    ));
                    self.lines += 1;
                    self.bytes += path.len() + chunk.len();
                    rest = &rest[end..];
                    if rest.is_empty() {
                        break;
                    }
                }
            }
        }
        fn value(&mut self, path: &str, value: &Value, depth: usize) {
            if self.omitted {
                return;
            }
            if depth > 16 {
                self.line(path, "<nesting limit; see saved plist>");
                return;
            }
            match value {
                Value::Dictionary(d) => {
                    self.line(path, &format!("dictionary[{}]", d.len()));
                    for (key, v) in d {
                        self.value(&format!("{path}.{key}"), v, depth + 1);
                        if self.omitted {
                            break;
                        }
                    }
                }
                Value::Array(a) => {
                    self.line(path, &format!("array[{}]", a.len()));
                    for (i, v) in a.iter().enumerate() {
                        self.value(&format!("{path}[{i}]"), v, depth + 1);
                        if self.omitted {
                            break;
                        }
                    }
                }
                Value::String(s) => self.line(path, s),
                Value::Data(b) => {
                    self.line(path, &format!("data[{} B]", b.len()));
                    if (b.starts_with(b"bplist00") || b.starts_with(b"<?xml"))
                        && b.len() <= TEXT_BUDGET
                        && let Ok(v) = wire::decode_plist(b)
                    {
                        self.value(path, &v, depth + 1);
                        return;
                    }
                    if b.starts_with(&[0x1f, 0x8b]) {
                        let mut decoded = Vec::new();
                        let result = flate2::read::GzDecoder::new(&b[..])
                            .take((TEXT_BUDGET + 1) as u64)
                            .read_to_end(&mut decoded);
                        if result.is_ok() && decoded.len() <= TEXT_BUDGET {
                            self.value(path, &Value::Data(decoded), depth + 1);
                            return;
                        }
                        self.line(
                            path,
                            "<gzip decode failed or exceeded limit; see saved plist>",
                        );
                    } else if let Ok(text) = std::str::from_utf8(b) {
                        self.line(path, text.trim_end_matches('\0'));
                    } else {
                        self.line(
                            path,
                            "<binary data; use diagnostic plist/transcript for original bytes>",
                        );
                    }
                }
                _ => self.line(path, &format!("{value:?}")),
            }
        }
    }
    let mut render = Render {
        bytes: 0,
        lines: 0,
        omitted: false,
        level,
        output: &mut output,
    };
    render.value(name, value, 0);
    if render.omitted {
        (render.output)(Record::new(
            Level::Warning,
            "diagnostics",
            format!(
                "{name}: diagnostic text limit reached; original data requires a saved plist/transcript (CLI: --transcript)"
            ),
        ));
    }
}

/// Read available logs from an already running restore service, without firmware.
pub fn collect_logs(ecid: u64, output: &Path) -> Result<()> {
    std::fs::create_dir(output).context("creating a new diagnostic directory")?;
    let mut diagnostics = Diagnostics {
        directory: Some(output.into()),
        ..Diagnostics::new(None)
    };
    diagnostics.host();
    diagnostics.capture(
        "target",
        &wire::dict([("ECID", format!("{ecid:016x}").into())]),
        Level::Debug,
    );
    let (_session, mut main, _) =
        connection::wait_restored_ecid(ecid, None, Duration::from_secs(10))
            .inspect_err(|error| diagnostics.failure(error, None))?;
    let result = diagnostics.query(&mut main, &mut None);
    if let Err(error) = &result {
        diagnostics.failure(error, None);
    }
    result
}

#[cfg(test)]
#[path = "../../tests/unit/restore/diagnostics.rs"]
mod tests;
