//! One record format for terminal output, GUI workers and saved journals.
use serde::{Deserialize, Serialize};
use std::{
    cell::Cell,
    fmt::{self, Write as _},
    io::{self, Write},
    marker::PhantomData,
    rc::Rc,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicU8, AtomicU64, AtomicUsize, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};

static STARTED: OnceLock<Instant> = OnceLock::new();
static MIN_LEVEL: AtomicU8 = AtomicU8::new(Level::Info as u8);
static BACKGROUND: OnceLock<Queue> = OnceLock::new();
thread_local! {
    static FIRMWARE_TRANSFER: Cell<bool> = const { Cell::new(false) };
}
#[cfg(windows)]
pub use crate::platform::logging::connect_elevated;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum Level {
    Trace,
    Debug,
    Info,
    Warning,
    Error,
}

impl Level {
    pub fn label(self) -> &'static str {
        match self {
            Self::Trace => "TRACE",
            Self::Debug => "DEBUG",
            Self::Info => "INFO",
            Self::Warning => "WARN",
            Self::Error => "ERROR",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub elapsed_ms: u64,
    pub level: Level,
    pub source: String,
    pub message: String,
}

impl Record {
    pub fn new(level: Level, source: impl Into<String>, message: impl fmt::Display) -> Self {
        let mut record = Self {
            elapsed_ms: elapsed_ms(),
            level,
            source: source.into(),
            message: message.to_string(),
        };
        record.normalize();
        record
    }

    #[cfg(any(windows, test))]
    pub(crate) fn parse_json(line: &str) -> io::Result<Self> {
        let mut record: Self = serde_json::from_str(line).map_err(io::Error::other)?;
        record.normalize();
        Ok(record)
    }

    #[cfg(any(windows, test))]
    pub(crate) fn write_json(&self, mut output: impl Write) -> io::Result<()> {
        serde_json::to_writer(&mut output, self).map_err(io::Error::other)?;
        output.write_all(b"\n")
    }

    pub fn normalize(&mut self) {
        // External diagnostics must stay on one row and cannot inject terminal controls.
        fn clean(text: &mut String) {
            if text.trim().len() == text.len()
                && !text.chars().any(|ch| ch.is_control() || ch == '\u{00b7}')
            {
                return;
            }
            let mut result = String::new();
            for ch in text.chars() {
                match ch {
                    '\n' => result.push_str(" / "),
                    '\r' | '\t' => result.push(' '),
                    '\u{00b7}' => result.push(','),
                    ch if ch.is_control() => {
                        let _ = write!(result, "\\u{{{:x}}}", ch as u32);
                    }
                    ch => result.push(ch),
                }
            }
            *text = result.trim().to_owned();
        }
        clean(&mut self.source);
        clean(&mut self.message);
    }

    pub fn write_to(&self, mut output: impl Write) -> io::Result<()> {
        writeln!(output, "{self}")
    }
}

impl fmt::Display for Record {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let seconds = self.elapsed_ms / 1000;
        write!(
            f,
            "{:02}:{:02}:{:02}.{:03} {:5} {:12} {}",
            seconds / 3600,
            seconds / 60 % 60,
            seconds % 60,
            self.elapsed_ms % 1000,
            self.level.label(),
            self.source,
            self.message
        )
    }
}

pub fn init(level: Level) {
    STARTED.get_or_init(Instant::now);
    MIN_LEVEL.store(level as u8, Ordering::Relaxed);
}

/// Monotonic timestamp captured by producers, before asynchronous delivery.
pub fn elapsed_ms() -> u64 {
    STARTED.get_or_init(Instant::now).elapsed().as_millis() as u64
}

enum Pending {
    Record(Record),
    Flush(mpsc::Sender<()>),
}

/// Buffer records within a bounded byte budget and report diagnostic overload.
#[derive(Clone)]
pub(crate) struct Queue {
    sender: mpsc::Sender<(Pending, usize)>,
    budget: Arc<Budget>,
}

const MAX_QUEUED_BYTES: usize = 16 * 1024 * 1024;

#[derive(Default)]
struct Budget {
    bytes: AtomicUsize,
    omitted: AtomicU64,
}

impl Queue {
    // None requests a buffered sink flush, including while the producer is idle.
    pub(crate) fn new(mut output: impl FnMut(Option<Record>) + Send + 'static) -> io::Result<Self> {
        let (tx, rx) = mpsc::channel();
        let budget = Arc::new(Budget::default());
        let consumer_budget = budget.clone();
        std::thread::Builder::new()
            .name("zalivka-journal".into())
            .spawn(move || {
                let mut dirty = false;
                let mut flushed = Instant::now();
                loop {
                    let incoming = rx.recv_timeout(Duration::from_millis(200));
                    let omitted = consumer_budget.omitted.swap(0, Ordering::AcqRel);
                    if omitted != 0 {
                        output(Some(Record::new(
                            Level::Warning,
                            "journal",
                            format_args!("Queue full; omitted {omitted} DEBUG/TRACE records"),
                        )));
                        dirty = true;
                    }
                    let pending = match incoming {
                        Ok(pending) => Some(pending),
                        Err(mpsc::RecvTimeoutError::Disconnected) => {
                            output(None);
                            return;
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => None,
                    };
                    if let Some((pending, cost)) = pending {
                        dirty = true;
                        match pending {
                            Pending::Record(record) => output(Some(record)),
                            Pending::Flush(done) => {
                                output(None);
                                dirty = false;
                                flushed = Instant::now();
                                let _ = done.send(());
                            }
                        }
                        consumer_budget.bytes.fetch_sub(cost, Ordering::AcqRel);
                    }
                    if dirty && flushed.elapsed() >= Duration::from_millis(200) {
                        output(None);
                        dirty = false;
                        flushed = Instant::now();
                    }
                }
            })?;
        Ok(Self { sender: tx, budget })
    }

    fn reserve(&self, cost: usize) -> bool {
        self.budget
            .bytes
            .try_update(Ordering::AcqRel, Ordering::Acquire, |bytes| {
                bytes
                    .checked_add(cost)
                    .filter(|next| *next <= MAX_QUEUED_BYTES)
            })
            .is_ok()
    }

    fn enqueue(&self, pending: Pending, cost: usize) -> Result<(), Pending> {
        self.sender.send((pending, cost)).map_err(|error| {
            self.budget.bytes.fetch_sub(cost, Ordering::AcqRel);
            error.0.0
        })
    }

    pub(crate) fn record(&self, record: Record) -> Result<(), Record> {
        let cost = 128 + record.source.len() + record.message.len();
        if !self.reserve(cost) {
            if record.level <= Level::Debug {
                self.budget.omitted.fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }
            // Preserve important messages with synchronous delivery under overload.
            return Err(record);
        }
        self.enqueue(Pending::Record(record), cost)
            .map_err(|pending| {
                let Pending::Record(record) = pending else {
                    unreachable!()
                };
                record
            })
    }

    pub(crate) fn flush(&self) -> io::Result<()> {
        let (tx, rx) = mpsc::channel();
        self.sender
            .send((Pending::Flush(tx), 0))
            .map_err(|_| io::Error::other("journal thread stopped"))?;
        rx.recv()
            .map_err(|_| io::Error::other("journal thread stopped"))
    }
}

pub struct FlushGuard;

impl Drop for FlushGuard {
    fn drop(&mut self) {
        if let Some(queue) = BACKGROUND.get() {
            let _ = queue.flush();
        }
    }
}

/// Buffer CLI diagnostics off the transport threads and drain them before exit.
pub fn background() -> io::Result<FlushGuard> {
    if BACKGROUND.get().is_none() {
        let mut stderr = io::BufWriter::with_capacity(256 * 1024, io::stderr());
        let queue = Queue::new(move |record| match record {
            Some(record) => write_default(record, &mut stderr),
            None => {
                let _ = stderr.flush();
            }
        })?;
        let _ = BACKGROUND.set(queue);
    }
    Ok(FlushGuard)
}

pub fn enabled(level: Level) -> bool {
    if level == Level::Trace && firmware_transfer_active() {
        return false;
    }
    level as u8 >= MIN_LEVEL.load(Ordering::Relaxed) || crate::progress::active()
}

pub(crate) fn firmware_transfer_active() -> bool {
    FIRMWARE_TRANSFER.with(Cell::get)
}

/// Suppress per-packet traces and payload formatting on this transfer thread.
/// FDR and other concurrent services keep their own complete diagnostics.
pub(crate) fn firmware_transfer() -> FirmwareTransfer {
    FirmwareTransfer {
        previous: FIRMWARE_TRANSFER.with(|active| active.replace(true)),
        thread: PhantomData,
    }
}

pub(crate) struct FirmwareTransfer {
    previous: bool,
    thread: PhantomData<Rc<()>>,
}

impl Drop for FirmwareTransfer {
    fn drop(&mut self) {
        FIRMWARE_TRANSFER.with(|active| active.set(self.previous));
    }
}

pub fn emit(level: Level, source: &str, message: fmt::Arguments<'_>) {
    if enabled(level) {
        publish(Record::new(level, source, message));
    }
}

pub(crate) fn plist(source: &'static str, context: &'static str, value: &plist::Value) {
    if !enabled(Level::Trace) {
        return;
    }
    emit(
        Level::Trace,
        source,
        format_args!("{context}: {}", plist_summary(value)),
    );
}

/// Keep protocol identifiers visible without expanding payloads or nested collections.
fn plist_summary(value: &plist::Value) -> String {
    fn text(value: &str, limit: usize) -> String {
        match value.char_indices().nth(limit) {
            Some((end, _)) => format!("{:?}… ({} B)", &value[..end], value.len()),
            None => format!("{value:?}"),
        }
    }

    fn field(value: &plist::Value) -> String {
        match value {
            plist::Value::Data(bytes) => format!("data[{} B]", bytes.len()),
            plist::Value::String(value) => text(value, 96),
            plist::Value::Array(values) => format!("array[{}]", values.len()),
            plist::Value::Dictionary(values) => format!("dict[{}]", values.len()),
            plist::Value::Boolean(value) => value.to_string(),
            plist::Value::Integer(value) => value.to_string(),
            plist::Value::Real(value) => value.to_string(),
            plist::Value::Date(value) => value.to_xml_format(),
            plist::Value::Uid(value) => format!("UID({})", value.get()),
            _ => "unknown".into(),
        }
    }

    let plist::Value::Dictionary(values) = value else {
        return field(value);
    };
    const IDENTIFIERS: &[&str] = &["MsgType", "Request", "DataType", "Status", "Error", "Log"];
    let identifiers = IDENTIFIERS
        .iter()
        .copied()
        .filter_map(|key| values.get(key).map(|value| (key, value)));
    let other_fields = values
        .iter()
        .filter(|(key, _)| !IDENTIFIERS.contains(&key.as_str()))
        .map(|(key, value)| (key.as_str(), value));
    let mut fields: Vec<_> = identifiers
        .chain(other_fields)
        .take(8)
        .map(|(key, value)| format!("{}={}", text(key, 48), field(value)))
        .collect();
    if values.len() > fields.len() {
        fields.push(format!("+{} fields", values.len() - fields.len()));
    }
    format!("{{{}}}", fields.join(", "))
}

pub fn publish(record: Record) {
    if !enabled(record.level) {
        return;
    }
    let record = match crate::progress::log(record) {
        Ok(()) => return,
        Err(record) => record,
    };
    let record = match BACKGROUND.get() {
        Some(queue) => match queue.record(record) {
            Ok(()) => return,
            Err(record) => record,
        },
        None => record,
    };
    write_default(record, io::stderr().lock());
}

fn write_default(record: Record, mut stderr: impl Write) {
    #[cfg(windows)]
    if crate::platform::logging::write_elevated(&record) {
        return;
    }
    let _ = record.write_to(&mut stderr);
}

#[macro_export]
macro_rules! log {
    ($level:ident, $source:literal, $($args:tt)*) => {
        if $crate::logging::enabled($crate::logging::Level::$level) {
            $crate::logging::emit($crate::logging::Level::$level, $source, format_args!($($args)*))
        }
    };
}

#[cfg(test)]
#[path = "../tests/unit/logging.rs"]
mod tests;
