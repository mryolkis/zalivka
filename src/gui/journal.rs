//! Buffered disk journal and bounded GUI history for one operation.
use super::{Level, Record};
use std::{
    collections::VecDeque,
    fs::File,
    io::{BufWriter, Write},
};

pub(super) struct Journal {
    pub(super) log: BufWriter<File>,
    started_ms: u64,
    error: Option<String>,
    pending: VecDeque<Record>,
}

impl Journal {
    pub(super) fn new(log: File) -> Self {
        Self {
            log: BufWriter::with_capacity(256 * 1024, log),
            started_ms: zalivka::logging::elapsed_ms(),
            error: None,
            pending: VecDeque::new(),
        }
    }

    /// Return whether new records need to wake a sleeping GUI.
    pub(super) fn record(&mut self, mut record: Record) -> bool {
        record.elapsed_ms = record.elapsed_ms.saturating_sub(self.started_ms);
        record.normalize();
        if self.error.is_none()
            && let Err(error) = record.write_to(&mut self.log)
        {
            self.error = Some(error.to_string());
            record
                .message
                .push_str(&format!(" / Disk journal incomplete: {error}"));
            record.level = record.level.max(Level::Warning);
        }
        let wake = self.pending.is_empty();
        self.pending.push_back(record);
        super::trim_logs(&mut self.pending);
        wake
    }

    /// Record the first flush failure once, retaining all later records in memory.
    pub(super) fn flush(&mut self) -> bool {
        if self.error.is_none()
            && let Err(error) = self.log.flush()
        {
            self.error = Some(error.to_string());
            self.record(Record::new(
                Level::Warning,
                "journal",
                format!("Disk journal incomplete: {error}"),
            ));
            return true;
        }
        false
    }

    pub(super) fn error(&self) -> Option<&String> {
        self.error.as_ref()
    }

    pub(super) fn drain(&mut self) -> (Vec<Record>, Option<String>) {
        (self.pending.drain(..).collect(), self.error.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_and_flush_failures_report_once_and_keep_later_memory_records() {
        for capacity in [1, 256 * 1024] {
            let file = tempfile::NamedTempFile::new().unwrap();
            let mut journal = Journal::new(File::open(file.path()).unwrap());
            journal.log = BufWriter::with_capacity(capacity, File::open(file.path()).unwrap());
            journal.record(Record::new(Level::Debug, "test", "original record"));
            journal.flush();
            assert!(journal.error().is_some());
            for _ in 0..2 {
                journal.record(Record::new(Level::Error, "test", "later error"));
                assert!(!journal.flush());
            }
            let (records, error) = journal.drain();
            assert!(error.is_some());
            assert_eq!(
                records
                    .iter()
                    .filter(|record| record.message.contains("Disk journal incomplete"))
                    .count(),
                1
            );
            assert_eq!(records.iter().filter(|record| record.level == Level::Error && record.message == "later error").count(), 2);
            assert!(records[0].message.starts_with("original record"));
            assert!(std::fs::read(file.path()).unwrap().is_empty());
            assert!(journal.drain().0.is_empty());
            assert!(journal.error().is_some());
        }
    }

    #[test]
    fn trace_history_is_bounded_while_the_disk_journal_remains_complete() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut journal = Journal::new(file.reopen().unwrap());
        journal.record(Record::new(Level::Info, "restore", "Starting stage"));
        for index in 0..8000 {
            journal.record(Record::new(Level::Trace, "fdr:conn", index));
        }
        assert!(!journal.flush());
        assert_eq!(journal.pending.len(), 4000);
        assert_eq!(journal.pending.front().unwrap().level, Level::Info);
        assert_eq!(
            std::fs::read_to_string(file.path())
                .unwrap()
                .lines()
                .count(),
            8001
        );
    }
}
