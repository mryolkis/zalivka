//! Apply background events and finish jobs only after their logs are drained.
use super::theme::Tone;
use super::worker::Output;
use super::{App, Event, Notice, Picker, SCAN_INTERVAL, UI_REFRESH_INTERVAL, journal};
use eframe::egui;
use std::time::Instant;
use zalivka::progress;

const MAX_EVENTS: usize = 256;

impl App {
    pub(super) fn collect_job_logs(&mut self) -> bool {
        if let Some(job) = &mut self.job {
            let Some((lines, error)) = job.pending_logs() else {
                return false;
            };
            if !lines.is_empty() {
                job.last_activity = Instant::now();
            }
            for line in lines {
                self.journal_line(line);
            }
            self.journal_error(error.as_deref());
        }
        true
    }

    pub(super) fn poll(&mut self, ctx: &egui::Context) {
        // Leave time for rendering and input even during a burst of log records.
        for index in 0..MAX_EVENTS {
            let Ok(event) = self.rx.try_recv() else { break };
            // This frame already displays the events it consumes. Schedule
            // another only when a full batch may have left queued events.
            if index == MAX_EVENTS - 1 {
                ctx.request_repaint_after(UI_REFRESH_INTERVAL);
            }
            self.apply_event(event, ctx);
        }
        self.finish_job();
    }

    fn apply_event(&mut self, event: Event, ctx: &egui::Context) {
        match event {
            Event::Host(host) => {
                self.checking_host = false;
                self.host = host;
            }
            Event::Scan { devices } => self.apply_scan(devices),
            Event::Firmware(request, release) => self.apply_firmware(request, release),
            Event::Worker(id, output) => {
                let Some(job) = &mut self.job else { return };
                if job.id != id {
                    return;
                }
                if matches!(&output, Output::State(progress::Event::RebootRequired)) {
                    self.windows_reboot_required = true;
                }
                job.output(output);
            }
            Event::Picked(picker, path) => {
                self.picking = false;
                let Some(path) = path else { return };
                match picker {
                    Picker::Firmware => {
                        self.setup.ipsw = path.display().to_string();
                        self.setup.automatic = false;
                    }
                    Picker::Cache => self.setup.cache = path.display().to_string(),
                    Picker::Tokens => self.setup.tokens = path.display().to_string(),
                    Picker::Connect => self.setup.connect_data = path.display().to_string(),
                    Picker::Log => self.save_journal(path, ctx),
                }
            }
            Event::Saved(Ok(path)) => {
                self.notice = Some(Notice {
                    title: "Journal saved".into(),
                    detail: path.display().to_string(),
                    journal_error: None,
                    tone: Tone::Success,
                    expires_at: Some(Instant::now() + super::NOTICE_LIFETIME),
                });
            }
            Event::Saved(Err(error)) => self.error("Journal not saved", error),
        }
    }

    fn apply_scan(
        &mut self,
        devices: std::result::Result<Vec<zalivka::device::DeviceInfo>, String>,
    ) {
        self.scanning = false;
        match devices {
            Ok(devices) => {
                if self.setup.ecid.is_empty() && devices.len() == 1 {
                    self.setup.ecid = format!("{:016x}", devices[0].ecid);
                }
                self.devices = devices;
                self.scan_error = None;
            }
            Err(error) => {
                self.devices.clear();
                self.scan_error = Some(error);
            }
        }
        if self
            .firmware
            .as_ref()
            .is_some_and(|firmware| self.target().is_none_or(|device| !firmware.matches(device)))
        {
            self.firmware = None;
        }
    }

    fn apply_firmware(
        &mut self,
        request: u64,
        release: std::result::Result<zalivka::catalog::Release, String>,
    ) {
        let Some(firmware) = &self.firmware else {
            return;
        };
        if firmware.request != request {
            return;
        }
        if self.target().is_some_and(|device| firmware.matches(device)) {
            self.firmware.as_mut().expect("firmware present").release = Some(release);
        } else {
            self.firmware = None;
        }
    }

    fn save_journal(&mut self, path: std::path::PathBuf, ctx: &egui::Context) {
        self.collect_job_logs();
        let source = self.log_path.clone();
        let journal = self.job.as_ref().map(|job| job.journal.clone());
        let logs = self.job.as_ref().map(|job| job.context.clone());
        let text = if source.is_none() {
            format!(
                "Incomplete journal: saved the last {} records from memory.\n{}\n",
                self.logs.len(),
                self.journal_text(true)
            )
        } else {
            String::new()
        };
        let spawn = self.background(ctx, "save", move || {
            if let Some(logs) = logs
                && let Err(error) = logs.flush_logs()
            {
                return Event::Saved(Err(error.to_string()));
            }
            let result = journal::save_log(path, source.as_deref(), &text, journal.as_deref())
                .map_err(|error| format!("{error:#}"));
            Event::Saved(result)
        });
        if let Err(error) = spawn {
            self.error("Journal not saved", error);
        }
    }

    /// Take the finished job only after its last in-memory records were drained.
    fn finish_job(&mut self) {
        if !self.collect_job_logs() {
            return;
        }
        if self.job.as_ref().is_none_or(|job| job.completion.is_none()) {
            return;
        }
        let job = self.job.take().expect("finished job");
        let completion = job.completion.as_ref().expect("completion present");
        self.windows_reboot_required |= completion.reboot_required;
        self.journal_error(completion.journal_error.as_deref());
        let notice = completion.notice(job.action);
        if notice.tone == Tone::Error {
            self.journal_open = true;
        }
        self.notice = Some(notice);
        self.last_scan = Instant::now() - SCAN_INTERVAL;
    }
}
