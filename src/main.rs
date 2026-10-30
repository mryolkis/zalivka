#![cfg_attr(all(windows, feature = "gui"), windows_subsystem = "windows")]

mod cli;
#[cfg(feature = "gui")]
mod gui;

use std::process::ExitCode;

fn main() -> ExitCode {
    zalivka::logging::init(zalivka::logging::Level::Trace);
    if let Some(code) = elevated_helper() {
        std::process::exit(code as i32);
    }
    let _logs = match zalivka::logging::background() {
        Ok(logs) => logs,
        Err(error) => {
            zalivka::log!(Error, "journal", "Starting journal thread: {error}");
            return ExitCode::FAILURE;
        }
    };
    match cli::run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            zalivka::log!(Error, "app", "{error:#}");
            ExitCode::FAILURE
        }
    }
}

/// The private UAC helper exits before CLI parsing; `drivers` handles the code.
#[cfg(windows)]
fn elevated_helper() -> Option<u32> {
    zalivka::drivers::run_elevated_helper()
}

#[cfg(not(windows))]
fn elevated_helper() -> Option<u32> {
    None
}
