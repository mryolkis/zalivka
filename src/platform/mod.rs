//! Host operating-system integration: USB, drivers, proxy policy and desktop services.
//!
//! Protocols and application logic use the public modules in the crate root;
//! native APIs and platform selection belong here.
mod desktop;
pub(crate) mod drivers;
mod localization;
pub(crate) mod logging;
mod paths;
pub(crate) mod proxy;
pub(crate) mod tls;
pub(crate) mod usb;

#[cfg(target_os = "linux")]
pub(crate) mod linux;
#[cfg(any(target_os = "macos", test))]
pub mod macos;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) mod unix;
#[cfg(windows)]
#[allow(unsafe_code)]
pub(crate) mod windows;

pub use desktop::{attach_parent_console, open_directory, system_font};
pub(crate) use localization::system_languages;
pub use paths::{app_directory, config_directory};
