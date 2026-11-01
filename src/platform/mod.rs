//! Host operating-system integration: USB, drivers, proxy policy and desktop services.
//!
//! Protocols and application logic use the public modules in the crate root;
//! native APIs and platform selection belong here.
#[cfg(feature = "gui")]
mod desktop;
pub(crate) mod drivers;
mod localization;
#[cfg(windows)]
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

#[cfg(feature = "gui")]
pub use desktop::open_directory;
#[cfg(all(windows, feature = "gui"))]
pub use desktop::{attach_parent_console, system_font};
pub(crate) use localization::system_languages;
pub use paths::{app_directory, config_directory};
