// SPDX-License-Identifier: Apache-2.0
// Adapted from macvdmtool (Asahi Linux Contributors, 2021) and
// ThunderboltPatcher (osy86, 2019). See licenses/macvdmtool-APACHE-2.0.txt.
//! Small AppleHPMLib ABI binding. All native handles stay on the helper thread.
use super::protocol::{self, Controller};
use anyhow::{Context, Result, ensure};
use core_foundation::{
    base::{CFType, CFTypeRef, TCFType},
    dictionary::CFMutableDictionaryRef,
    number::CFNumber,
    string::{CFString, CFStringRef},
    uuid::{CFUUID, CFUUIDBytes, CFUUIDCreateFromUUIDBytes, CFUUIDGetUUIDBytes, CFUUIDRef},
};
use std::{
    ffi::{CStr, c_char, c_void},
    ptr,
};

#[link(name = "IOKit", kind = "framework")]
unsafe extern "C" {
    fn IOServiceMatching(name: *const c_char) -> CFMutableDictionaryRef;
    fn IOServiceGetMatchingServices(
        port: u32,
        matching: CFMutableDictionaryRef,
        iterator: *mut u32,
    ) -> i32;
    fn IOServiceGetMatchingService(port: u32, matching: CFMutableDictionaryRef) -> u32;
    fn IOIteratorNext(iterator: u32) -> u32;
    fn IOObjectRelease(object: u32) -> i32;
    fn IORegistryEntryGetName(entry: u32, name: *mut c_char) -> i32;
    fn IORegistryEntryCreateCFProperty(
        entry: u32,
        key: CFStringRef,
        allocator: *const c_void,
        options: u32,
    ) -> CFTypeRef;
    fn IOCreatePlugInInterfaceForService(
        service: u32,
        plugin_type: CFUUIDRef,
        interface_type: CFUUIDRef,
        plugin: *mut *mut *mut Unknown,
        score: *mut i32,
    ) -> i32;
    fn IODestroyPlugInInterface(plugin: *mut *mut Unknown) -> i32;
}

unsafe extern "C" {
    fn geteuid() -> u32;
}

pub(super) fn is_root() -> bool {
    unsafe { geteuid() == 0 }
}

struct Object(u32);
impl Drop for Object {
    fn drop(&mut self) {
        unsafe {
            if self.0 != 0 {
                IOObjectRelease(self.0);
            }
        }
    }
}

#[repr(C)]
struct Unknown {
    reserved: *mut c_void,
    query: unsafe extern "C" fn(*mut c_void, CFUUIDBytes, *mut *mut c_void) -> i32,
    add_ref: unsafe extern "C" fn(*mut c_void) -> u32,
    release: unsafe extern "C" fn(*mut c_void) -> u32,
}

#[repr(C)]
struct HpmInterface {
    base: Unknown,
    version: u16,
    revision: u16,
    read: unsafe extern "C" fn(*mut c_void, u64, u8, *mut c_void, u64, u32, *mut u64) -> i32,
    write: unsafe extern "C" fn(*mut c_void, u64, u8, *const c_void, u64, u32) -> i32,
    command: unsafe extern "C" fn(*mut c_void, u64, u32, u32) -> i32,
}

struct Hpm {
    plugin: *mut *mut Unknown,
    device: *mut *mut HpmInterface,
}

fn uuid(bytes: [u8; 16]) -> CFUUID {
    // CFUUIDBytes is a repr(C) structure containing exactly sixteen u8 fields.
    let bytes: CFUUIDBytes = unsafe { std::mem::transmute(bytes) };
    unsafe { CFUUID::wrap_under_create_rule(CFUUIDCreateFromUUIDBytes(ptr::null(), bytes)) }
}

fn status(code: i32, operation: &str) -> Result<()> {
    ensure!(code == 0, "{operation}: IOKit error {:#010x}", code as u32);
    Ok(())
}

impl Hpm {
    fn open(service: u32) -> Result<Self> {
        let kind = uuid([
            0x12, 0xa1, 0xdc, 0xcf, 0xcf, 0x7a, 0x47, 0x75, 0xbe, 0xe5, 0x9c, 0x43, 0x19, 0xf4,
            0xcd, 0x2b,
        ]);
        let plugin_id = uuid([
            0xc2, 0x44, 0xe8, 0x58, 0x10, 0x9c, 0x11, 0xd4, 0x91, 0xd4, 0x00, 0x50, 0xe4, 0xc6,
            0x42, 0x6f,
        ]);
        let mut hpm = Self {
            plugin: ptr::null_mut(),
            device: ptr::null_mut(),
        };
        let mut score = 0;
        status(
            unsafe {
                IOCreatePlugInInterfaceForService(
                    service,
                    kind.as_concrete_TypeRef(),
                    plugin_id.as_concrete_TypeRef(),
                    &mut hpm.plugin,
                    &mut score,
                )
            },
            "opening Apple USB-C controller",
        )?;
        ensure!(
            !hpm.plugin.is_null() && !unsafe { *hpm.plugin }.is_null(),
            "Apple USB-C plugin is unavailable"
        );
        let interface = uuid([
            0xc1, 0x3a, 0xcd, 0xd9, 0x20, 0x9e, 0x4b, 0x01, 0xb7, 0xbe, 0xe0, 0x5c, 0xd8, 0x83,
            0xc7, 0xb1,
        ]);
        status(
            unsafe {
                ((**hpm.plugin).query)(
                    hpm.plugin.cast(),
                    CFUUIDGetUUIDBytes(interface.as_concrete_TypeRef()),
                    ptr::addr_of_mut!(hpm.device).cast(),
                )
            },
            "querying AppleHPMLib interface",
        )?;
        ensure!(
            !hpm.device.is_null() && !unsafe { *hpm.device }.is_null(),
            "AppleHPMLib returned an empty interface"
        );
        Ok(hpm)
    }
}

impl Drop for Hpm {
    fn drop(&mut self) {
        unsafe {
            if !self.device.is_null() && !(*self.device).is_null() {
                ((**self.device).base.release)(self.device.cast());
            }
            if !self.plugin.is_null() {
                IODestroyPlugInInterface(self.plugin);
            }
        }
    }
}

impl Controller for Hpm {
    fn read(&mut self, register: u8) -> Result<Vec<u8>> {
        let mut bytes = [0u8; 64];
        let mut length = 0;
        status(
            unsafe {
                ((**self.device).read)(
                    self.device.cast(),
                    0,
                    register,
                    bytes.as_mut_ptr().cast(),
                    bytes.len() as u64,
                    0,
                    &mut length,
                )
            },
            "reading Apple USB-C register",
        )?;
        ensure!(
            (1..=64).contains(&length),
            "invalid Apple USB-C register length {length}"
        );
        Ok(bytes[..length as usize].to_vec())
    }

    fn command(&mut self, command: [u8; 4], args: &[u8]) -> Result<u8> {
        if !args.is_empty() {
            status(
                unsafe {
                    ((**self.device).write)(
                        self.device.cast(),
                        0,
                        9,
                        args.as_ptr().cast(),
                        args.len() as u64,
                        0,
                    )
                },
                "writing Apple USB-C command arguments",
            )?;
        }
        status(
            unsafe {
                ((**self.device).command)(self.device.cast(), 0, u32::from_be_bytes(command), 0)
            },
            "executing Apple USB-C command",
        )?;
        Ok(self.read(9)?[0] & 0xf)
    }
}

fn unlock_key() -> Result<[u8; 4]> {
    let matching = unsafe { IOServiceMatching(c"IOPlatformExpertDevice".as_ptr()) };
    ensure!(!matching.is_null(), "matching the host Mac platform");
    // IOServiceGetMatchingService consumes the matching dictionary.
    let service = Object(unsafe { IOServiceGetMatchingService(0, matching) });
    ensure!(service.0 != 0, "host Mac platform is unavailable");
    let mut name = [0u8; 128];
    status(
        unsafe { IORegistryEntryGetName(service.0, name.as_mut_ptr().cast()) },
        "reading the host Mac model",
    )?;
    let model = CStr::from_bytes_until_nul(&name).context("invalid host Mac model name")?;
    ensure!(
        model.to_bytes().len() >= 4,
        "host Mac model name is too short"
    );
    crate::log!(Debug, "dfu", "Host model: {}", model.to_string_lossy());
    // macvdmtool forms a big-endian model word, then sends it little-endian.
    Ok([name[3], name[2], name[1], name[0]])
}

pub(super) fn enter_dfu() -> Result<()> {
    let key = unlock_key()?;
    let matching = unsafe { IOServiceMatching(c"AppleHPM".as_ptr()) };
    ensure!(!matching.is_null(), "matching Apple USB-C controllers");
    let mut iterator = 0;
    status(
        unsafe { IOServiceGetMatchingServices(0, matching, &mut iterator) },
        "enumerating Apple USB-C controllers",
    )?;
    let iterator = Object(iterator);
    let mut connected = Vec::new();
    loop {
        let service = Object(unsafe { IOIteratorNext(iterator.0) });
        if service.0 == 0 {
            break;
        }
        let key = CFString::new("RID");
        let value = unsafe {
            IORegistryEntryCreateCFProperty(service.0, key.as_concrete_TypeRef(), ptr::null(), 0)
        };
        if value.is_null() {
            continue;
        }
        let value = unsafe { CFType::wrap_under_create_rule(value) };
        if value.downcast::<CFNumber>().and_then(|n| n.to_i64()) != Some(0) {
            continue;
        }
        // RID=0 selects the host's DFU port, as in the reference macvdmtool.
        let mut hpm = Hpm::open(service.0)?;
        if hpm.read(0x3f)?.first().is_some_and(|state| state & 1 != 0) {
            connected.push(hpm);
        }
    }
    ensure!(
        connected.len() == 1,
        "Expected one connection on the host DFU port, found {}; connect only the target Mac directly through the two DFU ports",
        connected.len()
    );
    crate::log!(
        Info,
        "dfu",
        "Requesting DFU mode through the host USB-C controller"
    );
    protocol::enter_dfu(&mut connected[0], key)
}
