//! Preferred UI languages reported by the host.
#[cfg(windows)]
#[allow(unsafe_code)]
pub(crate) fn system_languages() -> Vec<String> {
    use windows_sys::Win32::Globalization::{GetUserPreferredUILanguages, MUI_LANGUAGE_NAME};
    let mut count = 0;
    let mut size = 0;
    if unsafe {
        GetUserPreferredUILanguages(
            MUI_LANGUAGE_NAME,
            &mut count,
            std::ptr::null_mut(),
            &mut size,
        )
    } == 0
        || !(1..=65536).contains(&size)
    {
        return Vec::new();
    }
    let mut buffer = vec![0; size as usize];
    if unsafe {
        GetUserPreferredUILanguages(
            MUI_LANGUAGE_NAME,
            &mut count,
            buffer.as_mut_ptr(),
            &mut size,
        )
    } == 0
    {
        return Vec::new();
    }
    buffer
        .split(|unit| *unit == 0)
        .filter(|name| !name.is_empty())
        .map(String::from_utf16_lossy)
        .collect()
}

#[cfg(not(windows))]
pub(crate) fn system_languages() -> Vec<String> {
    for name in ["LC_ALL", "LC_MESSAGES", "LANGUAGE", "LANG"] {
        if let Ok(value) = std::env::var(name)
            && !value.trim().is_empty()
        {
            return value.split(':').map(String::from).collect();
        }
    }
    Vec::new()
}
