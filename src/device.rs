//! Identification metadata exposed by Apple's USB DFU and recovery transports.
use anyhow::{Context, Result, ensure};
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Dfu,
    PortDfu,
    Recovery,
}

impl Mode {
    pub fn from_pid(pid: u16) -> Option<Self> {
        match pid {
            0x1227 => Some(Self::Dfu),
            0xf014 => Some(Self::PortDfu),
            0x1280..=0x1283 => Some(Self::Recovery),
            _ => None,
        }
    }

    pub fn can_restore(self) -> bool {
        matches!(self, Self::Dfu | Self::PortDfu)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeviceInfo {
    pub ecid: u64,
    pub chip_id: u32,
    pub board_id: u32,
    pub security_domain: Option<u32>,
    pub iboot_flags: Option<u32>,
    pub chip_fuse_mode: Option<u32>,
    pub mode: Mode,
    pub serial: String,
    pub ap_nonce: Vec<u8>,
    pub sep_nonce: Vec<u8>,
}

impl DeviceInfo {
    /// Port DFU identifies the USB controller; its board word also encodes the
    /// SoC's CPID and BDID, which are the values firmware selection needs.
    pub fn hardware_ids(&self) -> (u32, u32) {
        match self.mode {
            Mode::PortDfu => ((self.board_id >> 8) & 0xffff, self.board_id >> 24),
            Mode::Dfu | Mode::Recovery => (self.chip_id, self.board_id),
        }
    }

    pub(crate) fn serial_hex(&self, name: &str) -> Result<u64> {
        parse_hex(
            serial_field(&self.serial, name)?
                .with_context(|| format!("USB serial has no {name}"))?,
        )
    }

    pub fn parse(serial: &str, mode: Mode) -> Result<Self> {
        let required =
            |name| serial_field(serial, name)?.with_context(|| format!("USB serial has no {name}"));
        let number = |name| {
            required(name)
                .and_then(parse_hex)
                .with_context(|| format!("invalid {name}"))
        };
        let optional = |name| {
            serial_field(serial, name)?
                .map(|value| parse_hex(value).with_context(|| format!("invalid {name}: {value}")))
                .transpose()
        };
        let ecid = number("ECID")?;
        ensure!(ecid != 0, "device returned zero ECID");
        Ok(Self {
            ecid,
            chip_id: u32::try_from(number("CPID")?)?,
            board_id: u32::try_from(number("BDID")?)?,
            security_domain: optional("SDOM")?.map(u32::try_from).transpose()?,
            iboot_flags: optional("IBFL")?.map(u32::try_from).transpose()?,
            chip_fuse_mode: optional("CPFM")?.map(u32::try_from).transpose()?,
            mode,
            serial: serial.to_owned(),
            ap_nonce: Vec::new(),
            sep_nonce: Vec::new(),
        })
    }

    /// Replace both nonces only after both values parsed successfully.
    pub fn set_nonces(&mut self, serial: &str) -> Result<()> {
        let nonce = |name| {
            serial_field(serial, name)?
                .map(decode_hex)
                .transpose()
                .map(Option::unwrap_or_default)
        };
        let (ap, sep) = (nonce("NONC")?, nonce("SNON")?);
        self.ap_nonce = ap;
        self.sep_nonce = sep;
        Ok(())
    }
}

/// One whitespace-separated `KEY:VALUE` field in a USB serial string.
fn serial_field<'a>(serial: &'a str, key: &str) -> Result<Option<&'a str>> {
    let mut matches = serial
        .split_ascii_whitespace()
        .filter_map(|token| token.split_once(':'))
        .filter(|(name, _)| *name == key)
        .map(|(_, value)| value);
    let value = matches.next();
    ensure!(matches.next().is_none(), "duplicate USB serial field {key}");
    Ok(value)
}

/// Unsigned hexadecimal, with an optional `0x` prefix and no surrounding space.
fn parse_hex(value: &str) -> Result<u64> {
    let digits = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    ensure!(
        !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "expected hexadecimal digits"
    );
    Ok(u64::from_str_radix(digits, 16)?)
}

pub fn decode_hex(s: &str) -> Result<Vec<u8>> {
    hex::decode(s).context("expected an even number of hexadecimal digits")
}

pub fn parse_ecid(s: &str) -> std::result::Result<u64, String> {
    let ecid = parse_hex(s).map_err(|error| error.to_string())?;
    if ecid == 0 {
        return Err("ECID must be nonzero".into());
    }
    Ok(ecid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_fields_accept_only_optional_prefix_and_digits() {
        for (text, value) in [("10", 0x10), ("0x10", 0x10), ("0Xff", 0xff)] {
            assert_eq!(parse_hex(text).unwrap(), value);
        }
        for text in ["", "0x", "+1", "-1", " 1", "1 ", "0x0x1", "gg"] {
            assert!(parse_hex(text).is_err(), "{text:?}");
        }
    }

    #[test]
    fn serial_fields_reject_duplicates_and_missing_identifiers() {
        assert!(DeviceInfo::parse("CPID:8103 BDID:0A ECID:12 ECID:13", Mode::Dfu).is_err());
        assert!(DeviceInfo::parse("CPID:8103 BDID:0A", Mode::Dfu).is_err());
        assert!(DeviceInfo::parse("CPID:8103 BDID:0A ECID:0", Mode::Dfu).is_err());
        assert!(DeviceInfo::parse("CPID:8103 BDID:0A ECID:12", Mode::Dfu).is_ok());
    }

    #[test]
    fn port_dfu_reports_soc_identity_inside_its_board_word() {
        let controller =
            DeviceInfo::parse("ECID:2a CPID:0022 BDID:22813200", Mode::PortDfu).unwrap();
        assert_eq!(controller.hardware_ids(), (0x8132, 0x22));
        assert_eq!(controller.serial_hex("ECID").unwrap(), 0x2a);
    }
}
