//! IM4M measurements. Reading these does not authenticate Apple's signature.
use super::{Der, parse};
use anyhow::{Context, Result, ensure};
use asn1_rs::{Class, FromDer, ToDer};
use std::collections::BTreeMap;

pub struct Manifest<'a> {
    objects: BTreeMap<[u8; 4], BTreeMap<[u8; 4], Der<'a>>>,
}

fn properties(mut bytes: &[u8]) -> Result<BTreeMap<[u8; 4], Der<'_>>> {
    let mut fields = BTreeMap::new();
    while !bytes.is_empty() {
        let (rest, property) = asn1_rs::Any::from_der(bytes)
            .map_err(|error| anyhow::anyhow!("invalid IM4M property: {error}"))?;
        ensure!(
            property.class() == Class::Private && property.header.constructed(),
            "invalid IM4M private property"
        );
        let mut header = Vec::new();
        property.header.write_der_header(&mut header)?;
        ensure!(bytes.starts_with(&header), "noncanonical IM4M property");
        let name = property.tag().0.to_be_bytes();
        let (sequence, trailing) = parse(property.data)?;
        ensure!(
            sequence.tag == 0x30 && trailing.is_empty(),
            "invalid IM4M property sequence"
        );
        let (key, value) = parse(sequence.content)?;
        ensure!(
            key.tag == 0x16 && key.content == name,
            "IM4M property name mismatch"
        );
        let (value, trailing) = parse(value)?;
        ensure!(trailing.is_empty(), "trailing IM4M property data");
        ensure!(
            fields.insert(name, value).is_none(),
            "duplicate IM4M property {}",
            String::from_utf8_lossy(&name)
        );
        bytes = rest;
    }
    Ok(fields)
}

impl<'a> Manifest<'a> {
    pub fn check_hardware(&self, expected: &plist::Value) -> Result<()> {
        for (field, tag) in [
            ("ApChipID", b"CHIP"),
            ("ApBoardID", b"BORD"),
            ("ApSecurityDomain", b"SDOM"),
            ("ApECID", b"ECID"),
        ] {
            if let Some(value) = crate::wire::optional(expected, &[field])? {
                let value = crate::wire::number(value)?;
                ensure!(
                    self.number(tag)? == Some(value),
                    "IM4M {field} mismatch or missing property"
                );
            }
        }
        Ok(())
    }

    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        let (sequence, trailing) = parse(bytes)?;
        ensure!(
            sequence.tag == 0x30 && trailing.is_empty(),
            "invalid IM4M sequence"
        );
        let (magic, rest) = parse(sequence.content)?;
        ensure!(
            magic.tag == 0x16 && magic.content == b"IM4M",
            "ticket is not IM4M"
        );
        let (version, rest) = parse(rest)?;
        ensure!(
            version.tag == 0x02 && version.content == [0],
            "unsupported IM4M version"
        );
        let (body, mut rest) = parse(rest)?;
        ensure!(body.tag == 0x31, "invalid IM4M body");
        // Signature and certificates are optional for measurement fixtures. If
        // present, their envelopes must be well formed; authentication is separate.
        for tag in [0x04, 0x30] {
            if rest.is_empty() {
                break;
            }
            let (field, trailing) = parse(rest)?;
            ensure!(
                field.tag == tag,
                "invalid IM4M signature or certificate envelope"
            );
            rest = trailing;
        }
        ensure!(rest.is_empty(), "trailing IM4M fields");
        let mut body = properties(body.content)?;
        let body = body.remove(b"MANB").context("IM4M has no MANB")?;
        ensure!(body.tag == 0x31, "invalid IM4M MANB");
        let mut objects = BTreeMap::new();
        for (name, value) in properties(body.content)? {
            ensure!(value.tag == 0x31, "invalid IM4M object");
            objects.insert(
                name,
                properties(value.content)
                    .with_context(|| format!("parsing IM4M {}", String::from_utf8_lossy(&name)))?,
            );
        }
        Ok(Self { objects })
    }

    pub fn data(&self, object: &[u8; 4], key: &[u8; 4]) -> Result<Option<&'a [u8]>> {
        self.objects
            .get(object)
            .and_then(|fields| fields.get(key))
            .map(|value| {
                ensure!(value.tag == 0x04, "IM4M property is not data");
                Ok(value.content)
            })
            .transpose()
    }

    pub fn number(&self, key: &[u8; 4]) -> Result<Option<u64>> {
        self.objects
            .get(b"MANP")
            .and_then(|fields| fields.get(key))
            .map(|value| {
                ensure!(
                    value.tag == 0x02 && !value.content.is_empty() && value.content[0] & 0x80 == 0,
                    "invalid IM4M integer"
                );
                ensure!(
                    value.content.len() == 1
                        || value.content[0] != 0
                        || value.content[1] & 0x80 != 0,
                    "noncanonical IM4M integer"
                );
                value.content.iter().try_fold(0u64, |n, byte| {
                    n.checked_mul(256)
                        .and_then(|n| n.checked_add(u64::from(*byte)))
                        .context("IM4M integer overflow")
                })
            })
            .transpose()
    }

    pub fn digests(&self) -> Result<BTreeMap<[u8; 4], &'a [u8]>> {
        let mut digests = BTreeMap::new();
        for name in self.objects.keys().filter(|name| *name != b"MANP") {
            if let Some(digest) = self
                .data(name, b"DGST")
                .with_context(|| format!("checking IM4M {} DGST", String::from_utf8_lossy(name)))?
            {
                ensure!(
                    [20, 32, 48].contains(&digest.len()),
                    "unsupported IM4M DGST size for {}",
                    String::from_utf8_lossy(name)
                );
                digests.insert(*name, digest);
            }
        }
        Ok(digests)
    }
}
