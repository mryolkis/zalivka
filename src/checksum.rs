//! Digest selection shared by archive, component and download verification.
use sha2::{Digest, Sha256, Sha384, digest::DynDigest};

/// A hasher for the digest length advertised by Apple metadata.
///
/// SHA-1 remains necessary for catalog entries and archive digests; SHA-256 and
/// SHA-384 cover IMG4 components and newer manifests. Any other size is
/// unsupported rather than silently ignored.
pub(crate) fn hasher(length: usize) -> Option<Box<dyn DynDigest>> {
    match length {
        20 => Some(Box::new(sha1::Sha1::new())),
        32 => Some(Box::new(Sha256::new())),
        48 => Some(Box::new(Sha384::new())),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_standard_digest_lengths_get_a_hasher() {
        for length in [20, 32, 48] {
            assert!(hasher(length).is_some(), "{length}");
        }
        for length in [0, 16, 31, 64] {
            assert!(hasher(length).is_none(), "{length}");
        }
    }
}
