use super::*;
use sha2::{Digest, Sha256};

#[test]
fn dropping_a_partial_releases_its_lock_even_with_a_duplicate_handle() {
    let directory = tempfile::tempdir().unwrap();
    let part = directory.path().join("restore.ipsw.part");
    let expected = Sha256::digest(b"firmware payload");
    std::fs::write(&part, b"firmware").unwrap();
    let download = PartialDownload::open(&part, &expected).unwrap();
    // Model a descriptor inherited by another thread's subprocess.
    let duplicate = download.file.try_clone().unwrap();
    assert!(PartialDownload::open(&part, &expected).is_err());
    drop(download);

    let resumed = PartialDownload::open(&part, &expected).unwrap();
    assert_eq!(resumed.total, 8);
    assert!(!resumed.verified());
    assert_eq!(duplicate.metadata().unwrap().len(), 8);
}
