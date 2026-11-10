use super::*;
use std::io::Cursor;

#[test]
fn available_storage_accepts_directories_and_files_and_checks_required_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let file = tempfile::NamedTempFile::new_in(directory.path()).unwrap();
    assert!(available(directory.path()).unwrap() > 0);
    assert!(available(file.path()).unwrap() > 0);
    require(directory.path(), 0).unwrap();
    assert!(require(directory.path(), u64::MAX).is_err());
    assert!(available(&directory.path().join("missing")).is_err());
}

#[test]
fn bounded_reads_check_the_extra_byte_and_accept_the_full_u64_limit() {
    let bytes = b"metadata";
    for limit in [0, 7, 8, u64::MAX] {
        let mut input = Cursor::new(bytes);
        let result = read_limited(&mut input, limit, "metadata too large");
        if limit < bytes.len() as u64 {
            assert_eq!(result.unwrap_err().to_string(), "metadata too large");
            assert_eq!(input.position(), limit + 1);
        } else {
            assert_eq!(result.unwrap(), bytes);
            assert_eq!(input.position(), bytes.len() as u64);
        }
    }
    assert!(read_limited(&b""[..], 0, "empty").unwrap().is_empty());
}
