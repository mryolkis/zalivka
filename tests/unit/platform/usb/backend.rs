use super::*;

#[test]
fn output_buffers_reuse_capacity_without_sending_stale_bytes() {
    let mut buffer = Buffer::new(32768);
    buffer.extend_from_slice(&[0xaa; 32768]);
    let pointer = buffer.as_ptr();
    for data in [&[1, 2, 3][..], &[][..], &[4, 5][..]] {
        buffer = fill_buffer(Some(buffer), data, |_| panic!("must reuse capacity"));
        assert_eq!(&*buffer, data);
        assert_eq!(buffer.as_ptr(), pointer);
    }
}

#[test]
fn output_buffers_grow_for_larger_packets_and_accept_a_zero_length_first_write() {
    let buffer = fill_buffer(Some(Buffer::new(1)), &[42; 512], Buffer::new);
    assert_eq!(&*buffer, &[42; 512]);
    let buffer = fill_buffer(None, &[], Buffer::new);
    assert!(buffer.is_empty());
}
