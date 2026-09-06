use super::{normalize_text_content, validate_text_file_size};

#[test]
fn accepts_complete_files_at_requested_capacities() {
    for size in [129usize, 256, 512, 1_024] {
        assert_eq!(validate_text_file_size(size, size), Ok(()));
    }
}

#[test]
fn rejects_files_larger_than_the_caller_buffer() {
    for (file_size, capacity) in [(130usize, 129usize), (257, 256), (513, 512), (1_025, 1_024)] {
        assert_eq!(
            validate_text_file_size(file_size, capacity),
            Err("Text file exceeds buffer"),
        );
    }
}

#[test]
fn normalization_happens_after_the_complete_read() {
    let mut content = [0u8; 16];
    content[..10].copy_from_slice(b"\xEF\xBB\xBFhello\r\n");
    let length = normalize_text_content(&mut content, 10).unwrap();
    assert_eq!(length, 5);
    assert_eq!(&content[..length], b"hello");
    assert!(content[length..10].iter().all(|byte| *byte == 0));
}

#[test]
fn normalization_rejects_empty_content() {
    let mut content = *b" \r\n\t\0\0\0\0";
    assert_eq!(normalize_text_content(&mut content, 4), Err("Empty content"));
}
