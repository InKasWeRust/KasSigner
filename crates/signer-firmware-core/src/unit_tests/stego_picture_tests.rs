use crate::backup::stego_picture::{capacity_bits, extract};

#[test]
fn malformed_and_truncated_picture_inputs_fail_without_panicking() {
    let key = b"stego-picture-property";
    let mut output = [0u8; 256];
    let corpus: [&[u8]; 8] = [
        b"",
        b"\xff",
        b"\xff\xd8",
        b"\xff\xd8\xff\xd9",
        b"not-a-jpeg",
        b"\xff\xd8\xff\xda\x00\x00",
        b"\xff\xd8\xff\xc0\xff\xff",
        b"\xff\xd8\xff\xc4\xff\xff",
    ];
    for input in corpus {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = capacity_bits(input, key);
            let _ = extract(input, key, &mut output);
        }));
        assert!(
            result.is_ok(),
            "stego parser panicked for malformed corpus input"
        );
    }
}

#[test]
fn deterministic_external_input_sweep_is_panic_free() {
    let key = b"stego-picture-sweep";
    let mut data = [0u8; 512];
    let mut output = [0u8; 256];
    let mut state = 0x6d2b_79f5u32;
    for length in 0..=data.len() {
        for byte in data.iter_mut().take(length) {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            *byte = state as u8;
        }
        let input = &data[..length];
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = capacity_bits(input, key);
            let _ = extract(input, key, &mut output);
        }));
        assert!(
            result.is_ok(),
            "stego parser panicked at deterministic length {length}"
        );
    }
}
