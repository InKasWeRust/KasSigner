use super::{derive_legacy_32, derive_legacy_32_progress};

#[cfg(test)]
mod host_vectors {
    use alloc::vec::Vec;

    use super::super::hmac_sha256;
    use super::{derive_legacy_32, derive_legacy_32_progress};

    fn decode_32(hex_text: &str) -> [u8; 32] {
        assert_eq!(hex_text.len(), 64, "32-byte known-answer hex");
        let mut out = [0u8; 32];
        for (index, pair) in hex_text.as_bytes().chunks_exact(2).enumerate() {
            out[index] = (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]);
        }
        out
    }

    fn hex_nibble(value: u8) -> u8 {
        match value {
            b'0'..=b'9' => value - b'0',
            b'a'..=b'f' => value - b'a' + 10,
            b'A'..=b'F' => value - b'A' + 10,
            _ => panic!("invalid known-answer hex"),
        }
    }

    #[test]
    fn hmac_sha256_matches_rfc4231_short_block_and_long_key_vectors() {
        assert_eq!(
            hmac_sha256(&[0x0b; 20], b"Hi There"),
            decode_32("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
        );
        assert_eq!(
            hmac_sha256(b"Jefe", b"what do ya want for nothing?"),
            decode_32("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
        );
        let boundary_key = core::array::from_fn::<_, 64, _>(|index| index as u8);
        assert_eq!(
            hmac_sha256(&boundary_key, b"boundary"),
            decode_32("04660fc313657aa3500078e1f2788cc4e328654092b137f946516e4d7a17adae"),
        );
        assert_eq!(
            hmac_sha256(
                &[0xaa; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First",
            ),
            decode_32("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"),
        );
    }

    #[test]
    fn derive_legacy_32_matches_iteration_boundary_vectors() {
        assert_eq!(
            derive_legacy_32(b"password", b"salt", 1),
            decode_32("120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"),
        );
        assert_eq!(
            derive_legacy_32(b"password", b"salt", 2),
            decode_32("ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"),
        );

        let mut progress = Vec::new();
        let derived = derive_legacy_32_progress(b"password", b"salt", 21, &mut |current, total| {
            progress.push((current, total));
        });
        assert_eq!(derived, derive_legacy_32(b"password", b"salt", 21));
        assert_eq!(progress.first(), Some(&(1, 21)));
        assert_eq!(progress.last(), Some(&(20, 21)));
        assert_eq!(progress.len(), 20);
    }

    #[test]
    fn long_salt_truncation_and_progress_threshold_are_covered() {
        let salt_124 = [0x5au8; 124];
        let salt_160 = [0x5au8; 160];
        // Legacy readers intentionally cap the PBKDF2 salt contribution at 124
        // bytes so the four-byte block counter still fits the fixed buffer.
        assert_eq!(
            derive_legacy_32(b"password", &salt_124, 2),
            derive_legacy_32(b"password", &salt_160, 2),
        );

        let mut below_threshold_calls = 0u32;
        let below = derive_legacy_32_progress(b"password", b"salt", 19, &mut |_, _| {
            below_threshold_calls += 1;
        });
        assert_eq!(below_threshold_calls, 0);
        assert_eq!(below, derive_legacy_32(b"password", b"salt", 19));

        let mut threshold_calls = 0u32;
        let at_threshold = derive_legacy_32_progress(b"password", b"salt", 20, &mut |_, _| {
            threshold_calls += 1;
        });
        assert_eq!(threshold_calls, 19);
        assert_eq!(at_threshold, derive_legacy_32(b"password", b"salt", 20));
    }
}

/// Run the deterministic PBKDF2 tests used by host and firmware boot tests.
pub fn run_legacy_pbkdf2_tests() -> (u32, u32) {
    let mut passed = 0u32;
    let total = 3u32;

    let first = derive_legacy_32(b"password", b"salt", 100);
    let second = derive_legacy_32(b"password", b"salt", 100);
    if first == second && first != derive_legacy_32(b"different", b"salt", 100) {
        passed += 1;
    }

    if first != derive_legacy_32(b"password", b"other", 100) {
        passed += 1;
    }

    let mut progress_calls = 0u32;
    let derived = derive_legacy_32_progress(b"password", b"salt", 100, &mut |current, total| {
        if current > 0 && current < total {
            progress_calls += 1;
        }
    });
    if derived == first && progress_calls > 0 {
        passed += 1;
    }

    (passed, total)
}

#[test]
fn legacy_pbkdf2_vectors_pass() {
    let (passed, total) = run_legacy_pbkdf2_tests();
    assert_eq!(passed, total);
}
