use super::{ecc::gf::gf_mul, encode, matrix::version::select_version};

// Self-tests
// ═══════════════════════════════════════════════════════════════════

/// Run QR encoder self-tests. Returns (passed, total).
pub fn run_tests() -> (u32, u32) {
    let mut passed = 0u32;
    let total = 4u32;

    // Test 1: Version selection
    {
        if select_version(17) == Ok(1)
            && select_version(32) == Ok(2)
            && select_version(72) == Ok(4)
            && select_version(200).is_err()
        {
            passed += 1;
        }
    }

    // Test 2: GF(256) multiplication sanity
    {
        // gf_mul(2, 2) = 4 (no reduction)
        // gf_mul(0, anything) = 0
        // gf_mul(1, x) = x
        let ok = gf_mul(0, 42) == 0
            && gf_mul(1, 42) == 42
            && gf_mul(2, 2) == 4
            && gf_mul(2, 128) != 0; // should trigger reduction
        if ok {
            passed += 1;
        }
    }

    // Test 3: Encode small data, verify QR dimensions
    {
        let data = b"KSSN"; // 4 bytes -> V1 (21x21)
        if let Ok(qr) = encode(data) {
            if qr.size == 21 && qr.version == 1 {
                // Verify finder pattern top-left corner
                // Module (0,0) should be dark (finder pattern)
                if qr.get(0, 0) && qr.get(6, 0) && qr.get(0, 6) {
                    passed += 1;
                }
            }
        }
    }

    // Test 4: Encode 72 bytes (typical KSSN response), verify V4
    {
        let mut data = [0u8; 72];
        // Simulate KSSN header
        data[0] = b'K';
        data[1] = b'S';
        data[2] = b'S';
        data[3] = b'N';
        data[4] = 0x01; // version
        data[5] = 0x01; // 1 signature
        // Fill rest with test pattern
        for i in 6..72 {
            data[i] = (i & 0xFF) as u8;
        }

        if let Ok(qr) = encode(&data) {
            if qr.size == 33 && qr.version == 4 {
                // Basic structure check: finders should be present
                let tl = qr.get(0, 0) && qr.get(6, 0) && qr.get(0, 6);
                let tr = qr.get(32, 0) && qr.get(26, 0) && qr.get(32, 6);
                let bl = qr.get(0, 32) && qr.get(6, 32) && qr.get(0, 26);
                if tl && tr && bl {
                    passed += 1;
                }
            }
        }
    }

    (passed, total)
}

#[test]
fn qr_encoder_vectors_pass() {
    let (passed, total) = run_tests();
    assert_eq!(passed, total);
}
