// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

// runtime/unit_tests/boot.rs — Boot-time validation and self-test runner
//
// QR encoder/rqrr decoder round-trip (V1-V6) and BIP85 test vector.

extern crate alloc;

use crate::services::unit_tests::hardware::{HardwareTest, run_all_tests};

/// Decode QR from grayscale image using rqrr. Returns Option<(data, len)>.
#[inline(never)]
fn rqrr_test_decode(img: &[u8], w: usize, h: usize) -> Option<alloc::vec::Vec<u8>> {
    // rqrr's prepared image contains a large fixed LRU cache. Keep that verbose
    // boot-test fixture off the ProCpu stack; production decoding has its own
    // independently gated memory path.
    let mut prepared = alloc::boxed::Box::new(
        rqrr::PreparedImage::prepare_from_greyscale(w, h, |x, y| img[y * w + x]),
    );
    let grids = prepared.detect_grids();
    for grid in grids {
        let mut out = alloc::vec::Vec::new();
        if grid.decode_to(&mut out).is_ok() {
            return Some(out);
        }
    }
    None
}

#[cfg(not(feature = "skip-tests"))]
/// Run all boot-time validation tests. Keep this out-of-line so a later runtime
/// arithmetic trap cannot be misattributed to an inlined boot diagnostic.
#[inline(never)]
pub fn run_boot_tests() -> bool {
    let mut all_passed = true;

    let signing_vector_ok = offline_signer::crypto::schnorr::bip340_known_answer(
        &offline_signer::crypto::schnorr::BIP340_VECTOR0_EXPECTED,
    );
    log!(
        "   BIP-340 published signing vector: {}",
        if signing_vector_ok { "OK" } else { "FAIL" }
    );
    all_passed &= signing_vector_ok;
    {
        // Test payloads sized to fit each version (ECC Level L byte capacity)
        // V1: 17 max, V2: 32, V3: 53, V4: 78, V5: 106, V6: 134
        let test_payloads: [&[u8]; 6] = [
            b"KasSigner",                                    // V1: 9 bytes (cap 17)
            b"kaspa:qz0123456789abcdef01",                   // V2: 26 bytes (cap 32)
            b"kaspa:qz0123456789abcdef0123456789abcdef01234", // V3: 45 bytes (cap 53)
            b"kaspa:qz0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef012", // V4: 75 bytes (cap 78)
            b"kaspa:qz0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01", // V5: 106 bytes (cap 106)
            b"kaspa:qz0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abc", // V6: 133 bytes (cap 134)
        ];

        let mut qr_ok = 0u32;
        let mut qr_total = 0u32;
        let mut test_img = alloc::vec![128u8; 160 * 120];

        for (vi, payload) in test_payloads.iter().enumerate() {
            let ver = vi + 1;
            qr_total = qr_total.saturating_add(1);

            if let Ok(qr) = crate::qr::encoder::encode(payload) {
                let qr_size = qr.size as usize;
                // Pick scale to fit in 160x120 with quiet zone
                let scale = if qr_size + 2 <= 27 { 4 }     // V1-V2: scale 4
                            else { 2 };                       // V3-V6: scale 2
                let total_px = (qr_size + 2) * scale;

                if total_px <= 120 {
                    // Clear image
                    for p in test_img.iter_mut() { *p = 128; }
                    let ox = (160 - total_px) / 2;
                    let oy = (120 - total_px) / 2;
                    // Draw quiet zone (white)
                    for dy in 0..total_px {
                        for dx in 0..total_px { test_img[(oy+dy)*160+(ox+dx)] = 220; }
                    }
                    // Draw QR modules
                    for my in 0..qr_size {
                        for mx in 0..qr_size {
                            if qr.get(mx as u8, my as u8) {
                                let px = ox + (mx+1)*scale;
                                let py = oy + (my+1)*scale;
                                for dy in 0..scale { for dx in 0..scale {
                                    if (py+dy) < 120 && (px+dx) < 160 {
                                        test_img[(py+dy)*160+(px+dx)] = 20;
                                    }
                                }}
                            }
                        }
                    }
                    match rqrr_test_decode(&test_img, 160, 120) {
                        Some(decoded) if decoded.len() == payload.len() && decoded[..] == **payload => {
                            qr_ok = qr_ok.saturating_add(1);
                            log!("   V{} ({} bytes, {}x{}, scale {}): OK", ver, payload.len(), qr_size, qr_size, scale);
                        }
                        Some(decoded) => {
                            log!("   V{} ({} bytes): WRONG len={}", ver, payload.len(), decoded.len());
                        }
                        None => {
                            log!("   V{} ({} bytes, {}x{}, scale {}): FAIL (no decode)", ver, payload.len(), qr_size, qr_size, scale);
                        }
                    }
                } else {
                    log!("   V{}: image too small for scale={} total_px={}", ver, scale, total_px);
                }
            } else {
                log!("   V{}: encode failed for {} bytes", ver, payload.len());
            }
        }
        drop(test_img);
        log!("   QR V1-V6 round-trip (rqrr): {}/{}", qr_ok, qr_total);

        // Also test at camera decode resolution (240x180) with realistic scale
        {
            let mut camera_ok = 0u32;
            let mut camera_total = 0u32;
            let mut big_img = alloc::vec![128u8; 240 * 180];
            let cam_tests: [(&[u8], usize); 3] = [
                (b"kaspa:qz0123456789abcdef0123456789abcdef01234", 3),  // V3 scale 3
                (b"kaspa:qz0123456789abcdef0123456789abcdef01234", 4),  // V3 scale 4
                (b"kaspa:qz0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef012", 3), // V4 scale 3
            ];
            for &(payload, scale) in &cam_tests {
                camera_total = camera_total.saturating_add(1);
                if let Ok(qr) = crate::qr::encoder::encode(payload) {
                    let qr_size = qr.size as usize;
                    let total_px = (qr_size + 2) * scale;
                    if total_px > 240 || total_px > 180 { continue; }
                    for p in big_img.iter_mut() { *p = 128; }
                    let ox = (240 - total_px) / 2;
                    let oy = (180 - total_px) / 2;
                    for dy in 0..total_px {
                        for dx in 0..total_px { big_img[(oy+dy)*240+(ox+dx)] = 220; }
                    }
                    for my in 0..qr_size {
                        for mx in 0..qr_size {
                            if qr.get(mx as u8, my as u8) {
                                let px = ox + (mx+1)*scale;
                                let py = oy + (my+1)*scale;
                                for dy in 0..scale { for dx in 0..scale {
                                    if (py+dy) < 180 && (px+dx) < 240 {
                                        big_img[(py+dy)*240+(px+dx)] = 20;
                                    }
                                }}
                            }
                        }
                    }
                    match rqrr_test_decode(&big_img, 240, 180) {
                        Some(decoded) if decoded.len() == payload.len() => {
                            camera_ok = camera_ok.saturating_add(1);
                            log!("   240x180 {}x{} s{}: OK", qr_size, qr_size, scale);
                        }
                        None => { log!("   240x180 {}x{} s{}: FAIL (no decode)", qr_size, qr_size, scale); }
                        _ => { log!("   240x180 {}x{} s{}: WRONG", qr_size, qr_size, scale); }
                    }
                }
            }
            drop(big_img);
            if camera_ok != camera_total {
                all_passed = false;
                log!("   WARNING: Camera-resolution QR tests: {}/{} passed", camera_ok, camera_total);
            }
        }
        if qr_ok < qr_total {
            all_passed = false;
            log!("   WARNING: Not all QR versions pass round-trip!");
        }
    }

    // ── BIP85 child mnemonic derivation test ──
    {
        let bip85_ok = offline_signer::derivation::bip85::unit_tests::test_bip85_12word_index0();
        all_passed &= bip85_ok;
        log!("   BIP85 test vector: {}", if bip85_ok { "OK" } else { "FAIL" });
    }

    all_passed
}

/// Run startup self-tests (crypto, BIP39, QR encoder, etc.)
pub fn run_startup_tests(delay: &mut esp_hal::delay::Delay) -> bool {
    log!("Startup Self-Tests");
    log!("─────────────────────────");

    let test_results = run_all_tests();
    let all_passed = test_results.all_passed();

    if !all_passed {
        log!();
        log!("CRITICAL: Hardware tests failed!");
        log!("   SRAM:   {}", if test_results.passed(HardwareTest::Sram) { "OK" } else { "FAIL" });
        log!("   PSRAM:  {}", if test_results.passed(HardwareTest::Psram) { "OK" } else { "FAIL" });
        log!("   Argon2/PSRAM: {}", if test_results.passed(HardwareTest::Argon2Psram) { "OK" } else { "FAIL" });
        log!("   Flash:  {}", if test_results.passed(HardwareTest::Flash) { "OK" } else { "FAIL" });
        log!("   SHA256: {}", if test_results.passed(HardwareTest::Sha256) { "OK" } else { "FAIL" });
        log!("   Cannot continue safely.");
        #[cfg(feature = "hardware-tests")]
        log!("KASSIGNER_HARDWARE_TESTS: FAIL");
        // Permanent halt — do not boot with defective hardware.
        loop {
            delay.delay_millis(1000);
        }
    }

    log!();

    #[cfg(all(feature = "verbose-boot", not(feature = "skip-tests")))]
    let all_passed = super::software::run(all_passed);

    #[cfg(feature = "boot-kats-full")]
    {
        let full_passed = run_boot_tests();
        log!("[boot-kats-full] expanded software/QR KATs: {}", if full_passed { "PASS" } else { "FAIL" });
        if !(all_passed && full_passed) { log!("[boot-kats-full] FAIL; wallet routing disabled"); }
        crate::halt_forever(delay);
    }

    #[cfg(not(feature = "boot-kats-full"))]
    all_passed
}


#[cfg(feature = "hardware-tests")]
/// Emit the machine-readable result consumed by the host runner, then halt.
pub(crate) fn report_hardware_test_result(
    delay: &mut esp_hal::delay::Delay,
    startup_tests_ok: bool,
    boot_tests_ok: bool,
    signing_tests_ok: bool,
) -> ! {
    log!(
        "   HIL result components: startup={} boot={} signing={}",
        if startup_tests_ok { "OK" } else { "FAIL" },
        if boot_tests_ok { "OK" } else { "FAIL" },
        if signing_tests_ok { "OK" } else { "FAIL" },
    );
    let all_passed = startup_tests_ok && boot_tests_ok && signing_tests_ok;
    log!(
        "KASSIGNER_HARDWARE_TESTS: {}",
        if all_passed { "PASS" } else { "FAIL" }
    );
    loop {
        delay.delay_millis(1000);
    }
}

/// Signing pipeline self-test — M5Stack only (called at boot)
#[cfg(all(feature = "m5stack", feature = "hardware-tests"))]
pub fn test_signing_pipeline(ad: &mut crate::runtime::data::AppData) -> bool {
    use crate::runtime::signing::{derive_active_seed_with_checkpoint, populate_active_pubkeys_with_checkpoint, sign_and_serialize_multi};

    log!("[SIGN-TEST] Starting signing pipeline test...");

    let mut checkpoint = || {};
    if let Err(message) = populate_active_pubkeys_with_checkpoint(ad, &mut checkpoint) {
        log!("[SIGN-TEST] FAIL: {}", message);
        return false;
    }

    let pk = ad.wallet.addresses.pubkey_cache[0];
    if pk == [0u8; 32] {
        log!("[SIGN-TEST] FAIL: pubkey derivation returned zeros");
        return false;
    }
    log!("[SIGN-TEST] Derived pubkey[0]: {:02x}{:02x}{:02x}{:02x}...",
        pk[0], pk[1], pk[2], pk[3]);

    let mut tx = alloc::boxed::Box::new(offline_signer::transaction::model::Transaction::try_new().expect("transaction test allocation"));
    tx.version = 0;
    tx.network = offline_signer::address::KaspaNetwork::Mainnet;
    tx.num_inputs = 1;
    tx.num_outputs = 1;

    tx.inputs[0].previous_outpoint.transaction_id = [0xDE; 32];
    tx.inputs[0].previous_outpoint.index = 0;
    tx.inputs[0].utxo_entry.amount = 100_000_000;
    tx.inputs[0].sequence = u64::MAX;
    tx.inputs[0].sig_op_count = 1;

    tx.inputs[0].utxo_entry.script_public_key.version = 0;
    tx.inputs[0].utxo_entry.script_public_key.script[0] = 0x20;
    tx.inputs[0].utxo_entry.script_public_key.script[1..33].copy_from_slice(&pk);
    tx.inputs[0].utxo_entry.script_public_key.script[33] = 0xAC;
    tx.inputs[0].utxo_entry.script_public_key.script_len = 34;

    tx.outputs[0].value = 99_000_000;
    tx.outputs[0].script_public_key.version = 0;
    tx.outputs[0].script_public_key.script[0] = 0x20;
    tx.outputs[0].script_public_key.script[1..33].copy_from_slice(&pk);
    tx.outputs[0].script_public_key.script[33] = 0xAC;
    tx.outputs[0].script_public_key.script_len = 34;

    let Ok(seed) = derive_active_seed_with_checkpoint(ad, &mut checkpoint) else {
        log!("[SIGN-TEST] FAIL: active wallet is not a mnemonic");
        return false;
    };
    let mut signed_buf = [0u8; 1024];
    let signed_len = match sign_and_serialize_multi(&mut tx, &seed.bytes, &mut signed_buf) {
        Ok(length) => length,
        Err(error) => {
            log!("[SIGN-TEST] FAIL: signing/serialization error: {:?}", error);
            return false;
        }
    };

    log!("[SIGN-TEST] Signed response: {} bytes", signed_len);
    if signed_len == 0 {
        log!("[SIGN-TEST] FAIL: signing/serialization produced an empty response");
        return false;
    }

    if tx.inputs[0].sig_count > 0 {
        log!("[SIGN-TEST] OK — {} signature(s), response {} bytes",
            tx.inputs[0].sig_count, signed_len);
        true
    } else {
        log!("[SIGN-TEST] FAIL: no signature on input[0]");
        false
    }
}

/// M5Stack: signing pipeline self-test at boot
#[cfg(all(feature = "m5stack", feature = "hardware-tests"))]
pub(crate) fn run_signing_pipeline_test(ad: &mut crate::runtime::data::AppData) -> bool {
    let test_words = ["girl", "mad", "pet", "galaxy", "egg", "matter",
                      "matrix", "prison", "refuse", "sense", "ordinary", "nose"];
    for (i, word) in test_words.iter().enumerate() {
        ad.wallet.seeds.mnemonic_indices[i] = offline_signer::derivation::bip39::word_to_index(word).unwrap_or(0);
    }
    ad.wallet.seeds.word_count = 12;
    let Some(slot_index) = ad.wallet.seeds.seed_mgr.store(
        &ad.wallet.seeds.mnemonic_indices,
        12,
        b"",
        0,
    ) else {
        log!("   Signing pipeline test: FAIL (slot storage)");
        return false;
    };
    let mut checkpoint = || {};
    if crate::services::wallet_session::activate_slot_with_cache(
        ad,
        slot_index,
        &mut checkpoint,
    )
    .is_err()
    {
        log!("   Signing pipeline test: FAIL (activation)");
        return false;
    }

    // Signing pipeline test — M5Stack only.
    // On waveshare, k256 Schnorr signing overflows the default stack (~16KB needed).
    // The signing itself works fine at runtime (called from handler context with larger stack).
    let ok = test_signing_pipeline(ad);
    log!("   Signing pipeline test: {}", if ok { "OK" } else { "FAIL" });
    ad.wallet.seeds.seed_mgr.delete(slot_index);
    crate::services::wallet_session::clear_active_wallet(ad);
    ok
}
