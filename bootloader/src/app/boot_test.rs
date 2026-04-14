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

// app/boot_test.rs — Boot-time validation and self-test runner
//
// QR encoder/rqrr decoder round-trip (V1-V6) and BIP85 test vector.

extern crate alloc;

use crate::log;
use crate::{qr::encoder, wallet, features::self_test, app::input, ui::pin_ui, ui::setup_wizard, ui::seed_manager};
use crate::features::self_test::run_all_tests;

/// Decode QR from grayscale image using rqrr. Returns Option<(data, len)>.
fn rqrr_test_decode(img: &[u8], w: usize, h: usize) -> Option<alloc::vec::Vec<u8>> {
    let mut prepared = rqrr::PreparedImage::prepare_from_greyscale(w, h, |x, y| {
        img[y * w + x]
    });
    let grids = prepared.detect_grids();
    for grid in grids {
        let mut out = alloc::vec::Vec::new();
        if grid.decode_to(&mut out).is_ok() {
            return Some(out);
        }
    }
    None
}

#[cfg(not(feature = "silent"))]
/// Run all boot-time validation tests.
pub fn run_boot_tests() {
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
            qr_total += 1;

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
                            qr_ok += 1;
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
            let mut big_img = alloc::vec![128u8; 240 * 180];
            let cam_tests: [(&[u8], usize); 3] = [
                (b"kaspa:qz0123456789abcdef0123456789abcdef01234", 3),  // V3 scale 3
                (b"kaspa:qz0123456789abcdef0123456789abcdef01234", 4),  // V3 scale 4
                (b"kaspa:qz0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef012", 3), // V4 scale 3
            ];
            for &(payload, scale) in &cam_tests {
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
                            log!("   240x180 {}x{} s{}: OK", qr_size, qr_size, scale);
                        }
                        None => { log!("   240x180 {}x{} s{}: FAIL (no decode)", qr_size, qr_size, scale); }
                        _ => { log!("   240x180 {}x{} s{}: WRONG", qr_size, qr_size, scale); }
                    }
                }
            }
            drop(big_img);
        }
        if qr_ok < qr_total {
            log!("   WARNING: Not all QR versions pass round-trip!");
        }
    }

    // ── BIP85 child mnemonic derivation test ──
    {
        let bip85_ok = wallet::bip85::test_bip85_12word_index0();
        log!("   BIP85 test vector: {}", if bip85_ok { "OK" } else { "FAIL" });
    }
}

/// Run Phase 1 self-tests (crypto, BIP39, QR encoder, etc.)
pub fn run_phase1_tests(delay: &mut esp_hal::delay::Delay) {
    log!("Phase 1: Self-Tests");
    log!("─────────────────────────");

    let test_results = run_all_tests();

    if !test_results.all_passed {
        log!();
        log!("CRITICAL: Hardware tests failed!");
        log!("   SRAM:   {}", if test_results.sram_ok { "OK" } else { "FAIL" });
        log!("   PSRAM:  {}", if test_results.psram_ok { "OK" } else { "FAIL" });
        log!("   Flash:  {}", if test_results.flash_ok { "OK" } else { "FAIL" });
        log!("   SHA256: {}", if test_results.sha256_ok { "OK" } else { "FAIL" });
        log!("   Cannot continue safely.");
        // Permanent halt — do not boot with defective hardware
        loop {
            delay.delay_millis(1000);
        }
    }

    log!();

    // ═══════════════════════════════════════════════════════════════
    // PHASE 1.5: BIP39 Self-Tests (verbose/dev mode only)
    // ═══════════════════════════════════════════════════════════════
    #[cfg(all(feature = "verbose-boot", not(feature = "skip-tests")))]
    {
        log!("Phase 1.5: BIP39 Self-Tests");
        log!("─────────────────────────────");

        let (passed, total) = wallet::bip39::run_bip39_tests();
        log!("   BIP39 tests: {}/{} passed", passed, total);

        if passed != total {
            log!("   CRITICAL: BIP39 implementation has failures!");
        } else {
            log!("   BIP39 module verified OK");
        }

        let (passed32, total32) = wallet::bip32::run_bip32_tests();
        log!("   BIP32 tests: {}/{} passed", passed32, total32);

        if passed32 != total32 {
            log!("   CRITICAL: BIP32 implementation has failures!");
        } else {
            log!("   BIP32 module verified OK");
        }

        let (passed_sc, total_sc) = wallet::schnorr::run_schnorr_tests();
        log!("   Schnorr tests: {}/{} passed", passed_sc, total_sc);

        if passed_sc != total_sc {
            log!("   CRITICAL: Schnorr implementation has failures!");
        } else {
            log!("   Schnorr module verified OK");
        }

        let (passed_st, total_st) = wallet::storage::run_storage_tests();
        log!("   Storage tests: {}/{} passed", passed_st, total_st);

        if passed_st != total_st {
            log!("   CRITICAL: Storage implementation has failures!");
        } else {
            log!("   Storage module verified OK");
        }

        let (passed_sh, total_sh) = wallet::sighash::run_sighash_tests();
        log!("   SigHash tests: {}/{} passed", passed_sh, total_sh);

        if passed_sh != total_sh {
            log!("   CRITICAL: SigHash implementation has failures!");
        } else {
            log!("   SigHash+Blake2b module verified OK");
        }

        let (passed_ps, total_ps) = wallet::pskt::run_pskt_tests();
        log!("   KSPT tests: {}/{} passed", passed_ps, total_ps);

        if passed_ps != total_ps {
            log!("   CRITICAL: KSPT implementation has failures!");
        } else {
            log!("   KSPT module verified OK");
        }
        log!();

        // QR Encoder tests
        let (passed_qr, total_qr) = crate::qr::encoder::run_tests();
        log!("   QR tests: {}/{} passed", passed_qr, total_qr);

        if passed_qr != total_qr {
            log!("   CRITICAL: QR encoder has failures!");
        } else {
            log!("   QR encoder verified OK");
        }

        // QR decoder: rqrr has no internal test suite — round-trip tests in run_boot_tests() cover this
        log!("   QR decoder: rqrr V1-V40 (round-trip tested at boot)");
        log!();

        // App Input / State Machine tests
        let (passed_app, total_app) = crate::app::input::run_tests();
        log!("   App tests: {}/{} passed", passed_app, total_app);

        if passed_app != total_app {
            log!("   CRITICAL: App state machine has failures!");
        } else {
            log!("   App state machine verified OK");
        }


        // PIN UI tests
        let (passed_pin, total_pin) = pin_ui::run_pin_tests();
        log!("   PIN tests: {}/{} passed", passed_pin, total_pin);
        if passed_pin != total_pin {
            log!("   CRITICAL: PIN UI has failures!");
        } else {
            log!("   PIN UI verified OK");
        }

        // Setup Wizard tests
        let (passed_setup, total_setup) = setup_wizard::run_setup_tests();
        log!("   Setup tests: {}/{} passed", passed_setup, total_setup);
        if passed_setup != total_setup {
            log!("   CRITICAL: Setup wizard has failures!");
        } else {
            log!("   Setup wizard verified OK");
        }

        // Seed Manager tests (SeedQR, fingerprint, slot management)
        let (passed_sm, total_sm) = seed_manager::run_seed_manager_tests();
        log!("   SeedManager tests: {}/{} passed", passed_sm, total_sm);
        if passed_sm != total_sm {
            log!("   CRITICAL: SeedManager has failures!");
        } else {
            log!("   SeedManager verified OK");
        }

        // Address encoding tests (verified against official rusty-kaspa vectors)
        let (passed_addr, total_addr) = wallet::address::run_address_tests();
        log!("   Address tests: {}/{} passed", passed_addr, total_addr);
        if passed_addr != total_addr {
            log!("   CRITICAL: Address encoding has failures!");
        } else {
            log!("   Address encoding verified OK (matches rusty-kaspa)");
        }

        // xpub / kpub tests
        let (passed_xpub, total_xpub) = wallet::xpub::run_xpub_tests();
        log!("   xpub tests: {}/{} passed", passed_xpub, total_xpub);
        if passed_xpub != total_xpub {
            log!("   CRITICAL: xpub/kpub encoding has failures!");
        } else {
            log!("   xpub/kpub encoding verified OK");
        }
        log!();
    }
}

/// Signing pipeline self-test — M5Stack only (called at boot)
#[cfg(feature = "m5stack")]
pub fn test_signing_pipeline(ad: &mut crate::app::data::AppData) -> bool {
    use crate::app::signing::{derive_all_pubkeys, sign_and_serialize_multi, derive_seed};
    use crate::wallet;

    log!("[SIGN-TEST] Starting signing pipeline test...");

    let pp = ad.seed_mgr.active_slot()
        .map(|s: &crate::ui::seed_manager::SeedSlot| s.passphrase_str())
        .unwrap_or("");
    let mut pubkey_cache = [[0u8; 32]; 20];
    let mut acct_key_raw = [0u8; 65];
    derive_all_pubkeys(&ad.mnemonic_indices, ad.word_count, pp, &mut pubkey_cache, &mut acct_key_raw);

    let pk = pubkey_cache[0];
    if pk == [0u8; 32] {
        log!("[SIGN-TEST] FAIL: pubkey derivation returned zeros");
        return false;
    }
    log!("[SIGN-TEST] Derived pubkey[0]: {:02x}{:02x}{:02x}{:02x}...",
        pk[0], pk[1], pk[2], pk[3]);

    let mut tx = wallet::transaction::Transaction::new();
    tx.version = 0;
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

    let seed = derive_seed(&ad.mnemonic_indices, ad.word_count, pp);
    let mut signed_buf = [0u8; 1024];
    let signed_len = sign_and_serialize_multi(&mut tx, &seed.bytes, &mut signed_buf);

    log!("[SIGN-TEST] Signed response: {} bytes", signed_len);
    if signed_len == 0 {
        log!("[SIGN-TEST] FAIL: signing produced 0 bytes");
        return false;
    }

    if tx.inputs[0].sig_len > 0 {
        log!("[SIGN-TEST] OK — signature {} bytes, response {} bytes",
            tx.inputs[0].sig_len, signed_len);
        true
    } else {
        log!("[SIGN-TEST] FAIL: no signature on input[0]");
        false
    }
}
