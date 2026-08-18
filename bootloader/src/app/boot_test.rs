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
use crate::{qr::encoder, wallet, features::self_test, app::input, ui::setup_wizard, ui::seed_manager};
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

    // Crypto known-answer tests, called from here so main.rs needs no change.
    // run_boot_tests is gated on `skip-tests` only, never on `silent`, so
    // these run in every build including production (P-09 closed).
    #[cfg(not(feature = "skip-tests"))]
    run_crypto_kats();
}

/// Cryptographic known-answer tests. Runs on every boot, on every target.
///
/// A KAT feeds a primitive a fixed input whose correct output is published and
/// independently verified, then checks the primitive reproduces it exactly.
/// Crypto needs this because it has no natural failure signal: a subtly wrong
/// BIP32 derivation still yields a valid 32-byte key, deriving a valid address
/// that renders correctly and accepts funds nobody can ever spend. Nothing
/// crashes and nothing logs. So a failure here HALTS rather than warns, the
/// same way run_phase1_tests halts on a hardware fault.
///
/// Gating: `skip-tests` only. Deliberately not `verbose-boot`, which also turns
/// on the sighash debug dump and must never ship, and deliberately not `silent`,
/// because a logging flag must not be able to disable a correctness check.
/// Note `production` implies `silent`, so anything behind `silent` is absent
/// from exactly the builds that most need these to run.
///
/// STACK BUDGET. Every test reached from here shares main's ProCpu frame, and
/// the usable stack is whatever RWDATA leaves: measured 104,272 bytes on
/// M5Stack, 2026-08-14, and it FALLS as static data grows. `stack_probe`
/// reports the live figure at boot; trust that over any number written here.
///
/// `size_of::<Transaction>()` is 78,952 bytes, so a transaction built as a
/// stack local very nearly fills that budget on its own and two of them exceed
/// it outright. This comment used to say that the sighash and pskt tests must
/// stay in the verbose-boot block "until Transaction gains a heap-allocating
/// constructor". That constructor is `Transaction::new_boxed`
/// (transaction.rs:480), and as of 2026-08-14 all eight test sites use it, so
/// the condition has been met and the restriction lifted.
///
/// What the old wording missed is that the restriction was never holding: the
/// verbose-boot block runs on this same frame, so those tests were already
/// over budget there and had been failing to run at all. See N-15.
///
/// The rule that remains: no test reached from here may build a Transaction,
/// or anything else of that order, as a stack local.
// Gated to match its call site in main.rs. Without this the body still
// references run_bip39_tests / run_storage_tests, which skip-tests configures
/// Entropy health check. Two independent collections must differ, and neither
/// may be degenerate.
///
/// This exists because of the July 2026 COLDCARD disclosure. Mk2/Mk3 firmware
/// bound `ngu.random` to MicroPython's deterministic Yasmarang fallback instead
/// of the STM32 hardware RNG, because libngu tested whether a macro was DEFINED
/// rather than whether it was ENABLED. Wallet seeds were derived from MCU UID
/// and timer registers for five years and nothing at runtime noticed. A quorum
/// of researchers found it only after roughly 594 BTC was swept.
///
/// KasSigner is not vulnerable to that specific bug: TRM 25.4 requires the SAR
/// ADC, the high-speed ADC, or RC_FAST_CLK to be enabled or "pseudo-random
/// numbers will be returned", and crypto::entropy enables both RC_FAST_CLK and
/// the SAR ADC before sampling. This check is here so that if that ever stops
/// being true, the device says so instead of quietly generating guessable keys.
///
/// STACK: two 64-byte buffers plus a handful of scalars, about 150 bytes,
/// inside a function that is already #[inline(never)].
///
/// Deliberately weak as a statistical test. It catches a stuck, dead or
/// constant generator, which is the realistic failure mode, and nothing else.
/// It is not a randomness test and must not be described as one.
#[cfg(not(feature = "skip-tests"))]
#[inline(never)]
fn entropy_health_check() -> Result<(), &'static str> {
    let mut a = [0u8; 64];
    let mut b = [0u8; 64];
    // A refusal here is the check failing, not an error to swallow.
    crate::crypto::entropy::fill(&mut a)
        .map_err(|_| "hardware RNG failed continuous health tests")?;
    crate::crypto::entropy::fill(&mut b)
        .map_err(|_| "hardware RNG failed continuous health tests")?;

    if a == b {
        return Err("two collections identical");
    }
    if a.iter().all(|&x| x == 0) || b.iter().all(|&x| x == 0) {
        return Err("all-zero output");
    }
    if a.iter().all(|&x| x == a[0]) || b.iter().all(|&x| x == b[0]) {
        return Err("constant output");
    }

    // The three checks above test `fill`'s OUTPUT, which is a SHA-256 digest.
    // That is why they cannot see a dead source: 32 zero words hash to a
    // perfectly varied, non-constant, non-repeating 64 bytes. This test
    // reported "ENTROPY: ok" on every boot for the life of the project while
    // the hardware RNG returned 0x00000000 on every read (C-04). The statement
    // was true and meaningless.
    //
    // The health figures below are taken from INSIDE `fill`, over the raw WDEV
    // window before hashing, which is the only place a dead source is visible.
    //
    // Reported, not enforced. Whether a failure should refuse the operation is
    // a product decision still to be taken; this measures first.
    match crate::crypto::entropy::last_wdev_health() {
        Some(h) => {
            log!(
                "   [rng-health] repeats {}  distinct {}/32  ones {}/1024  stuck {}/32  mono {}  {}",
                h.repeats,
                h.distinct,
                h.ones,
                h.stuck_bits,
                h.monotonic,
                if h.healthy { "OK" } else { "DEGRADED" }
            );
            if !h.healthy {
                log!("   [rng-health] WARNING: hardware RNG failed its continuous tests");
            }
        }
        None => log!("   [rng-health] no window recorded"),
    }

    Ok(())
}

// out, so --features skip-tests failed to compile.
#[cfg(not(feature = "skip-tests"))]
#[inline(never)]
pub fn run_crypto_kats() {
    use esp_hal::time::Instant;

    // M-13, third sample point. The two around `early_lockdown` both read all
    // zeros, which does not distinguish "lockdown killed it" from "it was never
    // alive". This runs after every peripheral is up, so if it is still zero
    // here then the WDEV contribution to `fill()` has always been nil and the
    // entropy pool has been running on its other sources the whole time.
    #[cfg(feature = "rng-probe")]
    {
        let (d, o, z, r) = crate::crypto::entropy::probe_wdev(256);
        log!("   [rng-probe] LATE (post-init): distinct {}/256  ones {}/8192  zero_words {}  repeats {}",
            d, o, z, r);
        log!("   [rng-probe] SYSTEM_WIFI_CLK_EN = 0x{:08X}",
            crate::crypto::entropy::read_wifi_clk_en());
        let (d2, o2, z2, r2, saved) =
            crate::crypto::entropy::probe_wdev_with_modem_clk(256);
        log!("   [rng-probe] WITH modem clk:    distinct {}/256  ones {}/8192  zero_words {}  repeats {}  (restored 0x{:08X})",
            d2, o2, z2, r2, saved);
    }

    log!("Crypto Known-Answer Tests");
    log!("─────────────────────────────");

    let t_start = Instant::now();
    let mut failed: Option<&'static str> = None;

    let mut t_prev = t_start;
    macro_rules! kat {
        ($label:expr, $call:expr) => {{
            let (p, t) = $call;
            let now = Instant::now();
            log!("   {}: {}/{} [kat_t] {} ms", $label, p, t, (now - t_prev).as_millis());
            t_prev = now;
            if p != t && failed.is_none() { failed = Some($label); }
        }};
    }

    // Hash-only KATs. Both are pure SHA2/HMAC/PBKDF2 with sub-kilobyte
    // stack use, so they are safe in the boot frame on both targets.
    kat!("BIP39",   wallet::bip39::run_bip39_tests());
    kat!("STORAGE", wallet::storage::run_storage_tests());
    // DEF-04. These were excluded because main.rs documented k256 Schnorr
    // signing as needing ~16 KB of stack, which the boot frame did not have:
    // 57,600 bytes of internal SRAM were held by a QR_SRAM_IMG static in
    // camera_loop.rs (section 2a). That static is gone, so the margin should
    // now exist. If it does not, the symptom is a stack-guard panic during
    // this block at boot, not a wrong answer.
    kat!("BIP32",   wallet::bip32::run_bip32_tests());
    kat!("SCHNORR", wallet::schnorr::run_schnorr_tests());
    // Consensus sighash vectors from rusty-kaspa 2.0.1: 27 known answers over
    // all six sighash types, both transaction versions, native and subnetwork.
    //
    // This is the KAT that most directly protects funds. Every other primitive
    // here can be checked against a published standard; the sighash is the one
    // place where being self-consistent and being right are different things,
    // because a digest that disagrees with the node by one field still signs
    // cleanly, still verifies against itself, and is still rejected by every
    // node on the network. Or worse, is accepted for something the review
    // screen did not show.
    //
    // Safe in the boot frame: each vector builds its transaction with
    // `Transaction::new_boxed`, so the 78,952-byte struct is on the heap and
    // the frame holds a pointer. See N-15 for what happened when it was not.
    kat!("SIGHASH", wallet::sighash::run_sighash_vectors());
    // 45' multisig against a cross-implementation address.
    //
    // Belongs beside the sighash vectors for the same reason: it is the only
    // multisig check whose expected value came from someone else's code. It
    // proves the parent-string sort, the shared cosigner index, the
    // /cosigner/chain/index path and the script layout all at once, because
    // getting any one of them wrong changes the hash completely.
    kat!("MS45", wallet::transaction::run_multisig_tests());
    // The last kat! writes t_prev and nothing reads it. Consume it explicitly
    // so adding a KAT below needs no change here and no warning is emitted.
    let _ = t_prev;


    // Entropy health check. Not a KAT (there is no known answer for a random
    // number), so it is reported separately and has its own failure message.
    // Timed with SYSTIMER directly, in MICROSECONDS, not with Duration.
    //
    // The figure that matters is whether entropy::delay_us_systimer actually
    // spaces the 32 RNG reads by 2 us each. Two fill() calls should therefore
    // cost on the order of 1000 us. Milliseconds truncate that to "0 ms",
    // which is equally consistent with the spacing working and with it being
    // a no-op, so it cannot answer the question it was added to answer.
    //
    // SYSTIMER runs at 16 MHz (see the /16_000 ms conversions in
    // handlers/camera_loop.rs). The 20-cycle pause after latching mirrors
    // crypto::entropy::mix_systimer, which waits before reading the latched
    // value; delay_us_systimer does not, and if that turns out to matter this
    // measurement is what will show it.
    let t_ent0 = unsafe {
        core::ptr::write_volatile(0x6002_3004u32 as *mut u32, 1 << 30);
        for _ in 0..20u32 { core::hint::spin_loop(); }
        core::ptr::read_volatile(0x6002_3044u32 as *const u32)
    };
    let entropy_err = entropy_health_check().err();
    let t_ent1 = unsafe {
        core::ptr::write_volatile(0x6002_3004u32 as *mut u32, 1 << 30);
        for _ in 0..20u32 { core::hint::spin_loop(); }
        core::ptr::read_volatile(0x6002_3044u32 as *const u32)
    };
    log!("   ENTROPY: {} [kat_t] {} us",
         if entropy_err.is_none() { "ok" } else { "FAILED" },
         t_ent1.wrapping_sub(t_ent0) / 16);

    log!("   [kat_t] total {} ms", (Instant::now() - t_start).as_millis());

    if let Some(why) = entropy_err {
        log!();
        log!("CRITICAL: entropy health check FAILED: {}", why);
        log!("   The RNG is not producing varying output. Any seed, nonce or");
        log!("   ephemeral key generated now would be predictable. This is the");
        log!("   failure that cost COLDCARD Mk3 users their funds. Refusing to boot.");
        loop { core::hint::spin_loop(); }
    }

    if let Some(module) = failed {
        log!();
        log!("CRITICAL: {} known-answer test FAILED.", module);
        log!("   A crypto primitive is producing wrong output.");
        log!("   This device would derive or sign incorrectly with no other");
        log!("   visible symptom. Refusing to boot.");
        // Halt rather than return. A failing KAT means a primitive is emitting
        // well-formed wrong output, which has no other symptom: a wrong BIP32
        // child is still a valid key, deriving a valid address that accepts
        // funds nobody can ever spend. No BootDisplay is reachable from
        // run_boot_tests, so this halts on the log alone.
        loop { core::hint::spin_loop(); }
    }

    log!("   All crypto KATs passed");
    log!();
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


        // PIN UI tests removed 2026-08-14. `ui::pin_ui` is referenced by
        // nothing outside its own tests: KasSigner is stateless and has no PIN,
        // which Phase 5 prints two screens later. Reporting "PIN UI verified OK"
        // asserted that a subsystem worked when the subsystem is not reachable,
        // and a boot log that says that about one line is worth less on all the
        // others. Same family as L-09 (validate_pin / PinStrength in
        // storage.rs). Removing the module itself is tracked there.

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

        // SD backup container KATs. Costs one 100k PBKDF2 derivation, so this
        // is the slow one in this block.
        let (passed_sdb, total_sdb) = crate::hw::sd_backup::run_sd_backup_tests();
        log!("   SD backup tests: {}/{} passed", passed_sdb, total_sdb);
        if passed_sdb != total_sdb {
            log!("   CRITICAL: SD backup container has failures!");
        } else {
            log!("   SD backup container verified OK");
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

/// Signing pipeline self-test, M5Stack only (called at boot).
/// Waveshare cannot run this at boot: k256 Schnorr signing needs ~16 KB of
/// stack, which the boot frame does not have.
/// `#[inline(never)]` for the same reason as `run_signing_pipeline_test` in
/// main.rs: `acct_key_raw` here is a real derived account key, and inlining it
/// into `main` makes its 65 bytes a permanent slot that no wipe path can reach.
#[cfg(feature = "m5stack")]
#[inline(never)]
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

    // Heap-in-place, same reason as `AppData::new`. Whether LLVM elides the
    // temporary for a given `Box::new(Transaction::new())` is not something to
    // rely on: it did not elide it in `AppData::new`, where the 79 KB slot
    // ended up permanently reserved in `main`'s frame.
    let mut tx = match wallet::transaction::Transaction::new_boxed() {
        Some(t) => t,
        None => {
            log!("[SIGN-TEST] FAIL: transaction allocation failed");
            return false;
        }
    };
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

    // The boot test always runs a fixed 12-word mnemonic, so None here
    // would mean word_count was corrupted before the test ran; report it
    // as a test failure rather than unwrapping.
    let seed = match derive_seed(&ad.mnemonic_indices, ad.word_count, pp) {
        Some(s) => s,
        None => {
            log!("[SIGN-TEST] FAIL: word_count {} is not a mnemonic", ad.word_count);
            return false;
        }
    };
    let mut signed_buf = [0u8; 1024];
    let acct = wallet::bip32::derive_account_key(&seed.bytes).expect("boot-test account derive");
    let signed_len = sign_and_serialize_multi(&mut tx, &acct.to_raw(), None, &mut signed_buf);

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
