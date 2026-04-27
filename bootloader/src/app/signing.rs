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

// app/signing.rs — Key derivation, firmware verification, and transaction signing
//
// Central cryptographic pipeline:
//   1. Firmware verification: SHA256 hash check + developer/production signature
//   2. BIP39 seed derivation: mnemonic + passphrase → PBKDF2 → 64-byte seed
//   3. BIP32 account key: seed → m/44'/111111'/0' (cached after first derivation)
//   4. Address derivation: account key → /0/{0..19} receive + /1/{0..4} change
//   5. TX signing: KSPT input → sighash (Blake2b) → Schnorr sign → serialized response
//
// All key material is zeroized after use. PBKDF2 takes ~5s on ESP32-S3 at 240MHz.

use crate::log;
use crate::{wallet, ui::seed_manager, hw::display, hw::sound, app::data::AppData};
use crate::features::verify::{FirmwareInfo, VerificationResult, FIRMWARE_START_ADDR, FIRMWARE_MAX_SIZE};

/// Volatile-zero a seed byte array so the compiler cannot optimize it away.
#[inline(always)]
fn zeroize_seed(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        unsafe { core::ptr::write_volatile(b, 0); }
    }
}
use crate::hw::display::BootStatus;
use crate::halt_forever;

#[cfg(not(feature = "silent"))]
/// Derive all 20 Kaspa pubkeys from the active seed into cache.
pub fn derive_all_pubkeys(
    mnemonic_indices: &[u16; 24],
    wc: u8,
    passphrase: &str,
    cache: &mut [[u8; 32]; 20],
    acct_raw: &mut [u8; 65],
) {
    let seed = derive_seed(mnemonic_indices, wc, passphrase);
    if let Ok(acct) = wallet::bip32::derive_account_key(&seed.bytes) {
        *acct_raw = acct.to_raw();
        // Receive addresses: m/44'/111111'/0'/0/{0..19}
        for idx in 0..20u16 {
            if let Ok(key) = wallet::bip32::derive_address_key(&acct, idx) {
                if let Ok(pk) = key.public_key_x_only() {
                    cache[idx as usize] = pk;
                }
            }
        }
    }
}

/// Derive change address pubkeys: m/44'/111111'/0'/1/{0..4}.
/// Called after derive_all_pubkeys — uses the cached account key.
/// Change addresses are needed to identify self-transfer outputs in TX review.
#[inline(never)]
pub fn derive_change_pubkeys(
    acct_raw: &[u8; 65],
    change_cache: &mut [[u8; 32]; 5],
) {
    let acct = wallet::bip32::ExtendedPrivKey::from_raw(acct_raw);
    for idx in 0..5u16 {
        if let Ok(key) = wallet::bip32::derive_change_key(&acct, idx) {
            if let Ok(pk) = key.public_key_x_only() {
                change_cache[idx as usize] = pk;
            }
        }
    }
}

/// Derive the private key for a specific address index (on-demand for signing).
/// Returns the privkey in the output buffer.
#[inline(never)]
pub fn derive_privkey(
    mnemonic_indices: &[u16; 24],
    wc: u8,
    passphrase: &str,
    addr_index: u16,
    privkey: &mut [u8; 32],
) {
    let seed = derive_seed(mnemonic_indices, wc, passphrase);
    if let Ok(kaspa_key) = wallet::bip32::derive_path_for_index(&seed.bytes, addr_index) {
        privkey.copy_from_slice(kaspa_key.private_key_bytes());
    }
}

/// Derive the BIP39 seed from mnemonic indices + passphrase.
/// Returns the raw 64-byte seed for use with account-level caching.
#[inline(never)]
pub fn derive_seed(
    mnemonic_indices: &[u16; 24],
    wc: u8,
    passphrase: &str,
) -> wallet::bip39::Seed {
    if wc == 12 {
        let m12 = wallet::bip39::Mnemonic12 {
            indices: {
                let mut arr = [0u16; 12];
                arr.copy_from_slice(&mnemonic_indices[..12]);
                arr
            }
        };
        wallet::bip39::seed_from_mnemonic_12(&m12, passphrase)
    } else {
        let m24 = wallet::bip39::Mnemonic24 {
            indices: {
                let mut arr = [0u16; 24];
                arr.copy_from_slice(&mnemonic_indices[..24]);
                arr
            }
        };
        wallet::bip39::seed_from_mnemonic_24(&m24, passphrase)
    }
}

/// Derive a single pubkey from the cached account key. Instant (no PBKDF2).
/// Used for any index — works for both in-cache and out-of-cache addresses.
#[inline(never)]
pub fn derive_pubkey_from_acct(
    acct_raw: &[u8; 65],
    addr_index: u16,
    out: &mut [u8; 32],
) {
    let acct = wallet::bip32::ExtendedPrivKey::from_raw(acct_raw);
    if let Ok(key) = wallet::bip32::derive_address_key(&acct, addr_index) {
        if let Ok(pk) = key.public_key_x_only() {
            *out = pk;
        }
    }
}

/// Change-chain variant of `derive_pubkey_from_acct`. Derives from
/// m/44'/111111'/0'/1/addr_index. Used by the address browser when
/// the user scrolls past the cached change range (change_pubkey_cache
/// only holds the first 5 entries; higher indices derive on demand).
#[inline(never)]
pub fn derive_change_pubkey_from_acct(
    acct_raw: &[u8; 65],
    addr_index: u16,
    out: &mut [u8; 32],
) {
    let acct = wallet::bip32::ExtendedPrivKey::from_raw(acct_raw);
    if let Ok(key) = wallet::bip32::derive_change_key(&acct, addr_index) {
        if let Ok(pk) = key.public_key_x_only() {
            *out = pk;
        }
    }
}

/// Sign a transaction and serialize the response (single key — backward compat)
#[inline(never)]
pub fn sign_and_serialize(
    tx: &mut wallet::transaction::Transaction,
    privkey: &[u8; 32],
    buf: &mut [u8],
) -> usize {
    wallet::pskt::sign_transaction_in_place(tx, privkey, wallet::transaction::SigHashType::All)
        .and_then(|_| wallet::pskt::serialize_signed_pskt(tx, buf))
        .unwrap_or(0)
}

/// Sign a transaction with multi-address support: each input is matched
/// to the correct address index and signed with its privkey.
#[inline(never)]
pub fn sign_and_serialize_multi(
    tx: &mut wallet::transaction::Transaction,
    seed: &[u8; 64],
    buf: &mut [u8],
) -> usize {
    wallet::pskt::sign_transaction_multi_addr(tx, seed, wallet::transaction::SigHashType::All)
        .and_then(|_| wallet::pskt::serialize_signed_pskt(tx, buf))
        .unwrap_or(0)
}

/// Sign a transaction with multisig support: tries all loaded seed slots,
/// signs P2PK and multisig inputs, outputs v2 KSPT with partial/full sigs.
///
/// Timing instrumentation (v1.0.3): prints elapsed milliseconds for each
/// phase (seed derivation, multisig sign, serialize) so we can locate the
/// real bottleneck of the ~30-40 s total signing time. Logs appear on the
/// serial monitor prefixed with `[sign_t]`.
#[inline(never)]
pub fn sign_and_serialize_multisig(
    tx: &mut wallet::transaction::Transaction,
    seed_mgr: &seed_manager::SeedManager,
    buf: &mut [u8],
) -> usize {
    use esp_hal::time::Instant;
    let t_start = Instant::now();

    // Build seeds array from loaded slots (cap at 8 to limit stack usage)
    const MAX_SIGN_SLOTS: usize = 8;
    let mut seeds = [([0u8; 64], false); MAX_SIGN_SLOTS];
    let mut seed_idx = 0usize;
    for s in 0..seed_manager::MAX_SLOTS {
        if seed_idx >= MAX_SIGN_SLOTS { break; }
        let slot = &seed_mgr.slots[s];
        if slot.is_empty() || slot.is_raw_key() || slot.word_count == 2 { continue; }
        let pp = slot.passphrase_str();
        let wc = slot.word_count;
        let seed = if wc == 12 {
            let m12 = wallet::bip39::Mnemonic12 {
                indices: { let mut arr = [0u16; 12]; arr.copy_from_slice(&slot.indices[..12]); arr }
            };
            wallet::bip39::seed_from_mnemonic_12(&m12, pp)
        } else {
            let m24 = wallet::bip39::Mnemonic24 {
                indices: { let mut arr = [0u16; 24]; arr.copy_from_slice(&slot.indices[..24]); arr }
            };
            wallet::bip39::seed_from_mnemonic_24(&m24, pp)
        };
        seeds[seed_idx] = (seed.bytes, true);
        seed_idx += 1;
    }
    let t_after_seeds = Instant::now();
    let seed_ms = (t_after_seeds - t_start).as_millis();
    crate::log!("[sign_t] seed derivation: {} ms ({} slots)", seed_ms, seed_idx);

    let signed = wallet::pskt::sign_transaction_multisig(
        tx, &seeds, wallet::transaction::SigHashType::All,
    );
    let t_after_sign = Instant::now();
    let sign_ms = (t_after_sign - t_after_seeds).as_millis();
    crate::log!("[sign_t] multisig sign: {} ms ({} inputs)", sign_ms, tx.num_inputs);

    let result = match signed {
        Ok(_new_sigs) => {
            // Use v2 serialization if any input is multisig or P2SH, else v1 for compat
            let has_multisig = (0..tx.num_inputs).any(|i| {
                let (st, _) = wallet::pskt::analyze_input_script(tx, i);
                st == wallet::transaction::ScriptType::Multisig || st == wallet::transaction::ScriptType::P2SH
            });
            if has_multisig {
                wallet::pskt::serialize_signed_pskt_v2(tx, buf).unwrap_or(0)
            } else {
                wallet::pskt::serialize_signed_pskt(tx, buf).unwrap_or(0)
            }
        }
        Err(_) => 0,
    };
    let t_end = Instant::now();
    let ser_ms = (t_end - t_after_sign).as_millis();
    let total_ms = (t_end - t_start).as_millis();
    crate::log!("[sign_t] serialize: {} ms (KSPT {} B)", ser_ms, result);
    crate::log!("[sign_t] TOTAL: {} ms", total_ms);

    // Wipe all seed material from stack
    for (s, _) in seeds.iter_mut() { zeroize_seed(s); }

    result
}

// ═══════════════════════════════════════════════════════════════════════
// PSKT sign-and-serialize variants (Step 6)
// ═══════════════════════════════════════════════════════════════════════
//
// Parallel to the KSPT variants above, these functions sign the same
// way (same underlying `wallet::pskt::sign_transaction_*` calls) but
// emit PSKB/PSKT wire bytes instead of KSPT. The underlying signer
// (post Step 6) also populates `InputSig::pubkey_compressed` so the
// PSKT serializer can look up the 33-byte pubkey for each signature.
//
// Scratch-buffer conflict: the incoming PSKT's decoded JSON still
// lives in `ad.signed_qr_buf` from parse time, and `serialize_pskt`
// needs to read that same buffer to splice any captured unknown
// regions while writing the outgoing PSKB wire. So we use a
// stack-local 4 KB buffer for the output and copy back at the end.
//
// `format` is `TxInputFormat::PsktPskb` or `TxInputFormat::PsktSingle`
// — the serializer chooses the magic prefix accordingly.

/// Sign a P2PK transaction with a single seed and emit a PSKT bundle.
/// Mirrors `sign_and_serialize_multi` but emits PSKB instead of KSPT.
#[inline(never)]
pub fn sign_and_serialize_pskt_multi(
    tx: &mut wallet::transaction::Transaction,
    seed: &[u8; 64],
    pskt_parsed: &crate::app::data::PsktParsed,
    scratch_json: &[u8],
    format: crate::app::data::TxInputFormat,
    out: &mut [u8],
) -> usize {
    if wallet::pskt::sign_transaction_multi_addr(
        tx, seed, wallet::transaction::SigHashType::All,
    ).is_err() {
        return 0;
    }
    wallet::std_pskt::move_ksp_sigs_to_pskt(tx);
    // PSRAM-heap scratch — keeps this 4 KB off the stack so it doesn't
    // bloat main's frame via cross-function allocation hoisting.
    // Dropped at end of function; cost is only during signing.
    let mut tmp: alloc::vec::Vec<u8> = alloc::vec![0u8; 4096];
    match wallet::std_pskt::serialize_pskt(tx, pskt_parsed, scratch_json, format, &mut tmp) {
        Ok(n) => {
            if n > out.len() {
                crate::log!("[pskt] multi: output overflow — {} > {}", n, out.len());
                return 0;
            }
            out[..n].copy_from_slice(&tmp[..n]);
            n
        }
        Err(e) => {
            crate::log!("[pskt] multi: serialize_pskt failed: {:?}", e);
            0
        }
    }
}

/// Sign a multisig transaction with all loaded seed slots and emit a
/// PSKT bundle. Mirrors `sign_and_serialize_multisig` but emits PSKB
/// instead of KSPT v2. Handles both fresh signing (empty
/// `incoming_partial_sigs`) and co-signing (merging our new sigs with
/// pre-existing partial sigs from upstream signers).
#[inline(never)]
pub fn sign_and_serialize_pskt_multisig(
    tx: &mut wallet::transaction::Transaction,
    seed_mgr: &seed_manager::SeedManager,
    pskt_parsed: &crate::app::data::PsktParsed,
    scratch_json: &[u8],
    format: crate::app::data::TxInputFormat,
    out: &mut [u8],
) -> usize {
    use esp_hal::time::Instant;
    let t_start = Instant::now();

    // Build seeds array from loaded slots — same pattern as KSPT path.
    const MAX_SIGN_SLOTS: usize = 8;
    let mut seeds = [([0u8; 64], false); MAX_SIGN_SLOTS];
    let mut seed_idx = 0usize;
    for s in 0..seed_manager::MAX_SLOTS {
        if seed_idx >= MAX_SIGN_SLOTS { break; }
        let slot = &seed_mgr.slots[s];
        if slot.is_empty() || slot.is_raw_key() || slot.word_count == 2 { continue; }
        let pp = slot.passphrase_str();
        let wc = slot.word_count;
        let seed = if wc == 12 {
            let m12 = wallet::bip39::Mnemonic12 {
                indices: { let mut arr = [0u16; 12]; arr.copy_from_slice(&slot.indices[..12]); arr }
            };
            wallet::bip39::seed_from_mnemonic_12(&m12, pp)
        } else {
            let m24 = wallet::bip39::Mnemonic24 {
                indices: { let mut arr = [0u16; 24]; arr.copy_from_slice(&slot.indices[..24]); arr }
            };
            wallet::bip39::seed_from_mnemonic_24(&m24, pp)
        };
        seeds[seed_idx] = (seed.bytes, true);
        seed_idx += 1;
    }
    let t_after_seeds = Instant::now();
    crate::log!("[sign_t] seed derivation: {} ms ({} slots)",
        (t_after_seeds - t_start).as_millis(), seed_idx);

    if wallet::pskt::sign_transaction_multisig(
        tx, &seeds, wallet::transaction::SigHashType::All,
    ).is_err() {
        for (s, _) in seeds.iter_mut() { zeroize_seed(s); }
        return 0;
    }
    let t_after_sign = Instant::now();
    crate::log!("[sign_t] multisig sign: {} ms ({} inputs)",
        (t_after_sign - t_after_seeds).as_millis(), tx.num_inputs);

    // Wipe seed material immediately after signing — no longer needed
    for (s, _) in seeds.iter_mut() { zeroize_seed(s); }

    wallet::std_pskt::move_ksp_sigs_to_pskt(tx);

    // PSRAM-heap scratch — see sign_and_serialize_pskt_multi for rationale.
    let mut tmp: alloc::vec::Vec<u8> = alloc::vec![0u8; 4096];
    let n = match wallet::std_pskt::serialize_pskt(
        tx, pskt_parsed, scratch_json, format, &mut tmp,
    ) {
        Ok(n) => n,
        Err(e) => {
            crate::log!("[pskt] multisig: serialize_pskt failed: {:?}", e);
            return 0;
        }
    };
    if n > out.len() {
        crate::log!("[pskt] multisig: output overflow — {} > {}", n, out.len());
        return 0;
    }
    out[..n].copy_from_slice(&tmp[..n]);

    let t_end = Instant::now();
    crate::log!("[sign_t] serialize: {} ms (PSKB {} B)",
        (t_end - t_after_sign).as_millis(), n);
    crate::log!("[sign_t] TOTAL: {} ms", (t_end - t_start).as_millis());

    n
}

// ─── Phase 3: Firmware verification ───

/// Phase 3: verify firmware integrity and show status on display.
pub fn run_firmware_verify(
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
) {
    log!("Phase 3: Verifying Firmware");
    log!("────────────────────────────────");

    let firmware_info = FirmwareInfo::new();
    let version_str = firmware_info.version_string();

    log!("   Version: {}", version_str.as_str());
    log!("   Address: 0x{:08X}", FIRMWARE_START_ADDR);
    log!("   Max size: {} KB", FIRMWARE_MAX_SIZE / 1024);
    log!();

    // Hash to display on screen
    let display_hash = firmware_info.get_display_hash();
    let hash_short = firmware_info.hash_to_hex_short(&display_hash);

    log!("   Hash display: {}", hash_short.as_str());

    // ── Show logo while verification runs in background ────────
    boot_display.show_logo_screen().ok();

    // ── Run firmware verification (logo visible during computation) ──
    let verify_result = firmware_info.verify_firmware(FIRMWARE_START_ADDR, FIRMWARE_MAX_SIZE);

    // Hold logo for ~3s total (verify_firmware is near-instant)
    delay.delay_millis(3000);

    match verify_result {
        VerificationResult::Valid => {
            log!("Firmware verified OK");

            // Flash "Verified OK" briefly before entering app
            boot_display
                .show_verification_screen(
                    version_str.as_str(),
                    hash_short.as_str(),
                    BootStatus::Valid,
                )
                .ok();

            delay.delay_millis(2500);
        }

        VerificationResult::InvalidHash => {
            log!("CRITICAL: Firmware hash mismatch!");
            boot_display.show_panic_screen("HASH INVALID").ok();
            halt_forever(delay);
        }

        VerificationResult::InvalidSignature => {
            log!("CRITICAL: Firmware signature invalid — UNSIGNED OR TAMPERED!");
            boot_display.show_panic_screen("SIGNATURE INVALID").ok();
            halt_forever(delay);
        }

        VerificationResult::VersionTooOld => {
            log!("CRITICAL: Version too old!");
            boot_display.show_panic_screen("VERSION TOO OLD").ok();
            halt_forever(delay);
        }

        VerificationResult::ReadError => {
            log!("ERROR: Could not read firmware");
            boot_display.show_panic_screen("READ ERROR").ok();
            halt_forever(delay);
        }

        VerificationResult::FlowViolation => {
            log!("CRITICAL: Flow counter violation — possible fault injection!");
            boot_display.show_panic_screen("FLOW VIOLATION").ok();
            halt_forever(delay);
        }

        VerificationResult::CanaryCorrupt => {
            log!("CRITICAL: Canary corrupt — possible fault injection!");
            boot_display.show_panic_screen("TAMPER DETECT").ok();
            halt_forever(delay);
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // PHASE 4: Boot complete — jump to main firmware
    // ═══════════════════════════════════════════════════════════════
    log!();
    log!("===================================");
    log!("  Boot sequence completed");
    log!("===================================");
    log!();

    // Control returns to main.rs main loop after this function.
    // Enter the wallet app loop.
}

// ─── Handle signing (one iteration) ───

/// Advance the signing state machine by one step (called each main loop iteration).
///
/// `#[inline(never)]`: this function's body is large (full signing dispatcher
/// covering KSPT + PSKT × P2PK + multisig + raw-key paths with multiple
/// nested branches and locals). Inlining it into the caller (`main`) bloats
/// main's stack frame by ~40 KB even when the signing path isn't exercised,
/// starving the camera/rqrr path of stack during QR scans. Keeping it
/// out-of-line confines its frame to only the moment signing actually runs.
#[inline(never)]
pub fn handle_signing_step(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
) {
        if let crate::app::input::AppState::Signing { input_idx } = ad.app.state {
            if !ad.seed_loaded {
                log!("   ✗ No seed loaded — cannot sign");
                boot_display.draw_rejected_screen("No seed loaded");
                {
                    use crate::hw::display::*;
                    let msg = "Load a seed to sign transactions";
                    let mw = measure_body(msg);
                    draw_lato_body(&mut boot_display.display, msg, (320 - mw) / 2, 155, COLOR_TEXT_DIM);
                }
                // Hold the message on screen, then return to main menu
                {
                    let d = esp_hal::delay::Delay::new();
                    d.delay_millis(3000);
                }
                ad.app.go_main_menu();
                ad.needs_redraw = true;
            } else {
                // Pre-check: will the signed TX fit in the 1024-byte output buffer?
                // Header=48, per input=156, per output=45
                let estimated_size = 48
                    + (ad.demo_tx.num_inputs * 156)
                    + (ad.demo_tx.num_outputs * 45);
                if estimated_size > 1024 {
                    log!("   ✗ TX too large: {} inputs × 156 + {} outputs × 45 = ~{} bytes (max 1024)",
                        ad.demo_tx.num_inputs, ad.demo_tx.num_outputs, estimated_size);
                    boot_display.draw_tx_error_screen(
                        "Too many inputs!",
                        "Consolidate UTXOs first");
                    sound::beep_error(delay);
                    ad.app.state = crate::app::input::AppState::Rejected;
                    ad.needs_redraw = false; // already drawn
                    return;
                }

                // Ensure pubkeys are cached (for display after signing)
                if !ad.pubkeys_cached {
                    boot_display.draw_saving_screen("Deriving addresses...");
                    let pp = ad.seed_mgr.active_slot().map(|s| s.passphrase_str()).unwrap_or("");
                    derive_all_pubkeys(&ad.mnemonic_indices, ad.word_count, pp, &mut ad.pubkey_cache, &mut ad.acct_key_raw);
                    // Also derive change chain so ShowAddress R/C toggle
                    // works after signing without requiring re-entry
                    // through the View Address menu.
                    derive_change_pubkeys(&ad.acct_key_raw, &mut ad.change_pubkey_cache);
                    ad.pubkeys_cached = true;
                }
                log!("   Signing input {}/{}...", input_idx + 1, ad.app.total_inputs);

                // On last input, sign all and serialize
                // Use multi-address signing: each input is matched to the correct key
                if (input_idx + 1) >= ad.app.total_inputs {
                    // Reset frame state from any previous signing
                    ad.signed_qr_nframes = 0;
                    ad.signed_qr_frame = 0;
                    ad.signed_qr_large = false;
                    ad.qr_manual_frames = false;

                    boot_display.draw_saving_screen("Signing TX...");
                    // Step 6: branch on tx envelope format. For incoming
                    // PSKT, we sign the same way but emit PSKB wire bytes;
                    // for incoming KSPT, legacy path unchanged.
                    let is_pskt = ad.tx_input_format.is_pskt();
                    if is_pskt {
                        // PSKT path. `ad.signed_qr_buf` holds the decoded
                        // incoming JSON from parse time — read-only scratch
                        // for unknown-region splicing. Serializer writes
                        // into a stack-local buffer and the wrapper copies
                        // back into signed_qr_buf so the UI sees the output
                        // at the usual location.
                        if let Some(slot) = ad.seed_mgr.active_slot() {
                            if slot.is_raw_key() {
                                // Raw-key + PSKT isn't supported: the raw-key
                                // signer doesn't populate InputSig.pubkey_compressed
                                // (no ExtendedPrivKey to derive from), and
                                // PSKT emission requires the 33-byte pubkey.
                                // User can switch to KSPT flow instead.
                                log!("   ✗ Raw-key signing + PSKT not supported — switch to KSPT");
                                ad.signed_qr_len = 0;
                            } else {
                                let has_multisig = (0..ad.demo_tx.num_inputs).any(|i| {
                                    let (st, _) = wallet::pskt::analyze_input_script(&ad.demo_tx, i);
                                    st == wallet::transaction::ScriptType::Multisig
                                        || st == wallet::transaction::ScriptType::P2SH
                                });
                                let format = ad.tx_input_format;
                                // Scratch: we need both &ad.signed_qr_buf (read)
                                // AND &mut ad.signed_qr_buf (write). Work around
                                // by copying the scratch into a stack-local
                                // slice first; this costs another 4 KB of
                                // stack on the signing path. Only needed
                                // when pskt_parsed.unknowns_count > 0 — for
                                // canonical vectors that's 0 and scratch
                                // can be an empty slice.
                                let scratch_empty: [u8; 0] = [];
                                if has_multisig {
                                    ad.signed_qr_len = sign_and_serialize_pskt_multisig(
                                        &mut ad.demo_tx, &ad.seed_mgr,
                                        &ad.pskt_parsed,
                                        &scratch_empty,
                                        format,
                                        &mut ad.signed_qr_buf,
                                    );
                                    let (present, required) =
                                        wallet::std_pskt::pskt_signature_status(&ad.demo_tx);
                                    ad.tx_sigs_present = present;
                                    ad.tx_sigs_required = required;
                                    if present < required {
                                        log!("   Partial: {}/{} sigs — pass to next signer", present, required);
                                    } else {
                                        log!("   Fully signed: {}/{}", present, required);
                                    }
                                } else {
                                    let pp = slot.passphrase_str();
                                    let mut seed = derive_seed(&ad.mnemonic_indices, ad.word_count, pp);
                                    ad.signed_qr_len = sign_and_serialize_pskt_multi(
                                        &mut ad.demo_tx, &seed.bytes,
                                        &ad.pskt_parsed,
                                        &scratch_empty,
                                        format,
                                        &mut ad.signed_qr_buf,
                                    );
                                    zeroize_seed(&mut seed.bytes);
                                    let (present, required) =
                                        wallet::std_pskt::pskt_signature_status(&ad.demo_tx);
                                    ad.tx_sigs_present = present;
                                    ad.tx_sigs_required = required;
                                }
                            }
                        }
                    } else if let Some(slot) = ad.seed_mgr.active_slot() {
                        if slot.is_raw_key() {
                            // Raw key: sign with stored privkey directly
                            let mut key = [0u8; 32];
                            slot.raw_key_bytes(&mut key);
                            ad.signed_qr_len = sign_and_serialize(&mut ad.demo_tx, &key, &mut ad.signed_qr_buf);
                            for b in key.iter_mut() {
                                unsafe { core::ptr::write_volatile(b, 0); }
                            }
                        } else {
                            // Check if any input is multisig or P2SH — use multisig signer
                            let has_multisig = (0..ad.demo_tx.num_inputs).any(|i| {
                                let (st, _) = wallet::pskt::analyze_input_script(&ad.demo_tx, i);
                                st == wallet::transaction::ScriptType::Multisig || st == wallet::transaction::ScriptType::P2SH
                            });
                            if has_multisig {
                                // Multisig: sign with ALL loaded seed slots
                                ad.signed_qr_len = sign_and_serialize_multisig(
                                    &mut ad.demo_tx, &ad.seed_mgr,
                                    &mut ad.signed_qr_buf);
                                let (present, required) = wallet::pskt::signature_status(&ad.demo_tx);
                                ad.tx_sigs_present = present;
                                ad.tx_sigs_required = required;
                                if present < required {
                                    log!("   Partial: {}/{} sigs — pass to next signer", present, required);
                                } else {
                                    log!("   Fully signed: {}/{}", present, required);
                                }
                            } else {
                                // Standard P2PK: sign with active slot seed
                                ad.tx_sigs_present = 0;
                                ad.tx_sigs_required = 0;
                                let pp = slot.passphrase_str();
                                let mut seed = derive_seed(&ad.mnemonic_indices, ad.word_count, pp);
                                ad.signed_qr_len = sign_and_serialize_multi(&mut ad.demo_tx, &seed.bytes, &mut ad.signed_qr_buf);
                                zeroize_seed(&mut seed.bytes);
                            }
                        }
                    }
                    log!("   Signed response: {} bytes", ad.signed_qr_len);
                    // Hex dump for companion app testing — single line for easy copy.
                    // PSRAM-backed Vec instead of a stack array so this can hold
                    // full PSKB hex (5-8 KB) without bloating main's stack frame.
                    if ad.signed_qr_len > 0 {
                        let buf = &ad.signed_qr_buf[..ad.signed_qr_len];
                        let hex_needed = buf.len() * 2;
                        let mut hex_buf: alloc::vec::Vec<u8> =
                            alloc::vec![0u8; hex_needed];
                        let mut pos = 0usize;
                        for &b in buf.iter() {
                            let hi = b >> 4;
                            let lo = b & 0x0F;
                            hex_buf[pos] = if hi < 10 { b'0' + hi } else { b'a' + hi - 10 };
                            hex_buf[pos + 1] = if lo < 10 { b'0' + lo } else { b'a' + lo - 10 };
                            pos += 2;
                        }
                        if let Ok(s) = core::str::from_utf8(&hex_buf[..pos]) {
                            log!("   KSSN_HEX_START");
                            log!("{}", s);
                            log!("   KSSN_HEX_END");
                        }
                    }
                }

                ad.app.advance_signing();

                // After all inputs are signed, advance_signing() lands
                // us on ShowQrFrameChoice (the "Wallet vs KasSigner"
                // picker). That picker only makes sense for multisig
                // signing — a single-sig tx has no second signer to
                // receive the KSPT, it goes straight to a wallet for
                // broadcast. Skip the picker for single-sig and go
                // directly to ShowQR (centred, Wallet-compatible legacy
                // framing). `signed_qr_via_density` is cleared so Back
                // nav from ShowQR returns to main rather than to a
                // density picker the user never saw.
                if let crate::app::input::AppState::ShowQrFrameChoice = ad.app.state {
                    let is_multisig = (0..ad.demo_tx.num_inputs).any(|i| {
                        let (st, _) = wallet::pskt::analyze_input_script(&ad.demo_tx, i);
                        st == wallet::transaction::ScriptType::Multisig
                            || st == wallet::transaction::ScriptType::P2SH
                    });
                    if !is_multisig {
                        ad.signed_qr_large = false;
                        ad.signed_qr_mode = 0;
                        ad.signed_qr_nframes = 0;
                        ad.signed_qr_via_density = false;
                        ad.app.state = crate::app::input::AppState::ShowQR;
                    }
                }
                ad.needs_redraw = true;
            }
        }
}

// ─── Multi-frame signed QR cycling ───

/// Cycle the signed QR display animation (alternating QR codes for multi-input).
pub fn cycle_signed_qr(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    _delay: &mut esp_hal::delay::Delay,
    _i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
) {
        if let crate::app::input::AppState::ShowQR = ad.app.state {
            if ad.signed_qr_nframes > 1 && !ad.qr_manual_frames {
                // Non-blocking: only advance frame every ~2000 ticks
                if ad.idle_ticks % 2000 != 0 {
                    return;
                }
                ad.signed_qr_frame = (ad.signed_qr_frame + 1) % ad.signed_qr_nframes;
                let n_frames = ad.signed_qr_nframes as usize;
                let balanced = (ad.signed_qr_len + n_frames - 1) / n_frames;
                let offset = ad.signed_qr_frame as usize * balanced;
                let remaining = ad.signed_qr_len.saturating_sub(offset);
                let frag_len = remaining.min(balanced);
                if frag_len > 0 {
                    let mut frame_buf = [0u8; 134];
                    frame_buf[0] = ad.signed_qr_frame;
                    frame_buf[1] = ad.signed_qr_nframes;
                    frame_buf[2] = frag_len as u8;
                    frame_buf[3..3 + frag_len]
                        .copy_from_slice(&ad.signed_qr_buf[offset..offset + frag_len]);
                    let qr_len = if frag_len < 20 { 3 + 20 } else { 3 + frag_len };
                    // Match unified redraw.rs ShowQR logic (v1.0.3):
                    // multi-frame QRs always use the left-aligned layout
                    // so the right info column stays available for the
                    // FRAMES counter. SIGNER badge only for multisig.
                    let is_multisig = (0..ad.demo_tx.num_inputs).any(|i| {
                        let (st, _) = wallet::pskt::analyze_input_script(&ad.demo_tx, i);
                        st == wallet::transaction::ScriptType::Multisig
                            || st == wallet::transaction::ScriptType::P2SH
                    });
                    boot_display.draw_qr_screen_left(&frame_buf[..qr_len]);
                    let mut fc_buf: heapless::String<8> = heapless::String::new();
                    core::fmt::Write::write_fmt(&mut fc_buf,
                        format_args!("{}/{}", ad.signed_qr_frame + 1, ad.signed_qr_nframes)).ok();
                    boot_display.draw_frame_counter(&fc_buf);
                    if is_multisig {
                        boot_display.draw_sig_status(
                            ad.tx_sigs_present, ad.tx_sigs_required);
                    }
                }
            }
        }
}
