// KasSigner — Air-gapped hardware wallet for Kaspa
// Copyright (C) 2025 KasSigner Project (kassigner@proton.me)
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
//   5. TX signing: PSKT input → sighash (Blake2b) → Schnorr sign → serialized response
//
// All key material is zeroized after use. PBKDF2 takes ~5s on ESP32-S3 at 240MHz.

use crate::log;
use crate::{wallet, ui::seed_manager, hw::display, app::data::AppData};
use crate::features::verify::{FirmwareInfo, VerificationResult, FIRMWARE_START_ADDR, FIRMWARE_MAX_SIZE};
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

/// Sign a transaction and serialize the response (single key — backward compat)
#[inline(never)]
pub fn sign_and_serialize(
    tx: &mut wallet::transaction::Transaction,
    privkey: &[u8; 32],
    buf: &mut [u8; 1024],
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
    buf: &mut [u8; 1024],
) -> usize {
    wallet::pskt::sign_transaction_multi_addr(tx, seed, wallet::transaction::SigHashType::All)
        .and_then(|_| wallet::pskt::serialize_signed_pskt(tx, buf))
        .unwrap_or(0)
}

/// Sign a transaction with multisig support: tries all loaded seed slots,
/// signs P2PK and multisig inputs, outputs v2 PSKT with partial/full sigs.
#[inline(never)]
pub fn sign_and_serialize_multisig(
    tx: &mut wallet::transaction::Transaction,
    seed_mgr: &seed_manager::SeedManager,
    buf: &mut [u8; 1024],
) -> usize {
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

    let signed = wallet::pskt::sign_transaction_multisig(
        tx, &seeds, wallet::transaction::SigHashType::All,
    );
    match signed {
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
    }
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
pub fn handle_signing_step(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
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
                ad.app.state = crate::app::input::AppState::Rejected;
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
                    boot_display.draw_rejected_screen("Too many inputs!");
                    // Show detail on second line
                    {
                        use crate::hw::display::*;
                        let mut msg: heapless::String<48> = heapless::String::new();
                        let _ = core::fmt::Write::write_fmt(&mut msg,
                            format_args!("{} inputs — max 5. Compound first.", ad.demo_tx.num_inputs));
                        let mw = measure_body(msg.as_str());
                        draw_lato_body(&mut boot_display.display, msg.as_str(), (320 - mw) / 2, 155, COLOR_TEXT_DIM);
                    }
                    ad.app.state = crate::app::input::AppState::Rejected;
                    ad.needs_redraw = true;
                    return;
                }

                // Ensure pubkeys are cached (for display after signing)
                if !ad.pubkeys_cached {
                    boot_display.draw_saving_screen("Deriving addresses...");
                    let pp = ad.seed_mgr.active_slot().map(|s| s.passphrase_str()).unwrap_or("");
                    derive_all_pubkeys(&ad.mnemonic_indices, ad.word_count, pp, &mut ad.pubkey_cache, &mut ad.acct_key_raw);
                    ad.pubkeys_cached = true;
                }
                log!("   Signing input {}/{}...", input_idx + 1, ad.app.total_inputs);

                // On last input, sign all and serialize
                // Use multi-address signing: each input is matched to the correct key
                if (input_idx + 1) >= ad.app.total_inputs {
                    boot_display.draw_saving_screen("Signing TX...");
                    if let Some(slot) = ad.seed_mgr.active_slot() {
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
                                let seed = derive_seed(&ad.mnemonic_indices, ad.word_count, pp);
                                ad.signed_qr_len = sign_and_serialize_multi(&mut ad.demo_tx, &seed.bytes, &mut ad.signed_qr_buf);
                            }
                        }
                    }
                    log!("   Signed response: {} bytes", ad.signed_qr_len);
                    // Hex dump for companion app testing — single line for easy copy
                    if ad.signed_qr_len > 0 {
                        let buf = &ad.signed_qr_buf[..ad.signed_qr_len];
                        let hex_needed = buf.len() * 2;
                        let mut hex_buf = [0u8; 2100]; // signed_qr_buf max is 1024 = 2048 hex
                        if hex_needed > hex_buf.len() {
                            log!("   WARNING: Signed TX is {} bytes — serial hex output skipped.", buf.len());
                            log!("   Tip: reduce the number of UTXOs (inputs) by compounding first.");
                            log!("   The signed QR on screen still works — scan it with the companion.");
                        } else {
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
                }

                ad.app.advance_signing();
                ad.needs_redraw = true;
            }
        }
}

// ─── Multi-frame signed QR cycling ───

/// Cycle the signed QR display animation (alternating QR codes for multi-input).
pub fn cycle_signed_qr(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
) {
        if let crate::app::input::AppState::ShowQR = ad.app.state {
            if ad.signed_qr_nframes > 1 {
                ad.signed_qr_frame = (ad.signed_qr_frame + 1) % ad.signed_qr_nframes;
                let max_payload = 53usize;
                let offset = ad.signed_qr_frame as usize * max_payload;
                let remaining = ad.signed_qr_len.saturating_sub(offset);
                let frag_len = remaining.min(max_payload);
                if frag_len > 0 {
                    let mut frame_buf = [0u8; 134];
                    frame_buf[0] = ad.signed_qr_frame;
                    frame_buf[1] = ad.signed_qr_nframes;
                    frame_buf[2] = frag_len as u8;
                    frame_buf[3..3 + frag_len]
                        .copy_from_slice(&ad.signed_qr_buf[offset..offset + frag_len]);
                    // Pad short frames to minimum 20 bytes payload for reliable QR scanning
                    let qr_len = if frag_len < 20 { 3 + 20 } else { 3 + frag_len };
                    boot_display.draw_qr_screen(&frame_buf[..qr_len]);
                    let mut fc_buf: heapless::String<8> = heapless::String::new();
                    core::fmt::Write::write_fmt(&mut fc_buf,
                        format_args!("{}/{}", ad.signed_qr_frame + 1, ad.signed_qr_nframes)).ok();
                    boot_display.draw_frame_counter(&fc_buf);
                }
                for _ in 0..25 {
                    delay.delay_millis(100);
                    let ts = crate::hw::touch::read_touch(i2c);
                    if !matches!(ts, crate::hw::touch::TouchState::NoTouch) {
                        ad.app.go_main_menu();
                        ad.needs_redraw = true;
                        break;
                    }
                }
            }
        }
}
