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

/// Derive all 20 Kaspa pubkeys from the active seed into cache.
pub fn derive_all_pubkeys(
    mnemonic_indices: &[u16; 24],
    wc: u8,
    passphrase: &str,
    cache: &mut [[u8; 32]; 20],
    acct_raw: &mut [u8; 65],
) {
    // HARD GUARD, do not remove. `mnemonic_indices` is only BIP39 word
    // indices when wc is 12 or 24. Raw-key slots (wc==1) and xprv slots
    // (wc==2) pack their 32 raw key bytes into the SAME array, and
    // `derive_seed` routes everything that is not 12 into the 24-word
    // path, which indexes a 2048-entry wordlist with those bytes and
    // panics (observed: index 44263). Callers should use
    // `fill_display_caches`, which dispatches on word_count; this guard
    // is here so that forgetting to is harmless rather than fatal.
    let mut seed = wallet::bip39::Seed { bytes: [0u8; 64] };
    if !derive_seed_into(mnemonic_indices, wc, passphrase, &mut seed) {
        return; // not a mnemonic slot: caches stay as they were
    }
    if let Ok(acct) = wallet::bip32::derive_account_key(&seed.bytes) {
        *acct_raw = acct.to_raw();
        // Receive addresses: m/44'/111111'/0'/0/{0..19}
        // Via ChainParent: 4 + 20 scalar multiplies instead of 60.
        if let Ok(chain) = wallet::bip32::ChainParent::new(&acct, 0) {
            for idx in 0..20u32 {
                if let Ok(key) = chain.derive(idx) {
                    if let Ok(pk) = key.public_key_x_only() {
                        cache[idx as usize] = pk;
                    }
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
    // Via ChainParent: 4 + 5 scalar multiplies instead of 15. See the
    // type's docs; the win applies to all callers of this helper.
    if let Ok(chain) = wallet::bip32::ChainParent::new(&acct, 1) {
        for idx in 0..5u32 {
            if let Ok(key) = chain.derive(idx) {
                if let Ok(pk) = key.public_key_x_only() {
                    change_cache[idx as usize] = pk;
                }
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
    // No mnemonic means no BIP39 seed; leave `privkey` untouched, which
    // is what this function already did when derivation failed.
    let mut seed = wallet::bip39::Seed { bytes: [0u8; 64] };
    if !derive_seed_into(mnemonic_indices, wc, passphrase, &mut seed) {
        return;
    }
    if let Ok(kaspa_key) = wallet::bip32::derive_path_for_index(&seed.bytes, addr_index) {
        privkey.copy_from_slice(kaspa_key.private_key_bytes());
    }
}

/// Derive the BIP39 seed from mnemonic indices + passphrase.
/// Returns the raw 64-byte seed for use with account-level caching.
#[inline(never)]
/// Returns `None` unless `wc` is 12 or 24.
///
/// This used to return a Seed unconditionally, routing every word count
/// that was not 12 into the 24-word branch. That is wrong for the two
/// non-mnemonic slot types: raw-key slots (wc==1) and xprv slots (wc==2)
/// pack their 32 raw key bytes into the SAME `indices` array a mnemonic
/// uses for BIP39 word indices. Reading those bytes as word indices
/// panics on the first value above 2047, which with key material is a
/// near certainty.
///
/// That was not only theoretical: Sign Message, the stealth scan and the
/// ECIES decrypt path all call this with whatever word count is active,
/// so all three crashed outright on an xprv or raw-key slot.
///
/// Returning `Option` rather than guarding internally is deliberate. A
/// guard that returned a zeroed seed would turn a crash into silently
/// signing with the wrong key, which is far worse. `None` forces every
/// caller to say what it does for a slot that has no mnemonic.
/// As `derive_seed`, writing into a caller-owned `Seed`.
///
/// Returns false when `wc` is neither 12 nor 24, leaving `out` untouched.
///
/// Preferred wherever the call sits in statement position. Returning a `Seed`
/// by value leaves a second copy in the caller's frame when the value is moved
/// out, which `Seed`'s `Drop` never sees because `Drop` runs on the owner's
/// copy only. That copy was measured on hardware at 0x3FCD627C, 64 bytes below
/// the owner's, surviving an explicit zeroize of `seed.bytes`.
pub fn derive_seed_into(
    mnemonic_indices: &[u16; 24],
    wc: u8,
    passphrase: &str,
    out: &mut wallet::bip39::Seed,
) -> bool {
    match wc {
        12 => {
            let m12 = wallet::bip39::Mnemonic12 {
                indices: {
                    let mut arr = [0u16; 12];
                    arr.copy_from_slice(&mnemonic_indices[..12]);
                    arr
                }
            };
            wallet::bip39::seed_from_mnemonic_12_into(&m12, passphrase, out);
        }
        24 => {
            let m24 = wallet::bip39::Mnemonic24 { indices: *mnemonic_indices };
            wallet::bip39::seed_from_mnemonic_24_into(&m24, passphrase, out);
        }
        _ => return false,
    }
    #[cfg(feature = "sentinel-scan")]
    crate::app::stack_probe::capture_seed_needle(&out.bytes);
    true
}

pub fn derive_seed(
    mnemonic_indices: &[u16; 24],
    wc: u8,
    passphrase: &str,
) -> Option<wallet::bip39::Seed> {
    if !matches!(wc, 12 | 24) {
        return None;
    }
    if wc == 12 {
        let m12 = wallet::bip39::Mnemonic12 {
            indices: {
                let mut arr = [0u16; 12];
                arr.copy_from_slice(&mnemonic_indices[..12]);
                arr
            }
        };
        let s = wallet::bip39::seed_from_mnemonic_12(&m12, passphrase);
        #[cfg(feature = "sentinel-scan")]
        crate::app::stack_probe::capture_seed_needle(&s.bytes);
        Some(s)
    } else {
        let m24 = wallet::bip39::Mnemonic24 {
            indices: {
                let mut arr = [0u16; 24];
                arr.copy_from_slice(&mnemonic_indices[..24]);
                arr
            }
        };
        let s = wallet::bip39::seed_from_mnemonic_24(&m24, passphrase);
        #[cfg(feature = "sentinel-scan")]
        crate::app::stack_probe::capture_seed_needle(&s.bytes);
        Some(s)
    }
}

// `ExtBanksMut`, `ext_find_pubkey` and `ext_scan_find` moved to
// kassigner-core (core/src/ext.rs), verbatim. Re-exported here so the
// `crate::app::signing::` paths in the firmware still resolve.
pub use kassigner_core::ext::{ExtBanksMut, ext_find_pubkey, ext_scan_find};

/// Ensure `ad.chain_cache` holds the chain parents for the CURRENT
/// account key, rebuilding if the account key has changed or the cache
/// is empty. Returns false when no usable account key is loaded.
///
/// Validity is decided by comparing the full 65-byte account key the
/// cache was built from, not by any write site remembering to clear it.
/// `acct_key_raw` is written from slot select, from `derive_all_pubkeys`
/// in the menu and tx handlers, and zeroed in the delete path; a cache
/// that trusted all of those would eventually sign with the wrong
/// wallet's chain key.
#[inline(never)]
pub fn ensure_chain_cache(ad: &mut crate::app::data::AppData) -> bool {
    if ad.acct_key_raw[..32].iter().all(|&b| b == 0) {
        ad.chain_cache = None;
        return false;
    }
    let fresh = match ad.chain_cache.as_ref() {
        Some(c) => c.matches(&ad.acct_key_raw),
        None => false,
    };
    if !fresh {
        match wallet::bip32::ChainCache::build(&ad.acct_key_raw) {
            Ok(c) => ad.chain_cache = Some(alloc::boxed::Box::new(c)),
            Err(_) => {
                ad.chain_cache = None;
                return false;
            }
        }
    }
    true
}

/// Idle pump: derive ONE next extended pubkey (alternating chains) into
/// the ext banks. Called from the main menu when the user is idle; each
/// call costs one BIP32 derivation (~110ms). Full banks (200+200) fill in
/// ~45s of cumulative idle and then this returns false forever (until a
/// slot switch wipes the banks).
///
/// The pump primes the session account key itself: on a cold cache its
/// FIRST act is the one-time PBKDF2 stretch (~6s, placed in genuine
/// idleness by the caller's quiet gate), after which bank filling
/// proceeds normally. Without this, a fresh session's idle time filled
/// nothing and the first sign fell through empty banks to the deep scan.
pub fn pump_ext_pubkeys(ad: &mut crate::app::data::AppData) -> bool {
    if ad.acct_key_raw[..32].iter().all(|&b| b == 0) {
        // Cold cache. Prime it from here only for a loaded MNEMONIC
        // seed (12 or 24 words). xprv slots (wc==2) arrive pre-cached
        // at slot select, so an empty cache there means nothing to
        // derive from; raw-key slots (wc==1) have no BIP32 account and
        // stretching their stale mnemonic_indices would cache garbage.
        // The stretch normally runs at seed load now; this branch is a
        // safety net for any path that missed the load-time prime.
        if !ad.seed_loaded || !matches!(ad.word_count, 12 | 24) {
            return false;
        }
        // One-time stretch, fired from idle. Serial shows
        // "[acct] session cache MISS — PBKDF2 stretch".
        if !ensure_session_account_key(ad) {
            return false;
        }
        // The stretch was this iteration's work; banks start next call.
        return true;
    }
    let (recv_n, chg_n) = (ad.ext_recv_n as usize, ad.ext_chg_n as usize);
    let (recv_cap, chg_cap) = (ad.ext_recv.len(), ad.ext_chg.len());
    if recv_n >= recv_cap && chg_n >= chg_cap {
        return false;
    }
    // Chain parents held across pump calls: one scalar multiply per
    // index instead of three, so a full 200+200 fill costs ~16s of idle
    // instead of ~47s and each tick blocks touch for ~39ms instead of
    // ~117ms. Rebuild happens here, inside the same tick, if the active
    // account key changed.
    if !ensure_chain_cache(ad) {
        return false;
    }
    let cache = match ad.chain_cache.as_ref() {
        Some(c) => c,
        None => return false,
    };
    // `cache` borrows ad.chain_cache; the bank writes below borrow
    // ad.ext_* . Disjoint fields, so both borrows coexist.
    // Alternate chains so both fronts advance together.
    if recv_n <= chg_n && recv_n < recv_cap {
        if let Ok(key) = cache.recv.derive(recv_n as u32) {
            if let Ok(pk) = key.public_key_x_only() {
                ad.ext_recv[recv_n] = pk;
                ad.ext_recv_n = (recv_n + 1) as u16;
            }
        } else {
            ad.ext_recv_n = (recv_n + 1) as u16; // skip unusable index
        }
    } else if chg_n < chg_cap {
        if let Ok(key) = cache.chg.derive(chg_n as u32) {
            if let Ok(pk) = key.public_key_x_only() {
                ad.ext_chg[chg_n] = pk;
                ad.ext_chg_n = (chg_n + 1) as u16;
            }
        } else {
            ad.ext_chg_n = (chg_n + 1) as u16;
        }
    }
    true
}

/// Fill the display pubkey caches (20 receive, 5 change) from an already
/// derived BIP32 account key. Used by slot types that HAVE an account key
/// but no mnemonic to re-derive it from, i.e. xprv slots.
pub fn fill_caches_from_acct(
    acct_raw: &[u8; 65],
    cache: &mut [[u8; 32]; 20],
    change_cache: &mut [[u8; 32]; 5],
) -> bool {
    if acct_raw[..32].iter().all(|&b| b == 0) {
        return false;
    }
    let acct = wallet::bip32::ExtendedPrivKey::from_raw(acct_raw);
    let chain = match wallet::bip32::ChainParent::new(&acct, 0) {
        Ok(c) => c,
        Err(_) => return false,
    };
    for idx in 0..20u32 {
        if let Ok(key) = chain.derive(idx) {
            if let Ok(pk) = key.public_key_x_only() {
                cache[idx as usize] = pk;
            }
        }
    }
    derive_change_pubkeys(acct_raw, change_cache);
    true
}

/// Restore a raw-key slot's single pubkey into `cache[0]`.
///
/// Raw-key slots (word_count == 1) have no BIP32 chain: one private key,
/// one address. Its bytes are packed into the slot's `indices` array the
/// same way an xprv's are, so the key has to be unpacked rather than
/// treated as BIP39 word indices.
/// Takes the decoded 32-byte key, not the packed `[u16; 24]`.
///
/// It used to take the raw slot array and unpack it here, which meant the
/// caller had to know that a raw-key slot stores its key in the field named
/// `indices`. `SeedSlot::as_raw_key` owns that encoding now (H-08).
pub fn fill_cache_from_raw_key(
    key_in: &[u8; 32],
    cache: &mut [[u8; 32]; 20],
) -> bool {
    let mut key = [0u8; 32];
    {
        key.copy_from_slice(key_in);
    }
    let ok = match wallet::bip32::pubkey_from_raw_key(&key) {
        Ok(pk) => {
            cache[0] = pk;
            true
        }
        Err(_) => false,
    };
    for b in key.iter_mut() {
        unsafe { core::ptr::write_volatile(b as *mut u8, 0) };
    }
    ok
}

/// Where the passphrase for a seed load comes from.
pub enum PassphraseSource {
    /// Store with no passphrase.
    Empty,
    /// Take it from `ad.pp_input`.
    PpInput,
}

/// The one way a mnemonic becomes the active wallet.
///
/// Store, activate, reset the display state, then prime the account key behind
/// a "Deriving keys..." screen. Returns the slot index, or `None` if every slot
/// is occupied (the caller owns the rejection screen, since the wording and the
/// state to return to differ per entry point).
///
/// Every source of a mnemonic ends here: manual word entry, SeedQR from the
/// camera, dice, TRNG, SD restore and stego recovery. That is the point. The
/// tail used to be copied at each site, and the stego copy had dropped the
/// prime call, so a stego-recovered slot carried no account key and, once the
/// fingerprint moved behind that key, no fingerprint either. Same shape as
/// DEF-01 and the root of H-07: a flow duplicated instead of shared, with the
/// copies drifting apart.
///
/// Reads `ad.mnemonic_indices` and `ad.word_count`, so callers that produce a
/// new mnemonic (BIP85, for instance) must write those two first.
///
/// One deliberate exception: `run_signing_pipeline_test` in main.rs calls
/// `SeedManager::store` directly. It runs at boot with no display, loads a
/// fixed test mnemonic, and deletes the slot before the UI ever sees it.
///
/// The mnemonic and passphrase are passed to `store` as borrows of their live
/// fields rather than copied into locals, so this adds no second copy of either
/// to the stack.
// `match stored { Some(i) => i, None => return None }` rather than `stored?`.
// The early return sits immediately after `ad.pp_input.reset()` and before the
// slot is logged; written out, the control flow is visible at a glance in a
// function that handles seed material on several paths. `?` would hide it.
#[allow(clippy::question_mark)]
pub fn load_active_mnemonic(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    pp_source: PassphraseSource,
) -> Option<usize> {
    let (stored, had_pp) = match pp_source {
        PassphraseSource::PpInput => {
            let n = ad.pp_input.len.min(64);
            (
                ad.seed_mgr.store(
                    &ad.mnemonic_indices,
                    ad.word_count,
                    &ad.pp_input.buf[..n],
                    n as u8,
                ),
                n > 0,
            )
        }
        PassphraseSource::Empty => (
            ad.seed_mgr.store(&ad.mnemonic_indices, ad.word_count, &[], 0),
            false,
        ),
    };

    // Clear the keyboard buffer on every path, including the ones that stored
    // without a passphrase: backing out of the keyboard used to leave whatever
    // had been typed sitting in `pp_input`.
    ad.pp_input.reset();

    let slot_idx = match stored {
        Some(i) => i,
        None => return None,
    };
    // Log only whether a passphrase was used, never its length: length narrows
    // the brute-force space.
    log!("   Seed stored in slot {} (pp={})", slot_idx, if had_pp { "yes" } else { "no" });

    ad.seed_mgr.activate(slot_idx);
    ad.seed_loaded = true;
    ad.pubkeys_cached = false;
    ad.current_addr_index = 0;
    ad.extra_pubkey_index = 0xFFFF;

    // Synchronous prime behind the confirming tap: wipes any stale cache from
    // the previous slot, then runs the one-time PBKDF2 stretch HERE so it never
    // freezes the menu later and signing starts warm. Also the point at which
    // the slot's fingerprint becomes computable.
    boot_display.draw_saving_screen("Deriving keys...");
    prime_after_seed_load(ad);
    Some(slot_idx)
}

/// Fill in the active slot's display fingerprint from the account key.
///
/// The fingerprint is `SHA256(controlling private key)[0..4]`, so for a
/// mnemonic slot it cannot exist until the PBKDF2 stretch and the three
/// hardened BIP32 derivations have run. `SeedManager::store` therefore leaves
/// it zeroed and this fills it in, from the two places that produce a valid
/// `acct_key_raw`: `ensure_session_account_key` and `fill_display_caches`.
///
/// Deriving it inside `store` instead would pay the stretch twice, since every
/// caller of `store` primes the account key immediately afterwards.
///
/// Cheap (one SHA-256) and idempotent, so calling it on every prime is fine.
/// Raw-key and xprv slots already carry a fingerprint from their own store
/// path and are left alone.
pub fn refresh_active_fingerprint(ad: &mut AppData) {
    if !matches!(ad.word_count, 12 | 24) {
        return;
    }
    if ad.acct_key_raw[..32].iter().all(|&b| b == 0) {
        return;
    }
    // Hashed straight out of `acct_key_raw`. `seed_mgr` and `acct_key_raw` are
    // disjoint fields, so this borrows both without a 32-byte copy on the
    // stack: this runs on the seed-load path, which has no headroom to spare.
    let key = &ad.acct_key_raw[..32];
    if let Some(slot) = ad.seed_mgr.active_slot_mut() {
        slot.set_fingerprint_from_key(key);
    }
}

/// Fill the display pubkey caches for whatever kind of slot is active.
///
/// CRITICAL: `derive_all_pubkeys` must never be reached for word_count 1
/// or 2. Both raw-key and xprv slots pack their 32 key bytes into
/// `slot.indices`, the same array a mnemonic slot uses for BIP39 word
/// indices, and `derive_seed` routes anything that is not 12 into the
/// 24-word path. That reads key bytes as word indices and panics on the
/// first value above 2047 (observed: index 44263 into a 2048-entry
/// wordlist). Dispatch on word_count here so no caller has to remember.
///
/// Returns true if the caches are now valid.
pub fn fill_display_caches(ad: &mut crate::app::data::AppData) -> bool {
    let ok = match ad.word_count {
        12 | 24 => {
            // Copy the passphrase out first: `passphrase_str` borrows
            // ad.seed_mgr, and the derive call below needs &mut on other
            // fields of ad.
            let mut pp_buf = [0u8; 64];
            let mut pp_len = 0usize;
            if let Some(slot) = ad.seed_mgr.active_slot() {
                let pp = slot.passphrase_str();
                pp_len = pp.len().min(64);
                pp_buf[..pp_len].copy_from_slice(&pp.as_bytes()[..pp_len]);
            }
            let pp = core::str::from_utf8(&pp_buf[..pp_len]).unwrap_or("");
            #[cfg(feature = "sentinel-scan")]
            crate::app::stack_probe::capture_pp_needle(&pp_buf[..pp_len]);
            derive_all_pubkeys(
                &ad.mnemonic_indices,
                ad.word_count,
                pp,
                &mut ad.pubkey_cache,
                &mut ad.acct_key_raw,
            );
            derive_change_pubkeys(&ad.acct_key_raw, &mut ad.change_pubkey_cache);

            // Control: `pp_buf` is still live here, so this must hit.
            #[cfg(feature = "sentinel-scan")]
            crate::app::stack_probe::scan_pp_needle("caches, pp live");

            // The passphrase is the 25th word: as sensitive as the mnemonic it
            // extends. `ensure_session_account_key` wipes its own copy on both
            // the success and failure paths; this arm held one for the whole
            // of two derive calls and let it go out of scope untouched.
            //
            // The whole buffer, not `..pp_len`: nothing is gained by reasoning
            // about which tail bytes are already zero.
            for b in pp_buf.iter_mut() {
                unsafe { core::ptr::write_volatile(b, 0); }
            }
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);

            // The measurement.
            #[cfg(feature = "sentinel-scan")]
            crate::app::stack_probe::scan_pp_needle("caches, after pp wipe");
            true
        }
        2 => fill_caches_from_acct(
            &ad.acct_key_raw,
            &mut ad.pubkey_cache,
            &mut ad.change_pubkey_cache,
        ),
        1 => {
            // `as_raw_key` decodes only for a raw-key slot, so the arm and the
            // decode cannot drift apart (H-08).
            let key = match ad.seed_mgr.active_slot().and_then(|s| s.as_raw_key()) {
                Some(k) => k,
                None => return false,
            };
            fill_cache_from_raw_key(&key, &mut ad.pubkey_cache)
        }
        _ => false,
    };
    if ok {
        ad.pubkeys_cached = true;
        // The mnemonic branch above has just produced the account key. This is
        // the lazy path (stego restore, slot switch), so it is the first point
        // at which the slot's fingerprint can exist.
        refresh_active_fingerprint(ad);
    }
    ok
}

/// Ensure the session account key is cached in `ad.acct_key_raw`.
/// First call of a session pays the PBKDF2 seed stretch ONCE (the ~20s
/// "Deriving" phase that used to run on EVERY signing session); afterwards
/// every sign starts instantly. xprv slots arrive pre-cached at slot
/// select. Returns false if no key could be produced.
#[inline(never)]
pub fn ensure_session_account_key(
    ad: &mut crate::app::data::AppData,
) -> bool {
    if ad.acct_key_raw[..32].iter().any(|&b| b != 0) {
        crate::log!("   [acct] session cache HIT");
        return true;
    }
    if ad.active_kind() == crate::ui::seed_manager::SlotKind::Xprv {
        return false; // xprv slot with empty cache: nothing to derive from
    }
    crate::log!("   [acct] session cache MISS — PBKDF2 stretch");
    // Copy the passphrase out of the slot borrow before mutating ad.
    let (mut pp_bytes, pp_len) = match ad.seed_mgr.active_slot() {
        Some(slot) => {
            let p = slot.passphrase_str();
            let mut b = [0u8; 64];
            let l = p.len().min(64);
            b[..l].copy_from_slice(&p.as_bytes()[..l]);
            (b, l)
        }
        None => ([0u8; 64], 0),
    };
    let pp = core::str::from_utf8(&pp_bytes[..pp_len]).unwrap_or("");

    // Derived straight into a buffer this frame owns, rather than through
    // `derive_seed`'s return value.
    //
    // Measured, not assumed: with `derive_seed` here, a scan taken while the
    // seed was live found THREE copies, and one at 0x3FCD627C, 64 bytes below
    // the owner's, survived the zeroize loop below. That is the copy the move
    // out of `derive_seed` leaves in the caller's frame, which `Seed`'s `Drop`
    // and the loop below both miss, because both only know about `seed.bytes`.
    // Writing into `seed` directly means there is no return value to move and
    // no second copy to leave behind.
    //
    // This is the hot path: a stateless device re-derives on every cache miss,
    // so this one call site accounts for most derivations the device performs.
    // The other `derive_seed` callers are unchanged until measured.
    let mut seed = wallet::bip39::Seed { bytes: [0u8; 64] };
    let derived = match ad.word_count {
        12 => {
            let m12 = wallet::bip39::Mnemonic12 {
                indices: {
                    let mut arr = [0u16; 12];
                    arr.copy_from_slice(&ad.mnemonic_indices[..12]);
                    arr
                }
            };
            wallet::bip39::seed_from_mnemonic_12_into(&m12, pp, &mut seed);
            true
        }
        24 => {
            let m24 = wallet::bip39::Mnemonic24 {
                indices: ad.mnemonic_indices,
            };
            wallet::bip39::seed_from_mnemonic_24_into(&m24, pp, &mut seed);
            true
        }
        _ => false,
    };
    if !derived {
        for b in pp_bytes.iter_mut() {
            unsafe { core::ptr::write_volatile(b, 0); }
        }
        return false;
    }
    // Re-point the needle at the seed just derived. `derive_seed` captures it
    // for the paths that still go through it; this path no longer does, and
    // without this the scan below hunts whatever seed was derived last,
    // reports zero, and the zero means nothing.
    #[cfg(feature = "sentinel-scan")]
    crate::app::stack_probe::capture_seed_needle(&seed.bytes);

    // Positive control, taken while `seed` is still live on this frame: this
    // MUST hit, and it is the only proof the scan works at this depth. The
    // `after signing` scan cannot serve as one, because the QR decoder reaches
    // 0x3FCD2760 while derivation bottoms out at 0x3FCD2970, so by then the
    // camera path has already overwritten every frame PBKDF2 used.
    #[cfg(feature = "sentinel-scan")]
    crate::app::stack_probe::scan_seed_needle("stretch, seed live");

    if let Ok(acct) = wallet::bip32::derive_account_key(&seed.bytes) {
        ad.acct_key_raw.copy_from_slice(&acct.to_raw());
    }
    for b in seed.bytes.iter_mut() {
        unsafe { core::ptr::write_volatile(b, 0); }
    }
    for b in pp_bytes.iter_mut() {
        unsafe { core::ptr::write_volatile(b, 0); }
    }

    // The measurement. The owner's copy is wiped by the loop above, so a hit
    // here is a copy left in a deeper frame by PBKDF2 or by the derivation
    // that follows it, in a frame no `Drop` and no owner-side wipe reaches.
    #[cfg(feature = "sentinel-scan")]
    crate::app::stack_probe::scan_seed_needle("after stretch wipe");
    // The fingerprint refresh deliberately does NOT happen here. This is the
    // deepest frame in the firmware: touch handler, load_active_mnemonic,
    // prime_after_seed_load, here, derive_seed, PBKDF2. Adding a SHA-256 at
    // this depth tripped the stack guard on M5Stack. It runs at the tail of
    // `prime_after_seed_load` instead, once these frames have been popped and
    // `acct_key_raw` still holds the key this function just derived.
    ad.acct_key_raw[..32].iter().any(|&b| b != 0)
}

/// Our own 45' multisig account key, as descriptor parts.
///
/// Returns `None` when there is no seed to derive from: no slot loaded, or an
/// xprv slot, which is imported at 44' account level and cannot walk down the
/// 45' branch.
///
/// Deliberately derives the seed rather than reusing `acct_key_raw`. That field
/// holds the 44' account key, a different subtree; putting it into a 45'
/// descriptor would produce an entry that parses, checksums and renders a
/// plausible address that no quorum can spend. Same wipe discipline as
/// `ensure_session_account_key`: seed and passphrase copy are zeroed on every
/// exit path.
pub fn own_multisig_parts(
    ad: &mut crate::app::data::AppData,
) -> Option<wallet::xpub::KpubParts> {
    if !ad.seed_loaded || ad.active_kind() == crate::ui::seed_manager::SlotKind::Xprv {
        crate::log!("   [ms45] no seed to derive our own cosigner key from");
        return None;
    }
    let (mut pp_bytes, pp_len) = match ad.seed_mgr.active_slot() {
        Some(slot) => {
            let p = slot.passphrase_str();
            let mut b = [0u8; 64];
            let l = p.len().min(64);
            b[..l].copy_from_slice(&p.as_bytes()[..l]);
            (b, l)
        }
        None => ([0u8; 64], 0),
    };
    let pp = core::str::from_utf8(&pp_bytes[..pp_len]).unwrap_or("");
    let seed_opt = derive_seed(&ad.mnemonic_indices, ad.word_count, pp);
    let mut seed = match seed_opt {
        Some(s) => s,
        None => {
            for b in pp_bytes.iter_mut() {
                unsafe { core::ptr::write_volatile(b, 0); }
            }
            return None;
        }
    };
    let parts = wallet::xpub::derive_multisig_account_parts(&seed.bytes, 0).ok();
    for b in seed.bytes.iter_mut() {
        unsafe { core::ptr::write_volatile(b, 0); }
    }
    for b in pp_bytes.iter_mut() {
        unsafe { core::ptr::write_volatile(b, 0); }
    }
    parts
}

/// Outcome of resolving our slot in a 45' descriptor.
///
/// Three states rather than a bool, because the two failures need different
/// words on screen. Collapsing them reports a good descriptor as bad, which is
/// the kind of message that sends someone to look in the wrong place.
#[derive(PartialEq, Eq, Clone, Copy)]
pub enum MsResolve {
    /// Index resolved, or the config is 44' and has no index.
    Ok,
    /// No seed loaded, or the slot cannot produce one. The descriptor was not
    /// examined and may be perfectly good.
    NoSeed,
    /// Parsed fine, but our account key is not among its cosigners. Either the
    /// descriptor belongs to someone else, or one of its keys is wrong, and
    /// this is the check that catches a 44'-vs-45' `kpub` mix-up.
    NotOurs,
}

/// Resolve our own slot in a loaded 45' descriptor, i.e. `cosigner_index`.
///
/// Returns true when the config is usable. For a 44' config it is a no-op that
/// returns true, because 44' has no cosigner index: every participant shares
/// one address family.
///
/// **A false return must be treated as a refusal to load, not a default.**
/// It means our account key is not among the descriptor's cosigners, so either
/// the descriptor is not ours, or one of the keys in it is wrong. Choosing a
/// family anyway would display addresses for a wallet we cannot sign for.
///
/// This is also the only check that catches a 44'-vs-45' `kpub` mix-up. Such a
/// key parses cleanly, has a valid checksum and yields a plausible address, so
/// nothing earlier can reject it. It fails here, on the device of the
/// participant whose key is wrong, which is the one place the mistake can be
/// fixed.
///
/// Cost: three hardened derivations plus a PBKDF2 stretch if the seed is not
/// already in hand, the same price as `ensure_session_account_key`. It runs
/// once per descriptor load, not per address.
///
/// The 45' account key is NOT cached in `acct_key_raw`. That field holds the
/// 44' key at `m/44'/111111'/0'` and the whole display and signing path reads
/// it; a different subtree in the same slot would be silently wrong everywhere.
pub fn resolve_ms_cosigner_index(ad: &mut crate::app::data::AppData) -> MsResolve {
    if !ad.ms_creating.v45 {
        return MsResolve::Ok;
    }
    if !ad.seed_loaded {
        // Not a bad descriptor, and not the wrong one: there is simply nothing
        // to compare it against yet. The multisig menu has no seed guard, so
        // this path is reachable, and reporting it as "Bad descriptor" would
        // send the user to check a file that is fine.
        crate::log!("   [ms45] no seed loaded, cannot resolve cosigner index");
        return MsResolve::NoSeed;
    }
    if ad.active_kind() == crate::ui::seed_manager::SlotKind::Xprv {
        // An xprv slot is imported at account level on the 44' path, so there
        // is no seed to walk down the 45' branch from.
        crate::log!("   [ms45] xprv slot cannot derive a 45' account key");
        return MsResolve::NoSeed;
    }

    let (mut pp_bytes, pp_len) = match ad.seed_mgr.active_slot() {
        Some(slot) => {
            let p = slot.passphrase_str();
            let mut b = [0u8; 64];
            let l = p.len().min(64);
            b[..l].copy_from_slice(&p.as_bytes()[..l]);
            (b, l)
        }
        None => ([0u8; 64], 0),
    };
    let pp = core::str::from_utf8(&pp_bytes[..pp_len]).unwrap_or("");
    let seed_opt = derive_seed(&ad.mnemonic_indices, ad.word_count, pp);
    let mut seed = match seed_opt {
        Some(s) => s,
        None => {
            for b in pp_bytes.iter_mut() {
                unsafe { core::ptr::write_volatile(b, 0); }
            }
            return MsResolve::NoSeed;
        }
    };

    let n = ad.ms_creating.n as usize;
    let found = match wallet::bip32::derive_multisig_account_key(&seed.bytes, 0) {
        Ok(ms_acct) => wallet::bip32::resolve_cosigner_index(
            &ms_acct,
            &ad.ms_creating.cosigner_pubkeys,
            n,
        ),
        Err(_) => None,
    };

    for b in seed.bytes.iter_mut() {
        unsafe { core::ptr::write_volatile(b, 0); }
    }
    for b in pp_bytes.iter_mut() {
        unsafe { core::ptr::write_volatile(b, 0); }
    }

    match found {
        Some(idx) => {
            ad.ms_creating.cosigner_index = idx;
            crate::log!("   [ms45] cosigner index {} of {}", idx, n);
            MsResolve::Ok
        }
        None => {
            crate::log!("   [ms45] our account key is not in this descriptor");
            MsResolve::NotOurs
        }
    }
}

/// Wipe the previous slot's session cache and synchronously prime the
/// new one. Called at every seed-load confirmation point (passphrase OK,
/// slot select, BIP85 auto-load, delete-fallback activation) so the
/// one-time PBKDF2 stretch lands behind the button press the user just
/// made, never as a menu freeze. The caller draws the "Deriving keys..."
/// screen BEFORE calling this when word_count is 12 or 24.
/// Raw-key (wc==1) and xprv (wc==2) slots skip the stretch: raw keys
/// have no BIP32 account; xprv slots arrive pre-cached by the caller
/// (which fills acct_key_raw AFTER this wipe, or skips this entirely).
#[inline(never)]
pub fn prime_after_seed_load(ad: &mut crate::app::data::AppData) -> bool {
    ad.acct_key_raw = [0u8; 65];
    ad.ext_recv_n = 0;
    ad.ext_chg_n = 0;
    // Correctness does not depend on this (ChainCache self-validates),
    // but dropping it here frees the allocation and zeroizes the old
    // wallet's chain keys at the moment the slot changes.
    ad.chain_cache = None;
    if !matches!(ad.word_count, 12 | 24) {
        return false;
    }
    if !ensure_session_account_key(ad) {
        return false;
    }
    // Shallow enough to be safe, and `acct_key_raw` provably belongs to the
    // slot that was just activated: this function zeroed it on entry.
    refresh_active_fingerprint(ad);
    // Fill the display pubkey caches from the fresh account key, so no
    // later path (Sign TX, View Address, post-sign display) falls into
    // its own !pubkeys_cached branch. Those branches call
    // derive_all_pubkeys, which predates the session cache and re-runs
    // the FULL PBKDF2 stretch from the mnemonic; landing there after a
    // load-time prime would pay the stretch twice. ~25 derivations,
    // roughly 3s on top of the stretch, all behind the same screen.
    //
    // Both loops go through `ChainParent`, which hoists the two
    // index-independent scalar multiplies out of the per-index work: 25
    // indices cost 4 + 25 multiplies instead of 75.
    let acct = wallet::bip32::ExtendedPrivKey::from_raw(&ad.acct_key_raw);
    if let Ok(chain) = wallet::bip32::ChainParent::new(&acct, 0) {
        for idx in 0..20u32 {
            if let Ok(key) = chain.derive(idx) {
                if let Ok(pk) = key.public_key_x_only() {
                    ad.pubkey_cache[idx as usize] = pk;
                }
            }
        }
    }
    derive_change_pubkeys(&ad.acct_key_raw, &mut ad.change_pubkey_cache);
    ad.pubkeys_cached = true;
    true
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

/// Collapse a serializer `Result` to a byte count, naming the failure first.
///
/// Every caller here has to end up with a `usize`, because `signed_qr_len` is
/// one, and `.unwrap_or(0)` did that by throwing the reason away. The cost is
/// recorded twice in this file: once at the unknown-region bug below, where a
/// transaction signed correctly in ~170 ms and reached the user as "Signing
/// Failed" with nothing to act on, and once as N-06, where a large transaction
/// overflows `SIGNED_QR_BUF_LEN` and reports `Signed response: 0 bytes`.
///
/// The error already carries a user-facing mapping, `PsktError::screen_text`,
/// which renders `OutputBufferTooSmall` as "Result too large / Split the
/// transaction". Nothing was wrong with the message; it was discarded one
/// frame before anything could read it.
///
/// This does not change what the caller receives: a failure is still 0 bytes,
/// and the UI still shows "Signing Failed". It changes what the serial log
/// says, so the cause is identifiable instead of guessable.
///
/// N-06 note: at 32 inputs the redeem script is written once per input, and
/// the real covenant scripts are 57 to 101 bytes (piggy bank, dead-man switch,
/// 2-of-3). That puts a 32-input spend at 7.1 to 8.6 KB of the 14,528-byte
/// buffer, so this path is NOT reachable for any covenant this project builds:
/// v3 only overflows once a redeem exceeds 287 bytes with one signature per
/// input, or 221 with two. Deduplicating the redeem would save 1.8 to 3.1 KB
/// and was deferred as not worth a wire-format change. If that changes, the
/// arithmetic is in INTERNAL_FINDINGS.md under N-06.
#[inline(never)]
fn serialized_or_zero(
    r: Result<usize, wallet::pskt::PsktError>,
    which: &str,
    num_inputs: usize,
) -> usize {
    match r {
        Ok(n) => n,
        Err(e) => {
            let (line1, line2) = e.screen_text();
            crate::log!(
                "   SERIALIZE FAILED ({}): {} / {} — {} inputs, buffer {} bytes",
                which,
                line1,
                line2,
                num_inputs,
                crate::app::data::SIGNED_QR_BUF_LEN
            );
            0
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
    let n = tx.num_inputs;
    serialized_or_zero(
        wallet::pskt::sign_transaction_in_place(tx, privkey, wallet::transaction::SigHashType::All)
            .and_then(|_| wallet::pskt::serialize_signed_pskt(tx, buf)),
        "v1",
        n,
    )
}

/// Sign a transaction with multi-address support: each input is matched
/// to the correct address index and signed with its privkey.
#[inline(never)]
pub fn sign_and_serialize_multi(
    tx: &mut wallet::transaction::Transaction,
    acct_raw: &[u8; 65],
    ext: Option<ExtBanksMut<'_>>,
    buf: &mut [u8],
) -> usize {
    let acct = wallet::bip32::ExtendedPrivKey::from_raw(acct_raw);
    let n = tx.num_inputs;
    serialized_or_zero(
        wallet::pskt::sign_transaction_multi_addr(tx, &acct, wallet::transaction::SigHashType::All, ext)
            .and_then(|_| wallet::pskt::serialize_signed_pskt(tx, buf)),
        "v1 multi-addr",
        n,
    )
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

    // ONE SLOT SIGNS: the selected one, and only it.
    //
    // This loop used to derive every loaded slot and hand all of them to the
    // signer, which then tried each against every input. Two consequences.
    //
    // CORRECTNESS. `active_seed_idx` guides which key is preferred, and there
    // were two independent ways for it to come back None while signing went
    // ahead anyway with whatever else was loaded:
    //   (a) the active slot holds an xprv (`word_count == 2`), so the guard
    //       below `continue`s before the assignment;
    //   (b) `MAX_SLOTS` is 16 but the loop breaks at `MAX_SIGN_SLOTS` 8, so
    //       an active slot past the eighth loaded one is never reached.
    // In both cases the device signed with a key the user had not selected.
    //
    // COST. Each slot costs a full PBKDF2 stretch, and the multisig path
    // rebuilds its address/pubkey table per slot per pass. Deriving one slot
    // instead of up to eight removes the largest measured cost on this path.
    //
    // Multisig is unaffected in substance: a cosigner signs one at a time,
    // and this device holds one cosigner's key. Signing every loaded slot
    // filled positions the user did not choose to fill.
    const MAX_SIGN_SLOTS: usize = 1;
    let mut seeds = [([0u8; 64], false); MAX_SIGN_SLOTS];
    let mut seed_idx = 0usize;
    let mut active_seed_idx: Option<usize> = None;
    let active_mgr_slot = seed_mgr.active as usize;
    // [S6]. Was `for s in active_mgr_slot..=active_mgr_slot`, a range that runs
    // exactly once, left behind when MAX_SIGN_SLOTS went to 1. A reader meets a
    // loop and assumes multi-slot, which is the opposite of the property this
    // code exists to enforce: ONE slot, the one the user selected.
    //
    // The two escapes were `continue`, and they worked only because the refusal
    // sits AFTER the loop. Straight-line, both become "no usable mnemonic", the
    // block is skipped, `active_seed_idx` stays None, and the same refusal
    // fires. That equivalence is the whole of this change; nothing else moves.
    let slot = &seed_mgr.slots[active_mgr_slot];
    // An xprv or raw-key slot cannot be reached through the mnemonic
    // derivation below. Falling through to another slot would sign with a key
    // the user did not select, so this refuses instead.
    //
    // `as_mnemonic` rather than `slot.indices`: on a raw-key or xprv slot that
    // array holds a packed private key, and feeding it to
    // `seed_from_mnemonic_*` reads key bytes as BIP39 word indices. The kind
    // guard and the read are one expression so a future edit cannot separate
    // them (H-08).
    let usable = if slot.is_empty() || slot.is_raw_key() || slot.word_count == 2 {
        None
    } else {
        slot.as_mnemonic()
    };
    if let Some((indices, wc)) = usable {
        // Claimed only once a mnemonic is proven present. Claimed earlier, a
        // slot that passed the kind guard but failed `as_mnemonic` left the
        // index claimed with no seed stored: `sign_transaction_multisig` skips
        // it on the `.1` flag, so the outcome was an unsigned result rather
        // than the explicit refusal below.
        active_seed_idx = Some(seed_idx);
        let pp = slot.as_passphrase()
            .and_then(|b| core::str::from_utf8(b).ok())
            .unwrap_or("");
        let seed = if wc == 12 {
            let m12 = wallet::bip39::Mnemonic12 {
                indices: { let mut arr = [0u16; 12]; arr.copy_from_slice(&indices[..12]); arr }
            };
            wallet::bip39::seed_from_mnemonic_12(&m12, pp)
        } else {
            let m24 = wallet::bip39::Mnemonic24 {
                indices: { let mut arr = [0u16; 24]; arr.copy_from_slice(&indices[..24]); arr }
            };
            wallet::bip39::seed_from_mnemonic_24(&m24, pp)
        };
        seeds[seed_idx] = (seed.bytes, true);
        seed_idx += 1;
    }
    let t_after_seeds = Instant::now();
    let seed_ms = (t_after_seeds - t_start).as_millis();
    crate::log!("[sign_t] seed derivation: {} ms ({} slots, active={})", seed_ms, seed_idx,
        active_seed_idx.map(|i| i as i32).unwrap_or(-1));

    // No usable seed in the selected slot: refuse rather than sign with
    // nothing. Reachable when the active slot holds an xprv or a raw key,
    // which the mnemonic derivation above cannot use. Previously the loop
    // fell through to other slots and signed with a key the user had not
    // chosen; now there is nothing to fall through to, so this must be an
    // explicit refusal.
    if active_seed_idx.is_none() {
        crate::log!("[sign] refused: selected slot holds no usable seed");
        return 0;
    }

    let signed = wallet::pskt::sign_transaction_multisig(
        tx, &seeds, wallet::transaction::SigHashType::All, active_seed_idx,
    );
    let t_after_sign = Instant::now();
    let sign_ms = (t_after_sign - t_after_seeds).as_millis();
    crate::log!("[sign_t] multisig sign: {} ms ({} inputs)", sign_ms, tx.num_inputs);

    let result = match signed {
        Ok(new_sigs) => {
            // Use v2 serialization if any input is multisig or P2SH, else v1 for compat
            let has_multisig = (0..tx.num_inputs).any(|i| {
                let (st, _) = wallet::pskt::analyze_input_script(tx, i);
                st == wallet::transaction::ScriptType::Multisig || st == wallet::transaction::ScriptType::P2SH
            });

            // Zero new signatures on a multisig transaction is a FAILURE, not a
            // pass-through. It used to serialize anyway, returning a PSKB that
            // looks normal, carries no new signature, and is only revealed as
            // useless when a node rejects the broadcast.
            //
            // The likeliest cause is a payload built without its derivation map.
            // A standard multisig PSKB carries `bip32_derivations` per input;
            // without it the device cannot know which of the N cosigner slots
            // this address belongs to, and the only alternative is to search
            // `n + 2n + 2n*SIGN_MATCH_DEPTH` derivations per input per seed
            // slot. At SIGN_MATCH_DEPTH = 100 that is 609 derivations for a
            // 2-of-3, which measured against the BIP32 and MS45 KATs is between
            // 5 and 24 seconds PER INPUT, per slot. Not a viable fallback at
            // either end of that range, so the device reports the malformed
            // payload instead of grinding.
            //
            // The other cause is an honest one: the transaction is not ours to
            // sign. Same outcome, and the message names both.
            if has_multisig && new_sigs == 0 {
                crate::log!(
                    "   MULTISIG: no key matched any input ({} inputs). Payload is \
                     missing its bip32_derivations map, or this wallet is not a \
                     cosigner.",
                    tx.num_inputs
                );
                for (s, _) in seeds.iter_mut() { zeroize_seed(s); }
                return 0;
            }

            if has_multisig {
                serialized_or_zero(
                    wallet::pskt::serialize_signed_pskt_v2(tx, buf),
                    "v3 multisig",
                    tx.num_inputs,
                )
            } else {
                serialized_or_zero(
                    wallet::pskt::serialize_signed_pskt(tx, buf),
                    "v1",
                    tx.num_inputs,
                )
            }
        }
        Err(_) => {
            // Signing itself failed, not serialization. Distinguished from the
            // serializer failures above so the log says which half broke.
            crate::log!("   SIGNING FAILED before serialization ({} inputs)", tx.num_inputs);
            0
        }
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
// `format` is `TxInputFormat::PsktPskb`, the only PSKT envelope; the
// serializer writes the `PSKB` magic for it.

/// Sign a P2PK transaction with a single seed and emit a PSKT bundle.
/// Mirrors `sign_and_serialize_multi` but emits PSKB instead of KSPT.
#[inline(never)]
pub fn sign_and_serialize_pskt_multi(
    tx: &mut wallet::transaction::Transaction,
    acct_raw: &[u8; 65],
    ext: Option<ExtBanksMut<'_>>,
    pskt_parsed: &crate::app::data::PsktParsed,
    scratch_json: &[u8],
    format: crate::app::data::TxInputFormat,
    out: &mut [u8],
) -> usize {
    // PSRAM-heap scratch — keeps this 8 KB off the stack so it doesn't
    // bloat main's frame via cross-function allocation hoisting.
    // Dropped at end of function; cost is only during signing.
    let mut tmp: alloc::vec::Vec<u8> = alloc::vec![0u8; crate::app::data::SIGNED_QR_BUF_LEN];

    // Pre-flight, before any key operation.
    //
    // The size check inside `HexWriter` is exact but runs at the end, so a
    // bundle too large to emit used to be parsed, signed and only then
    // refused: an 11-input PSKB spent about two seconds on eleven
    // signatures and eleven verifications before `OutputBufferTooSmall`,
    // and every one of them was discarded.
    //
    // Both ceilings are checked, because they bind at different points. On
    // this format the emit frames bind first, at 10 inputs, while the
    // buffer binds at 11. A payload that fits the buffer but not 64 frames
    // would otherwise produce a stream no receiver can assemble.
    //
    // 227 bytes per frame is the densest emit mode, so this is the most
    // permissive frame test; the density chooser then greys out anything
    // sparser that still will not fit.
    let predicted = match wallet::std_pskt::predict_emitted_size(
        tx, pskt_parsed, scratch_json, format, tx.num_inputs, &mut tmp,
    ) {
        Ok(n) => n,
        Err(e) => {
            crate::log!("[pskt] multi: unsigned bundle will not serialize: {:?}", e);
            return 0;
        }
    };
    let fits_buffer = predicted <= tmp.len() && predicted <= out.len();
    let fits_frames = crate::handlers::camera_loop::density_fits(predicted, 227);
    if !fits_buffer || !fits_frames {
        crate::log!(
            "[pskt] multi: {} inputs would emit {} bytes, buffer {} frames {}, refused before signing",
            tx.num_inputs, predicted,
            if fits_buffer { "ok" } else { "over" },
            if fits_frames { "ok" } else { "over" },
        );
        return 0;
    }

    let acct = wallet::bip32::ExtendedPrivKey::from_raw(acct_raw);
    if wallet::pskt::sign_transaction_multi_addr(
        tx, &acct, wallet::transaction::SigHashType::All, ext,
    ).is_err() {
        // Named, not silent. This returns the same 0 as a serialization
        // failure, and the serializer logs its error while this did not, so a
        // wrong-seed scan and a broken serializer were indistinguishable in
        // the log. They need different answers from the user: load the right
        // seed, versus report a bug.
        crate::log!("[pskt] multi: signing failed: no loaded key matches any input");
        return 0;
    }
    wallet::std_pskt::move_ksp_sigs_to_pskt(tx);
    // `tmp` was allocated above for the pre-flight; reused here.
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

    // N-14: predict the emitted size BEFORE ANYTHING ELSE.
    //
    // Placed above the seed gathering, not merely above the signing. The
    // prediction needs only the parsed transaction, so a payload that cannot
    // be returned is refused without a PBKDF2 stretch and without putting seed
    // material on the stack at all. Measured with vector M8: the first version
    // sat after the slot was unlocked and the log showed `seed derivation:
    // 651 ms` before the refusal - work spent on a transaction that was never
    // going to be signed.
    //
    // Same pre-flight `sign_and_serialize_pskt_multi` has, and it applies to
    // BOTH schemes: a 44' and a 45' input serialize to the same JSON shape, one
    // `partialSigs` entry with a 64-byte Schnorr signature, so the scheme does
    // not enter the arithmetic. 44' creation is disabled from 1.0.6 but those
    // wallets hold funds and must stay spendable, and they overflow the same
    // way.
    //
    // This was parked because the signature count was unknown before signing:
    // the device used to sign with every loaded slot, so a worst-case estimate
    // meant assuming MAX_SIGS_PER_INPUT = 5 and over-refusing exactly where
    // payloads are already tight. `MAX_SIGN_SLOTS` is 1 now - one slot signs -
    // so this device adds at most ONE signature per input and the prediction is
    // exact rather than pessimistic.
    //
    // `predict_emitted_size` SERIALIZES the unsigned bundle rather than
    // estimating it, so the `bip32Derivations` map that N-20 made survive is
    // counted for real; the per-input constant covers only the signature entry.
    // Measured against the vectors: M5 grew 2484 -> 2902 wire bytes for one
    // signature and M6 grew 2902 -> 3326, both about 418 against the 568 the
    // predictor assumes.
    //
    // Both ceilings are checked because they bind at different points: the
    // output buffer, and 64 QR frames at the densest 227-byte mode, beyond
    // which no receiver can assemble the stream whatever the buffer holds.
    {
        let mut dry: alloc::vec::Vec<u8> =
            alloc::vec![0u8; crate::app::data::SIGNED_QR_BUF_LEN];
        match wallet::std_pskt::predict_emitted_size(
            tx, pskt_parsed, scratch_json, format, tx.num_inputs, &mut dry,
        ) {
            Ok(predicted) => {
                let fits_buffer = predicted <= dry.len() && predicted <= out.len();
                let fits_frames =
                    crate::handlers::camera_loop::density_fits(predicted, 227);
                if !fits_buffer || !fits_frames {
                    crate::log!(
                        "[pskt] multisig: {} inputs would emit {} bytes, buffer {} frames {}, refused before signing",
                        tx.num_inputs, predicted,
                        if fits_buffer { "ok" } else { "over" },
                        if fits_frames { "ok" } else { "over" },
                    );
                    return 0;
                }
            }
            Err(e) => {
                crate::log!("[pskt] multisig: unsigned bundle will not serialize: {:?}", e);
                return 0;
            }
        }
    }

    // ONE SLOT SIGNS, same as the KSPT path above and for the same reasons:
    // `active_seed_idx` could come back None while signing proceeded with a
    // key the user had not selected, and deriving every loaded slot cost a
    // full PBKDF2 stretch each.
    const MAX_SIGN_SLOTS: usize = 1;
    let mut seeds = [([0u8; 64], false); MAX_SIGN_SLOTS];
    let mut seed_idx = 0usize;
    let mut active_seed_idx: Option<usize> = None;
    let active_mgr_slot = seed_mgr.active as usize;
    // [S6]. Was `for s in active_mgr_slot..=active_mgr_slot`, a range that runs
    // exactly once, left behind when MAX_SIGN_SLOTS went to 1. A reader meets a
    // loop and assumes multi-slot, which is the opposite of the property this
    // code exists to enforce: ONE slot, the one the user selected.
    //
    // The two escapes were `continue`, and they worked only because the refusal
    // sits AFTER the loop. Straight-line, both become "no usable mnemonic", the
    // block is skipped, `active_seed_idx` stays None, and the same refusal
    // fires. That equivalence is the whole of this change; nothing else moves.
    let slot = &seed_mgr.slots[active_mgr_slot];
    // An xprv or raw-key slot cannot be reached through the mnemonic
    // derivation below. Falling through to another slot would sign with a key
    // the user did not select, so this refuses instead.
    //
    // `as_mnemonic` rather than `slot.indices`: on a raw-key or xprv slot that
    // array holds a packed private key, and feeding it to
    // `seed_from_mnemonic_*` reads key bytes as BIP39 word indices. The kind
    // guard and the read are one expression so a future edit cannot separate
    // them (H-08).
    let usable = if slot.is_empty() || slot.is_raw_key() || slot.word_count == 2 {
        None
    } else {
        slot.as_mnemonic()
    };
    if let Some((indices, wc)) = usable {
        // Claimed only once a mnemonic is proven present. Claimed earlier, a
        // slot that passed the kind guard but failed `as_mnemonic` left the
        // index claimed with no seed stored: `sign_transaction_multisig` skips
        // it on the `.1` flag, so the outcome was an unsigned result rather
        // than the explicit refusal below.
        active_seed_idx = Some(seed_idx);
        let pp = slot.as_passphrase()
            .and_then(|b| core::str::from_utf8(b).ok())
            .unwrap_or("");
        let seed = if wc == 12 {
            let m12 = wallet::bip39::Mnemonic12 {
                indices: { let mut arr = [0u16; 12]; arr.copy_from_slice(&indices[..12]); arr }
            };
            wallet::bip39::seed_from_mnemonic_12(&m12, pp)
        } else {
            let m24 = wallet::bip39::Mnemonic24 {
                indices: { let mut arr = [0u16; 24]; arr.copy_from_slice(&indices[..24]); arr }
            };
            wallet::bip39::seed_from_mnemonic_24(&m24, pp)
        };
        seeds[seed_idx] = (seed.bytes, true);
        seed_idx += 1;
    }
    let t_after_seeds = Instant::now();
    crate::log!("[sign_t] seed derivation: {} ms ({} slots, active={})",
        (t_after_seeds - t_start).as_millis(), seed_idx,
        active_seed_idx.map(|i| i as i32).unwrap_or(-1));

    // Same refusal as the KSPT path: an xprv or raw-key slot cannot be used
    // by the mnemonic derivation above, and there is no longer another slot
    // to fall through to.
    if active_seed_idx.is_none() {
        crate::log!("[sign] refused: selected slot holds no usable seed");
        for (s, _) in seeds.iter_mut() { zeroize_seed(s); }
        return 0;
    }

    // The COUNT matters, not just Ok/Err. This used to be `.is_err()`, which
    // let `Ok(0)` through: no key matched any input, nothing was signed, and
    // the device serialized and displayed a QR that looks like a signed
    // response and carries no new signature. The user broadcasts it and the
    // node rejects it, with nothing on the device having said so.
    //
    // Observed 2026-08-15 with vector M3 (45' hint pointing at the wrong
    // cosigner index): 9 frames emitted, 0/2 signatures, no error. The refusal
    // to sign was CORRECT - the key derived at the hinted path is not in the
    // redeem script, and the redeem script is the authority - but staying
    // silent about it was not.
    //
    // The likely causes, in order: the payload is missing its
    // `bip32_derivations` map, the hint points at a path this wallet does not
    // own, or the transaction simply is not ours to sign. All three are the
    // same outcome for the user and the log names them.
    let new_sigs = match wallet::pskt::sign_transaction_multisig(
        tx, &seeds, wallet::transaction::SigHashType::All, active_seed_idx,
    ) {
        Ok(n) => n,
        Err(_) => {
            crate::log!("[pskt] multisig: signing failed: no loaded key matches any input");
            for (s, _) in seeds.iter_mut() { zeroize_seed(s); }
            return 0;
        }
    };
    if new_sigs == 0 {
        crate::log!(
            "[pskt] multisig: no key matched any input ({} inputs). Missing or wrong \
             bip32_derivations, or this wallet is not a cosigner.",
            tx.num_inputs
        );
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
    let mut tmp: alloc::vec::Vec<u8> = alloc::vec![0u8; crate::app::data::SIGNED_QR_BUF_LEN];
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
            // Dev builds reach this arm even when the hash did NOT match:
            // features/verify.rs logs "[DEV] WARNING: Hash mismatch, continuing"
            // and then returns Valid regardless, so this arm cannot be used to
            // claim the firmware was verified. Report the build kind instead.
            // The displayed hash is still shown, which is what a developer
            // checks against their own build. See H-02.
            #[cfg(feature = "production")]
            {
                log!("Firmware verified OK");
            }
            #[cfg(not(feature = "production"))]
            {
                log!("Firmware check complete (dev build, not enforced)");
            }

            #[cfg(feature = "production")]
            let boot_status = BootStatus::Valid;
            #[cfg(not(feature = "production"))]
            let boot_status = BootStatus::DevBuild;

            boot_display
                .show_verification_screen(
                    version_str.as_str(),
                    hash_short.as_str(),
                    boot_status,
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
                // Pre-check: will the signed TX fit in the signed_qr_buf?
                // Capacity is read from the buffer itself rather than
                // repeated here; the previous copy said 4096 while the
                // buffer was 8192. Header=48, per
                // input=156, per output=45.
                //
                // These are KSPT figures. PSKB costs about 878 wire bytes
                // per unsigned input and 568 more once signed, so a PSKB
                // bundle passes this check and then fails in the
                // serializer; that path has its own pre-flight in
                // `sign_and_serialize_pskt_multi`. (Was 1024, a stale value
                // from when the buffer was smaller: it rejected valid
                // 6-input consolidations that fit fine.)
                let estimated_size = 48
                    + (ad.demo_tx.num_inputs * 156)
                    + (ad.demo_tx.num_outputs * 45);
                let cap = ad.signed_qr_buf.len();
                if estimated_size > cap {
                    log!("   ✗ TX too large: {} inputs × 156 + {} outputs × 45 = ~{} bytes (max {})",
                        ad.demo_tx.num_inputs, ad.demo_tx.num_outputs, estimated_size, cap);
                    boot_display.draw_tx_error_screen(
                        "Too many inputs!",
                        "Consolidate UTXOs first");
                    sound::beep_error(delay);
                    ad.app.state = crate::app::input::AppState::Rejected;
                    ad.needs_redraw = false; // already drawn
                    return;
                }

                // Ensure pubkeys are cached (for display after signing).
                // Goes through fill_display_caches, which dispatches on
                // word_count: calling derive_all_pubkeys directly here
                // panicked on xprv and raw-key slots, whose packed key
                // bytes were read as BIP39 word indices.
                if !ad.pubkeys_cached {
                    boot_display.draw_saving_screen("Deriving addresses...");
                    fill_display_caches(ad);
                }
                // Progress through the review, not a key operation. Signing
                // happens once, on the last input, in the branch below. The
                // old wording said "Signing input N/M" for every step, so a
                // log could read "Signing input 10/10" immediately followed
                // by "refused before signing", which is a contradiction.
                log!("   Input {}/{} reviewed", input_idx + 1, ad.app.total_inputs);

                // On last input, sign all and serialize
                // Use multi-address signing: each input is matched to the correct key
                if (input_idx + 1) >= ad.app.total_inputs {
                    // Reset frame state from any previous signing
                    ad.signed_qr_nframes = 0;
                    ad.signed_qr_frame = 0;
                    ad.signed_qr_large = false;
                    ad.qr_manual_frames = false;
                    // The LENGTH was missing from this list, and the refusal
                    // below reads it. Every other field here was cleared per
                    // signing run and this one persisted for the whole
                    // session, so after any successful signing the check
                    // downstream passed on the PREVIOUS transaction's value
                    // and stopped testing anything. That is the M3 case the
                    // check exists for, quietly reopened for every
                    // transaction after the first successful one.
                    //
                    // Here rather than at the top of the function: this is the
                    // only place a signing run begins, so re-entering the
                    // review of an earlier input cannot wipe a result that has
                    // already been produced.
                    ad.signed_qr_len = 0;

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
                                // Scratch: the serializer needs both
                                // `&ad.signed_qr_buf` (read: it still holds the
                                // decoded incoming JSON from parse time) and
                                // `&mut ad.signed_qr_buf[..]` (write: the
                                // output). Two borrows of one field.
                                //
                                // This used to be resolved by passing an EMPTY
                                // slice, which silently broke every bundle
                                // carrying an unknown region. `scratch_range`
                                // returns `Err(UnexpectedToken)` when
                                // `end > scratch.len()`, and its callers use
                                // `?`, so ONE captured region aborts the whole
                                // serialization. `unwrap_or(0)` then turns that
                                // into `signed_qr_len = 0`, and the user gets
                                // "Signing Failed" for a transaction that
                                // signed correctly and failed only to
                                // re-serialize.
                                //
                                // Confirmed on hardware with three test
                                // vectors: an unknown top-level field, a
                                // non-empty `global.proprietaries`, and a
                                // non-empty `input.proprietaries`. All three
                                // signed in ~170 ms and returned 0 bytes.
                                //
                                // Fixed by copying the decoded JSON into PSRAM
                                // so the two borrows are of different memory.
                                // Allocated only when there is something to
                                // preserve: canonical bundles carry no unknown
                                // regions and pay nothing.
                                let scratch_empty: [u8; 0] = [];
                                let scratch_owned: alloc::vec::Vec<u8> =
                                    if ad.pskt_parsed.unknowns_count > 0 {
                                        let n = (ad.pskt_parsed.json_len as usize)
                                            .min(ad.signed_qr_buf.len());
                                        let mut v = alloc::vec::Vec::new();
                                        if v.try_reserve(n).is_ok() {
                                            v.extend_from_slice(&ad.signed_qr_buf[..n]);
                                        } else {
                                            crate::log!("   [pskt] PSRAM alloc failed, unknown regions will not survive");
                                        }
                                        v
                                    } else {
                                        alloc::vec::Vec::new()
                                    };
                                let scratch: &[u8] = if scratch_owned.is_empty() {
                                    &scratch_empty
                                } else {
                                    &scratch_owned
                                };
                                if has_multisig {
                                    ad.signed_qr_len = sign_and_serialize_pskt_multisig(
                                        &mut ad.demo_tx, &ad.seed_mgr,
                                        &ad.pskt_parsed,
                                        scratch,
                                        format,
                                        &mut ad.signed_qr_buf[..],
                                    );
                                    let (present, required) =
                                        wallet::std_pskt::pskt_signature_status(&ad.demo_tx);
                                    ad.tx_sigs_present = present;
                                    ad.tx_sigs_required = required;
                                    // Three outcomes, not two. A zero-length
                                    // response means the signer refused and
                                    // added nothing, and saying "pass to next
                                    // signer" there tells the user to hand on a
                                    // payload that gained no signature.
                                    // Observed with vector M3 (45' hint at the
                                    // wrong cosigner index): the refusal was
                                    // correct, the line that followed it was not.
                                    if ad.signed_qr_len == 0 {
                                        log!("   REFUSED: nothing signed, no response emitted");
                                    } else if present < required {
                                        log!("   Partial: {}/{} sigs — pass to next signer", present, required);
                                    } else {
                                        log!("   Fully signed: {}/{}", present, required);
                                    }
                                } else {
                                    // Session account-key cache: the PBKDF2
                                    // stretch runs once per session, not per
                                    // signing (this was the fixed ~20s).
                                    let t0 = esp_hal::xtensa_lx::timer::get_cycle_count();
                                    let acct_ready = ensure_session_account_key(ad);
                                    let t1 = esp_hal::xtensa_lx::timer::get_cycle_count();
                                    if acct_ready {
                                        let acct_raw = ad.acct_key_raw;
                                        // Disjoint field borrows: NO array copies
                                        // (12.8KB on the sign stack would repeat
                                        // the precomputed-tables overflow).
                                        ad.signed_qr_len = sign_and_serialize_pskt_multi(
                                            &mut ad.demo_tx, &acct_raw,
                                            Some((&mut ad.ext_recv[..], &mut ad.ext_recv_n, &mut ad.ext_chg[..], &mut ad.ext_chg_n)),
                                            &ad.pskt_parsed,
                                            scratch,
                                            format,
                                            &mut ad.signed_qr_buf[..],
                                        );
                                    } else {
                                        ad.signed_qr_len = 0;
                                    }
                                    let t2 = esp_hal::xtensa_lx::timer::get_cycle_count();
                                    crate::log!("   [t] acct={}ms sign+ser={}ms",
                                        t1.wrapping_sub(t0) / 240_000, t2.wrapping_sub(t1) / 240_000);
                                    let (present, required) =
                                        wallet::std_pskt::pskt_signature_status(&ad.demo_tx);
                                    ad.tx_sigs_present = present;
                                    ad.tx_sigs_required = required;
                                }
                            }
                        }
                    } else if let Some(slot) = ad.seed_mgr.active_slot() {
                        if let Some(mut key) = slot.as_raw_key() {
                            // Raw key: sign with stored privkey directly.
                            // `as_raw_key` replaces `is_raw_key()` plus a
                            // separate unpack, so the check and the decode are
                            // one operation (H-08).
                            ad.signed_qr_len = sign_and_serialize(&mut ad.demo_tx, &key, &mut ad.signed_qr_buf[..]);
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
                                    &mut ad.signed_qr_buf[..]);
                                let (present, required) = wallet::pskt::signature_status(&ad.demo_tx);
                                ad.tx_sigs_present = present;
                                ad.tx_sigs_required = required;
                                // Same three outcomes as the PSKB path above.
                                if ad.signed_qr_len == 0 {
                                    log!("   REFUSED: nothing signed, no response emitted");
                                } else if present < required {
                                    log!("   Partial: {}/{} sigs — pass to next signer", present, required);
                                } else {
                                    log!("   Fully signed: {}/{}", present, required);
                                }
                            } else {
                                // Standard P2PK: sign with active slot seed
                                ad.tx_sigs_present = 0;
                                ad.tx_sigs_required = 0;
                                let t0 = esp_hal::xtensa_lx::timer::get_cycle_count();
                                let acct_ready = ensure_session_account_key(ad);
                                let t1 = esp_hal::xtensa_lx::timer::get_cycle_count();
                                if acct_ready {
                                    let acct_raw = ad.acct_key_raw;
                                    ad.signed_qr_len = sign_and_serialize_multi(&mut ad.demo_tx, &acct_raw, Some((&mut ad.ext_recv[..], &mut ad.ext_recv_n, &mut ad.ext_chg[..], &mut ad.ext_chg_n)), &mut ad.signed_qr_buf[..]);
                                } else {
                                    ad.signed_qr_len = 0;
                                }
                                let t2 = esp_hal::xtensa_lx::timer::get_cycle_count();
                                crate::log!("   [t] acct={}ms sign+ser={}ms",
                                    t1.wrapping_sub(t0) / 240_000, t2.wrapping_sub(t1) / 240_000);
                                // Residue measurement. `Seed` zeroizes on drop,
                                // so any hit here is a copy left behind by the
                                // move out of `derive_seed` or by derivation
                                // internals, in a frame no `Drop` reaches.
                                #[cfg(feature = "sentinel-scan")]
                                crate::app::stack_probe::scan_seed_needle("after signing");
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
                            // Marker renamed from KSSN_HEX_* on 2026-08-14 (N-05).
                            // What this dumps is `signed_qr_buf`, filled by
                            // `sign_and_serialize_multi` -> `serialize_signed_pskt`,
                            // which writes PSKT_MAGIC, "KSPT". KSSN is a different
                            // format (SIGNED_MAGIC, pskt.rs:87) that this device has
                            // never emitted here: it is reachable only from
                            // `pskt::test_full_sign_flow`. The label named a format
                            // the payload is not.
                            log!("   KSPT_HEX_START");
                            log!("{}", s);
                            log!("   KSPT_HEX_END");
                        }
                    }
                    // Nothing was signed. Say so, and do NOT walk to the QR
                    // screens.
                    //
                    // INSIDE the last-input block, which is the whole point.
                    // It used to sit outside it, immediately after the closing
                    // brace, at the same depth as the `if` itself. On input 1
                    // of a MULTI-INPUT transaction the signing block is
                    // correctly skipped, because signing runs once on the last
                    // input, so the length was correctly still zero and this
                    // refused a transaction that had not been given its chance
                    // yet. It returned before `advance_signing()`, so input 2
                    // never happened and no multi-input transaction could be
                    // signed at all unless a previous run had left a stale
                    // non-zero length behind.
                    //
                    // Found on hardware 2026-09-01 with a 2-in 1-out bundle
                    // the device owned at m/44'/111111'/0'/0/0: cold boot
                    // refused it, and it signed only after an unrelated
                    // single-input vector had signed first. The serial ended
                    // at "Input 1/2 reviewed" with nothing after it, because
                    // every line that follows lives in the block being
                    // skipped.
                    //
                    // `advance_signing()` moved to ShowQrFrameChoice regardless of
                    // the result, and `ShowQR` draws its payload under
                    // `if ad.signed_qr_len > 0`, so a zero-signature attempt ended
                    // on an EMPTY screen. The refusal existed only in the log,
                    // which a production build does not print, so the user saw a
                    // signing attempt produce a blank page and nothing else.
                    //
                    // Not hypothetical: vector M3 on 2026-08-15, a 45' hint aimed
                    // at the wrong cosigner index, emitted 9 frames with 0 of 2
                    // signatures and no error. Returning 0 fixed the fake signed
                    // payload; this fixes what the user is told about it.
                    //
                    // Three causes land here and are indistinguishable at this
                    // point, so the message names none of them: the payload has no
                    // `bip32_derivations`, the hint points at a path this wallet
                    // does not own, or the transaction is not ours to sign. The log
                    // above already separates them for anyone with a serial cable.
                    if ad.signed_qr_len == 0 {
                        boot_display.draw_rejected_screen("Nothing signed");
                        {
                            use crate::hw::display::*;
                            let msg = "No key matched this bundle";
                            let mw = measure_body(msg);
                            draw_lato_body(&mut boot_display.display, msg, (320 - mw) / 2, 155, COLOR_TEXT_DIM);
                        }
                        sound::beep_error(delay);
                        // Same shape as the "No seed loaded" refusal above: a local
                        // Delay to hold the message, rather than borrowing the one
                        // passed in.
                        {
                            let d = esp_hal::delay::Delay::new();
                            d.delay_millis(3000);
                        }
                        ad.app.state = crate::app::input::AppState::Rejected;
                        ad.needs_redraw = true;
                        return;
                    }
                }

                ad.app.advance_signing();

                // The signing path has produced a payload, so whatever
                // `signed_qr_buf` held before (a descriptor QR left over from
                // the multisig create or descriptor screen) is gone. Clear the
                // descriptor flag HERE, on both the single-sig and the multisig
                // route. It used to be cleared only inside the single-sig
                // branch below, so a multisig sign after viewing a descriptor
                // reached ShowQrFrameChoice with the flag still set: the picker
                // was titled DESCRIPTOR QR and ShowQR framed the signed bundle
                // as a descriptor. Found on the provisioned units, 2026-08-18.
                ad.qr_is_descriptor = false;

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
                // Auto-cycle: Phone/KasSee = ~400ms, KasSigner = ~2s
                let cycle_interval = if ad.signed_qr_via_density { 2000u32 } else { 400u32 };
                if ad.idle_ticks % cycle_interval != 0 {
                    return;
                }
                ad.signed_qr_frame = (ad.signed_qr_frame + 1) % ad.signed_qr_nframes;
                let n_frames = ad.signed_qr_nframes as usize;
                let balanced = (ad.signed_qr_len + n_frames - 1) / n_frames;
                let offset = ad.signed_qr_frame as usize * balanced;
                let remaining = ad.signed_qr_len.saturating_sub(offset);
                let frag_len = remaining.min(balanced);
                if frag_len > 0 {
                    let mut frame_buf = [0u8; 230];
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
                    // A descriptor is not a transaction, so the signature badge
                    // means nothing beside it. `demo_tx` still holds whatever was
                    // parsed last, which is where the stale m-of-n came from.
                    //
                    // The SECOND of two badge draws: `redraw.rs` has the other.
                    // Guarding only that one left this path - the frame-paging
                    // redraw - still drawing it, which is why the badge came back
                    // as soon as the frames advanced.
                    let is_multisig = !ad.qr_is_descriptor
                        && (0..ad.demo_tx.num_inputs).any(|i| {
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
