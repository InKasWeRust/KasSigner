// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

// ext.rs — the extended pubkey bank scan used by the signing resolve
// path. Moved verbatim from bootloader/src/app/signing.rs (the banks
// themselves, the idle pump that fills them and `EXT_BANK_DEPTH` stay in
// the firmware; this is only the lookup and the extend-as-you-search).

use crate::wallet;

/// The extended pubkey banks as handed to the signing path:
/// (receive bank, receive fill front, change bank, change fill front).
///
/// Slices rather than fixed arrays: the banks are heap-allocated boxed
/// slices on `AppData`, so the depth is set once by
/// the firmware's `app::data::EXT_BANK_DEPTH` and read back with `.len()` instead
/// of being repeated as a literal in every signature.
///
/// The fronts are `&mut u16` because the deep scan advances them as it
/// derives, and the banks are `&mut` because it stores what it derives.
/// Both call sites borrow these as four disjoint fields of `AppData`,
/// alongside `&mut demo_tx` and `&mut signed_qr_buf`, so no bank is ever
/// copied onto the sign stack.
pub type ExtBanksMut<'a> = (&'a mut [[u8; 32]], &'a mut u16, &'a mut [[u8; 32]], &'a mut u16);

/// Look up a pubkey in the extended banks. Returns (index, is_change).
pub fn ext_find_pubkey(
    ext_recv: &[[u8; 32]], recv_n: u16,
    ext_chg: &[[u8; 32]], chg_n: u16,
    target: &[u8; 32],
) -> Option<(u16, bool)> {
    for i in 0..(recv_n as usize) {
        if &ext_recv[i] == target { return Some((i as u16, false)); }
    }
    for i in 0..(chg_n as usize) {
        if &ext_chg[i] == target { return Some((i as u16, true)); }
    }
    None
}

/// Find a pubkey's (index, is_change), extending the banks as it searches.
///
/// This replaces `bip32::find_address_index_for_pubkey` in the signing
/// resolve path. That function walked 100 receive indices and then 100
/// change indices and DISCARDED every derivation, so a change-chain
/// address at index 37 cost 137 derivations and the next signature at a
/// nearby index paid the same price again from scratch.
///
/// Three differences, all consequences of writing the results down:
///
/// 1. The already-filled part of the banks is a RAM comparison, so work
///    the idle pump has done is never repeated.
/// 2. New derivations are stored at their bank slot and the front is
///    advanced, so they serve every later lookup, later input, later
///    signature, and the pump resumes from the new front instead of
///    recovering ground already walked.
/// 3. Both chains advance together rather than the receive chain being
///    exhausted first, which halves the cost of a change-chain hit:
///    index 37 on the change chain is ~74 derivations, not 137.
///
/// The bound is the bank length, so `EXT_BANK_DEPTH` is the single place
/// the signing wall is defined. Raising it raises the real ceiling rather
/// than only the ceiling the idle pump happens to have reached.
///
/// Stack: this calls exactly what the function it replaces called
/// (`derive_address_key` / `derive_change_key` / `public_key_x_only`),
/// so the resolve-phase frame is unchanged. That matters because phase 1
/// in `sign_transaction_multi_addr` is deliberately the shallow half of
/// the signing pass.
pub fn ext_scan_find(
    acct: &wallet::bip32::ExtendedPrivKey,
    ext_recv: &mut [[u8; 32]], recv_n: &mut u16,
    ext_chg: &mut [[u8; 32]], chg_n: &mut u16,
    target: &[u8; 32],
) -> Option<(u16, bool)> {
    // Filled region first: no derivation, pure RAM.
    if let Some(hit) = ext_find_pubkey(ext_recv, *recv_n, ext_chg, *chg_n, target) {
        return Some(hit);
    }
    // Hoist the two chain keys and their public keys out of the loop.
    // `derive_address_key` / `derive_change_key` rebuild both on every
    // single index, which is two redundant scalar multiplies per step;
    // see `ChainParent`. Built here rather than by the caller so the
    // RAM-only fast path above never pays for them.
    let chain_recv = match wallet::bip32::ChainParent::new(acct, 0) {
        Ok(p) => p,
        Err(_) => return None,
    };
    let chain_chg = match wallet::bip32::ChainParent::new(acct, 1) {
        Ok(p) => p,
        Err(_) => return None,
    };
    loop {
        let r = *recv_n as usize;
        let c = *chg_n as usize;
        if r >= ext_recv.len() && c >= ext_chg.len() {
            return None;
        }
        // Advance the shorter chain, but never a chain that is already
        // full. Written as an explicit choice rather than an if/else-if
        // pair so that every iteration provably advances one front and
        // the loop cannot spin when the banks differ in length.
        let take_recv = r < ext_recv.len() && (r <= c || c >= ext_chg.len());
        if take_recv {
            // A derivation failure at an index is not fatal: skip it the
            // way the idle pump does, leaving the slot zeroed. A zeroed
            // slot cannot false-match, since an all-zero x-only pubkey is
            // not a valid point.
            *recv_n = (r + 1) as u16;
            if let Ok(key) = chain_recv.derive(r as u32) {
                if let Ok(pk) = key.public_key_x_only() {
                    ext_recv[r] = pk;
                    if &pk == target {
                        return Some((r as u16, false));
                    }
                }
            }
        } else {
            *chg_n = (c + 1) as u16;
            if let Ok(key) = chain_chg.derive(c as u32) {
                if let Ok(pk) = key.public_key_x_only() {
                    ext_chg[c] = pk;
                    if &pk == target {
                        return Some((c as u16, true));
                    }
                }
            }
        }
    }
}
