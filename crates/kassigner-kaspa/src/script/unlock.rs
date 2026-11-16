// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//! Writing the unlocking script that spends a signed output (upstream:
//! `pay_to_script_hash_signature_script` and `ScriptBuilder` in
//! `crypto/txscript/src/`, and the wallet's
//! `finalize_pskt_one_or_more_sig_and_redeem_script`). A signature is pushed
//! as `OP_DATA_65 <signature> <sighash type>`.
//!
//! `OP_CHECKMULTISIG` walks signatures against keys in the script's order and
//! wants exactly the threshold's number: one out of order, or one too many,
//! fails the spend. Upstream's finalizer pushes a map's order and all it
//! holds, which can fail a 2-of-3; this writer sorts by key position and
//! takes the first M.
//!
//! Pushes take the builder's forms: `OP_DATA_n` to 75 bytes, `OP_PUSHDATA1`
//! to 255, `OP_PUSHDATA2` to 65,535. Nothing pushed here is the single byte 1
//! to 16 or 0x81 that the builder writes as a small-number opcode.

/// `OP_PUSHDATA1`.
const OP_PUSHDATA1: u8 = 0x4c;
/// `OP_PUSHDATA2`.
const OP_PUSHDATA2: u8 = 0x4d;
/// The largest `OP_DATA_n`.
const OP_DATA_MAX: usize = 75;

/// Bytes of a signature's push: the opcode, 64 bytes, the sighash type.
pub const SIGNATURE_PUSH_LEN: usize = 1 + 64 + 1;

/// Why an unlocking script was not written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnlockError {
    /// The caller's buffer cannot hold the script.
    BufferTooSmall,
    /// A push longer than `OP_PUSHDATA2` carries.
    PushTooLong,
    /// Fewer signatures than the threshold, or two at one position.
    Signatures,
}

/// One signature with the position of its key in the script's key set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PositionedSignature<'a> {
    pub position: u8,
    pub sighash_type: u8,
    pub signature: &'a [u8; 64],
}

/// Bytes a push of `len` bytes takes with its opcode.
pub const fn push_len(len: usize) -> usize {
    if len <= OP_DATA_MAX {
        1 + len
    } else if len <= u8::MAX as usize {
        2 + len
    } else {
        3 + len
    }
}

/// `data` as a canonical push into `out`: bytes written.
///
/// # Errors
///
/// `PushTooLong` past 65,535 bytes, `BufferTooSmall`.
pub fn push(data: &[u8], out: &mut [u8]) -> Result<usize, UnlockError> {
    let len = data.len();
    if len > u16::MAX as usize {
        return Err(UnlockError::PushTooLong);
    }
    let total = push_len(len);
    let out = out.get_mut(..total).ok_or(UnlockError::BufferTooSmall)?;
    let head = if len <= OP_DATA_MAX {
        out[0] = len as u8;
        1
    } else if len <= u8::MAX as usize {
        out[0] = OP_PUSHDATA1;
        out[1] = len as u8;
        2
    } else {
        out[0] = OP_PUSHDATA2;
        out[1..3].copy_from_slice(&(len as u16).to_le_bytes());
        3
    };
    out[head..].copy_from_slice(data);
    Ok(total)
}

/// A signature's push: `OP_DATA_65`, the signature, the sighash type.
fn push_signature(s: &PositionedSignature<'_>, out: &mut [u8]) -> Result<usize, UnlockError> {
    let out = out
        .get_mut(..SIGNATURE_PUSH_LEN)
        .ok_or(UnlockError::BufferTooSmall)?;
    out[0] = 65;
    out[1..65].copy_from_slice(s.signature);
    out[65] = s.sighash_type;
    Ok(SIGNATURE_PUSH_LEN)
}

/// The unlocking script of a pay-to-public-key input: its one signature.
///
/// # Errors
///
/// `BufferTooSmall`.
pub fn single_key(
    signature: &[u8; 64],
    sighash_type: u8,
    out: &mut [u8],
) -> Result<usize, UnlockError> {
    push_signature(
        &PositionedSignature {
            position: 0,
            sighash_type,
            signature,
        },
        out,
    )
}

/// The unlocking script of a pay-to-script-hash input: `required`
/// signatures in key order, then the redeem script pushed. `signatures` may
/// hold more, in any order; the `required` lowest positions are taken. KCC-3
/// is one of one.
///
/// # Errors
///
/// `Signatures` for fewer than `required` positions, or two at a position
/// taken (two at a higher one may be refused too, depending on order);
/// `PushTooLong` for a redeem script past 65,535 bytes; `BufferTooSmall`.
pub fn script_hash(
    signatures: &[PositionedSignature<'_>],
    required: usize,
    redeem: &[u8],
    out: &mut [u8],
) -> Result<usize, UnlockError> {
    if signatures.len() < required {
        return Err(UnlockError::Signatures);
    }
    let mut n = 0usize;
    let mut last: Option<u8> = None;
    for _ in 0..required {
        // The lowest position above the last written; a pass each, as a
        // threshold is small and nothing here allocates.
        let mut next: Option<&PositionedSignature<'_>> = None;
        for s in signatures {
            if last.is_some_and(|l| s.position <= l) {
                continue;
            }
            match next {
                Some(best) if s.position > best.position => {}
                Some(best) if s.position == best.position => return Err(UnlockError::Signatures),
                _ => next = Some(s),
            }
        }
        let s = next.ok_or(UnlockError::Signatures)?;
        n += push_signature(s, &mut out[n..])?;
        last = Some(s.position);
    }
    n += push(redeem, out.get_mut(n..).ok_or(UnlockError::BufferTooSmall)?)?;
    Ok(n)
}

/// Bytes [`script_hash`] writes for `required` signatures over `redeem`.
pub const fn script_hash_len(required: usize, redeem_len: usize) -> usize {
    required * SIGNATURE_PUSH_LEN + push_len(redeem_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **Pushes take the builder's forms**, refused past 65,535 bytes.
    #[test]
    fn pushes_take_the_canonical_forms() {
        let mut out = [0u8; 70_000];
        assert_eq!(push(&[7; 75], &mut out), Ok(76));
        assert_eq!(out[0], 75);
        assert_eq!(push(&[7; 76], &mut out), Ok(78));
        assert_eq!(&out[..2], &[OP_PUSHDATA1, 76]);
        assert_eq!(push(&[7; 256], &mut out), Ok(259));
        assert_eq!(&out[..3], &[OP_PUSHDATA2, 0x00, 0x01]);
        assert_eq!(push(&[7; 65_536], &mut out), Err(UnlockError::PushTooLong));
        assert_eq!(
            push(&[7; 76], &mut [0u8; 77]),
            Err(UnlockError::BufferTooSmall)
        );
        assert_eq!(push_len(75), 76);
        assert_eq!(push_len(76), 78);
        assert_eq!(push_len(256), 259);
    }

    /// **Signatures by position, exactly the threshold, then the redeem
    /// script**; two at one position and too few are refused.
    #[test]
    fn signatures_come_out_by_position_then_the_redeem() {
        let a = [0xAA; 64];
        let b = [0xBB; 64];
        let c = [0xCC; 64];
        let at = |position, signature| PositionedSignature {
            position,
            sighash_type: 1,
            signature,
        };
        let redeem = [0x51; 100];
        let mut out = [0u8; 512];
        let n = script_hash(&[at(2, &c), at(0, &a), at(1, &b)], 2, &redeem, &mut out).unwrap();
        assert_eq!(n, script_hash_len(2, 100));
        assert_eq!(out[0], 65);
        assert_eq!(&out[1..65], &a);
        assert_eq!(out[65], 1);
        assert_eq!(&out[67..131], &b);
        assert_eq!(&out[132..134], &[OP_PUSHDATA1, 100]);
        assert_eq!(&out[134..234], &redeem);
        assert_eq!(
            script_hash(&[at(0, &a)], 2, &redeem, &mut out),
            Err(UnlockError::Signatures)
        );
        assert_eq!(
            script_hash(&[at(0, &a), at(0, &b)], 2, &redeem, &mut out),
            Err(UnlockError::Signatures)
        );
        let n = single_key(&a, 1, &mut out).unwrap();
        assert_eq!(n, SIGNATURE_PUSH_LEN);
        assert_eq!(&out[1..65], &a);
    }
}
