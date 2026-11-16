// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Recognising standard script shapes (upstream:
//! `crypto/txscript/src/script_class.rs`, and
//! `crypto/txscript/src/standard/multisig.rs` for multisig).
//!
//! The standard forms have exact byte layouts upstream defines; KCC-3's
//! redeem script ([`kcc3_key`]) is a wallet convention kaspanet publishes,
//! exact all the same. Nothing else belongs here: recognising a covenant
//! means knowing a construction somebody wrote. Those render through the
//! disassembler, as the wire format has no covenant type byte: a
//! self-declared label comes from the party a signer exists to distrust.
//!
//! The engine accepts more than this recognises: at the pin script numbers
//! need not be minimal (`crypto/txscript/src/data_stack.rs`), so a redeem
//! script with a non-minimal count runs, while [`parse_multisig`] reads
//! counts only as `ScriptBuilder::add_i64` writes them. The safe direction:
//! such a script is shown as it is, not named a multisig.

use super::{Disassembler, Step};
use crate::address::Version;
use crate::constants::MAX_SCRIPT_PUBLIC_KEY_VERSION;
use crate::multisig::MAX_KEYS;
use crate::tx::ScriptPublicKey;

/// Standard locking script forms, under the one script version consensus
/// runs. Anything else is `NonStandard`, a valid covenant included.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScriptClass {
    NonStandard,
    /// `OpData32 <32 bytes> OpCheckSig`
    PubKey,
    /// `OpData33 <33 bytes> OpCheckSigEcdsa`
    PubKeyEcdsa,
    /// `OpBlake2b OpData32 <32 bytes> OpEqual`
    ScriptHash,
}

const OP_DATA_32: u8 = 0x20;
const OP_DATA_33: u8 = 0x21;
const OP_1: u8 = 0x51;
const OP_16: u8 = 0x60;
const OP_BLAKE2B: u8 = 0xaa;
const OP_CHECKSIG_ECDSA: u8 = 0xab;
const OP_CHECKSIG: u8 = 0xac;
const OP_CHECKMULTISIG: u8 = 0xae;
const OP_EQUAL: u8 = 0x87;

/// Pay to public key: 34 bytes, a 32-byte push then a signature check.
pub const fn is_pay_to_pubkey(spk: &[u8]) -> bool {
    spk.len() == 34 && spk[0] == OP_DATA_32 && spk[33] == OP_CHECKSIG
}

/// Pay to public key, ECDSA: 35 bytes, a 33-byte push then an ECDSA check.
pub const fn is_pay_to_pubkey_ecdsa(spk: &[u8]) -> bool {
    spk.len() == 35 && spk[0] == OP_DATA_33 && spk[34] == OP_CHECKSIG_ECDSA
}

/// Pay to script hash: 35 bytes, a hash opcode, a 32-byte push, an equality
/// check.
pub const fn is_pay_to_script_hash(spk: &[u8]) -> bool {
    spk.len() == 35 && spk[0] == OP_BLAKE2B && spk[1] == OP_DATA_32 && spk[34] == OP_EQUAL
}

/// Classify a locking script (upstream: `ScriptClass::from_script`).
///
/// Any version but [`MAX_SCRIPT_PUBLIC_KEY_VERSION`] is `NonStandard`: the
/// engine accepts a spend under a higher version unrun
/// (`AcceptedUnknownVersion`), so the key in its bytes guards nothing.
pub const fn classify(spk: &ScriptPublicKey<'_>) -> ScriptClass {
    let script = spk.script;
    if spk.version != MAX_SCRIPT_PUBLIC_KEY_VERSION {
        ScriptClass::NonStandard
    } else if is_pay_to_pubkey(script) {
        ScriptClass::PubKey
    } else if is_pay_to_pubkey_ecdsa(script) {
        ScriptClass::PubKeyEcdsa
    } else if is_pay_to_script_hash(script) {
        ScriptClass::ScriptHash
    } else {
        ScriptClass::NonStandard
    }
}

/// The address payload of a standard locking script: its version and the
/// key or script hash it pushes, for [`crate::address::encode`] (upstream:
/// `extract_script_pub_key_address`). `None` where [`classify`] says
/// `NonStandard` and upstream errs with `PubKeyFormat`.
pub fn address_payload<'a>(spk: &ScriptPublicKey<'a>) -> Option<(Version, &'a [u8])> {
    let script = spk.script;
    match classify(spk) {
        ScriptClass::PubKey => Some((Version::PubKey, &script[1..33])),
        ScriptClass::PubKeyEcdsa => Some((Version::PubKeyEcdsa, &script[1..34])),
        ScriptClass::ScriptHash => Some((Version::ScriptHash, &script[2..34])),
        ScriptClass::NonStandard => None,
    }
}

/// A recognised multisig redeem script: `m`, the keys, `n`, and the check.
/// Keys are borrowed from the script; `n` is the keys present, which equal
/// the declared count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Multisig<'a> {
    /// Signatures required.
    pub required: u8,
    /// Keys present.
    pub total: u8,
    /// The key pushes, walked by [`Multisig::keys`].
    script: &'a [u8],
}

impl<'a> Multisig<'a> {
    /// The public keys, in script order.
    pub fn keys(&self) -> impl Iterator<Item = &'a [u8]> + '_ {
        Disassembler::new(self.script)
            .filter_map(Result::ok)
            .filter(|s: &Step<'a>| !s.data.is_empty())
            .map(|s| s.data)
    }
}

/// The 32-byte pushes of a script, in order: the Schnorr keys it names, as a
/// BIP340 key reaches a checking opcode as a push of that width. Reading
/// bytes, not naming a construction. A 33-byte (ECDSA) push is not yielded.
/// Ends at a truncated push, which [`Disassembler`] does not guess at.
pub fn schnorr_keys(script: &[u8]) -> impl Iterator<Item = &[u8]> + '_ {
    Disassembler::new(script)
        .filter_map(Result::ok)
        .filter(|s: &Step<'_>| s.data.len() == 32)
        .map(|s| s.data)
}

/// Whether `redeem` is the script `spk` locks to: `spk` is
/// pay-to-script-hash by [`classify`], version included, and carries
/// [`redeem_hash`] of `redeem`. Without this check a signer signs against a
/// redeem script the network never runs.
pub fn redeem_matches(spk: &ScriptPublicKey<'_>, redeem: &[u8]) -> bool {
    classify(spk) == ScriptClass::ScriptHash && redeem_hash(redeem)[..] == spk.script[2..34]
}

/// The hash a pay-to-script-hash script carries for `redeem`: Blake2b-256,
/// unkeyed, as upstream's `pay_to_script_hash_script` and `OpBlake2b` compute
/// it.
pub fn redeem_hash(redeem: &[u8]) -> [u8; 32] {
    use blake2::digest::consts::U32;
    use blake2::{Blake2b, Digest};

    let mut out = [0u8; 32];
    out.copy_from_slice(&Blake2b::<U32>::digest(redeem));
    out
}

/// The key of KCC-3's redeem script, "Pay-to-Public-Key-Hash via P2SH"
/// (`kaspanet/kccs` pull request 37): exactly `<P> OP_CHECKSIG`, P a 32-byte
/// x-only key. `None` for any other script, a longer one ending the same way
/// included: the address commits to the hash of this exact script.
pub fn kcc3_key(redeem: &[u8]) -> Option<&[u8]> {
    is_pay_to_pubkey(redeem).then(|| &redeem[1..33])
}

/// Bytes of a pay-to-public-key script: a 32-byte push and the check.
pub const PAY_TO_PUBKEY_LEN: usize = 34;

/// Bytes of a pay-to-script-hash script: the hash opcode, a 32-byte push and
/// the equality check.
pub const PAY_TO_SCRIPT_HASH_LEN: usize = 35;

/// The script that pays `key`: `<key> OP_CHECKSIG` (upstream:
/// `pay_to_pub_key`).
pub const fn pay_to_pubkey(key: &[u8; 32]) -> [u8; PAY_TO_PUBKEY_LEN] {
    let mut out = [0u8; PAY_TO_PUBKEY_LEN];
    out[0] = OP_DATA_32;
    let mut i = 0;
    while i < 32 {
        out[1 + i] = key[i];
        i += 1;
    }
    out[33] = OP_CHECKSIG;
    out
}

/// The script that pays the redeem script hashing to `hash`:
/// `OP_BLAKE2B <hash> OP_EQUAL` (upstream: `pay_to_script_hash`).
pub const fn pay_to_script_hash(hash: &[u8; 32]) -> [u8; PAY_TO_SCRIPT_HASH_LEN] {
    let mut out = [0u8; PAY_TO_SCRIPT_HASH_LEN];
    out[0] = OP_BLAKE2B;
    out[1] = OP_DATA_32;
    let mut i = 0;
    while i < 32 {
        out[2 + i] = hash[i];
        i += 1;
    }
    out[34] = OP_EQUAL;
    out
}

/// Bytes of KCC-3's redeem script: a 32-byte push and the check.
pub const KCC3_REDEEM_LEN: usize = PAY_TO_PUBKEY_LEN;

/// KCC-3's redeem script for `key`: `<key> OP_CHECKSIG`, the
/// pay-to-public-key script behind a script hash.
pub const fn kcc3_redeem(key: &[u8; 32]) -> [u8; KCC3_REDEEM_LEN] {
    pay_to_pubkey(key)
}

/// The script hash a KCC-3 address for `key` carries, under the script-hash
/// version: [`redeem_hash`] of [`kcc3_redeem`].
pub fn kcc3_script_hash(key: &[u8; 32]) -> [u8; 32] {
    redeem_hash(&kcc3_redeem(key))
}

/// A count up to [`MAX_KEYS`] as `ScriptBuilder::add_i64` writes it: `OP_0`,
/// `OP_1` to `OP_16`, or a one-byte push of 17 to 20. The value and the
/// offset after it.
fn read_count(script: &[u8], at: usize) -> Option<(u8, usize)> {
    match *script.get(at)? {
        0x00 => Some((0, at + 1)),
        op @ OP_1..=OP_16 => Some((op - OP_1 + 1, at + 1)),
        0x01 => {
            let v = *script.get(at + 1)?;
            (17..=MAX_KEYS as u8).contains(&v).then_some((v, at + 2))
        }
        _ => None,
    }
}

/// Recognise a multisig redeem script: the threshold, each key as a 32-byte
/// push, the key count, `OP_CHECKMULTISIG`, both numbers as `add_i64` writes
/// them. At most [`MAX_KEYS`] keys and a threshold no larger than their
/// count, as the engine accepts (`op_check_multisig_schnorr_or_ecdsa`);
/// anything else is `None`.
///
/// The declared count must match the keys present: a script claiming three
/// and carrying two is not multisig. Nor is a threshold of zero, which the
/// engine takes with no signature: anyone's to spend. [`multisig_shape`]
/// reads that for a signer that refuses it by name.
pub fn parse_multisig(script: &[u8]) -> Option<Multisig<'_>> {
    multisig_shape(script).filter(|m| m.required > 0)
}

/// A multisig-shaped script as [`parse_multisig`] reads one, a threshold of
/// zero included, so a signer can refuse it by name.
pub fn multisig_shape(script: &[u8]) -> Option<Multisig<'_>> {
    let (required, keys_start) = read_count(script, 0)?;
    let mut at = keys_start;
    let mut count: usize = 0;
    while script.get(at) == Some(&OP_DATA_32) {
        if at + 33 > script.len() {
            return None;
        }
        at += 33;
        count += 1;
    }
    let keys_end = at;
    let (declared, at) = read_count(script, at)?;
    if script.get(at) != Some(&OP_CHECKMULTISIG) || at + 1 != script.len() {
        return None;
    }
    if count == 0 || count > MAX_KEYS || usize::from(declared) != count {
        return None;
    }
    if required > declared {
        return None;
    }
    Some(Multisig {
        required,
        total: declared,
        script: &script[keys_start..keys_end],
    })
}
