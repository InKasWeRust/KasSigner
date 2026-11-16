// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Legacy KSPT, versions `0x01` through `0x05`: read, and written in one
//! shape only. As with the container's `KAS\x04`, a device on new firmware
//! still reads what a companion nobody updated sends; the old path gains no
//! features.
//!
//! The one shape written is the single-signature reply, [`write_signed`]: a
//! wallet built on v1.0.7 sends `0x01` and reads only that answer. It is
//! there for those wallets and goes once they read `0x06`.
//!
//! The version byte alone does not decide the layout: `flags` was a live
//! bitfield, and its bits decided which fields a body holds.
//!
//! | version | flags | shape |
//! |---|---|---|
//! | `0x01` | bit `0x01` clear | unsigned: optional `u8` redeem, inline covenants |
//! | `0x01` | bit `0x01` set | single-signature: a `u8` length and a sighash byte, inline covenants, never a redeem |
//! | `0x04` | any | unsigned, as `0x01` with bit `0x01` clear; that bit is ignored |
//! | `0x02` | any | multi-signature: a signature count, `u8` redeem length |
//! | `0x03`, `0x05` | any | multi-signature: a signature count, `u16` redeem length |
//!
//! On the unsigned shape, bit `0x02` gives every input a redeem script. On
//! the unsigned and single-signature shapes, bit `0x04` gives every output
//! an inline covenant binding. The single-signature shape's signature field
//! is a length, not a count, so it cannot express multisig.

use super::{read_body, skip_input, Cursor, Kspt, KsptError, Shape, MAGIC, SIGNATURE_LEN};
use crate::profile::Profile;
use kassigner_kaspa::sighash::SIG_HASH_ALL;

/// `flags` bit meanings, up to `0x05`.
const FLAG_SIGNED: u8 = 0x01;
const FLAG_HAS_REDEEM: u8 = 0x02;
const FLAG_HAS_COVENANT: u8 = 0x04;

/// Every bit that meant something. Anything else was never written.
const KNOWN_FLAGS: u8 = FLAG_SIGNED | FLAG_HAS_REDEEM | FLAG_HAS_COVENANT;

/// Resolve a body shape from a version and its flags.
///
/// # Errors
///
/// `UnsupportedVersion` outside `0x01` to `0x05`, `ReservedFlags` for a bit
/// no version defined.
pub fn shape_of(version: u8, flags: u8) -> Result<Shape, KsptError> {
    if flags & !KNOWN_FLAGS != 0 {
        return Err(KsptError::ReservedFlags(flags));
    }
    let has_redeem = flags & FLAG_HAS_REDEEM != 0;
    let has_covenant = flags & FLAG_HAS_COVENANT != 0;
    let signed = flags & FLAG_SIGNED != 0;

    // A known bit a version does not use is ignored, not refused: v1.0.7
    // units set the signed bit on their `0x05` replies, which a refusal
    // would turn away. On `0x04` the signed bit is ignored and the payload
    // read as unsigned, as v1.0.7's parser reads it.
    match version {
        0x01 if signed => Ok(Shape::LegacySingleSig { has_covenant }),
        0x01 | 0x04 => Ok(Shape::LegacyUnsigned {
            has_redeem,
            has_covenant,
        }),
        0x02 => Ok(Shape::LegacyMultiSig { redeem_width: 1 }),
        0x03 | 0x05 => Ok(Shape::LegacyMultiSig { redeem_width: 2 }),
        v => Err(KsptError::UnsupportedVersion(v)),
    }
}

/// Parse a legacy payload, `0x01` through `0x05`.
///
/// The canonical [`super::parse`] returns `UseLegacyParser` for these, not
/// `UnsupportedVersion`, so a caller knows a reader exists.
///
/// # Errors
///
/// The first violation found, left to right.
pub fn parse<'a>(bytes: &'a [u8], profile: &Profile) -> Result<Kspt<'a>, KsptError> {
    let mut c = Cursor::new(bytes);

    if c.take(4)? != MAGIC {
        return Err(KsptError::BadMagic);
    }
    let version = c.u8()?;
    if version == super::VERSION {
        // The canonical parser reads this one.
        return Err(KsptError::UnsupportedVersion(version));
    }
    let flags = c.u8()?;
    let shape = shape_of(version, flags)?;
    read_body(bytes, c, version, shape, profile)
}

/// Read a payload of any version, canonical or legacy, as a reader taking
/// bytes off a camera must.
///
/// # Errors
///
/// `UnsupportedVersion` for a version byte nothing implements.
pub fn parse_any<'a>(bytes: &'a [u8], profile: &Profile) -> Result<Kspt<'a>, KsptError> {
    match super::parse(bytes, profile) {
        Err(KsptError::UseLegacyParser(_)) => parse(bytes, profile),
        other => other,
    }
}

/// Where `flags` sits: after the magic and the version.
const FLAGS_AT: usize = MAGIC.len() + 1;

/// What a single-signature reply adds after each input: a length byte, the
/// signature, its sighash type.
pub const SIGNED_RECORD_LEN: usize = 1 + SIGNATURE_LEN + 1;

/// The record's length byte.
const SIGNATURE_LEN_BYTE: u8 = 64;
const _: () = assert!(SIGNATURE_LEN_BYTE as usize == SIGNATURE_LEN);

/// Why [`write_signed`] wrote nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignedError {
    /// The request does not read as a legacy payload.
    Request(KsptError),
    /// Not a `0x01` request of single-key inputs: another version, signed
    /// already, or with a redeem script on its inputs.
    NotSingleKey,
    /// Not one signature for each input.
    Signatures { given: usize, inputs: usize },
    /// `out` is shorter than the reply.
    TooSmall { needed: usize },
}

/// A `0x01` request's reply as a v1.0.7 unit wrote it, into `out`,
/// returning its length: the request byte for byte, the signed flag set,
/// and after each input its signature, `signatures[i]` over
/// `SIGHASH_ALL`, as a length byte, the signature and the sighash type.
///
/// Only an unsigned `0x01` request with no redeem scripts has this answer:
/// the shape holds one signature an input and no redeem script, so it
/// cannot say multisig. The signatures are the caller's, taken as given:
/// read the reply back and verify it before showing it.
///
/// # Errors
///
/// As [`SignedError`]; nothing is written past what fits.
pub fn write_signed(
    request: &[u8],
    profile: &Profile,
    signatures: &[[u8; SIGNATURE_LEN]],
    out: &mut [u8],
) -> Result<usize, SignedError> {
    let parsed = parse(request, profile).map_err(SignedError::Request)?;
    let shape = parsed.shape;
    if parsed.version != 0x01
        || !matches!(
            shape,
            Shape::LegacyUnsigned {
                has_redeem: false,
                ..
            }
        )
    {
        return Err(SignedError::NotSingleKey);
    }
    if signatures.len() != parsed.num_inputs {
        return Err(SignedError::Signatures {
            given: signatures.len(),
            inputs: parsed.num_inputs,
        });
    }
    let needed = request.len() + parsed.num_inputs * SIGNED_RECORD_LEN;
    let Some(out) = out.get_mut(..needed) else {
        return Err(SignedError::TooSmall { needed });
    };

    // The inputs, outputs and records run to the request's end, so the
    // inputs begin that far from it.
    let rest = parsed.inputs.len() + parsed.outputs.len() + parsed.records.len();
    let inputs_at = request.len() - rest;
    out[..inputs_at].copy_from_slice(&request[..inputs_at]);
    out[FLAGS_AT] |= FLAG_SIGNED;

    let mut at = inputs_at;
    let mut c = Cursor::new(parsed.inputs);
    let mut total = 0u64;
    for (i, signature) in signatures.iter().enumerate() {
        let start = c.pos;
        skip_input(&mut c, shape, profile, &mut total, i).map_err(SignedError::Request)?;
        let input = &parsed.inputs[start..c.pos];
        out[at..at + input.len()].copy_from_slice(input);
        at += input.len();
        out[at] = SIGNATURE_LEN_BYTE;
        out[at + 1..at + 1 + SIGNATURE_LEN].copy_from_slice(signature);
        out[at + 1 + SIGNATURE_LEN] = SIG_HASH_ALL.to_u8();
        at += SIGNED_RECORD_LEN;
    }
    let tail = &request[inputs_at + parsed.inputs.len()..];
    out[at..at + tail.len()].copy_from_slice(tail);
    Ok(needed)
}
