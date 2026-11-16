// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! KSPT, the transaction format.
//!
//! Version `0x06` is canonical and the one this crate's writer produces.
//! `0x01` to `0x05` are read in [`legacy`], as the container reads
//! `KAS\x04`: the two ends of a scan update separately, so a unit on new
//! firmware still reads a companion nobody updated. The old path gains no
//! features. One old shape is still produced, [`legacy::write_signed`]: the
//! single-signature reply a wallet built on v1.0.7 reads.
//!
//! The earlier versions folded two axes, signed or not and hints or not,
//! into one number, and `flags` decided field widths: `0x01` signed, `0x02`
//! a redeem script on every input, `0x04` a covenant binding inline on every
//! output. That made three body shapes behind five version bytes. `0x06`
//! makes the signature count and the redeem length unconditional, zero when
//! unsigned, and covenants records, so `flags` is reserved. It costs three
//! bytes per unsigned input, and no header bit can disagree with the body.
//!
//! [`parse`] validates the framing and returns borrowed views; inputs,
//! outputs and records are walked by iterator, so a caller copies what it
//! needs into its own storage. Every limit is the caller's [`Profile`]: a
//! larger one makes no payload valid, it lets the caller read a larger one.

pub mod legacy;
pub mod transaction;
mod writer;

pub use writer::{
    draft_len, write, write_draft, written_len, CoinCovenant, Draft, InputSignature, Mismatch,
    SIGNATURE_LEN,
};

use crate::profile::Profile;
use kassigner_kaspa::constants::checked_add_value;

/// Every payload begins with these four bytes.
pub const MAGIC: [u8; 4] = *b"KSPT";

/// The canonical version, and the only one written.
pub const VERSION: u8 = 0x06;

/// The escape value in a script-length field: a length of 255 or more is
/// this byte and a `u16`. The short form is required wherever it fits, so
/// this is never a literal length.
pub(crate) const LEN_ESCAPE: u8 = 0xFF;

/// One signature record: position, sighash type, signature.
pub(crate) const SIG_RECORD_LEN: usize = 1 + 1 + 64;

pub(crate) const REC_COVENANT: u8 = 0x43;
pub(crate) const REC_HINT_IN: u8 = 0x44;
pub(crate) const REC_HINT_OUT: u8 = 0x45;
pub(crate) const REC_KCC3_HINT_IN: u8 = 0x46;
pub(crate) const REC_ACCOUNT_HINT_IN: u8 = 0x47;
pub(crate) const REC_ACCOUNT_HINT_OUT: u8 = 0x48;
pub(crate) const REC_COIN_COVENANT: u8 = 0x49;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KsptError {
    /// Ran out of bytes mid-field.
    Truncated { at: usize },
    /// Not a KSPT payload.
    BadMagic,
    /// A version byte no reader implements.
    UnsupportedVersion(u8),
    /// A legacy version reached the canonical parser: unlike
    /// `UnsupportedVersion`, readable by [`legacy::parse`].
    UseLegacyParser(u8),
    /// `flags` is reserved in `0x06` and must be zero: up to `0x05` it was a
    /// live bitfield.
    ReservedFlags(u8),
    /// A count or length exceeds the caller's profile.
    OverProfile {
        field: Field,
        value: usize,
        limit: usize,
    },
    /// Zero inputs, or zero outputs.
    Empty { field: Field },
    /// A script length used the escape where the short form fits: two
    /// encodings of one length would make two byte strings of one
    /// transaction.
    NonCanonicalLength { at: usize },
    /// A second record naming something an earlier one already named: two
    /// covenant bindings for one output, two hints for one input or output,
    /// or two covenants for one input's coin. On a legacy shape a covenant record for an output already
    /// bound inline is the second binding. Refused rather than resolved:
    /// keeping either drops what the sender wrote in the other.
    RepeatedRecord { marker: u8, at: usize },
    /// A record naming an input or output the payload does not have: `index`
    /// past the inputs for `0x44`, `0x46`, `0x47` and `0x49`, past the
    /// outputs for `0x43`, `0x45` and `0x48`. Refused rather than skipped: a sender that
    /// knows what it sent writes no record pointing at nothing.
    RecordIndexOutOfRange { marker: u8, at: usize, index: u8 },
    /// A covenant binding, a `0x43` record or one bound inline, binding
    /// `output` to an authorizing `input` the payload does not have.
    /// Consensus refuses it (`AuthInputOutOfBounds`); refused here, no reader
    /// of the records indexes the inputs with it.
    AuthorizingInputOutOfRange { at: usize, output: u8, input: u16 },
    /// A record marker this version does not define. `0x53` among them, on
    /// every version: a retired stealth tweak no signer applied. Never reuse
    /// it: an old companion may still send it.
    UnknownRecord { marker: u8, at: usize },
    /// Bytes remain after the last record: a signer must not sign a payload
    /// it only partly understood.
    TrailingData { at: usize },
    /// A value, or a running total, exceeds the total supply: amounts each
    /// legal can sum to more than exists.
    ValueOutOfRange { field: Field, at: usize },
    /// A covenant present-flag that is neither zero nor one, on a legacy
    /// shape. Read as absent, it would drop a binding the sender meant.
    BadCovenantFlag { at: usize, value: u8 },
    /// The caller's output buffer is too small.
    BufferTooSmall,
    /// A payload was to be written from a transaction and a source payload
    /// that describe different transactions. See [`write()`].
    SourceMismatch { at: Mismatch },
    /// A signature to write names an input the transaction does not have.
    NoSuchInput { index: usize },
    /// Two signatures for one key position on one input: to write, or read
    /// from a payload, on every version.
    DuplicateSignature { input: usize, pubkey_pos: u8 },
    /// A `0x06` input's signature at `pubkey_pos` follows one at a higher
    /// position. The writer emits them ascending, so `0x06` has one encoding
    /// of a transaction. Older versions are not held to it: v1.0.7 appended
    /// each signature, so a reply passed from a cosigner at a later position
    /// to one at an earlier one descends.
    SignaturesOutOfOrder { input: usize, pubkey_pos: u8 },
    /// A signature already on an input is not 64 bytes: the legacy
    /// single-signature shape declares any length.
    SignatureLength { input: usize, len: usize },
    /// A count or length larger than its field on the wire can hold.
    Unencodable { field: Field, value: usize },
}

/// Which limit was exceeded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Field {
    Inputs,
    Outputs,
    Script,
    Redeem,
    Payload,
    Signatures,
    /// An input's UTXO amount, or their running total.
    Amount,
    /// An output value, or their running total.
    Value,
}

/// A parsed payload, borrowing the bytes it was read from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Kspt<'a> {
    /// Format version. `0x06` from `parse`, one of `0x01` to `0x05` from
    /// [`legacy::parse`].
    pub version: u8,
    /// Kaspa's transaction version, which selects the signature hash layout.
    /// Not this format's version.
    pub tx_version: u16,
    pub num_inputs: usize,
    pub num_outputs: usize,
    pub lock_time: u64,
    pub subnetwork_id: [u8; 20],
    pub gas: u64,
    pub payload: &'a [u8],
    pub(crate) inputs: &'a [u8],
    pub(crate) outputs: &'a [u8],
    pub(crate) records: &'a [u8],
    pub(crate) shape: Shape,
}

/// How a body is laid out, so a caller can tell what it read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shape {
    /// `0x06`. Unconditional signature count and redeem length, covenants as
    /// records.
    Canonical,
    /// `0x01` without the signed flag, and `0x04` with or without it.
    /// Optional `u8` redeem and inline covenants, each under its flag bit.
    /// No signatures.
    LegacyUnsigned {
        has_redeem: bool,
        has_covenant: bool,
    },
    /// `0x01` with the signed flag. One signature per input as a length and a
    /// sighash byte, inline covenants under their flag bit, no redeem script.
    LegacySingleSig { has_covenant: bool },
    /// `0x02`, `0x03`, `0x05`. A signature count, then a redeem length one or
    /// two bytes wide, covenants as records.
    LegacyMultiSig { redeem_width: usize },
}

impl Shape {
    /// True when a covenant binding sits inside each output rather than
    /// arriving as a record.
    pub(crate) const fn inline_covenant(self) -> bool {
        matches!(
            self,
            Shape::LegacyUnsigned {
                has_covenant: true,
                ..
            } | Shape::LegacySingleSig { has_covenant: true }
        )
    }
}

/// One input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Input<'a> {
    pub prev_tx_id: [u8; 32],
    pub prev_index: u32,
    /// Sompi of the UTXO being spent: a signature commits to it, and the
    /// transaction does not otherwise carry it.
    pub amount: u64,
    pub sequence: u64,
    pub sig_op_count: u8,
    pub spk_version: u16,
    pub spk: &'a [u8],
    /// The signature bytes as on the wire, empty when unsigned. Read them
    /// through [`Input::signatures`]: [`Shape::LegacySingleSig`] stores one
    /// signature then its sighash byte, every other shape 66-byte records.
    pub signatures: &'a [u8],
    pub sig_count: usize,
    /// Empty when absent.
    pub redeem: &'a [u8],
    /// The shape this input was read under, which tells
    /// [`Input::signatures`] the layout.
    pub shape: Shape,
}

/// One signature on an input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signature<'a> {
    pub pubkey_pos: u8,
    pub sighash_type: u8,
    pub bytes: &'a [u8],
}

/// One output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Output<'a> {
    pub value: u64,
    pub spk_version: u16,
    pub spk: &'a [u8],
    /// Present only on the legacy shapes that carry it inline. On `0x06` a
    /// binding arrives as a [`Record::Covenant`].
    pub covenant: Option<CovenantBinding>,
}

/// An output's covenant binding: level 0's type, since the signature hash
/// folds it in and it belongs with the consensus rules.
pub use kassigner_kaspa::tx::CovenantBinding;

/// A record after the outputs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Record<'a> {
    /// `0x43`. Binds one output to a covenant. One per output.
    Covenant {
        output_index: u8,
        authorizing_input: u16,
        covenant_id: &'a [u8; 32],
    },
    /// `0x44`. Which derivation produced an input's address. One per input.
    InputHint(Hint),
    /// `0x45`. The same for an output, which is what lets a device verify
    /// change. One per output.
    OutputHint(Hint),
    /// `0x46`. Which KCC-3 address an input's is: chain and index below the
    /// KCC-3 account, `m/22'/111111'/0'`, for an input a companion knows by
    /// its address alone. One hint of any kind per input. The canonical
    /// version only.
    Kcc3InputHint(Kcc3Hint),
    /// `0x47`. Where an input's key is below the single-key account,
    /// `m/44'/111111'/0'`: chain and index, for an input past the unit's
    /// first addresses that its search would reach slowly or not at all.
    /// One hint of any kind per input. The canonical version only.
    AccountInputHint(AccountHint),
    /// `0x48`. The same for an output, so a unit can mark change past its
    /// first addresses. An output has this or a `0x45`, never both. The
    /// canonical version only.
    AccountOutputHint(AccountHint),
    /// `0x49`. The covenant the coin an input spends is bound to, as a node
    /// lists it on the UTXO (upstream's `UtxoEntry::covenant_id`, a bundle's
    /// `utxoEntry.covenantId`). An input with no such record spends an
    /// unbound coin. No signature covers it: it is what a node knows of the
    /// coin, which decides whether an output's binding continues a covenant
    /// and how much storage the coin frees. One per input. The canonical
    /// version only.
    CoinCovenant {
        input_index: u8,
        covenant_id: &'a [u8; 32],
    },
}

/// A KCC-3 address below its account: which input, its chain and index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Kcc3Hint {
    pub index: u8,
    pub chain: u32,
    pub addr_index: u32,
}

/// A key below the single-key account: which input or output, its chain
/// and index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccountHint {
    pub index: u8,
    pub chain: u32,
    pub addr_index: u32,
}

/// A derivation path below the account key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hint {
    pub index: u8,
    pub cosigner: u32,
    pub chain: u32,
    pub addr_index: u32,
}

/// Reads fields left to right, tracking where it is so an error can say where.
pub(crate) struct Cursor<'a> {
    pub(crate) b: &'a [u8],
    pub(crate) pos: usize,
}

impl<'a> Cursor<'a> {
    pub(crate) const fn new(b: &'a [u8]) -> Self {
        Self { b, pos: 0 }
    }
    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], KsptError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(KsptError::Truncated { at: self.pos })?;
        if end > self.b.len() {
            return Err(KsptError::Truncated { at: self.pos });
        }
        let s = &self.b[self.pos..end];
        self.pos = end;
        Ok(s)
    }
    pub(crate) fn u8(&mut self) -> Result<u8, KsptError> {
        Ok(self.take(1)?[0])
    }
    pub(crate) fn u16(&mut self) -> Result<u16, KsptError> {
        let s = self.take(2)?;
        Ok(u16::from_le_bytes([s[0], s[1]]))
    }
    pub(crate) fn u32(&mut self) -> Result<u32, KsptError> {
        let s = self.take(4)?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }
    pub(crate) fn u64(&mut self) -> Result<u64, KsptError> {
        let s = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(s);
        Ok(u64::from_le_bytes(a))
    }
    pub(crate) fn array<const N: usize>(&mut self) -> Result<&'a [u8; N], KsptError> {
        let s = self.take(N)?;
        s.try_into()
            .map_err(|_| KsptError::Truncated { at: self.pos })
    }
    /// A script length: one byte, or the escape then a `u16`.
    pub(crate) fn script_len(&mut self) -> Result<usize, KsptError> {
        let at = self.pos;
        let first = self.u8()?;
        if first != LEN_ESCAPE {
            return Ok(first as usize);
        }
        let long = self.u16()? as usize;
        if long < LEN_ESCAPE as usize {
            return Err(KsptError::NonCanonicalLength { at });
        }
        Ok(long)
    }
    pub(crate) const fn remaining(&self) -> usize {
        self.b.len() - self.pos
    }
}

pub(crate) fn bound(field: Field, value: usize, limit: usize) -> Result<(), KsptError> {
    if value > limit {
        return Err(KsptError::OverProfile {
            field,
            value,
            limit,
        });
    }
    Ok(())
}

/// Parse a canonical `0x06` payload.
///
/// # Errors
///
/// `UseLegacyParser` for `0x01` to `0x05` ([`legacy::parse`] reads them);
/// otherwise the first violation, left to right.
pub fn parse<'a>(bytes: &'a [u8], profile: &Profile) -> Result<Kspt<'a>, KsptError> {
    let mut c = Cursor::new(bytes);

    if c.take(4)? != MAGIC {
        return Err(KsptError::BadMagic);
    }
    let vb = c.u8()?;
    if vb != VERSION {
        return Err(if (0x01..=0x05).contains(&vb) {
            KsptError::UseLegacyParser(vb)
        } else {
            KsptError::UnsupportedVersion(vb)
        });
    }
    let flags = c.u8()?;
    if flags != 0 {
        return Err(KsptError::ReservedFlags(flags));
    }
    read_body(bytes, c, VERSION, Shape::Canonical, profile)
}

/// Read the global block, inputs, outputs and records; shared with
/// [`legacy::parse`], which differs in the header and the shape.
pub(crate) fn read_body<'a>(
    bytes: &'a [u8],
    mut c: Cursor<'a>,
    version: u8,
    shape: Shape,
    profile: &Profile,
) -> Result<Kspt<'a>, KsptError> {
    let tx_version = c.u16()?;
    let num_inputs = c.u8()? as usize;
    let num_outputs = c.u8()? as usize;
    let lock_time = c.u64()?;
    let subnetwork_id = *c.array::<20>()?;
    let gas = c.u64()?;
    let payload_len = c.u16()? as usize;

    if num_inputs == 0 {
        return Err(KsptError::Empty {
            field: Field::Inputs,
        });
    }
    if num_outputs == 0 {
        return Err(KsptError::Empty {
            field: Field::Outputs,
        });
    }
    bound(Field::Inputs, num_inputs, profile.max_inputs)?;
    bound(Field::Outputs, num_outputs, profile.max_outputs)?;
    bound(Field::Payload, payload_len, profile.max_payload)?;

    let payload = c.take(payload_len)?;

    // Walk to find where each region ends. The iterators walk the same bytes
    // again, a second pass over a few hundred bytes, so the caller keeps its
    // own storage.
    let inputs_start = c.pos;
    let mut total_in = 0u64;
    for i in 0..num_inputs {
        skip_input(&mut c, shape, profile, &mut total_in, i)?;
    }
    let inputs = &bytes[inputs_start..c.pos];

    let outputs_start = c.pos;
    let mut total_out = 0u64;
    // Outputs bound inline, so a record cannot bind one of them again.
    let mut inline = Seen::new();
    for i in 0..num_outputs {
        skip_output(
            &mut c,
            shape,
            profile,
            &mut total_out,
            i,
            &mut inline,
            num_inputs,
        )?;
    }
    let outputs = &bytes[outputs_start..c.pos];

    let records_start = c.pos;
    validate_records(&mut c, version, inline, num_inputs, num_outputs)?;
    let records = &bytes[records_start..c.pos];

    if c.remaining() != 0 {
        return Err(KsptError::TrailingData { at: c.pos });
    }

    Ok(Kspt {
        version,
        tx_version,
        num_inputs,
        num_outputs,
        lock_time,
        subnetwork_id,
        gas,
        payload,
        inputs,
        outputs,
        records,
        shape,
    })
}

fn skip_input(
    c: &mut Cursor<'_>,
    shape: Shape,
    p: &Profile,
    total: &mut u64,
    at: usize,
) -> Result<(), KsptError> {
    c.take(32)?; // prev_tx_id
    c.take(4)?; // prev_index
    let amount = c.u64()?;
    *total = checked_add_value(*total, amount).ok_or(KsptError::ValueOutOfRange {
        field: Field::Amount,
        at,
    })?;
    c.take(8)?; // sequence
    c.take(1)?; // sig_op_count
    c.take(2)?; // spk_version
    let spk_len = c.script_len()?;
    bound(Field::Script, spk_len, p.max_script)?;
    c.take(spk_len)?;

    match shape {
        Shape::Canonical => {
            let sig_count = c.u8()? as usize;
            bound(Field::Signatures, sig_count, p.max_sigs_per_input)?;
            skip_signatures(c, sig_count, true, at)?;
            let redeem_len = c.u16()? as usize;
            bound(Field::Redeem, redeem_len, p.max_redeem)?;
            c.take(redeem_len)?;
        }
        Shape::LegacyUnsigned { has_redeem, .. } => {
            if has_redeem {
                let redeem_len = c.u8()? as usize;
                bound(Field::Redeem, redeem_len, p.max_redeem)?;
                c.take(redeem_len)?;
            }
        }
        Shape::LegacySingleSig { .. } => {
            // A length rather than a count: zero, or a signature of that
            // length and a sighash byte. One signature at most: no multisig.
            let sig_len = c.u8()? as usize;
            if sig_len > 0 {
                c.take(sig_len)?;
                c.take(1)?; // sighash type
            }
        }
        Shape::LegacyMultiSig { redeem_width } => {
            let sig_count = c.u8()? as usize;
            bound(Field::Signatures, sig_count, p.max_sigs_per_input)?;
            skip_signatures(c, sig_count, false, at)?;
            let redeem_len = match redeem_width {
                1 => c.u8()? as usize,
                _ => c.u16()? as usize,
            };
            bound(Field::Redeem, redeem_len, p.max_redeem)?;
            c.take(redeem_len)?;
        }
    }
    Ok(())
}

/// Step over input `input`'s `count` signature records, at most one per key
/// position and, with `ascending` (`0x06`), positions strictly ascending.
fn skip_signatures(
    c: &mut Cursor<'_>,
    count: usize,
    ascending: bool,
    input: usize,
) -> Result<(), KsptError> {
    // One bit a position: a position is a byte.
    let mut seen = [0u64; 4];
    let mut last: Option<u8> = None;
    for _ in 0..count {
        let pubkey_pos = c.u8()?;
        c.take(SIG_RECORD_LEN - 1)?; // sighash type and signature
        let (word, bit) = (usize::from(pubkey_pos / 64), 1u64 << (pubkey_pos % 64));
        if seen[word] & bit != 0 {
            return Err(KsptError::DuplicateSignature { input, pubkey_pos });
        }
        seen[word] |= bit;
        if ascending && last.is_some_and(|l| pubkey_pos < l) {
            return Err(KsptError::SignaturesOutOfOrder { input, pubkey_pos });
        }
        last = Some(pubkey_pos);
    }
    Ok(())
}

/// Step over output `at`, marking it in `inline` if it carries a binding
/// inline, whose authorizing input must be one of the `inputs`.
fn skip_output(
    c: &mut Cursor<'_>,
    shape: Shape,
    p: &Profile,
    total: &mut u64,
    at: usize,
    inline: &mut Seen,
    inputs: usize,
) -> Result<(), KsptError> {
    let value = c.u64()?;
    *total = checked_add_value(*total, value).ok_or(KsptError::ValueOutOfRange {
        field: Field::Value,
        at,
    })?;
    c.take(2)?; // spk_version
    let spk_len = c.script_len()?;
    bound(Field::Script, spk_len, p.max_script)?;
    c.take(spk_len)?;

    if shape.inline_covenant() {
        let index = at as u8; // fewer than 256 outputs: the count is a byte
        let at = c.pos;
        match c.u8()? {
            0 => {}
            1 => {
                let input = c.u16()?;
                if usize::from(input) >= inputs {
                    return Err(KsptError::AuthorizingInputOutOfRange {
                        at,
                        output: index,
                        input,
                    });
                }
                c.take(32)?; // covenant id
                inline.mark(index);
            }
            // Neither absent nor present: refused, not read as absent.
            value => return Err(KsptError::BadCovenantFlag { at, value }),
        }
    }
    Ok(())
}

/// Walk the records, refusing anything left over. One loop dispatching on
/// the marker, so records may come in any order.
///
/// `bound` arrives holding the outputs a legacy shape bound inline: a record
/// binding one of them again is refused like a second record. A hint names
/// one of `inputs` or `outputs`, and a covenant record one of `outputs` and
/// an authorizing input one of `inputs`, or they are refused.
pub(crate) fn validate_records(
    c: &mut Cursor<'_>,
    version: u8,
    mut bound: Seen,
    inputs: usize,
    outputs: usize,
) -> Result<(), KsptError> {
    // Hints exist on 0x04, 0x05 and the canonical version, and KCC-3's and
    // the single-key account's on the canonical version alone. A record type
    // belongs to a version, not to whoever appends one.
    let hints_allowed = matches!(version, 0x04 | 0x05 | VERSION);
    let canonical_hints_allowed = version == VERSION;
    // What has been named already. An index is a byte, so 256 bits each.
    let mut hinted_in = Seen::new();
    let mut hinted_out = Seen::new();
    // A coin's covenant is no hint: an input may have one of each.
    let mut coins = Seen::new();
    loop {
        if c.remaining() == 0 {
            return Ok(());
        }
        let at = c.pos;
        let marker = c.b[c.pos];
        match marker {
            REC_COVENANT => {
                c.u8()?;
                let index = c.u8()?;
                let input = c.u16()?;
                c.take(32)?;
                if usize::from(index) >= outputs {
                    return Err(KsptError::RecordIndexOutOfRange { marker, at, index });
                }
                if usize::from(input) >= inputs {
                    return Err(KsptError::AuthorizingInputOutOfRange {
                        at,
                        output: index,
                        input,
                    });
                }
                if !bound.mark(index) {
                    return Err(KsptError::RepeatedRecord { marker, at });
                }
            }
            REC_HINT_IN | REC_HINT_OUT if hints_allowed => {
                c.u8()?;
                let index = c.u8()?;
                c.take(4 + 4 + 4)?;
                let (seen, count) = if marker == REC_HINT_IN {
                    (&mut hinted_in, inputs)
                } else {
                    (&mut hinted_out, outputs)
                };
                if usize::from(index) >= count {
                    return Err(KsptError::RecordIndexOutOfRange { marker, at, index });
                }
                if !seen.mark(index) {
                    return Err(KsptError::RepeatedRecord { marker, at });
                }
            }
            // An input's KCC-3 address or single-key account key, and an
            // output's single-key account key: one hint an input or output,
            // of any kind.
            REC_KCC3_HINT_IN | REC_ACCOUNT_HINT_IN | REC_ACCOUNT_HINT_OUT
                if canonical_hints_allowed =>
            {
                c.u8()?;
                let index = c.u8()?;
                c.take(4 + 4)?;
                let (seen, count) = if marker == REC_ACCOUNT_HINT_OUT {
                    (&mut hinted_out, outputs)
                } else {
                    (&mut hinted_in, inputs)
                };
                if usize::from(index) >= count {
                    return Err(KsptError::RecordIndexOutOfRange { marker, at, index });
                }
                if !seen.mark(index) {
                    return Err(KsptError::RepeatedRecord { marker, at });
                }
            }
            // The covenant an input's coin is bound to.
            REC_COIN_COVENANT if canonical_hints_allowed => {
                c.u8()?;
                let index = c.u8()?;
                c.take(32)?;
                if usize::from(index) >= inputs {
                    return Err(KsptError::RecordIndexOutOfRange { marker, at, index });
                }
                if !coins.mark(index) {
                    return Err(KsptError::RepeatedRecord { marker, at });
                }
            }
            _ => return Err(KsptError::UnknownRecord { marker, at }),
        }
    }
}

/// Which indices a record type has named so far.
pub(crate) struct Seen([u64; 4]);

impl Seen {
    const fn new() -> Self {
        Self([0; 4])
    }

    /// Mark `index`, returning false if it was already marked.
    fn mark(&mut self, index: u8) -> bool {
        let bit = 1u64 << (index % 64);
        let word = &mut self.0[index as usize / 64];
        let fresh = *word & bit == 0;
        *word |= bit;
        fresh
    }
}

impl<'a> Kspt<'a> {
    /// How this payload's body is laid out.
    pub const fn shape(&self) -> Shape {
        self.shape
    }

    /// The inputs, in order.
    pub fn inputs(&self) -> InputIter<'a> {
        InputIter {
            c: Cursor::new(self.inputs),
            left: self.num_inputs,
            shape: self.shape,
        }
    }

    /// The outputs, in order.
    pub fn outputs(&self) -> OutputIter<'a> {
        OutputIter {
            c: Cursor::new(self.outputs),
            left: self.num_outputs,
            shape: self.shape,
        }
    }

    /// The records, in the order they appear.
    ///
    /// Order carries no meaning: the marker identifies a record.
    pub fn records(&self) -> RecordIter<'a> {
        RecordIter {
            c: Cursor::new(self.records),
        }
    }
}

/// Walks the inputs.
pub struct InputIter<'a> {
    c: Cursor<'a>,
    left: usize,
    shape: Shape,
}

impl<'a> Iterator for InputIter<'a> {
    type Item = Input<'a>;

    fn next(&mut self) -> Option<Input<'a>> {
        if self.left == 0 {
            return None;
        }
        self.left -= 1;
        // Validated on parse; a failure here would mean the two walks
        // disagree, and gives None rather than a panic.
        let prev_tx_id = *self.c.array::<32>().ok()?;
        let prev_index = self.c.u32().ok()?;
        let amount = self.c.u64().ok()?;
        let sequence = self.c.u64().ok()?;
        let sig_op_count = self.c.u8().ok()?;
        let spk_version = self.c.u16().ok()?;
        let spk_len = self.c.script_len().ok()?;
        let spk = self.c.take(spk_len).ok()?;

        let (signatures, sig_count, redeem) = match self.shape {
            Shape::Canonical => {
                let n = self.c.u8().ok()? as usize;
                let sigs = self.c.take(n * SIG_RECORD_LEN).ok()?;
                let rl = self.c.u16().ok()? as usize;
                (sigs, n, self.c.take(rl).ok()?)
            }
            Shape::LegacyUnsigned { has_redeem, .. } => {
                let redeem = if has_redeem {
                    let rl = self.c.u8().ok()? as usize;
                    self.c.take(rl).ok()?
                } else {
                    &[][..]
                };
                (&[][..], 0, redeem)
            }
            Shape::LegacySingleSig { .. } => {
                // A length, then the signature and its sighash type, taken in
                // one run for `signatures()` to split.
                let sig_len = self.c.u8().ok()? as usize;
                if sig_len > 0 {
                    (self.c.take(sig_len + 1).ok()?, 1, &[][..])
                } else {
                    (&[][..], 0, &[][..])
                }
            }
            Shape::LegacyMultiSig { redeem_width } => {
                let n = self.c.u8().ok()? as usize;
                let sigs = self.c.take(n * SIG_RECORD_LEN).ok()?;
                let rl = match redeem_width {
                    1 => self.c.u8().ok()? as usize,
                    _ => self.c.u16().ok()? as usize,
                };
                (sigs, n, self.c.take(rl).ok()?)
            }
        };

        Some(Input {
            prev_tx_id,
            prev_index,
            amount,
            sequence,
            sig_op_count,
            spk_version,
            spk,
            signatures,
            sig_count,
            redeem,
            shape: self.shape,
        })
    }
}

impl<'a> Input<'a> {
    /// The signatures on this input, [`Input::sig_count`] of them, whatever
    /// shape carried them.
    ///
    /// [`Signature::pubkey_pos`] is zero on [`Shape::LegacySingleSig`], which
    /// has no position field: it carries one signature for a single-key
    /// input, whose only key is position zero.
    pub fn signatures(&self) -> impl Iterator<Item = Signature<'a>> + '_ {
        // The legacy shape's one signature: the sighash byte is the last of
        // the run, the signature the rest, whatever length was declared.
        let lone = match self.shape {
            Shape::LegacySingleSig { .. } if !self.signatures.is_empty() => {
                let split = self.signatures.len() - 1;
                Some(Signature {
                    pubkey_pos: 0,
                    sighash_type: self.signatures[split],
                    bytes: &self.signatures[..split],
                })
            }
            _ => None,
        };
        // Records, on every other shape; empty on that one, so only one half
        // yields anything.
        let records: &'a [u8] = match self.shape {
            Shape::LegacySingleSig { .. } => &[],
            _ => self.signatures,
        };
        records
            .chunks_exact(SIG_RECORD_LEN)
            .map(|r| Signature {
                pubkey_pos: r[0],
                sighash_type: r[1],
                bytes: &r[2..],
            })
            .chain(lone)
    }
}

/// Walks the outputs.
pub struct OutputIter<'a> {
    c: Cursor<'a>,
    left: usize,
    shape: Shape,
}

impl<'a> Iterator for OutputIter<'a> {
    type Item = Output<'a>;

    fn next(&mut self) -> Option<Output<'a>> {
        if self.left == 0 {
            return None;
        }
        self.left -= 1;
        let value = self.c.u64().ok()?;
        let spk_version = self.c.u16().ok()?;
        let spk_len = self.c.script_len().ok()?;
        let spk = self.c.take(spk_len).ok()?;

        let covenant = if self.shape.inline_covenant() {
            match self.c.u8().ok()? {
                1 => Some(CovenantBinding {
                    authorizing_input: self.c.u16().ok()?,
                    covenant_id: *self.c.array::<32>().ok()?,
                }),
                _ => None,
            }
        } else {
            None
        };

        Some(Output {
            value,
            spk_version,
            spk,
            covenant,
        })
    }
}

/// Walks the records.
pub struct RecordIter<'a> {
    c: Cursor<'a>,
}

impl<'a> Iterator for RecordIter<'a> {
    type Item = Record<'a>;

    fn next(&mut self) -> Option<Record<'a>> {
        if self.c.remaining() == 0 {
            return None;
        }
        let marker = self.c.u8().ok()?;
        match marker {
            REC_COVENANT => {
                let output_index = self.c.u8().ok()?;
                let authorizing_input = self.c.u16().ok()?;
                Some(Record::Covenant {
                    output_index,
                    authorizing_input,
                    covenant_id: self.c.array::<32>().ok()?,
                })
            }
            REC_HINT_IN => Some(Record::InputHint(self.hint()?)),
            REC_HINT_OUT => Some(Record::OutputHint(self.hint()?)),
            REC_KCC3_HINT_IN => Some(Record::Kcc3InputHint(Kcc3Hint {
                index: self.c.u8().ok()?,
                chain: self.c.u32().ok()?,
                addr_index: self.c.u32().ok()?,
            })),
            REC_ACCOUNT_HINT_IN => Some(Record::AccountInputHint(self.account_hint()?)),
            REC_ACCOUNT_HINT_OUT => Some(Record::AccountOutputHint(self.account_hint()?)),
            REC_COIN_COVENANT => Some(Record::CoinCovenant {
                input_index: self.c.u8().ok()?,
                covenant_id: self.c.array::<32>().ok()?,
            }),
            _ => None,
        }
    }
}

impl RecordIter<'_> {
    fn hint(&mut self) -> Option<Hint> {
        Some(Hint {
            index: self.c.u8().ok()?,
            cosigner: self.c.u32().ok()?,
            chain: self.c.u32().ok()?,
            addr_index: self.c.u32().ok()?,
        })
    }

    fn account_hint(&mut self) -> Option<AccountHint> {
        Some(AccountHint {
            index: self.c.u8().ok()?,
            chain: self.c.u32().ok()?,
            addr_index: self.c.u32().ok()?,
        })
    }
}

/// Longest script this format can carry: the escape and a `u16` top out
/// here. Consensus allows a million bytes since the covenant fork, ten
/// thousand before it (`crypto/txscript/src/lib.rs`), so longer scripts are
/// legal on the network but not expressible here. The ESP32-S3 profile
/// bounds scripts far lower: 512 for a locking script, 1,024 for a redeem.
pub const MAX_SCRIPT_LEN: usize = u16::MAX as usize;

/// Bytes a script length occupies when written, for a length the format can
/// carry.
pub const fn script_len_size(len: usize) -> usize {
    if len < LEN_ESCAPE as usize {
        1
    } else {
        3
    }
}

/// Write a script length, in the short form wherever it fits. `field` is
/// what the length belongs to, so a refusal says which.
///
/// # Errors
///
/// `Unencodable` past [`MAX_SCRIPT_LEN`], which the field cannot express.
/// `BufferTooSmall` if `out` cannot hold it.
pub fn write_script_len(field: Field, len: usize, out: &mut [u8]) -> Result<usize, KsptError> {
    if len > MAX_SCRIPT_LEN {
        return Err(KsptError::Unencodable { field, value: len });
    }
    let n = script_len_size(len);
    if out.len() < n {
        return Err(KsptError::BufferTooSmall);
    }
    if n == 1 {
        out[0] = len as u8;
    } else {
        out[0] = LEN_ESCAPE;
        out[1..3].copy_from_slice(&(len as u16).to_le_bytes());
    }
    Ok(n)
}
