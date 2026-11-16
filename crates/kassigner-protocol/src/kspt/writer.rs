// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Writing a KSPT.
//!
//! A payload is written from a [`Transaction`] and the [`Kspt`] it was
//! mapped from ([`transaction`](super::transaction)): the payload gives what
//! a signature does not commit to (redeem scripts, signatures, hints, the
//! coins' covenants), the transaction the covenant bindings. Every field both carry is compared,
//! and a difference is refused: whatever built the pair has a bug.
//!
//! The output is always `0x06`: a legacy payload's inline bindings become
//! records, its single signature a record at key position zero. Signatures
//! present and added are merged in ascending key position, the order a
//! multisig unlocking script needs; two at one position are refused. Every
//! bound [`parse`](super::parse) checks is checked against the same profile,
//! and so are its other refusals: no input, no output, and a covenant
//! binding naming an input the transaction lacks.
//!
//! A KCC-3 input can arrive with no redeem script: its address is
//! `<P> OP_CHECKSIG` behind a hash, and P stays on the device. The signer
//! supplies it ([`InputSignature::redeem`]), only for an input that came
//! without one and whose lock is its hash.
//!
//! A companion has no source: it writes a [`Draft`] with [`write_draft`],
//! through the same encoder, so a request and its reply share one layout.
//!
//! [`write()`] measures first, and every refusal happens while measuring,
//! so on any error `out` is untouched.

use kassigner_kaspa::constants::checked_add_value;
use kassigner_kaspa::script::{redeem_matches, KCC3_REDEEM_LEN};
use kassigner_kaspa::tx::{CovenantBinding, ScriptPublicKey, Transaction};

use super::{
    bound, write_script_len, AccountHint, Field, Hint, Input, Kcc3Hint, Kspt, KsptError, Record,
    Seen, MAGIC, REC_ACCOUNT_HINT_IN, REC_ACCOUNT_HINT_OUT, REC_COIN_COVENANT, REC_COVENANT,
    REC_HINT_IN, REC_HINT_OUT, REC_KCC3_HINT_IN, VERSION,
};
use crate::profile::Profile;

/// Bytes of the signature in a signature record.
pub const SIGNATURE_LEN: usize = 64;

/// A signature to add to an input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InputSignature {
    /// The input it signs.
    pub input: usize,
    /// Which key of the input's key set made it. Zero on an input with one key.
    pub pubkey_pos: u8,
    pub sighash_type: u8,
    pub signature: [u8; SIGNATURE_LEN],
    /// KCC-3's `<P> OP_CHECKSIG`, which only the holder of P can write, for
    /// an input that came without a redeem script; `None` otherwise.
    pub redeem: Option<[u8; KCC3_REDEEM_LEN]>,
}

impl InputSignature {
    /// Filler for storage that has not been signed into yet.
    pub const EMPTY: InputSignature = InputSignature {
        input: 0,
        pubkey_pos: 0,
        sighash_type: 0,
        signature: [0; SIGNATURE_LEN],
        redeem: None,
    };
}

/// An unsigned request's extras beside a transaction, with no parsed
/// source. Each hint names its input or output, as the parser reads it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Draft<'a> {
    /// One per input, in order: its redeem script, or empty. One given must
    /// be the script the input's lock is the hash of.
    pub redeems: &'a [&'a [u8]],
    /// `0x44`: which derivation produced an input's address.
    pub input_hints: &'a [Hint],
    /// `0x46`: which KCC-3 address an input's is.
    pub kcc3_hints: &'a [Kcc3Hint],
    /// `0x47`: where an input's key is below the single-key account.
    pub account_hints: &'a [AccountHint],
    /// `0x45`: which derivation produced an output's address, so a unit can
    /// mark change.
    pub output_hints: &'a [Hint],
    /// `0x48`: where an output's key is below the single-key account, so a
    /// unit can mark change past its first addresses.
    pub account_output_hints: &'a [AccountHint],
    /// `0x49`: the covenant an input's coin is bound to, as a node lists it.
    /// None for an input whose coin is unbound.
    pub coin_covenants: &'a [CoinCovenant],
}

/// The covenant the coin input `index` spends is bound to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoinCovenant {
    pub index: u8,
    pub covenant_id: [u8; 32],
}

/// Bytes [`write_draft`] will produce, without producing them.
///
/// # Errors
///
/// Everything [`write_draft`] refuses except `BufferTooSmall`.
pub fn draft_len(
    draft: &Draft<'_>,
    tx: &Transaction<'_>,
    profile: &Profile,
) -> Result<usize, KsptError> {
    let mut sink = Sink { out: None, len: 0 };
    emit(Source::Draft(draft), tx, &[], profile, &mut sink)?;
    Ok(sink.len)
}

/// Write `tx` as a canonical unsigned payload carrying `draft`; returns
/// bytes written.
///
/// # Errors
///
/// - `Empty` for a transaction with no input or no output, as the parser
///   refuses it.
/// - `AuthorizingInputOutOfRange` for a covenant binding naming an input the
///   transaction lacks, at the offset where the parser would refuse it.
/// - `SourceMismatch { at: Counts }` for other than one redeem per input;
///   `at: Input(i)` for a redeem script input `i`'s lock is not the hash of.
/// - `NoSuchInput` for a hint, or a coin's covenant, naming an input or
///   output past the end.
/// - `RepeatedRecord` for a second hint of any kind naming one input or one
///   output, or a second covenant for one input's coin, at the offset where
///   the parser would refuse it.
/// - `OverProfile`, `Unencodable` and `ValueOutOfRange` for what could not
///   be parsed back under `profile`.
/// - `BufferTooSmall` if `out` is shorter than [`draft_len`].
pub fn write_draft(
    draft: &Draft<'_>,
    tx: &Transaction<'_>,
    profile: &Profile,
    out: &mut [u8],
) -> Result<usize, KsptError> {
    let needed = draft_len(draft, tx, profile)?;
    let out = out.get_mut(..needed).ok_or(KsptError::BufferTooSmall)?;
    let mut sink = Sink {
        out: Some(out),
        len: 0,
    };
    emit(Source::Draft(draft), tx, &[], profile, &mut sink)?;
    Ok(sink.len)
}

/// What the encoder writes beside a transaction: a parsed payload or a
/// draft.
#[derive(Clone, Copy)]
enum Source<'s, 'a> {
    Parsed(&'s Kspt<'a>),
    Draft(&'s Draft<'a>),
}

/// Where a transaction and its source payload disagreed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mismatch {
    /// Version, lock time, subnetwork, gas or payload.
    Global,
    /// The number of inputs or outputs.
    Counts,
    /// The input at this position.
    Input(usize),
    /// The output at this position.
    Output(usize),
}

/// Bytes [`write()`] will produce, without producing them.
///
/// # Errors
///
/// Everything [`write()`] refuses except `BufferTooSmall`.
pub fn written_len(
    source: &Kspt<'_>,
    tx: &Transaction<'_>,
    added: &[InputSignature],
    profile: &Profile,
) -> Result<usize, KsptError> {
    let mut sink = Sink { out: None, len: 0 };
    emit(Source::Parsed(source), tx, added, profile, &mut sink)?;
    Ok(sink.len)
}

/// Write `tx` as a canonical payload, carrying what `source` holds beyond
/// it, with `added` merged into the signatures; returns bytes written. With
/// nothing added, a canonical re-encoding of `source`.
///
/// # Errors
///
/// - `SourceMismatch` when `tx` and `source` differ in a field both carry,
///   or a supplied redeem script differs between signatures, goes into an
///   input that has one, or is not what the input's lock is the hash of.
/// - `NoSuchInput` for a signature naming an input past the end.
/// - `DuplicateSignature` for two signatures at one key position of one
///   input, added or already there.
/// - `SignatureLength` for a signature already present that is not 64
///   bytes, which the legacy single-signature shape can declare.
/// - `OverProfile`, `Unencodable` and `ValueOutOfRange` for what could not
///   be parsed back under `profile`.
/// - `BufferTooSmall` if `out` is shorter than [`written_len`].
pub fn write(
    source: &Kspt<'_>,
    tx: &Transaction<'_>,
    added: &[InputSignature],
    profile: &Profile,
    out: &mut [u8],
) -> Result<usize, KsptError> {
    let needed = written_len(source, tx, added, profile)?;
    let out = out.get_mut(..needed).ok_or(KsptError::BufferTooSmall)?;
    let mut sink = Sink {
        out: Some(out),
        len: 0,
    };
    emit(Source::Parsed(source), tx, added, profile, &mut sink)?;
    Ok(sink.len)
}

/// Where bytes go: a buffer, or nowhere while measuring.
struct Sink<'o> {
    out: Option<&'o mut [u8]>,
    len: usize,
}

impl Sink<'_> {
    fn put(&mut self, bytes: &[u8]) -> Result<(), KsptError> {
        let end = self
            .len
            .checked_add(bytes.len())
            .ok_or(KsptError::BufferTooSmall)?;
        if let Some(out) = self.out.as_deref_mut() {
            out.get_mut(self.len..end)
                .ok_or(KsptError::BufferTooSmall)?
                .copy_from_slice(bytes);
        }
        self.len = end;
        Ok(())
    }
}

/// A value within the caller's profile and within its field on the wire:
/// nothing stops a caller's profile exceeding what a one-byte count can say.
fn fits(field: Field, value: usize, limit: usize, width: usize) -> Result<(), KsptError> {
    bound(field, value, limit)?;
    if value > width {
        return Err(KsptError::Unencodable { field, value });
    }
    Ok(())
}

const U8_MAX: usize = u8::MAX as usize;
const U16_MAX: usize = u16::MAX as usize;

fn emit(
    source: Source<'_, '_>,
    tx: &Transaction<'_>,
    added: &[InputSignature],
    p: &Profile,
    s: &mut Sink<'_>,
) -> Result<(), KsptError> {
    let ni = tx.inputs.len();
    let no = tx.outputs.len();
    // What the parser refuses first; a parsed source never has it.
    if ni == 0 {
        return Err(KsptError::Empty {
            field: Field::Inputs,
        });
    }
    if no == 0 {
        return Err(KsptError::Empty {
            field: Field::Outputs,
        });
    }
    match source {
        Source::Parsed(k) => {
            if k.num_inputs != ni || k.num_outputs != no {
                return Err(KsptError::SourceMismatch {
                    at: Mismatch::Counts,
                });
            }
            if k.tx_version != tx.version
                || k.lock_time != tx.lock_time
                || k.subnetwork_id != tx.subnetwork_id
                || k.gas != tx.gas
                || k.payload != tx.payload
            {
                return Err(KsptError::SourceMismatch {
                    at: Mismatch::Global,
                });
            }
        }
        Source::Draft(d) => {
            if d.redeems.len() != ni {
                return Err(KsptError::SourceMismatch {
                    at: Mismatch::Counts,
                });
            }
            let inputs = d
                .input_hints
                .iter()
                .map(|h| h.index)
                .chain(d.kcc3_hints.iter().map(|h| h.index))
                .chain(d.account_hints.iter().map(|h| h.index))
                .chain(d.coin_covenants.iter().map(|c| c.index));
            if let Some(index) = inputs.map(usize::from).find(|&i| i >= ni) {
                return Err(KsptError::NoSuchInput { index });
            }
            if let Some(index) = d
                .output_hints
                .iter()
                .map(|h| h.index)
                .chain(d.account_output_hints.iter().map(|h| h.index))
                .map(usize::from)
                .find(|&k| k >= no)
            {
                return Err(KsptError::NoSuchInput { index });
            }
        }
    }
    fits(Field::Inputs, ni, p.max_inputs, U8_MAX)?;
    fits(Field::Outputs, no, p.max_outputs, U8_MAX)?;
    fits(Field::Payload, tx.payload.len(), p.max_payload, U16_MAX)?;
    if let Some(a) = added.iter().find(|a| a.input >= ni) {
        return Err(KsptError::NoSuchInput { index: a.input });
    }

    s.put(&MAGIC)?;
    // Flags: reserved in `0x06`.
    s.put(&[VERSION, 0])?;
    s.put(&tx.version.to_le_bytes())?;
    s.put(&[ni as u8, no as u8])?;
    s.put(&tx.lock_time.to_le_bytes())?;
    s.put(&tx.subnetwork_id)?;
    s.put(&tx.gas.to_le_bytes())?;
    s.put(&(tx.payload.len() as u16).to_le_bytes())?;
    s.put(tx.payload)?;

    let mut total = 0u64;
    let mut walked = 0usize;
    let mut parsed_inputs = match source {
        Source::Parsed(k) => Some(k.inputs()),
        Source::Draft(_) => None,
    };
    for (i, t) in tx.inputs.iter().enumerate() {
        let spk = &t.utxo_entry.script_public_key;
        // What the source holds for this input beyond the transaction: its
        // redeem script and signatures.
        let (arrived, held): (&[u8], Option<Input<'_>>) = match source {
            Source::Parsed(_) => {
                let r = parsed_inputs.as_mut().and_then(Iterator::next).ok_or(
                    KsptError::SourceMismatch {
                        at: Mismatch::Counts,
                    },
                )?;
                if r.prev_tx_id != t.previous_outpoint.transaction_id
                    || r.prev_index != t.previous_outpoint.index
                    || r.amount != t.utxo_entry.amount
                    || r.sequence != t.sequence
                    || r.sig_op_count != t.sig_op_count
                    || r.spk_version != spk.version
                    || r.spk != spk.script
                {
                    return Err(KsptError::SourceMismatch {
                        at: Mismatch::Input(i),
                    });
                }
                (r.redeem, Some(r))
            }
            Source::Draft(d) => {
                let redeem = d.redeems[i];
                if !redeem.is_empty() && !redeem_matches(spk, redeem) {
                    return Err(KsptError::SourceMismatch {
                        at: Mismatch::Input(i),
                    });
                }
                (redeem, None)
            }
        };
        total =
            checked_add_value(total, t.utxo_entry.amount).ok_or(KsptError::ValueOutOfRange {
                field: Field::Amount,
                at: i,
            })?;
        s.put(&t.previous_outpoint.transaction_id)?;
        s.put(&t.previous_outpoint.index.to_le_bytes())?;
        s.put(&t.utxo_entry.amount.to_le_bytes())?;
        s.put(&t.sequence.to_le_bytes())?;
        s.put(&[t.sig_op_count])?;
        script(s, spk.version, spk.script, p)?;
        signatures(s, i, held.as_ref(), added, p)?;
        let redeem = redeem_of(i, spk, arrived, added)?;
        fits(Field::Redeem, redeem.len(), p.max_redeem, U16_MAX)?;
        s.put(&(redeem.len() as u16).to_le_bytes())?;
        s.put(redeem)?;
        walked += 1;
    }
    // A parsed payload yields every input it declares; if it did not, the
    // header written above would promise inputs the body lacks.
    if walked != ni || parsed_inputs.as_mut().is_some_and(|r| r.next().is_some()) {
        return Err(KsptError::SourceMismatch {
            at: Mismatch::Counts,
        });
    }

    let mut total = 0u64;
    let mut walked = 0usize;
    let mut parsed_outputs = match source {
        Source::Parsed(k) => Some(k.outputs()),
        Source::Draft(_) => None,
    };
    for (k, t) in tx.outputs.iter().enumerate() {
        let spk = &t.script_public_key;
        if let Source::Parsed(src) = source {
            let r = parsed_outputs.as_mut().and_then(Iterator::next).ok_or(
                KsptError::SourceMismatch {
                    at: Mismatch::Counts,
                },
            )?;
            if r.value != t.value
                || r.spk_version != spk.version
                || r.spk != spk.script
                || binding(src, k, r.covenant) != t.covenant
            {
                return Err(KsptError::SourceMismatch {
                    at: Mismatch::Output(k),
                });
            }
        }
        total = checked_add_value(total, t.value).ok_or(KsptError::ValueOutOfRange {
            field: Field::Value,
            at: k,
        })?;
        s.put(&t.value.to_le_bytes())?;
        script(s, spk.version, spk.script, p)?;
        walked += 1;
    }
    if walked != no || parsed_outputs.as_mut().is_some_and(|r| r.next().is_some()) {
        return Err(KsptError::SourceMismatch {
            at: Mismatch::Counts,
        });
    }

    // Records in one fixed order, so one byte string, though the parser
    // takes any: covenants, the coins' covenants, input hints, KCC-3 input
    // hints, single-key input hints, output hints, single-key output hints.
    // One hint an input and one an output, of any kind, and one covenant a
    // coin, as the parser reads them; a draft is checked here, at the offset
    // the parser would report.
    let mut hinted_in = Seen::new();
    let mut hinted_out = Seen::new();
    let mut coins = Seen::new();
    for (k, t) in tx.outputs.iter().enumerate() {
        if let Some(b) = t.covenant {
            // At the record's offset, as the parser reports it.
            if usize::from(b.authorizing_input) >= ni {
                return Err(KsptError::AuthorizingInputOutOfRange {
                    at: s.len,
                    output: k as u8,
                    input: b.authorizing_input,
                });
            }
            s.put(&[REC_COVENANT, k as u8])?;
            s.put(&b.authorizing_input.to_le_bytes())?;
            s.put(&b.covenant_id)?;
        }
    }
    match source {
        Source::Parsed(k) => {
            for r in k.records() {
                if let Record::CoinCovenant {
                    input_index,
                    covenant_id,
                } = r
                {
                    coin_covenant(s, &mut coins, input_index, covenant_id)?;
                }
            }
            for r in k.records() {
                if let Record::InputHint(h) = r {
                    hint(s, &mut hinted_in, REC_HINT_IN, &h)?;
                }
            }
            for r in k.records() {
                if let Record::Kcc3InputHint(h) = r {
                    kcc3_hint(s, &mut hinted_in, &h)?;
                }
            }
            for r in k.records() {
                if let Record::AccountInputHint(h) = r {
                    account_hint(s, &mut hinted_in, REC_ACCOUNT_HINT_IN, &h)?;
                }
            }
            for r in k.records() {
                if let Record::OutputHint(h) = r {
                    hint(s, &mut hinted_out, REC_HINT_OUT, &h)?;
                }
            }
            for r in k.records() {
                if let Record::AccountOutputHint(h) = r {
                    account_hint(s, &mut hinted_out, REC_ACCOUNT_HINT_OUT, &h)?;
                }
            }
        }
        Source::Draft(d) => {
            for c in d.coin_covenants {
                coin_covenant(s, &mut coins, c.index, &c.covenant_id)?;
            }
            for h in d.input_hints {
                hint(s, &mut hinted_in, REC_HINT_IN, h)?;
            }
            for h in d.kcc3_hints {
                kcc3_hint(s, &mut hinted_in, h)?;
            }
            for h in d.account_hints {
                account_hint(s, &mut hinted_in, REC_ACCOUNT_HINT_IN, h)?;
            }
            for h in d.output_hints {
                hint(s, &mut hinted_out, REC_HINT_OUT, h)?;
            }
            for h in d.account_output_hints {
                account_hint(s, &mut hinted_out, REC_ACCOUNT_HINT_OUT, h)?;
            }
        }
    }
    Ok(())
}

/// Output `k`'s covenant binding as the source carries it, inline or as a
/// `0x43` record, the two [`transaction::fill`] merges; the parser allows
/// at most one.
///
/// [`transaction::fill`]: super::transaction::fill
fn binding(
    source: &Kspt<'_>,
    k: usize,
    inline: Option<CovenantBinding>,
) -> Option<CovenantBinding> {
    inline.or_else(|| {
        source.records().find_map(|r| match r {
            Record::Covenant {
                output_index,
                authorizing_input,
                covenant_id,
            } if usize::from(output_index) == k => Some(CovenantBinding {
                authorizing_input,
                covenant_id: *covenant_id,
            }),
            _ => None,
        })
    })
}

/// Input `i`'s redeem script as written: the one it arrived with, or the
/// one its added signatures supply, the same in each that does, for an
/// input that arrived with none and whose lock is its hash.
fn redeem_of<'a>(
    i: usize,
    spk: &ScriptPublicKey<'_>,
    arrived: &'a [u8],
    added: &'a [InputSignature],
) -> Result<&'a [u8], KsptError> {
    let mismatch = KsptError::SourceMismatch {
        at: Mismatch::Input(i),
    };
    let mut supplied = added
        .iter()
        .filter(|a| a.input == i)
        .filter_map(|a| a.redeem.as_ref());
    let Some(first) = supplied.next() else {
        return Ok(arrived);
    };
    if supplied.any(|other| other != first) || !arrived.is_empty() || !redeem_matches(spk, first) {
        return Err(mismatch);
    }
    Ok(first)
}

fn script(s: &mut Sink<'_>, version: u16, script: &[u8], p: &Profile) -> Result<(), KsptError> {
    fits(Field::Script, script.len(), p.max_script, U16_MAX)?;
    s.put(&version.to_le_bytes())?;
    let mut len = [0u8; 3];
    let n = write_script_len(Field::Script, script.len(), &mut len)?;
    s.put(&len[..n])?;
    s.put(script)
}

/// Mark `index` as hinted, or refuse a second hint at the offset where the
/// parser would.
fn first_hint(s: &Sink<'_>, seen: &mut Seen, marker: u8, index: u8) -> Result<(), KsptError> {
    if seen.mark(index) {
        Ok(())
    } else {
        Err(KsptError::RepeatedRecord { marker, at: s.len })
    }
}

fn hint(s: &mut Sink<'_>, seen: &mut Seen, marker: u8, h: &Hint) -> Result<(), KsptError> {
    first_hint(s, seen, marker, h.index)?;
    s.put(&[marker, h.index])?;
    s.put(&h.cosigner.to_le_bytes())?;
    s.put(&h.chain.to_le_bytes())?;
    s.put(&h.addr_index.to_le_bytes())
}

/// A `0x49` record: input `index`'s coin's covenant, once an input, a
/// second refused at the offset where the parser would.
fn coin_covenant(
    s: &mut Sink<'_>,
    seen: &mut Seen,
    index: u8,
    covenant_id: &[u8; 32],
) -> Result<(), KsptError> {
    first_hint(s, seen, REC_COIN_COVENANT, index)?;
    s.put(&[REC_COIN_COVENANT, index])?;
    s.put(covenant_id)
}

fn kcc3_hint(s: &mut Sink<'_>, seen: &mut Seen, h: &Kcc3Hint) -> Result<(), KsptError> {
    first_hint(s, seen, REC_KCC3_HINT_IN, h.index)?;
    s.put(&[REC_KCC3_HINT_IN, h.index])?;
    s.put(&h.chain.to_le_bytes())?;
    s.put(&h.addr_index.to_le_bytes())
}

fn account_hint(
    s: &mut Sink<'_>,
    seen: &mut Seen,
    marker: u8,
    h: &AccountHint,
) -> Result<(), KsptError> {
    first_hint(s, seen, marker, h.index)?;
    s.put(&[marker, h.index])?;
    s.put(&h.chain.to_le_bytes())?;
    s.put(&h.addr_index.to_le_bytes())
}

/// An input's signature count and records: those it arrived with, if any,
/// and those added, merged in ascending key position.
fn signatures(
    s: &mut Sink<'_>,
    input: usize,
    r: Option<&Input<'_>>,
    added: &[InputSignature],
    p: &Profile,
) -> Result<(), KsptError> {
    let all = || {
        r.into_iter()
            .flat_map(|r| r.signatures())
            .map(|g| (g.pubkey_pos, g.sighash_type, g.bytes))
            .chain(
                added
                    .iter()
                    .filter(move |a| a.input == input)
                    .map(|a| (a.pubkey_pos, a.sighash_type, &a.signature[..])),
            )
    };

    let mut count = 0usize;
    for (_, _, bytes) in all() {
        if bytes.len() != SIGNATURE_LEN {
            return Err(KsptError::SignatureLength {
                input,
                len: bytes.len(),
            });
        }
        count += 1;
    }
    fits(Field::Signatures, count, p.max_sigs_per_input, U8_MAX)?;
    s.put(&[count as u8])?;

    // Each round writes the lowest position above the last one written. Two
    // at one position are refused in the round that reaches it, so the
    // rounds write `count` distinct positions.
    let mut last: Option<u8> = None;
    loop {
        let mut next: Option<(u8, u8, &[u8])> = None;
        let mut ties = 0usize;
        for candidate in all() {
            let pos = candidate.0;
            if last.is_some_and(|l| pos <= l) {
                continue;
            }
            match next {
                Some((best, _, _)) if pos > best => {}
                Some((best, _, _)) if pos == best => ties += 1,
                _ => {
                    next = Some(candidate);
                    ties = 1;
                }
            }
        }
        let Some((pos, sighash_type, bytes)) = next else {
            return Ok(());
        };
        if ties > 1 {
            return Err(KsptError::DuplicateSignature {
                input,
                pubkey_pos: pos,
            });
        }
        s.put(&[pos, sighash_type])?;
        s.put(bytes)?;
        last = Some(pos);
    }
}
