// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A rusty-kaspa bundle through a unit: [`kassigner_sdk::bundle`] over
//! owned values. An envelope is passed as its bytes, and one past
//! [`MAX_ENVELOPE`] is refused before anything is made for it.

use kassigner_kaspa::bip32_public::PUBLIC_KEY_SIZE;
use kassigner_kaspa::pskb::signature::{signers, Derivation, PartialSig};
use kassigner_kaspa::pskb::{Splice, SIGNATURE_LEN};
use kassigner_sdk::bundle::{
    self, FinalScratch, Hint, MergeScratch, ReadScratch, Scratch, SuppliedRedeem,
};
use kassigner_sdk::reply::FinishScratch;
use kassigner_sdk::watch;

use crate::reply::{unlocks_len, Checked, Finalized, CELL, INPUT, OUTPUT, SIGNATURE, SPEND};
use crate::request::{OutputSummary, Summary};
use crate::watch::{Account, Group};
use crate::{hex, unhex, Fault, Profile, Rates};

/// A hint as the builder holds it.
#[derive(Clone, Debug)]
enum Held {
    Account {
        account: watch::Account,
        chain: u32,
        index: u32,
        fingerprint: [u8; 4],
    },
    Group {
        group: Box<watch::Group>,
        cosigner: u32,
        chain: u32,
        index: u32,
        fingerprints: Vec<[u8; 4]>,
    },
}

/// The derivation hints for a bundle's inputs, one call an input.
#[derive(Clone, Debug, Default)]
pub struct Hints {
    held: Vec<(usize, Held)>,
}

/// A fingerprint from its hex, zeros when the app does not know it.
fn fingerprint(text: Option<String>) -> Result<[u8; 4], Fault> {
    match text {
        Some(t) if !t.trim().is_empty() => unhex::<4>(&t),
        _ => Ok([0; 4]),
    }
}

impl Hints {
    /// No hints yet.
    pub fn new() -> Hints {
        Hints::default()
    }

    /// Input `input` is a `44'` account's `chain`/`index`, of the seed with
    /// master fingerprint `fingerprint_hex` if known.
    pub fn account(
        &mut self,
        input: u32,
        account: &Account,
        chain: u32,
        index: u32,
        fingerprint_hex: Option<String>,
    ) -> Result<(), Fault> {
        self.held.push((
            input as usize,
            Held::Account {
                account: *account.inner(),
                chain,
                index,
                fingerprint: fingerprint(fingerprint_hex)?,
            },
        ));
        Ok(())
    }

    /// Input `input` is a `45'` group's `cosigner`/`chain`/`index`, with
    /// the cosigners' seed fingerprints in key order, hex, an empty string
    /// for one not known.
    pub fn group(
        &mut self,
        input: u32,
        group: &Group,
        cosigner: u32,
        chain: u32,
        index: u32,
        fingerprints: Vec<String>,
    ) -> Result<(), Fault> {
        let fingerprints = fingerprints
            .into_iter()
            .map(|f| fingerprint(Some(f)))
            .collect::<Result<Vec<_>, _>>()?;
        self.held.push((
            input as usize,
            Held::Group {
                group: Box::new(*group.inner()),
                cosigner,
                chain,
                index,
                fingerprints,
            },
        ));
        Ok(())
    }
}

/// What [`prepare_bundle`] made.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Prepared {
    /// The envelope, `PSKB` and hex, shown to the unit as format `pskb`.
    pub bytes: Vec<u8>,
    /// Inputs of the transaction.
    pub inputs: u32,
    /// Signatures the reply must carry in all.
    pub signatures: u32,
}

impl Prepared {
    /// The envelope as text.
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.bytes).into_owned()
    }
}

/// The longest envelope a bundle call takes, 1 MiB.
///
/// The rooms below grow with the envelope, about six times its length for
/// [`prepare_bundle`], so without a bound a file passed by mistake, or one
/// sent by a stranger, would have an app reserve six times whatever it is
/// fed before a byte of it is read. rusty-kaspa sets no length for a
/// bundle; this is the SDK's.
///
/// Measured on the SDK's profile: 32 inputs of a 3-key group paying 8
/// outputs come to 74,430 bytes; a further key adds 424 an input, a
/// signature 422, and a byte of script four (hex in the document, the
/// document hex in the envelope). Five keys and five signatures on every
/// input, with every script, redeem script and the payload at the
/// profile's longest, come to about 370 KB, so 1 MiB refuses no bundle a
/// unit could sign.
pub const MAX_ENVELOPE: usize = 1 << 20;

/// `envelope` held to [`MAX_ENVELOPE`], before any room is made for it.
fn within(envelope: &[u8]) -> Result<(), Fault> {
    if envelope.len() > MAX_ENVELOPE {
        return Err(Fault(format!(
            "TooLong {{ len: {}, limit: {MAX_ENVELOPE} }}",
            envelope.len()
        )));
    }
    Ok(())
}

/// Everything a bundle is worked in, for one envelope of `len` bytes.
struct Room<'a> {
    doc: Vec<u8>,
    inputs: Vec<kassigner_kaspa::tx::TransactionInput<'a>>,
    outputs: Vec<kassigner_kaspa::tx::TransactionOutput<'a>>,
    bytes: Vec<u8>,
    redeem: Vec<u8>,
    text: Vec<u8>,
    splices: Vec<Splice<'a>>,
    json: Vec<u8>,
}

impl Room<'_> {
    fn new(len: usize, p: &kassigner_sdk::Profile) -> Self {
        let members = p.max_inputs * p.max_sigs_per_input;
        Room {
            doc: vec![0u8; len + 64],
            inputs: vec![INPUT; p.max_inputs],
            outputs: vec![OUTPUT; p.max_outputs],
            bytes: vec![0u8; len + 64],
            redeem: vec![0u8; p.max_redeem],
            text: vec![0u8; 65_536 + members * 512],
            splices: vec![Splice::insert_at(0, &[]); 2 * members + 64],
            json: vec![0u8; 2 * len + 65_536 + members * 512],
        }
    }
}

/// The SDK's scratch over a room, built where the room lives.
macro_rules! scratch {
    ($room:expr) => {
        Scratch {
            doc: &mut $room.doc,
            inputs: &mut $room.inputs,
            outputs: &mut $room.outputs,
            bytes: &mut $room.bytes,
            redeem: &mut $room.redeem,
            text: &mut $room.text,
            splices: &mut $room.splices,
            json: &mut $room.json,
        }
    };
}

/// Prepare `bundle`, a wallet's envelope, for the unit: held to the unit's
/// rules, with `hints` written into its inputs.
///
/// # Errors
///
/// `TooLong { len, limit }` past [`MAX_ENVELOPE`], before anything else;
/// the SDK's [`BundleError`](kassigner_sdk::bundle::BundleError):
/// `Envelope(..)` and `Read(..)` for what is not a bundle, `Read(..)` too
/// for more inputs or outputs than the profile allows,
/// `NotOneTransaction { count }`, `Check(..)`, `Transaction(..)`,
/// `Multisig(..)`, `Redeem { input }`, `Hint { input }` for a hint it
/// refuses or an input the bundle lacks; the rest as that enum says.
pub fn prepare_bundle(bundle: &[u8], hints: &Hints, profile: &Profile) -> Result<Prepared, Fault> {
    within(bundle)?;
    let p = profile.inner();
    let mut room = Room::new(bundle.len(), p);
    let mut scratch = scratch!(room);
    let hints: Vec<(usize, Hint<'_>)> = hints
        .held
        .iter()
        .map(|(input, h)| {
            (
                *input,
                match h {
                    Held::Account {
                        account,
                        chain,
                        index,
                        fingerprint,
                    } => Hint::Account {
                        account,
                        chain: *chain,
                        index: *index,
                        fingerprint: *fingerprint,
                    },
                    Held::Group {
                        group,
                        cosigner,
                        chain,
                        index,
                        fingerprints,
                    } => Hint::Group {
                        group,
                        cosigner: *cosigner,
                        chain: *chain,
                        index: *index,
                        fingerprints,
                    },
                },
            )
        })
        .collect();
    let mut out = vec![0u8; 2 * bundle.len() + 131_072];
    let r = bundle::prepare(bundle, &hints, p, &mut scratch, &mut out).map_err(Fault::of)?;
    out.truncate(r.len);
    Ok(Prepared {
        bytes: out,
        inputs: r.inputs as u32,
        signatures: r.signatures as u32,
    })
}

/// Read `reply` against `request`, both envelopes: the same transaction,
/// every signature verified over it.
///
/// # Errors
///
/// `TooLong { len, limit }` for either envelope past [`MAX_ENVELOPE`],
/// before anything else; `NotTheRequest`; `Check(BadSignature { input })`
/// for a member that does not verify or is by a key the script does not
/// name; the rest as the SDK's
/// [`BundleError`](kassigner_sdk::bundle::BundleError) says.
pub fn read_bundle(request: &[u8], reply: &[u8], profile: &Profile) -> Result<Checked, Fault> {
    read(Some(request), reply, profile)
}

/// Read `signed`, a bundle signed already, with no request: every member
/// verified over its own transaction.
///
/// # Errors
///
/// As [`read_bundle`] but `NotTheRequest`.
pub fn read_signed_bundle(signed: &[u8], profile: &Profile) -> Result<Checked, Fault> {
    read(None, signed, profile)
}

/// [`read_bundle`], or [`read_signed_bundle`] with no request.
fn read(request: Option<&[u8]>, reply: &[u8], profile: &Profile) -> Result<Checked, Fault> {
    request.map_or(Ok(()), within)?;
    within(reply)?;
    let p = profile.inner();
    let mut req = Room::new(request.unwrap_or(reply).len(), p);
    let mut rep = Room::new(reply.len(), p);
    let mut scratch = ReadScratch {
        request: scratch!(req),
        doc: &mut rep.doc,
        inputs: &mut rep.inputs,
        outputs: &mut rep.outputs,
        bytes: &mut rep.bytes,
        redeem: &mut rep.redeem,
    };
    let c = match request {
        Some(request) => bundle::read(request, reply, p, &mut scratch),
        None => bundle::read_signed(reply, p, &mut scratch),
    }
    .map_err(Fault::of)?;
    Ok(Checked::of(c.signatures, c.signers, c.complete))
}

/// Merge `replies`, each a cosigner's answer to `request`, into one
/// envelope.
///
/// # Errors
///
/// As [`read_bundle`]; `Edit(SameKeyTwice)` for one key signing twice.
pub fn merge_bundles(
    request: &[u8],
    replies: &[&[u8]],
    profile: &Profile,
) -> Result<Vec<u8>, Fault> {
    merge(Some(request), replies, profile)
}

/// Merge `copies` of one bundle signed already into one envelope, each
/// verified over the first's transaction; a signature by a key that
/// signed an earlier copy is left out.
///
/// # Errors
///
/// `NotOneTransaction { count: 0 }` for no copies;
/// `Check(BadSignature { input })` for a member of a copy of another
/// transaction; otherwise as [`read_signed_bundle`].
pub fn merge_signed_bundles(copies: &[&[u8]], profile: &Profile) -> Result<Vec<u8>, Fault> {
    merge(None, copies, profile)
}

/// [`merge_bundles`], or [`merge_signed_bundles`] with no request.
fn merge(request: Option<&[u8]>, replies: &[&[u8]], profile: &Profile) -> Result<Vec<u8>, Fault> {
    request.map_or(Ok(()), within)?;
    replies.iter().try_for_each(|r| within(r))?;
    let p = profile.inner();
    let base = request.or(replies.first().copied()).unwrap_or(&[]);
    let longest = replies
        .iter()
        .map(|r| r.len())
        .max()
        .unwrap_or(0)
        .max(base.len());
    let members = p.max_inputs * p.max_sigs_per_input;
    let mut req = Room::new(base.len(), p);
    let mut rep = Room::new(longest, p);
    let mut scratch = ReadScratch {
        request: scratch!(req),
        doc: &mut rep.doc,
        inputs: &mut rep.inputs,
        outputs: &mut rep.outputs,
        bytes: &mut rep.bytes,
        redeem: &mut rep.redeem,
    };
    let mut keys = vec![[0u8; PUBLIC_KEY_SIZE]; members];
    let mut signatures = vec![[0u8; SIGNATURE_LEN]; members];
    let mut partial = vec![
        PartialSig {
            input: 0,
            public_key: &[0; PUBLIC_KEY_SIZE],
            signature: &[0; SIGNATURE_LEN],
            derivation: Derivation::Null,
        };
        members
    ];
    let mut redeems = vec![SuppliedRedeem::EMPTY; p.max_inputs];
    let mut merging = MergeScratch {
        keys: &mut keys,
        signatures: &mut signatures,
        partial: &mut partial,
        redeems: &mut redeems,
    };
    let mut out = vec![0u8; 4 * longest + 131_072 + members * 1024];
    let n = match request {
        Some(request) => bundle::merge(request, replies, p, &mut scratch, &mut merging, &mut out),
        None => bundle::merge_signed(replies, p, &mut scratch, &mut merging, &mut out),
    }
    .map_err(Fault::of)?;
    out.truncate(n);
    Ok(out)
}

/// Finish `reply`, a complete bundle reply to `request`: as
/// [`crate::reply::finalize_reply`] over a bundle.
///
/// # Errors
///
/// As [`read_bundle`]; `Finish(..)` as [`crate::reply::finalize_reply`]
/// says, `Finish(Signatures { .. })` for an input short of its threshold.
pub fn finalize_bundle(
    request: &[u8],
    reply: &[u8],
    allow_orphan: bool,
    rates: &Rates,
    profile: &Profile,
) -> Result<Finalized, Fault> {
    finalize(Some(request), reply, allow_orphan, rates, profile)
}

/// Finish `signed`, a complete bundle signed already, with no request, as
/// [`finalize_bundle`] does.
///
/// # Errors
///
/// As [`finalize_bundle`] but `NotTheRequest`.
pub fn finalize_signed_bundle(
    signed: &[u8],
    allow_orphan: bool,
    rates: &Rates,
    profile: &Profile,
) -> Result<Finalized, Fault> {
    finalize(None, signed, allow_orphan, rates, profile)
}

/// [`finalize_bundle`], or [`finalize_signed_bundle`] with no request.
fn finalize(
    request: Option<&[u8]>,
    reply: &[u8],
    allow_orphan: bool,
    rates: &Rates,
    profile: &Profile,
) -> Result<Finalized, Fault> {
    request.map_or(Ok(()), within)?;
    within(reply)?;
    let p = profile.inner();
    let members = p.max_inputs * p.max_sigs_per_input;
    let base = request.unwrap_or(reply);
    let mut room = Room::new(reply.len(), p);
    let mut request_doc = vec![0u8; base.len() + 64];
    let mut request_inputs = vec![INPUT; p.max_inputs];
    let mut request_outputs = vec![OUTPUT; p.max_outputs];
    let mut request_bytes = vec![0u8; base.len() + 64];
    let mut redeems = vec![0u8; p.max_inputs * p.max_redeem];
    let mut redeem_lens = vec![0usize; p.max_inputs];
    let mut sighash = vec![0u8; p.max_inputs];
    let mut keys = vec![[0u8; PUBLIC_KEY_SIZE]; members];
    let mut signature_bytes = vec![[0u8; SIGNATURE_LEN]; members];
    let mut signatures = vec![SIGNATURE; members];
    let mut ranges = vec![(0usize, 0usize); p.max_inputs];
    let mut spends = vec![SPEND; p.max_inputs];
    let mut unlocks = vec![0u8; unlocks_len(p)];
    let mut unlock_lens = vec![0usize; p.max_inputs];
    let mut cells_in = vec![CELL; p.max_inputs];
    let mut cells_out = vec![CELL; p.max_outputs];
    let mut scratch = FinalScratch {
        request_doc: &mut request_doc,
        request_inputs: &mut request_inputs,
        request_outputs: &mut request_outputs,
        request_bytes: &mut request_bytes,
        doc: &mut room.doc,
        inputs: &mut room.inputs,
        outputs: &mut room.outputs,
        bytes: &mut room.bytes,
        redeems: &mut redeems,
        redeem_lens: &mut redeem_lens,
        sighash: &mut sighash,
        keys: &mut keys,
        signature_bytes: &mut signature_bytes,
        signatures: &mut signatures,
        ranges: &mut ranges,
        spends: &mut spends,
        finish: FinishScratch {
            unlocks: &mut unlocks,
            unlock_lens: &mut unlock_lens,
            cells_in: &mut cells_in,
            cells_out: &mut cells_out,
        },
    };
    let f = match request {
        Some(request) => bundle::finalize(request, reply, p, rates.inner(), &mut scratch),
        None => bundle::finalize_signed(reply, p, rates.inner(), &mut scratch),
    }
    .map_err(Fault::of)?;
    Finalized::of(&f, allow_orphan)
}

/// Read `envelope`, a bundle, as [`crate::request::summary`] reads a KSPT.
/// Nothing is verified; [`read_bundle`] and [`read_signed_bundle`] do that.
///
/// # Errors
///
/// `TooLong { len, limit }` past [`MAX_ENVELOPE`], before anything else;
/// `Envelope(..)` and `Read(..)` for what is not a bundle,
/// `NotOneTransaction { count }`; the bundle editor's `EditError`, such as
/// `Malformed { input, field }`, for an input's `partialSigs` it cannot
/// read.
pub fn bundle_summary(envelope: &[u8], profile: &Profile) -> Result<Summary, Fault> {
    within(envelope)?;
    let mut room = Room::new(envelope.len(), profile.inner());
    let (held, tx) = bundle::transaction_of(
        envelope,
        &mut room.doc,
        &mut room.inputs,
        &mut room.outputs,
        &mut room.bytes,
    )
    .map_err(Fault::of)?;
    let mut total_in = 0u64;
    let mut outpoints = Vec::new();
    let mut signatures = 0u32;
    for (i, input) in tx.inputs.iter().enumerate() {
        total_in = total_in.saturating_add(input.utxo_entry.amount);
        outpoints.push(format!(
            "{}:{}",
            hex(&input.previous_outpoint.transaction_id),
            input.previous_outpoint.index
        ));
        signers(held, 0, i, |_| {
            signatures += 1;
            true
        })
        .map_err(Fault::of)?;
    }
    let mut total_out = 0u64;
    let mut outputs = Vec::new();
    for output in tx.outputs {
        total_out = total_out.saturating_add(output.value);
        let mut summary = OutputSummary::of(output.script_public_key.script, output.value);
        if let Some(binding) = output.covenant {
            summary.covenant_id = Some(hex(&binding.covenant_id));
            summary.authorizing_input = Some(u32::from(binding.authorizing_input));
        }
        outputs.push(summary);
    }
    Ok(Summary {
        inputs: tx.inputs.len() as u32,
        outpoints,
        total_in,
        outputs,
        total_out,
        signatures,
        lock_time: tx.lock_time,
        version: u32::from(tx.version),
    })
}
