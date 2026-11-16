// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A request: a transaction for a unit to sign, as a KSPT ([`build`]), a
//! rusty-kaspa bundle (PSKB) that other wallets read too ([`bundle`]), or
//! the WASM SDK's safe JSON ([`safe_json()`]).
//!
//! The app gives the coins it spends, each with its source, what it pays
//! and where the change goes. The builder writes the transaction, version 0
//! or, with an output bound to a covenant, version 1, with the signature
//! operations or compute budgets, redeem scripts and hints the unit needs,
//! after every check the unit makes on arrival without its key
//! ([`kassigner_protocol::check`]), within its [`Profile`], so a refusal
//! shows in the app, not on the unit.
//!
//! # Hints
//!
//! A `45'` coin always carries its cosigner hint, since a multisig key
//! comes from its hint alone; a `22'` coin carries its index hint when the
//! app knows it. A `44'` coin, or the key named to sign a card's UTXO,
//! carries its hint only past the unit's bank ([`RECEIVE_DEPTH`] receive
//! and [`CHANGE_DEPTH`] change keys); without it the unit searches, slowly,
//! up to [`SEARCH_DEPTH`](kassigner_protocol::check::SEARCH_DEPTH). A
//! card's UTXO always carries the card's program as its redeem script.
//!
//! The change's script is derived from the place the app names. An output
//! to the account's own receive address ([`Pay::own`]) and a sweep to the
//! wallet's own address are checked against that address. All three are
//! hinted alike, a group's always and a `44'` account's past the bank, and
//! the unit shows them as CHANGE on a change chain, YOURS on a `44'`
//! receive chain.
//!
//! # Fee
//!
//! As rusty-kaspa's wallet pays it: the mass as signed, estimated as the
//! wallet does, times the app's rate in sompi a gram, never under the
//! minimum relay fee over compute mass ([`kassigner_kaspa::mass`]). The mass
//! is the greater of compute and storage mass, storage estimated with the
//! change at what the coins leave over the outputs before the fee. A change
//! that would be dust, or costs more fee than it is worth, goes to the fee;
//! a sweep pays over compute mass alone. The app passes the fee rate and
//! the mass rates: nothing here reads the chain.
//!
//! The wallet's estimate (`calc_signature_compute_mass_for_inputs`) leaves
//! out the redeem script a script-hash input pushes after its signatures,
//! 104 bytes for a 2-of-3. It is counted here, or a group's spend would pay
//! under the minimum relay fee.
//!
//! # As a bundle
//!
//! [`bundle`] writes the same transaction as rusty-kaspa 2.1.0 writes a
//! version zero bundle ([`kassigner_kaspa::pskb::write`]), which every
//! release that reads bundles takes. Each input carries its whole
//! `utxoEntry`, from the [`EntryDetails`] the app passes, and its zero
//! `sequence`, so no reader takes it as final. The hints become derivations
//! at any index, as [`crate::bundle::prepare`] writes them, none for a
//! `22'` coin. Their seed fingerprints are zeros, since the unit reads the
//! path; an app that knows them writes them with [`crate::bundle::prepare`].
//!
//! # Not here
//!
//! No payload. Refused: a card's UTXO before the card's time
//! ([`RequestError::CardLocked`]) or in the safe JSON
//! ([`RequestError::CardInSafeJson`]), and an output bound to a covenant in
//! a bundle ([`RequestError::CovenantInBundle`]). Coins of any kind can be
//! spent together; a `22'` address is meant to be emptied in one sweep,
//! which the builder does not enforce.
//!
//! # Covenants
//!
//! A coin with a covenant id ([`Coin::covenant_id`]) is a UTXO of that
//! covenant, and an output can be bound to one ([`Payment::Covenant`]), in
//! one of two ways, KIP-20's two (`CovenantsContext::from_tx`):
//!
//! - [`Binding::Continue`]: the output continues the covenant of a bound
//!   coin the request spends, and that coin's input authorizes it. The id
//!   is the coin's.
//! - [`Binding::Start`]: the outputs one input authorizes start a new
//!   covenant. Its id is made from that input's outpoint and those outputs
//!   ([`kassigner_kaspa::sighash::covenant_id`]), once their values are
//!   final.
//!
//! The app never passes an id for an output. It names the coin whose input
//! authorizes it: which input that is matters to a covenant's program (in
//! KCC-1 the lowest input of a covenant leads), so the builder does not
//! choose it. The change is never bound.
//!
//! A covenant some coin is bound to and no output continues ends: what the
//! coin held leaves as plain KAS. Consensus allows that, but it is never
//! what a plain send means, so the builder refuses it
//! ([`RequestError::CovenantBound`]) unless the terms say so
//! ([`Terms::end_covenants`]). The request carries each bound coin's
//! covenant id, the unit shows every covenant on a page of its own, and the
//! storage mass counts bound coins and outputs as a node does.
//!
//! # Version 1
//!
//! A binding is consensus's from version 1, so a request with one is a
//! version 1 transaction; any other stays version 0. In version 1 an input
//! commits no signature operations but a compute budget, ten units for each
//! signature operation it would commit in version 0
//! ([`kassigner_kaspa::mass::compute_budget_for`]): the same mass and the
//! same room for its script. No signature covers the budget, and a KSPT
//! does not carry it: [`crate::reply::finish`] writes the same budgets
//! into the finished transaction, so the fee found here is the fee it pays.

use kassigner_kaspa::address::{self, Version};
use kassigner_kaspa::bip32_public::PUBLIC_KEY_SIZE;
use kassigner_kaspa::constants::checked_add_value;
use kassigner_kaspa::mass::SIGNATURE_SCRIPT_SIZE;
use kassigner_kaspa::mass::{
    compute_budget_for, is_dust, minimum_relay_fee, non_contextual_masses, plurality,
    signature_compute_mass, storage_mass, wallet_storage_mass, Cell, MassRates,
    BLOCK_STORAGE_MASS_LIMIT,
};
use kassigner_kaspa::pskb::write::{self as pskb_write, Global, Member, Version as BundleVersion};
use kassigner_kaspa::pskb::{encode_envelope, EnvelopeError};
use kassigner_kaspa::safe_json::{self, SafeJsonError};
use kassigner_kaspa::script::unlock::push_len;
use kassigner_kaspa::script::{
    pay_to_pubkey, pay_to_script_hash, KCC3_REDEEM_LEN, PAY_TO_SCRIPT_HASH_LEN,
};
use kassigner_kaspa::sighash::{covenant_id, SIG_HASH_ALL};
use kassigner_kaspa::tx::{
    CovenantBinding, EntryDetails, Outpoint, ScriptPublicKey, Transaction, TransactionInput,
    TransactionOutput, TxRuleError, UtxoEntry, SUBNETWORK_ID_NATIVE,
};
use kassigner_protocol::card::savings::{
    Savings, PROGRAM_LEN, SIGNATURE_SCRIPT_LEN as CARD_SCRIPT_LEN, SIG_OP_COUNT as CARD_SIG_OPS,
};
use kassigner_protocol::check::{self, MultisigError, CHANGE_DEPTH, RECEIVE_DEPTH};
use kassigner_protocol::kspt::{self, AccountHint, CoinCovenant, Draft, Hint, Kcc3Hint, KsptError};
use kassigner_protocol::profile::Profile;

use crate::bundle::{self as sdk_bundle, BundleError, Hint as BundleHint, DERIVATION_MAX};
use crate::watch::{self, Account, Group, Kcc3Address, WatchError, CHANGE, MAX_REDEEM, RECEIVE};

/// Where a coin came from: which watched thing, at which derivation. The
/// builder checks the coin's script against it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source<'a> {
    /// A `44'` account's `chain`/`index`.
    Account {
        account: &'a Account,
        chain: u32,
        index: u32,
    },
    /// A `45'` group's `cosigner`/`chain`/`index`.
    Group {
        group: &'a Group,
        cosigner: u32,
        chain: u32,
        index: u32,
    },
    /// A `22'` address, with its `chain`/`index` below the `22'` account
    /// when the app knows it.
    Kcc3 {
        address: &'a Kcc3Address,
        hint: Option<(u32, u32)>,
    },
    /// A Time-Locked Savings card's UTXO: the card and, when the app knows
    /// it, the key that signs it, the owner's or the recovery wallet's, as a
    /// `44'` account's receive `index` ([`crate::card::signer`]).
    Card {
        card: &'a Savings,
        signer: Option<(&'a Account, u32)>,
    },
}

/// A coin to spend: the output it is, where it came from, and the
/// covenant it is bound to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Coin<'a> {
    pub outpoint: Outpoint,
    pub amount: u64,
    pub source: Source<'a>,
    /// The covenant the coin is bound to, as a node lists it
    /// (`covenantId`), or `None`. Spending a bound coin with no output
    /// continuing its covenant ([`Binding::Continue`]) ends it: refused,
    /// [`RequestError::CovenantBound`], unless the terms say
    /// [`Terms::end_covenants`].
    pub covenant_id: Option<[u8; 32]>,
}

/// An output to pay: a locking script and a value, and whether the script
/// is the seed's own receive address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pay<'a> {
    pub script: &'a [u8],
    pub value: u64,
    /// `Some` when `script` pays the account's own receive address: the
    /// builder checks it and tells the unit, which shows it as YOURS.
    pub own: Option<Own<'a>>,
}

/// A `44'` account's receive address, `index`, that an output pays: a
/// payment from the seed to itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Own<'a> {
    pub account: &'a Account,
    pub index: u32,
}

/// Where the change goes, marked for the unit to show as CHANGE.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Change<'a> {
    /// No change output: what is left over the outputs is the fee.
    None,
    /// A `44'` account's `chain`/`index`.
    Account {
        account: &'a Account,
        chain: u32,
        index: u32,
    },
    /// A `45'` group's `cosigner`/`chain`/`index`.
    Group {
        group: &'a Group,
        cosigner: u32,
        chain: u32,
        index: u32,
    },
}

/// How an output is bound to a covenant. `coin` is the place, in the
/// request's coins, of the coin whose input authorizes the output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Binding {
    /// Not bound.
    None,
    /// The output continues the covenant `coin` is bound to, under that
    /// coin's id.
    Continue { coin: usize },
    /// The output starts a new covenant, with every other output `coin`
    /// starts one with: the id is made from the coin's outpoint and those
    /// outputs.
    Start { coin: usize },
}

/// What the request pays.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Payment<'a> {
    /// These outputs, and the change to `change`.
    Outputs {
        outputs: &'a [Pay<'a>],
        change: Change<'a>,
    },
    /// These outputs, `bindings[k]` saying how `outputs[k]` is bound to a
    /// covenant, and the change, never bound, to `change`. With any output
    /// bound the transaction is version 1.
    Covenant {
        outputs: &'a [Pay<'a>],
        bindings: &'a [Binding],
        change: Change<'a>,
    },
    /// Everything the coins hold, less the fee, to one script: a `22'`
    /// spend, emptying an account, or gathering its coins. `own` places `to`
    /// when it is the wallet's own, as a change is placed; [`Change::None`]
    /// otherwise.
    Sweep { to: &'a [u8], own: Change<'a> },
}

/// The fee rate, in sompi a gram of mass. The fee is never under the
/// minimum relay fee whatever the rate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeeRate {
    pub sompi_per_gram: u64,
}

impl FeeRate {
    /// The minimum relay rate, 100 sompi a gram: what rusty-kaspa's wallet
    /// pays by default.
    pub const MINIMUM: FeeRate = FeeRate {
        sompi_per_gram: kassigner_kaspa::mass::MINIMUM_RELAY_FEE_PER_KG / 1000,
    };
}

/// The terms a request is built under: the fee rate, the network's mass
/// rates, the unit's bounds and the lock time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Terms<'a> {
    pub rate: FeeRate,
    /// [`MassRates::MAINNET`] for mainnet.
    pub rates: &'a MassRates,
    pub profile: &'a Profile,
    /// The lock time: zero for none, else a DAA score or a time in
    /// milliseconds ([`kassigner_kaspa::constants::classify_lock_time`]).
    /// Every input's sequence is zero, so no block takes the transaction
    /// before it ([`Transaction::lock_time_binds`]). A bundle carries it as
    /// each input's `minTime`, the greatest of which rusty-kaspa takes.
    pub lock_time: u64,
    /// Whether the request may end a covenant: spend a UTXO bound to one
    /// ([`Coin::covenant_id`]) with no output continuing it
    /// ([`Binding::Continue`]), so what it held leaves as plain KAS. `false`
    /// refuses a bound UTXO whose covenant no output continues.
    pub end_covenants: bool,
}

/// The caller's buffers a request is built in: one slot per coin in every
/// per-coin array, at most `profile.max_inputs`; one per output plus one for
/// the change, at most `profile.max_outputs`.
pub struct Scratch<'s> {
    /// One per coin.
    pub inputs: &'s mut [TransactionInput<'s>],
    /// One per output, the change included.
    pub outputs: &'s mut [TransactionOutput<'s>],
    /// One per coin: its redeem script, [`MAX_REDEEM`] bytes each.
    pub redeems: &'s mut [[u8; MAX_REDEEM]],
    /// One per coin: the redeem script's length, or zero.
    pub redeem_lens: &'s mut [usize],
    /// One per coin: the slice of its redeem, for the draft.
    pub redeem_slices: &'s mut [&'s [u8]],
    /// The change output's script.
    pub change_script: &'s mut [u8; PAY_TO_SCRIPT_HASH_LEN],
    /// One per coin: its locking script, derived from its source.
    pub scripts: &'s mut [[u8; PAY_TO_SCRIPT_HASH_LEN]],
    /// One per coin: that script's length.
    pub script_lens: &'s mut [usize],
    /// One per coin, for `45'` hints.
    pub input_hints: &'s mut [Hint],
    /// One per coin, for `22'` hints.
    pub kcc3_hints: &'s mut [Kcc3Hint],
    /// One per coin, for `44'` hints.
    pub account_hints: &'s mut [AccountHint],
    /// One, for a group's change.
    pub output_hints: &'s mut [Hint],
    /// At least one, for a `44'` account's change; one per output, the
    /// change included, when outputs pay the account's own receive
    /// addresses past the unit's bank.
    pub account_output_hints: &'s mut [AccountHint],
    /// One per coin, for the storage mass.
    pub cells_in: &'s mut [Cell],
    /// One per output, the change included, for the storage mass.
    pub cells_out: &'s mut [Cell],
    /// One per coin, for the covenant ids of the bound ones.
    pub coin_covenants: &'s mut [CoinCovenant],
}

/// Why a request was not built.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestError {
    /// No coins, or no outputs.
    Empty,
    /// More coins or outputs than the profile, or than the scratch holds.
    TooMany,
    /// Coin `coin` is one given already: the same outpoint as an earlier
    /// coin's. A transaction spending an outpoint twice breaks consensus
    /// (upstream's `check_duplicate_transaction_inputs`), and the unit
    /// refuses the request on arrival.
    CoinTwice { coin: usize },
    /// A coin's source, or the change's place, could not be derived.
    Watch(WatchError),
    /// A group a unit does not sign.
    Multisig(MultisigError),
    /// A coin's hint with a hardened or out-of-range level, which the unit
    /// reads as no hint.
    BadHint { coin: usize },
    /// Coin `coin` is bound to a covenant no output continues, which
    /// spending it would end, and the terms do not say to
    /// ([`Terms::end_covenants`]).
    CovenantBound { coin: usize },
    /// Output `output`'s binding names a coin the request does not spend,
    /// or continues the covenant of a coin bound to none; or, with `output`
    /// the number of outputs, the bindings are not one per output.
    BadBinding { output: usize },
    /// A bundle cannot carry a request with an output bound to a covenant:
    /// it has no field for a version 1 input's compute budget.
    CovenantInBundle,
    /// The bindings break a consensus rule on covenants.
    Covenant(TxRuleError),
    /// Coin `coin`'s covenant id and its entry's ([`EntryDetails`]) are not
    /// the same.
    CovenantEntry { coin: usize },
    /// The change's place with a hardened or out-of-range level.
    BadChange,
    /// Coin `coin` is a card's UTXO and the key named to sign it is neither
    /// the card's owner's nor its recovery wallet's.
    NotTheCardsKey { coin: usize },
    /// Coin `coin` is a card's UTXO and the lock time is before the card's
    /// time, which the card's program and the unit refuse.
    CardLocked { coin: usize },
    /// Coin `coin` is a card's UTXO, which the safe JSON cannot carry: it
    /// has no redeem script for the card's program.
    CardInSafeJson { coin: usize },
    /// An output marked as the wallet's own (an own receive output, or a
    /// sweep's) that is not that address's, or whose place has a hardened or
    /// out-of-range level.
    BadOwn { output: usize },
    /// An output's value is dust.
    Dust { output: usize },
    /// A sweep's single output would be dust after the fee.
    SweepDust,
    /// The coins do not cover the outputs and the fee.
    Insufficient { have: u64, need: u64 },
    /// The storage mass is past a block's limit, which a node will not take
    /// ([`BLOCK_STORAGE_MASS_LIMIT`]): an output under 0.02 KAS, short of
    /// inputs that offset it.
    StorageMass { mass: u64 },
    /// A value or the fee past what Kaspa holds.
    ValueOutOfRange,
    /// The mass could not be computed: a value or size past range.
    Mass,
    /// The writer refused: over the profile, or a redeem script that is not
    /// its lock's.
    Kspt(KsptError),
    /// The request is longer than the unit reassembles.
    TooLong { len: usize, limit: usize },
    /// The bundle writer refused, or a buffer for it is short.
    Bundle(pskb_write::WriteError),
    /// The bundle's envelope does not fit the caller's buffer.
    Envelope(EnvelopeError),
    /// The safe JSON does not fit the caller's buffer.
    SafeJson(SafeJsonError),
}

impl From<SafeJsonError> for RequestError {
    fn from(e: SafeJsonError) -> Self {
        RequestError::SafeJson(e)
    }
}

impl From<pskb_write::WriteError> for RequestError {
    fn from(e: pskb_write::WriteError) -> Self {
        RequestError::Bundle(e)
    }
}

impl From<EnvelopeError> for RequestError {
    fn from(e: EnvelopeError) -> Self {
        RequestError::Envelope(e)
    }
}

impl From<WatchError> for RequestError {
    fn from(e: WatchError) -> Self {
        RequestError::Watch(e)
    }
}

impl From<kassigner_protocol::group::GroupError> for RequestError {
    fn from(e: kassigner_protocol::group::GroupError) -> Self {
        RequestError::Watch(WatchError::Group(e))
    }
}

impl From<KsptError> for RequestError {
    fn from(e: KsptError) -> Self {
        RequestError::Kspt(e)
    }
}

/// What [`build`], [`bundle`] or [`safe_json()`] made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    /// Bytes written to `out`: the KSPT, the bundle's envelope or the JSON.
    pub len: usize,
    /// The fee the transaction pays.
    pub fee: u64,
    /// The mass the fee was computed over.
    pub mass: u64,
    /// The change output's value, when there is one.
    pub change: Option<u64>,
    /// Signatures the reply must carry in all: a group input's threshold,
    /// one for any other input.
    pub signatures: usize,
}

/// A locking script from a mainnet address, into `out`: its length.
///
/// The network is checked: the script carries none, and the unit shows the
/// output as `kaspa:` whatever the text said.
///
/// # Errors
///
/// `NotAnAddress` for text that is not one, `NotMainnet` for one on another
/// network, `NotScriptHash` for an ECDSA key's.
pub fn script_of_address(
    text: &[u8],
    out: &mut [u8; PAY_TO_SCRIPT_HASH_LEN],
) -> Result<usize, WatchError> {
    let mut payload = [0u8; 33];
    let (network, version, n) =
        address::decode(text.trim_ascii(), &mut payload).map_err(WatchError::NotAnAddress)?;
    watch::mainnet(network)?;
    let key = <[u8; 32]>::try_from(&payload[..n.min(32)]).map_err(|_| WatchError::NotScriptHash)?;
    match version {
        Version::PubKey => {
            out[..34].copy_from_slice(&pay_to_pubkey(&key));
            Ok(34)
        }
        Version::ScriptHash => {
            *out = pay_to_script_hash(&key);
            Ok(PAY_TO_SCRIPT_HASH_LEN)
        }
        Version::PubKeyEcdsa => Err(WatchError::NotScriptHash),
    }
}

/// Whether `chain` is receive or change and `index` soft: what the unit
/// reads as a hint.
const fn is_hint_level(chain: u32, index: u32) -> bool {
    chain <= CHANGE && index & 0x8000_0000 == 0
}

/// Whether a `44'` key at `chain`/`index` lies past the unit's bank, the
/// first [`RECEIVE_DEPTH`] receive and [`CHANGE_DEPTH`] change keys: there
/// the request must say where it is.
const fn past_bank(chain: u32, index: u32) -> bool {
    index
        >= if chain == CHANGE {
            CHANGE_DEPTH
        } else {
            RECEIVE_DEPTH
        }
}

/// What [`assemble`] gives [`build`], [`bundle`] and [`safe_json()`]:
/// the transaction, its redeem scripts and hints, and the request, `len`
/// not yet known.
struct Assembled<'s> {
    tx: Transaction<'s>,
    draft: Draft<'s>,
    request: Request,
    /// The storage mass the signed transaction commits.
    storage_mass: u64,
}

/// Build a request for the unit: the KSPT into `out`.
///
/// `coins` are spent in the order given; `payment` says what for; `terms`
/// give the fee rate, the mass rates, the unit's bounds and the lock time.
/// Every per-coin buffer of `scratch` holds `coins.len()`, every per-output
/// one the outputs plus one for the change, and `out` [`kspt::draft_len`]
/// of the result.
///
/// # Errors
///
/// Any [`RequestError`] but `Bundle`, `Envelope`, `SafeJson`,
/// `CardInSafeJson` and `CovenantEntry`, which only [`bundle`] and
/// [`safe_json()`] give.
/// Nothing is written to `out` on an error.
pub fn build<'s>(
    coins: &[Coin<'_>],
    payment: Payment<'s>,
    terms: Terms<'_>,
    scratch: &'s mut Scratch<'s>,
    out: &mut [u8],
) -> Result<Request, RequestError> {
    let profile = terms.profile;
    let Assembled {
        tx, draft, request, ..
    } = assemble(coins, payment, terms, scratch)?;
    let len = kspt::draft_len(&draft, &tx, profile)?;
    if len > profile.max_reassembled {
        return Err(RequestError::TooLong {
            len,
            limit: profile.max_reassembled,
        });
    }
    let len = kspt::write_draft(&draft, &tx, profile, out)?;
    Ok(Request { len, ..request })
}

/// The caller's buffers a bundle is written in, besides a request's. The
/// per-key ones hold, per coin, at most a group's keys
/// ([`crate::bundle::HINT_KEYS`]), as many for the change, and one per own
/// receive output.
pub struct BundleScratch<'w> {
    /// One per key a derivation names.
    pub keys: &'w mut [[u8; PUBLIC_KEY_SIZE]],
    /// One per key: its key source.
    pub values: &'w mut [[u8; DERIVATION_MAX]],
    /// One per key: its key source's length.
    pub lens: &'w mut [usize],
    /// One per key, for the writer.
    pub members: &'w mut [Member<'w>],
    /// One per coin and per output, the change included: where its keys
    /// lie.
    pub ranges: &'w mut [(usize, usize)],
    /// One per coin.
    pub inputs: &'w mut [pskb_write::Input<'w>],
    /// One per output, the change included.
    pub outputs: &'w mut [pskb_write::Output<'w>],
    /// The bundle's document, before its envelope.
    pub doc: &'w mut [u8],
}

/// A derivation's refusal: `TooMany` for a short scratch, `refused` for
/// anything else, which is the hint's.
fn derivation_error(e: BundleError, refused: RequestError) -> RequestError {
    match e {
        BundleError::ScratchTooSmall(_) => RequestError::TooMany,
        _ => refused,
    }
}

/// Build the request as a bundle: the transaction [`build`] writes, as a
/// `PSKB` envelope into `out`.
///
/// `details` are the coins' entries past their value and script, one per
/// coin in the order of `coins`. `writing` is sized as [`BundleScratch`]
/// says, its `doc` for the document; `out` holds four bytes and twice the
/// document.
///
/// # Errors
///
/// As [`build`], but neither `Kspt` nor `TooLong`: a bundle is not only the
/// unit's, and [`crate::transport::Codes::plan`] refuses one too long for
/// the unit's frames. `TooMany` for `details` or `writing` short of the
/// coins; `CovenantEntry` for a coin and an entry naming different
/// covenants; `Bundle` for what the bundle writer refuses,
/// `Bundle(BufferTooSmall)` for `doc`; `Envelope(BufferTooSmall)` for
/// `out`.
pub fn bundle<'s>(
    coins: &[Coin<'_>],
    details: &[EntryDetails],
    payment: Payment<'s>,
    terms: Terms<'_>,
    scratch: &'s mut Scratch<'s>,
    writing: &'s mut BundleScratch<'s>,
    out: &mut [u8],
) -> Result<Request, RequestError> {
    let n = coins.len();
    if details.len() < n {
        return Err(RequestError::TooMany);
    }
    same_covenants(coins, &details[..n])?;
    let (pays, place, refused): (&[Pay<'_>], _, _) = match payment {
        Payment::Outputs { outputs, change } => (outputs, change, RequestError::BadChange),
        Payment::Covenant {
            outputs,
            bindings,
            change,
        } => {
            // A bound output makes a version 1 transaction, whose inputs
            // commit a compute budget a bundle has no field for.
            if bindings.iter().any(|b| *b != Binding::None) {
                return Err(RequestError::CovenantInBundle);
            }
            (outputs, change, RequestError::BadChange)
        }
        Payment::Sweep { own, .. } => (&[], own, RequestError::BadOwn { output: 0 }),
    };
    let Assembled {
        tx, draft, request, ..
    } = assemble(coins, payment, terms, scratch)?;
    let no = tx.outputs.len();
    let BundleScratch {
        keys,
        values,
        lens,
        members,
        ranges,
        inputs,
        outputs,
        doc,
    } = writing;
    if ranges.len() < n + no || inputs.len() < n || outputs.len() < no {
        return Err(RequestError::TooMany);
    }

    // Each coin's keys and key sources, none for a `22'` coin, which the
    // unit searches for; then each output's: an own receive output's, the
    // kept change's (the last output), or a sweep's own output's.
    let mut at = 0usize;
    let mut derive = |hint: &BundleHint<'_>, input: usize| -> Result<usize, BundleError> {
        let k = sdk_bundle::entries(
            hint,
            input,
            keys.get_mut(at..).unwrap_or_default(),
            values.get_mut(at..).unwrap_or_default(),
            lens.get_mut(at..).unwrap_or_default(),
        )?;
        at += k;
        Ok(at)
    };
    let mut from = 0usize;
    for (i, coin) in coins.iter().enumerate() {
        let hint = match coin.source {
            Source::Account {
                account,
                chain,
                index,
            } => Some(BundleHint::Account {
                account,
                chain,
                index,
                fingerprint: [0; 4],
            }),
            Source::Group {
                group,
                cosigner,
                chain,
                index,
            } => Some(BundleHint::Group {
                group,
                cosigner,
                chain,
                index,
                fingerprints: &[],
            }),
            Source::Kcc3 { .. } => None,
            // The card's named key, as a `44'` coin's.
            Source::Card { signer, .. } => signer.map(|(account, index)| BundleHint::Account {
                account,
                chain: RECEIVE,
                index,
                fingerprint: [0; 4],
            }),
        };
        let to = match hint {
            Some(h) => {
                derive(&h, i).map_err(|e| derivation_error(e, RequestError::BadHint { coin: i }))?
            }
            None => from,
        };
        ranges[i] = (from, to);
        from = to;
    }
    let place_at = match payment {
        Payment::Outputs { .. } | Payment::Covenant { .. } => request.change.map(|_| no - 1),
        Payment::Sweep { .. } => Some(0),
    };
    let place_hint = match place {
        Change::Group {
            group,
            cosigner,
            chain,
            index,
        } => Some(BundleHint::Group {
            group,
            cosigner,
            chain,
            index,
            fingerprints: &[],
        }),
        Change::Account {
            account,
            chain,
            index,
        } => Some(BundleHint::Account {
            account,
            chain,
            index,
            fingerprint: [0; 4],
        }),
        Change::None => None,
    };
    for k in 0..no {
        let (hint, refused) = if place_at == Some(k) {
            (place_hint, refused)
        } else {
            let own = pays.get(k).and_then(|p| p.own);
            let hint = own.map(|Own { account, index }| BundleHint::Account {
                account,
                chain: RECEIVE,
                index,
                fingerprint: [0; 4],
            });
            (hint, RequestError::BadOwn { output: k })
        };
        let to = match hint {
            Some(h) => derive(&h, n + k).map_err(|e| derivation_error(e, refused))?,
            None => from,
        };
        ranges[n + k] = (from, to);
        from = to;
    }
    let to = from;

    // The members over the keys, each run in key order, as a map holds them.
    let keys: &'s [[u8; PUBLIC_KEY_SIZE]] = keys;
    let values: &'s [[u8; DERIVATION_MAX]] = values;
    let lens: &'s [usize] = lens;
    let room = members.get_mut(..to).ok_or(RequestError::TooMany)?;
    for (j, m) in room.iter_mut().enumerate() {
        *m = Member {
            public_key: &keys[j],
            value: &values[j][..lens[j]],
        };
    }
    for &(from, to) in &ranges[..n + no] {
        room[from..to].sort_unstable_by(|a, b| a.public_key.cmp(b.public_key));
    }
    let members: &'s [Member<'s>] = members;

    for (i, (slot, input)) in inputs.iter_mut().zip(tx.inputs).enumerate() {
        let (from, to) = ranges[i];
        let redeem = draft.redeems[i];
        *slot = pskb_write::Input {
            previous_outpoint: input.previous_outpoint,
            utxo_entry: input.utxo_entry,
            details: details[i],
            sequence: Some(input.sequence),
            min_time: (tx.lock_time != 0).then_some(tx.lock_time),
            sighash_type: SIG_HASH_ALL.to_u8(),
            redeem_script: (!redeem.is_empty()).then_some(redeem),
            sig_op_count: Some(input.sig_op_count),
            derivations: &members[from..to],
        };
    }
    for (k, (slot, output)) in outputs.iter_mut().zip(tx.outputs).enumerate() {
        let (from, to) = ranges[n + k];
        *slot = pskb_write::Output {
            amount: output.value,
            script_public_key: output.script_public_key,
            covenant: output.covenant,
            derivations: &members[from..to],
        };
    }
    let inputs: &[pskb_write::Input<'_>] = &inputs[..n];
    let outputs: &[pskb_write::Output<'_>] = &outputs[..no];
    // No payload. The lock time is each input's `minTime`, never the
    // fallback, which rusty-kaspa takes only for a bundle with no inputs.
    let global = Global {
        version: BundleVersion::Zero,
        tx_version: tx.version,
        fallback_lock_time: None,
        payload: None,
    };
    let len = pskb_write::written_len(&global, inputs, outputs)?;
    let doc = doc
        .get_mut(..len)
        .ok_or(RequestError::Bundle(pskb_write::WriteError::BufferTooSmall))?;
    pskb_write::write(&global, inputs, outputs, doc)?;
    let len = encode_envelope(doc, out)?;
    Ok(Request { len, ..request })
}

/// Build the request in the WASM SDK's safe JSON (`serializeToSafeJSON`)
/// into `out`: the unsigned transaction [`build`] writes, each input with
/// the whole output it spends, the storage mass committed. A wallet signs
/// it; [`crate::reply::finalize_safe_json`] reads it back.
///
/// `details` are as [`bundle`] takes them; `out` holds
/// [`safe_json::written_len`] of the result.
///
/// # Errors
///
/// As [`build`], but neither `Kspt` nor `TooLong`; `TooMany` for `details`
/// short of the coins; `CovenantEntry` for a coin and an entry naming
/// different covenants; `CardInSafeJson` for a card's UTXO;
/// `SafeJson(BufferTooSmall)` for `out`.
pub fn safe_json<'s>(
    coins: &[Coin<'_>],
    details: &[EntryDetails],
    payment: Payment<'s>,
    terms: Terms<'_>,
    scratch: &'s mut Scratch<'s>,
    out: &mut [u8],
) -> Result<Request, RequestError> {
    let n = coins.len();
    let details = details.get(..n).ok_or(RequestError::TooMany)?;
    same_covenants(coins, details)?;
    if let Some(coin) = coins
        .iter()
        .position(|c| matches!(c.source, Source::Card { .. }))
    {
        return Err(RequestError::CardInSafeJson { coin });
    }
    let Assembled {
        tx,
        request,
        storage_mass,
        ..
    } = assemble(coins, payment, terms, scratch)?;
    let len = safe_json::write(&tx, details, storage_mass, out)?;
    Ok(Request { len, ..request })
}

/// `CovenantEntry` for the first coin whose entry names another covenant
/// than the coin does, or one where the coin names none; [`assemble`] takes
/// the coin's own `covenant_id`.
fn same_covenants(coins: &[Coin<'_>], details: &[EntryDetails]) -> Result<(), RequestError> {
    match coins
        .iter()
        .zip(details)
        .position(|(c, d)| c.covenant_id != d.covenant_id)
    {
        Some(coin) => Err(RequestError::CovenantEntry { coin }),
        None => Ok(()),
    }
}

/// The transaction for `coins` and `payment`, its fee found and every rule
/// the unit applies checked: what [`build`], [`bundle`] and [`safe_json()`]
/// share.
fn assemble<'s>(
    coins: &[Coin<'_>],
    payment: Payment<'s>,
    terms: Terms<'_>,
    scratch: &'s mut Scratch<'s>,
) -> Result<Assembled<'s>, RequestError> {
    let Terms {
        rate,
        rates,
        profile,
        lock_time,
        end_covenants,
    } = terms;
    let n = coins.len();
    if n == 0 {
        return Err(RequestError::Empty);
    }
    let Scratch {
        inputs,
        outputs,
        redeems,
        redeem_lens,
        redeem_slices,
        change_script,
        scripts,
        script_lens,
        input_hints,
        kcc3_hints,
        account_hints,
        output_hints,
        account_output_hints,
        cells_in,
        cells_out,
        coin_covenants,
    } = scratch;
    if n > profile.max_inputs
        || inputs.len() < n
        || redeems.len() < n
        || redeem_lens.len() < n
        || redeem_slices.len() < n
        || scripts.len() < n
        || script_lens.len() < n
        || input_hints.len() < n
        || kcc3_hints.len() < n
        || account_hints.len() < n
        || cells_in.len() < n
        || coin_covenants.len() < n
        || output_hints.is_empty()
        || account_output_hints.is_empty()
    {
        return Err(RequestError::TooMany);
    }
    // No coin twice, before any amount is added up: a second copy would
    // count in the inputs and the fee. Each against those before it, as
    // `Transaction::check_duplicate_inputs` does for the unit.
    if let Some(coin) = (1..n).find(|&i| coins[..i].iter().any(|c| c.outpoint == coins[i].outpoint))
    {
        return Err(RequestError::CoinTwice { coin });
    }

    // What is paid, and how each output is bound to a covenant: an output
    // past the bindings' end is not bound.
    let (pays, bindings, change, sweep_to, sweep_own): (
        &[Pay<'_>],
        &[Binding],
        Change<'_>,
        Option<&[u8]>,
        _,
    ) = match payment {
        Payment::Outputs { outputs, change } => (outputs, &[], change, None, Change::None),
        Payment::Covenant {
            outputs,
            bindings,
            change,
        } => {
            if bindings.len() != outputs.len() {
                return Err(RequestError::BadBinding {
                    output: outputs.len(),
                });
            }
            (outputs, bindings, change, None, Change::None)
        }
        Payment::Sweep { to, own } => (&[], &[], Change::None, Some(to), own),
    };
    let binding = |k: usize| bindings.get(k).copied().unwrap_or(Binding::None);
    // Each binding names a coin of the request, and one that continues a
    // covenant a coin bound to one.
    for (k, b) in bindings.iter().enumerate() {
        let named = match *b {
            Binding::None => continue,
            Binding::Continue { coin } => coins.get(coin).map(|c| c.covenant_id.is_some()),
            Binding::Start { coin } => coins.get(coin).map(|_| true),
        };
        if named != Some(true) {
            return Err(RequestError::BadBinding { output: k });
        }
    }
    // A binding is consensus's from version 1 (`CovenantBindingInV0`).
    let version: u16 = if bindings.iter().any(|b| *b != Binding::None) {
        1
    } else {
        0
    };
    // The covenant an output continues: its authorizing coin's.
    let continued = |k: usize| match binding(k) {
        Binding::Continue { coin } => coins.get(coin).and_then(|c| c.covenant_id),
        _ => None,
    };

    // The inputs: each coin's script from its source, its signature
    // operations, its redeem script and its hint.
    let mut have = 0u64;
    let mut signatures = 0usize;
    let mut min_sigs = 1u16;
    let (mut hints, mut kcc3s, mut accounts) = (0usize, 0usize, 0usize);
    // The bound coins' covenant ids, in input order, for the unit. A
    // covenant no output continues ends here, which the terms must say.
    let mut bound = 0usize;
    for (i, coin) in coins.iter().enumerate() {
        if let Some(covenant_id) = coin.covenant_id {
            let ends = !(0..bindings.len()).any(|k| continued(k) == Some(covenant_id));
            if ends && !end_covenants {
                return Err(RequestError::CovenantBound { coin: i });
            }
            coin_covenants[bound] = CoinCovenant {
                index: i as u8,
                covenant_id,
            };
            bound += 1;
        }
        have = checked_add_value(have, coin.amount).ok_or(RequestError::ValueOutOfRange)?;
        let (sig_op_count, needed) = match coin.source {
            Source::Account {
                account,
                chain,
                index,
            } => {
                if !is_hint_level(chain, index) {
                    return Err(RequestError::BadHint { coin: i });
                }
                if past_bank(chain, index) {
                    account_hints[accounts] = AccountHint {
                        index: i as u8,
                        chain,
                        addr_index: index,
                    };
                    accounts += 1;
                }
                let s = account.script(chain, index)?;
                scripts[i][..s.len()].copy_from_slice(&s);
                script_lens[i] = s.len();
                redeem_lens[i] = 0;
                (1u8, 1usize)
            }
            Source::Group {
                group,
                cosigner,
                chain,
                index,
            } => {
                if !is_hint_level(chain, index) || cosigner & 0x8000_0000 != 0 {
                    return Err(RequestError::BadHint { coin: i });
                }
                let len = group.redeem(cosigner, chain, index, &mut redeems[i])?;
                let ms = check::multisig(&redeems[i][..len])
                    .map_err(RequestError::Multisig)?
                    .ok_or(RequestError::Multisig(MultisigError::Unsupported {
                        required: 0,
                        keys: 0,
                    }))?;
                scripts[i] =
                    pay_to_script_hash(&kassigner_kaspa::script::redeem_hash(&redeems[i][..len]));
                script_lens[i] = PAY_TO_SCRIPT_HASH_LEN;
                redeem_lens[i] = len;
                input_hints[hints] = Hint {
                    index: i as u8,
                    cosigner,
                    chain,
                    addr_index: index,
                };
                hints += 1;
                min_sigs = min_sigs.max(u16::from(ms.required));
                (ms.total, usize::from(ms.required))
            }
            Source::Kcc3 { address, hint } => {
                if let Some((chain, index)) = hint {
                    if !is_hint_level(chain, index) {
                        return Err(RequestError::BadHint { coin: i });
                    }
                    kcc3_hints[kcc3s] = Kcc3Hint {
                        index: i as u8,
                        chain,
                        addr_index: index,
                    };
                    kcc3s += 1;
                }
                scripts[i] = address.script();
                script_lens[i] = PAY_TO_SCRIPT_HASH_LEN;
                redeem_lens[i] = 0;
                (1u8, 1usize)
            }
            Source::Card { card, signer } => {
                if let Some((account, index)) = signer {
                    if !is_hint_level(RECEIVE, index) {
                        return Err(RequestError::BadHint { coin: i });
                    }
                    if !crate::card::holds(account, card, index)? {
                        return Err(RequestError::NotTheCardsKey { coin: i });
                    }
                    if past_bank(RECEIVE, index) {
                        account_hints[accounts] = AccountHint {
                            index: i as u8,
                            chain: RECEIVE,
                            addr_index: index,
                        };
                        accounts += 1;
                    }
                }
                redeems[i][..PROGRAM_LEN].copy_from_slice(&card.program());
                scripts[i] = card.locking_script();
                script_lens[i] = PAY_TO_SCRIPT_HASH_LEN;
                redeem_lens[i] = PROGRAM_LEN;
                (CARD_SIG_OPS, 1usize)
            }
        };
        signatures += needed;
        // Version 1 commits no signature operations but the compute budget
        // that buys as much: the same mass, the same room for the script.
        let (sig_op_count, compute_budget) = if version == 0 {
            (sig_op_count, 0)
        } else {
            (0, compute_budget_for(sig_op_count))
        };
        inputs[i] = TransactionInput {
            previous_outpoint: coin.outpoint,
            sequence: 0,
            sig_op_count,
            compute_budget,
            signature_script: &[],
            utxo_entry: UtxoEntry {
                amount: coin.amount,
                script_public_key: ScriptPublicKey {
                    version: 0,
                    script: &[],
                },
            },
        };
    }
    // The scripts and redeems are borrowed into the inputs only now: a
    // borrow inside the loop above would hold the arrays.
    let scripts: &'s [[u8; PAY_TO_SCRIPT_HASH_LEN]] = scripts;
    let redeems: &'s [[u8; MAX_REDEEM]] = redeems;
    for (i, input) in inputs[..n].iter_mut().enumerate() {
        input.utxo_entry.script_public_key.script = &scripts[i][..script_lens[i]];
    }
    for (i, slot) in redeem_slices[..n].iter_mut().enumerate() {
        *slot = &redeems[i][..redeem_lens[i]];
    }
    // What each script-hash input pushes besides the signatures the
    // wallet's estimate counts: a group's redeem script, KCC-3's as the unit
    // supplies it, and a card's signature script past its one signature.
    let unlock_extra: u64 = coins
        .iter()
        .zip(redeem_lens.iter())
        .map(|(coin, &len)| match coin.source {
            Source::Account { .. } => 0,
            Source::Group { .. } => push_len(len) as u64,
            Source::Kcc3 { .. } => push_len(KCC3_REDEEM_LEN) as u64,
            Source::Card { .. } => CARD_SCRIPT_LEN as u64 - SIGNATURE_SCRIPT_SIZE,
        })
        .sum::<u64>()
        .saturating_mul(rates.mass_per_tx_byte);

    // The outputs and the change's script, then the fee over the mass, then
    // the change's value; no change output where it would be dust, the
    // wallet's rule.
    let no = pays.len() + usize::from(sweep_to.is_some());
    if no == 0 {
        return Err(RequestError::Empty);
    }
    // A sweep to the wallet's own address, checked against that address;
    // hinted below as the change is.
    let owned = match sweep_own {
        Change::None => true,
        Change::Account {
            account,
            chain,
            index,
        } => {
            is_hint_level(chain, index)
                && account.script(chain, index).ok().as_ref().map(|s| &s[..]) == sweep_to
        }
        Change::Group {
            group,
            cosigner,
            chain,
            index,
        } => {
            is_hint_level(chain, index)
                && cosigner & 0x8000_0000 == 0
                && crate::watch::group_script(group, cosigner, chain, index)
                    .ok()
                    .as_ref()
                    .map(|s| &s[..])
                    == sweep_to
        }
    };
    if !owned {
        return Err(RequestError::BadOwn { output: 0 });
    }
    let change_len = match change {
        Change::None => 0,
        Change::Account {
            account,
            chain,
            index,
        } => {
            if !is_hint_level(chain, index) {
                return Err(RequestError::BadChange);
            }
            let s = account.script(chain, index)?;
            change_script[..s.len()].copy_from_slice(&s);
            s.len()
        }
        Change::Group {
            group,
            cosigner,
            chain,
            index,
        } => {
            if !is_hint_level(chain, index) || cosigner & 0x8000_0000 != 0 {
                return Err(RequestError::BadChange);
            }
            **change_script = crate::watch::group_script(group, cosigner, chain, index)?;
            PAY_TO_SCRIPT_HASH_LEN
        }
    };
    let with_change = change_len > 0;
    let most = no + usize::from(with_change);
    if most > profile.max_outputs || outputs.len() < most || cells_out.len() < most {
        return Err(RequestError::TooMany);
    }
    // Each output to the account's own receive address, checked against
    // that address and hinted past the bank; the change's hint follows.
    let mut marked_account = 0usize;
    for (k, pay) in pays.iter().enumerate() {
        let Some(Own { account, index }) = pay.own else {
            continue;
        };
        if !is_hint_level(RECEIVE, index)
            || account.script(RECEIVE, index).ok().as_ref().map(|s| &s[..]) != Some(pay.script)
        {
            return Err(RequestError::BadOwn { output: k });
        }
        if past_bank(RECEIVE, index) {
            *account_output_hints
                .get_mut(marked_account)
                .ok_or(RequestError::TooMany)? = AccountHint {
                index: k as u8,
                chain: RECEIVE,
                addr_index: index,
            };
            marked_account += 1;
        }
    }
    let mut paid = 0u64;
    for (k, pay) in pays.iter().enumerate() {
        if is_dust(pay.value, pay.script.len()) {
            return Err(RequestError::Dust { output: k });
        }
        paid = checked_add_value(paid, pay.value).ok_or(RequestError::ValueOutOfRange)?;
        // A continued covenant's id is its coin's; a new one's is made
        // below, once every value is final, and weighs the same meanwhile.
        let covenant = match binding(k) {
            Binding::None => None,
            Binding::Continue { coin } | Binding::Start { coin } => Some(CovenantBinding {
                authorizing_input: coin as u16,
                covenant_id: continued(k).unwrap_or([0; 32]),
            }),
        };
        outputs[k] = TransactionOutput {
            value: pay.value,
            script_public_key: ScriptPublicKey {
                version: 0,
                script: pay.script,
            },
            covenant,
        };
    }
    if let Some(to) = sweep_to {
        outputs[0] = TransactionOutput {
            value: 0,
            script_public_key: ScriptPublicKey {
                version: 0,
                script: to,
            },
            covenant: None,
        };
    }
    let change_script: &'s [u8; PAY_TO_SCRIPT_HASH_LEN] = change_script;
    if with_change {
        outputs[no] = TransactionOutput {
            value: 0,
            script_public_key: ScriptPublicKey {
                version: 0,
                script: &change_script[..change_len],
            },
            covenant: None,
        };
    }

    // The fee in one pass, as rusty-kaspa 2.1.0's generator finds it (see
    // the module's Fee section): a payment keeps or drops its change as the
    // wallet would. The change, or the swept output, is what the fee leaves.
    let inputs: &'s [TransactionInput<'s>] = &inputs[..n];
    let compute_of = |count: usize, outputs: &[TransactionOutput<'_>]| {
        compute_mass(
            &transaction(version, inputs, &outputs[..count], lock_time),
            min_sigs,
            unlock_extra,
            rates,
        )
    };
    let price = |compute: u64, mass: u64| -> Result<u64, RequestError> {
        let asked = mass
            .checked_mul(rate.sompi_per_gram)
            .ok_or(RequestError::ValueOutOfRange)?;
        Ok(asked.max(minimum_relay_fee(compute)))
    };
    let parameter = rates.storage_mass_parameter;
    // Each output's value for the wallet's estimate. A bound output's 32
    // bytes more make it two storage units, which a node weighs as two
    // outputs of half its value.
    let values = pays.iter().enumerate().flat_map(|(k, p)| {
        let units = if binding(k) == Binding::None {
            1
        } else {
            plurality(p.script.len(), true)
        };
        core::iter::repeat_n(p.value / units, units as usize)
    });
    // The inputs in storage units, as a node counts them: one each, and a
    // bound coin's 32 bytes more make it two. The wallet's estimate takes
    // their count, the same number where no coin is bound.
    let units_in: u64 = coins
        .iter()
        .zip(inputs)
        .map(|(coin, input)| {
            plurality(
                input.utxo_entry.script_public_key.script.len(),
                coin.covenant_id.is_some(),
            )
        })
        .sum();
    let (fee, change_value, mass) = if let Some(to) = sweep_to {
        let compute = compute_of(1, outputs)?;
        let fee = price(compute, compute)?;
        let left = have.saturating_sub(fee);
        if is_dust(left, to.len()) {
            return Err(RequestError::SweepDust);
        }
        outputs[0].value = left;
        (fee, None, compute)
    } else {
        let compute_no = compute_of(no, outputs)?;
        let storage_no = wallet_storage_mass(values.clone(), have, units_in, parameter)
            .ok_or(RequestError::Mass)?;
        let before = have
            .checked_sub(paid)
            .filter(|&v| with_change && !is_dust(v, change_len));
        let (keep, compute, storage) = match before {
            Some(v) => {
                let compute_with = compute_of(no + 1, outputs)?;
                let storage_with =
                    wallet_storage_mass(values.chain([v]), have, units_in, parameter)
                        .ok_or(RequestError::Mass)?;
                if storage_with == 0 || storage_with < compute_with {
                    (true, compute_with, 0)
                } else if storage_with < storage_no {
                    (true, compute_with, storage_with)
                } else {
                    let with = price(compute_with, compute_with.max(storage_with))?;
                    let without = price(compute_no, compute_no.max(storage_no))?;
                    if with.saturating_sub(without) > v {
                        (false, compute_no, storage_no)
                    } else {
                        (true, compute_with, storage_with)
                    }
                }
            }
            None => (false, compute_no, storage_no),
        };
        // The wallet caps storage mass at 100,000 grams; a node takes up to
        // a block's limit, and so does this.
        if storage > BLOCK_STORAGE_MASS_LIMIT {
            return Err(RequestError::StorageMass { mass: storage });
        }
        let mass = compute.max(storage);
        let fee = price(compute, mass)?;
        let need = checked_add_value(paid, fee).ok_or(RequestError::ValueOutOfRange)?;
        if have < need {
            return Err(RequestError::Insufficient { have, need });
        }
        let left = have - need;
        if keep && !is_dust(left, change_len) {
            outputs[no].value = left;
            (fee, Some(left), mass)
        } else {
            (fee + left, None, mass)
        }
    };
    let count = no + usize::from(change_value.is_some());
    // Each new covenant's id, now that its outputs' values are final: made
    // from its authorizing input's outpoint and the outputs it starts, in
    // output order (KIP-20; upstream's `covenant_id`).
    for k in 0..no {
        let Binding::Start { coin } = binding(k) else {
            continue;
        };
        let starts = |j: usize| binding(j) == Binding::Start { coin };
        if (0..k).any(starts) {
            continue;
        }
        let id = covenant_id(
            &inputs[coin].previous_outpoint,
            outputs[..no]
                .iter()
                .enumerate()
                .filter(|(j, _)| starts(*j))
                .map(|(j, o)| (j as u32, o)),
        );
        for (j, output) in outputs[..no].iter_mut().enumerate() {
            if starts(j) {
                output.covenant = Some(CovenantBinding {
                    authorizing_input: coin as u16,
                    covenant_id: id,
                });
            }
        }
    }
    let outputs: &'s [TransactionOutput<'s>] = &outputs[..count];
    let tx = transaction(version, inputs, outputs, lock_time);
    // Every binding against the coins the inputs spend, as the unit and a
    // node hold them (upstream's `CovenantsContext::from_tx`).
    tx.check_covenant_ids_of(|i| coins.get(i).and_then(|c| c.covenant_id))
        .map_err(RequestError::Covenant)?;
    // A card's UTXO under the unit's rules (level 1): a lock time at or
    // past the card's time. Its input is never final here.
    for (i, redeem) in redeem_slices[..n].iter().enumerate() {
        check::card(&tx, i, redeem).map_err(|_| RequestError::CardLocked { coin: i })?;
    }
    // The storage mass the signed transaction commits, as consensus
    // computes it over the final values, a bound coin counted as bound.
    let coin_covenants: &'s [CoinCovenant] = &coin_covenants[..bound];
    let is_bound = |i: usize| coins.get(i).is_some_and(|c| c.covenant_id.is_some());
    let storage_mass = storage_of(&tx, is_bound, rates, cells_in, cells_out)?;
    // A node refuses a transaction over the block's storage limit
    // (`validate_transaction_limits_in_context`). The estimate above priced
    // the fee on the change before the fee; the real change, or a sweep's own
    // output, can carry a far larger storage mass. Checked here on the final
    // values, so the unit is never asked to sign what no node will take.
    if storage_mass > BLOCK_STORAGE_MASS_LIMIT {
        return Err(RequestError::StorageMass { mass: storage_mass });
    }

    // The kept change, or a sweep's own output, hinted: a group's always,
    // an account's past the bank on either chain.
    let (at, place) = match (sweep_to, change_value) {
        (Some(_), _) => (0, sweep_own),
        (None, Some(_)) => (no, change),
        (None, None) => (0, Change::None),
    };
    let mut marked = 0usize;
    match place {
        Change::Group {
            cosigner,
            chain,
            index,
            ..
        } => {
            output_hints[0] = Hint {
                index: at as u8,
                cosigner,
                chain,
                addr_index: index,
            };
            marked = 1;
        }
        Change::Account { chain, index, .. } if past_bank(chain, index) => {
            *account_output_hints
                .get_mut(marked_account)
                .ok_or(RequestError::TooMany)? = AccountHint {
                index: at as u8,
                chain,
                addr_index: index,
            };
            marked_account += 1;
        }
        Change::Account { .. } | Change::None => {}
    }
    let draft = Draft {
        redeems: &redeem_slices[..n],
        input_hints: &input_hints[..hints],
        kcc3_hints: &kcc3_hints[..kcc3s],
        account_hints: &account_hints[..accounts],
        output_hints: &output_hints[..marked],
        account_output_hints: &account_output_hints[..marked_account],
        coin_covenants,
    };
    Ok(Assembled {
        tx,
        draft,
        storage_mass,
        request: Request {
            len: 0,
            fee,
            mass,
            change: change_value,
            signatures,
        },
    })
}

/// A transaction of `version`, `inputs` and `outputs` under `lock_time`,
/// nothing else set.
fn transaction<'t>(
    version: u16,
    inputs: &'t [TransactionInput<'t>],
    outputs: &'t [TransactionOutput<'t>],
    lock_time: u64,
) -> Transaction<'t> {
    Transaction {
        version,
        inputs,
        outputs,
        lock_time,
        subnetwork_id: SUBNETWORK_ID_NATIVE,
        gas: 0,
        payload: &[],
    }
}

/// The storage mass of `tx` as consensus finds it, which the signed
/// transaction commits: `bound(i)` says whether input `i`'s coin is bound
/// to a covenant, which takes 32 bytes more of storage (upstream's
/// `UtxoPlurality`), as an output with a binding does.
fn storage_of(
    tx: &Transaction<'_>,
    bound: impl Fn(usize) -> bool,
    rates: &MassRates,
    cells_in: &mut [Cell],
    cells_out: &mut [Cell],
) -> Result<u64, RequestError> {
    for (i, (cell, input)) in cells_in.iter_mut().zip(tx.inputs).enumerate() {
        *cell = Cell {
            plurality: plurality(input.utxo_entry.script_public_key.script.len(), bound(i)),
            amount: input.utxo_entry.amount,
        };
    }
    for (cell, output) in cells_out.iter_mut().zip(tx.outputs) {
        *cell = Cell {
            plurality: plurality(
                output.script_public_key.script.len(),
                output.covenant.is_some(),
            ),
            amount: output.value,
        };
    }
    storage_mass(
        &cells_in[..tx.inputs.len()],
        &cells_out[..tx.outputs.len()],
        rates.storage_mass_parameter,
    )
    .ok_or(RequestError::Mass)
}

/// The compute mass of `tx` as it will be signed: its own, the signatures'
/// the wallet counts, and the redeem scripts the wallet leaves out.
fn compute_mass(
    tx: &Transaction<'_>,
    min_sigs: u16,
    unlock_extra: u64,
    rates: &MassRates,
) -> Result<u64, RequestError> {
    let (compute, _transient) = non_contextual_masses(tx, rates).ok_or(RequestError::Mass)?;
    compute
        .checked_add(signature_compute_mass(tx.inputs.len(), min_sigs, rates))
        .and_then(|c| c.checked_add(unlock_extra))
        .ok_or(RequestError::Mass)
}
