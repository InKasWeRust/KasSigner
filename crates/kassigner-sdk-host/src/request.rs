// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A request built for the unit: [`kassigner_sdk::request`] over owned
//! values.
//!
//! A [`RequestBuilder`] holds copies of what the SDK takes as borrowed
//! slices, one call at a time, and builds the request in one SDK call: a
//! KSPT, a bundle or the safe JSON. [`summary`] reads a request back.
//!
//! # Covenants
//!
//! A coin can be bound to a covenant ([`Coin::bound_to`]), and an output
//! to one, in the SDK's two ways: it continues the covenant of a coin the
//! request spends ([`RequestBuilder::continue_covenant`]), or starts a new
//! one ([`RequestBuilder::start_covenant`]), whose id [`summary`] reads
//! back from the request. Each names the coin whose input authorizes the
//! output, by its place among the coins; no id is passed for an output. A
//! covenant some coin is bound to and no output continues ends, which a
//! build refuses unless told it may ([`RequestBuilder::end_covenants`]).
//! With an output bound the transaction is version 1, which a bundle
//! cannot carry.

use kassigner_kaspa::mass::Cell;
use kassigner_kaspa::pskb::write::{Input as BundleInput, Member, Output as BundleOutput};
use kassigner_kaspa::script::PAY_TO_SCRIPT_HASH_LEN;
use kassigner_kaspa::tx::{
    EntryDetails, Outpoint, ScriptPublicKey, TransactionInput, TransactionOutput, UtxoEntry,
};
use kassigner_protocol::kspt::{self, AccountHint, CoinCovenant, Hint, Kcc3Hint};
use kassigner_sdk::bundle::{DERIVATION_MAX, HINT_KEYS};
use kassigner_sdk::request::{
    self, Binding, BundleScratch, Change, FeeRate, Own, Pay, Payment, Scratch, Source, Terms,
};
use kassigner_sdk::watch::{self, MAX_REDEEM, RECEIVE};

use kassigner_sdk::card::Savings;

use crate::card::Card;
use crate::watch::{Account, Group, Kcc3Address};
use crate::{hex, unhex, Fault, Profile, Rates};

/// A coin to spend, as the builder holds it.
#[derive(Clone, Debug)]
enum Spent {
    Account {
        account: watch::Account,
        chain: u32,
        index: u32,
    },
    Group {
        group: Box<watch::Group>,
        cosigner: u32,
        chain: u32,
        index: u32,
    },
    Kcc3 {
        address: watch::Kcc3Address,
        hint: Option<(u32, u32)>,
    },
    Card {
        card: Savings,
        signer: Option<(watch::Account, u32)>,
    },
}

/// An output to pay, as the builder holds it.
#[derive(Clone, Debug)]
struct Paying {
    script: Vec<u8>,
    value: u64,
    own: Option<(watch::Account, u32)>,
    /// How it is bound to a covenant.
    binding: Binding,
}

/// Where the change goes, or a sweep's output when it is the wallet's own,
/// as the builder holds it.
#[derive(Clone, Debug)]
enum ChangeTo {
    None,
    Account {
        account: watch::Account,
        chain: u32,
        index: u32,
    },
    Group {
        group: Box<watch::Group>,
        cosigner: u32,
        chain: u32,
        index: u32,
    },
}

const BLANK_INPUT: TransactionInput<'static> = TransactionInput {
    previous_outpoint: Outpoint {
        transaction_id: [0; 32],
        index: 0,
    },
    sequence: 0,
    sig_op_count: 0,
    compute_budget: 0,
    signature_script: &[],
    utxo_entry: UtxoEntry {
        amount: 0,
        script_public_key: ScriptPublicKey {
            version: 0,
            script: &[],
        },
    },
};

const BLANK_OUTPUT: TransactionOutput<'static> = TransactionOutput {
    value: 0,
    script_public_key: ScriptPublicKey {
        version: 0,
        script: &[],
    },
    covenant: None,
};

const BLANK_HINT: Hint = Hint {
    index: 0,
    cosigner: 0,
    chain: 0,
    addr_index: 0,
};

const BLANK_ACCOUNT_HINT: AccountHint = AccountHint {
    index: 0,
    chain: 0,
    addr_index: 0,
};

/// Everything a request is built in, for `n` coins and `no` outputs, the
/// change among them.
struct Room<'a> {
    inputs: Vec<TransactionInput<'a>>,
    outputs: Vec<TransactionOutput<'a>>,
    redeems: Vec<[u8; MAX_REDEEM]>,
    redeem_lens: Vec<usize>,
    redeem_slices: Vec<&'a [u8]>,
    change_script: [u8; PAY_TO_SCRIPT_HASH_LEN],
    scripts: Vec<[u8; PAY_TO_SCRIPT_HASH_LEN]>,
    script_lens: Vec<usize>,
    input_hints: Vec<Hint>,
    kcc3_hints: Vec<Kcc3Hint>,
    account_hints: Vec<AccountHint>,
    output_hints: [Hint; 1],
    account_output_hints: Vec<AccountHint>,
    cells_in: Vec<Cell>,
    cells_out: Vec<Cell>,
    coin_covenants: Vec<CoinCovenant>,
}

impl Room<'_> {
    fn new(n: usize, no: usize) -> Self {
        let cell = Cell {
            plurality: 0,
            amount: 0,
        };
        Room {
            inputs: vec![BLANK_INPUT; n],
            outputs: vec![BLANK_OUTPUT; no],
            redeems: vec![[0u8; MAX_REDEEM]; n],
            redeem_lens: vec![0usize; n],
            redeem_slices: vec![&[]; n],
            change_script: [0u8; PAY_TO_SCRIPT_HASH_LEN],
            scripts: vec![[0u8; PAY_TO_SCRIPT_HASH_LEN]; n],
            script_lens: vec![0usize; n],
            input_hints: vec![BLANK_HINT; n],
            kcc3_hints: vec![
                Kcc3Hint {
                    index: 0,
                    chain: 0,
                    addr_index: 0
                };
                n
            ],
            account_hints: vec![BLANK_ACCOUNT_HINT; n],
            output_hints: [BLANK_HINT; 1],
            account_output_hints: vec![BLANK_ACCOUNT_HINT; no.max(1)],
            cells_in: vec![cell; n],
            cells_out: vec![cell; no],
            coin_covenants: vec![
                CoinCovenant {
                    index: 0,
                    covenant_id: [0; 32],
                };
                n
            ],
        }
    }
}

/// The SDK's scratch over a room, built where the room lives.
macro_rules! request_scratch {
    ($room:expr) => {
        Scratch {
            inputs: &mut $room.inputs,
            outputs: &mut $room.outputs,
            redeems: &mut $room.redeems,
            redeem_lens: &mut $room.redeem_lens,
            redeem_slices: &mut $room.redeem_slices,
            change_script: &mut $room.change_script,
            scripts: &mut $room.scripts,
            script_lens: &mut $room.script_lens,
            input_hints: &mut $room.input_hints,
            kcc3_hints: &mut $room.kcc3_hints,
            account_hints: &mut $room.account_hints,
            output_hints: &mut $room.output_hints,
            account_output_hints: &mut $room.account_output_hints,
            cells_in: &mut $room.cells_in,
            cells_out: &mut $room.cells_out,
            coin_covenants: &mut $room.coin_covenants,
        }
    };
}

/// Gathers a request's coins, outputs and change, then builds it.
#[derive(Clone, Debug)]
pub struct RequestBuilder {
    coins: Vec<(Coin, Spent)>,
    pays: Vec<Paying>,
    change: ChangeTo,
    sweep: Option<(Vec<u8>, ChangeTo)>,
    /// The network's DAA score now, if given ([`Self::at_daa_score`]).
    daa_score: Option<u64>,
    /// The transaction's lock time, zero for none ([`Self::lock_until`]).
    lock_time: u64,
    /// Whether the request may end a covenant ([`Self::end_covenants`]).
    end_covenants: bool,
}

/// A coin to spend: an output, its sompi and, for a bundle, its entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Coin {
    outpoint: Outpoint,
    amount: u64,
    entry: Option<EntryDetails>,
    covenant_id: Option<[u8; 32]>,
}

impl Coin {
    /// The output `txId` (hex) : `index`, holding `amount` sompi.
    pub fn new(tx_id: &str, index: u32, amount: u64) -> Result<Coin, Fault> {
        Ok(Coin {
            outpoint: Outpoint {
                transaction_id: unhex::<32>(tx_id)?,
                index,
            },
            amount,
            entry: None,
            covenant_id: None,
        })
    }

    /// As [`Coin::new`], with the entry a node lists: the accepting block's
    /// DAA score and whether a coinbase made it.
    pub fn with_entry(
        tx_id: &str,
        index: u32,
        amount: u64,
        block_daa_score: u64,
        is_coinbase: bool,
    ) -> Result<Coin, Fault> {
        Ok(Coin {
            entry: Some(EntryDetails {
                block_daa_score,
                is_coinbase,
                covenant_id: None,
            }),
            ..Coin::new(tx_id, index, amount)?
        })
    }

    /// The same coin, bound to the covenant `covenant_id` (hex), as a node
    /// lists it. A build refuses it, `CovenantBound { coin }`, unless an
    /// output continues its covenant
    /// ([`RequestBuilder::continue_covenant`]) or the request may end one
    /// ([`RequestBuilder::end_covenants`]).
    ///
    /// # Errors
    ///
    /// A covenant id that is not 32 bytes of hex.
    pub fn bound_to(self, covenant_id: &str) -> Result<Coin, Fault> {
        Ok(Coin {
            covenant_id: Some(unhex::<32>(covenant_id)?),
            ..self
        })
    }

    /// The covenant it is bound to, hex, when it is.
    pub fn covenant_id(&self) -> Option<String> {
        self.covenant_id.map(|c| hex(&c))
    }

    /// The DAA score of the block that accepted it, when given.
    pub fn block_daa_score(&self) -> Option<u64> {
        self.entry.map(|e| e.block_daa_score)
    }

    /// Whether a coinbase made it, when given.
    pub fn is_coinbase(&self) -> Option<bool> {
        self.entry.map(|e| e.is_coinbase)
    }

    /// Whether it can be spent at the network's DAA score `daa_score`: a
    /// coinbase's coin once matured, 1,000 DAA score on mainnet, any other
    /// at once. `None` for a coin made without its entry.
    pub fn spendable_at(&self, daa_score: u64) -> Option<bool> {
        self.entry.map(|e| e.spendable_at(daa_score))
    }

    /// The transaction id, hex.
    pub fn tx_id(&self) -> String {
        hex(&self.outpoint.transaction_id)
    }

    /// The output's index.
    pub fn index(&self) -> u32 {
        self.outpoint.index
    }

    /// Sompi.
    pub fn amount(&self) -> u64 {
        self.amount
    }
}

impl RequestBuilder {
    /// An empty request.
    pub fn new() -> RequestBuilder {
        RequestBuilder {
            coins: Vec::new(),
            pays: Vec::new(),
            change: ChangeTo::None,
            sweep: None,
            daa_score: None,
            lock_time: 0,
            end_covenants: false,
        }
    }

    /// Let the request end a covenant: spend a coin bound to one
    /// ([`Coin::bound_to`]) with no output continuing it, so what the coin
    /// held leaves as plain KAS. Without it a build refuses such a coin,
    /// `CovenantBound { coin }`. The unit shows the covenant ending, `No
    /// output continues it`.
    pub fn end_covenants(&mut self) {
        self.end_covenants = true;
    }

    /// Bind output `output`, by its place among the outputs paid so far,
    /// to the covenant coin `coin` is bound to, by its place among the
    /// coins: the output continues that covenant, under the coin's id, and
    /// the coin's input authorizes it. The transaction is then version 1.
    ///
    /// # Errors
    ///
    /// `BadBinding { output }` for an output not paid yet. A build gives it
    /// for a coin the request does not spend, or one bound to no covenant.
    pub fn continue_covenant(&mut self, output: u32, coin: u32) -> Result<(), Fault> {
        self.bind(
            output,
            Binding::Continue {
                coin: coin as usize,
            },
        )
    }

    /// Bind output `output`, by its place among the outputs paid so far,
    /// to a new covenant that coin `coin`'s input authorizes, by its place
    /// among the coins. Every output started from the same coin is of that
    /// one covenant; its id is made from the coin's outpoint and those
    /// outputs, and [`summary`] reads it from the built request. The
    /// transaction is then version 1.
    ///
    /// # Errors
    ///
    /// `BadBinding { output }` for an output not paid yet. A build gives it
    /// for a coin the request does not spend.
    pub fn start_covenant(&mut self, output: u32, coin: u32) -> Result<(), Fault> {
        self.bind(
            output,
            Binding::Start {
                coin: coin as usize,
            },
        )
    }

    /// Set output `output`'s binding; `BadBinding { output }` if there is
    /// no such output.
    fn bind(&mut self, output: u32, binding: Binding) -> Result<(), Fault> {
        match self.pays.get_mut(output as usize) {
            Some(pay) => {
                pay.binding = binding;
                Ok(())
            }
            None => Err(Fault(format!("BadBinding {{ output: {output} }}"))),
        }
    }

    /// The network's DAA score now, a node's `virtualDaaScore`, at which
    /// builds refuse a coinbase's coin not yet matured. A coin made without
    /// its entry is not checked.
    pub fn at_daa_score(&mut self, daa_score: u64) {
        self.daa_score = Some(daa_score);
    }

    /// The transaction's lock time: below 500,000,000,000 a DAA score, else
    /// a time in milliseconds; zero, the default, for none. No block takes
    /// the transaction until it is past.
    pub fn lock_until(&mut self, lock_time: u64) {
        self.lock_time = lock_time;
    }

    /// Spend `coin`, of a `44'` account's `chain`/`index`.
    pub fn spend_account(&mut self, account: &Account, chain: u32, index: u32, coin: &Coin) {
        self.coins.push((
            *coin,
            Spent::Account {
                account: *account.inner(),
                chain,
                index,
            },
        ));
    }

    /// Spend `coin`, of a `45'` group's `cosigner`/`chain`/`index`.
    pub fn spend_group(
        &mut self,
        group: &Group,
        cosigner: u32,
        chain: u32,
        index: u32,
        coin: &Coin,
    ) {
        self.coins.push((
            *coin,
            Spent::Group {
                group: Box::new(*group.inner()),
                cosigner,
                chain,
                index,
            },
        ));
    }

    /// Spend `coin`, of a `22'` address, with its `chain`/`index` below the
    /// `22'` account when the app knows them (both or neither).
    pub fn spend_kcc3(
        &mut self,
        address: &Kcc3Address,
        coin: &Coin,
        chain: Option<u32>,
        index: Option<u32>,
    ) -> Result<(), Fault> {
        let hint = match (chain, index) {
            (Some(c), Some(i)) => Some((c, i)),
            (None, None) => None,
            _ => return Err(Fault("a hint is a chain and an index".to_string())),
        };
        self.coins.push((
            *coin,
            Spent::Kcc3 {
                address: *address.inner(),
                hint,
            },
        ));
        Ok(())
    }

    /// Spend `coin`, a UTXO of `card`, with the key that signs it when the
    /// app knows it, `account`'s receive `index` ([`Card::signer`]): both or
    /// neither. The lock time must be on or after the card's.
    pub fn spend_card(
        &mut self,
        card: &Card,
        coin: &Coin,
        account: Option<&Account>,
        index: Option<u32>,
    ) -> Result<(), Fault> {
        let signer = match (account, index) {
            (Some(a), Some(i)) => Some((*a.inner(), i)),
            (None, None) => None,
            _ => return Err(Fault("a signer is an account and an index".to_string())),
        };
        self.coins.push((
            *coin,
            Spent::Card {
                card: *card.inner(),
                signer,
            },
        ));
        Ok(())
    }

    /// Pay `amount` sompi to `address`, a mainnet address.
    pub fn pay(&mut self, address: &str, amount: u64) -> Result<(), Fault> {
        let mut script = [0u8; PAY_TO_SCRIPT_HASH_LEN];
        let n = request::script_of_address(address.as_bytes(), &mut script).map_err(Fault::of)?;
        self.pays.push(Paying {
            script: script[..n].to_vec(),
            value: amount,
            own: None,
            binding: Binding::None,
        });
        Ok(())
    }

    /// Pay `amount` sompi to a locking script.
    pub fn pay_script(&mut self, script: &[u8], amount: u64) {
        self.pays.push(Paying {
            script: script.to_vec(),
            value: amount,
            own: None,
            binding: Binding::None,
        });
    }

    /// Pay `amount` sompi to a `44'` account's own receive address `index`,
    /// marked so the unit checks it and shows it as YOURS.
    ///
    /// # Errors
    ///
    /// `Derivation(..)` for an index with no address: a hardened one.
    pub fn pay_account(&mut self, account: &Account, index: u32, amount: u64) -> Result<(), Fault> {
        let account = *account.inner();
        let script = account.script(RECEIVE, index).map_err(Fault::of)?;
        self.pays.push(Paying {
            script: script.to_vec(),
            value: amount,
            own: Some((account, index)),
            binding: Binding::None,
        });
        Ok(())
    }

    /// Send the change to a `44'` account's `chain`/`index`.
    pub fn change_to_account(&mut self, account: &Account, chain: u32, index: u32) {
        self.change = ChangeTo::Account {
            account: *account.inner(),
            chain,
            index,
        };
    }

    /// Send the change to a `45'` group's `cosigner`/`chain`/`index`,
    /// marked for the unit to show as CHANGE.
    pub fn change_to_group(&mut self, group: &Group, cosigner: u32, chain: u32, index: u32) {
        self.change = ChangeTo::Group {
            group: Box::new(*group.inner()),
            cosigner,
            chain,
            index,
        };
    }

    /// Everything the coins hold, less the fee, to `address`, a mainnet
    /// address, instead of `pay` and a change: a `22'` spend, or emptying
    /// an account.
    pub fn sweep_to(&mut self, address: &str) -> Result<(), Fault> {
        let mut script = [0u8; PAY_TO_SCRIPT_HASH_LEN];
        let n = request::script_of_address(address.as_bytes(), &mut script).map_err(Fault::of)?;
        self.sweep = Some((script[..n].to_vec(), ChangeTo::None));
        Ok(())
    }

    /// As [`sweep_to`](Self::sweep_to), to a `44'` account's own
    /// `chain`/`index`, marked so the unit checks it and shows YOURS or
    /// CHANGE.
    ///
    /// # Errors
    ///
    /// `Derivation(..)` for a place with no address: a hardened index.
    pub fn sweep_to_account(
        &mut self,
        account: &Account,
        chain: u32,
        index: u32,
    ) -> Result<(), Fault> {
        let account = *account.inner();
        let script = account.script(chain, index).map_err(Fault::of)?;
        self.sweep = Some((
            script.to_vec(),
            ChangeTo::Account {
                account,
                chain,
                index,
            },
        ));
        Ok(())
    }

    /// As [`sweep_to`](Self::sweep_to), to a `45'` group's own
    /// `cosigner`/`chain`/`index`, marked so the unit shows CHANGE.
    ///
    /// # Errors
    ///
    /// `Group(Multisig(..))` for a place with no address: a hardened level.
    pub fn sweep_to_group(
        &mut self,
        group: &Group,
        cosigner: u32,
        chain: u32,
        index: u32,
    ) -> Result<(), Fault> {
        let group = *group.inner();
        let script = watch::group_script(&group, cosigner, chain, index).map_err(Fault::of)?;
        self.sweep = Some((
            script.to_vec(),
            ChangeTo::Group {
                group: Box::new(group),
                cosigner,
                chain,
                index,
            },
        ));
        Ok(())
    }

    /// Build the KSPT the unit reads, at `fee_rate` sompi a gram but never
    /// under the minimum relay fee.
    ///
    /// # Errors
    ///
    /// `ImmatureCoinbase { coin }` first, under a DAA score given
    /// ([`at_daa_score`](Self::at_daa_score)); then the SDK's
    /// [`RequestError`](kassigner_sdk::request::RequestError): `Empty`,
    /// `TooMany`, `CoinTwice { coin }`, `Watch(..)`, `Multisig(..)`,
    /// `BadHint { coin }`,
    /// `CovenantBound { coin }`, `BadBinding { output }`, `BadChange`,
    /// `NotTheCardsKey { coin }`,
    /// `CardLocked { coin }`, `BadOwn { output }`, `Dust { output }`,
    /// `SweepDust`, `Insufficient { have, need }`, `StorageMass { mass }`,
    /// `ValueOutOfRange`, `Mass`, `Kspt(..)`, `TooLong { len, limit }`.
    pub fn build(&self, fee_rate: u64, rates: &Rates, profile: &Profile) -> Result<Request, Fault> {
        self.matured()?;
        let p = profile.inner();
        let coins = self.sdk_coins();
        let pays = self.sdk_pays();
        let bindings = self.sdk_bindings();
        let mut room = Room::new(coins.len(), pays.len() + 1);
        let mut scratch = request_scratch!(room);
        let mut out = vec![0u8; p.max_reassembled];
        let r = request::build(
            &coins,
            self.payment(&pays, &bindings),
            self.terms(fee_rate, rates, profile),
            &mut scratch,
            &mut out,
        )
        .map_err(Fault::of)?;
        out.truncate(r.len);
        Ok(Request::of(out, &r))
    }

    /// Build the request as rusty-kaspa's bundle (PSKB): the transaction
    /// [`build`](Self::build) makes, every coin with its whole entry and
    /// every input with its keys' paths, shown to the unit as format `pskb`.
    ///
    /// # Errors
    ///
    /// `NoEntry { coin }` for a coin made without its entry, after
    /// `ImmatureCoinbase`; otherwise as [`build`](Self::build) but never
    /// `Kspt(..)` or `TooLong`, and `Bundle(..)` if the bundle writer
    /// refuses; `CovenantInBundle` for an output bound to a covenant, which
    /// a bundle cannot carry.
    pub fn build_bundle(
        &self,
        fee_rate: u64,
        rates: &Rates,
        profile: &Profile,
    ) -> Result<Request, Fault> {
        self.matured()?;
        let details = self.details()?;
        let coins = self.sdk_coins();
        let pays = self.sdk_pays();
        let bindings = self.sdk_bindings();
        let (n, no) = (coins.len(), pays.len() + 1);
        let mut room = Room::new(n, no);
        let mut scratch = request_scratch!(room);

        let owns = self.pays.iter().filter(|p| p.own.is_some()).count();
        let keys_room = (n + 1) * HINT_KEYS + owns;
        let mut keys = vec![[0u8; 33]; keys_room];
        let mut values = vec![[0u8; DERIVATION_MAX]; keys_room];
        let mut lens = vec![0usize; keys_room];
        let mut members = vec![
            Member {
                public_key: &[0; 33],
                value: &[],
            };
            keys_room
        ];
        let mut ranges = vec![(0usize, 0usize); n + no];
        let mut inputs = vec![
            BundleInput {
                previous_outpoint: BLANK_INPUT.previous_outpoint,
                utxo_entry: BLANK_INPUT.utxo_entry,
                details: EntryDetails {
                    block_daa_score: 0,
                    is_coinbase: false,
                    covenant_id: None,
                },
                sequence: None,
                min_time: None,
                sighash_type: 0,
                redeem_script: None,
                sig_op_count: None,
                derivations: &[],
            };
            n
        ];
        let mut outputs = vec![
            BundleOutput {
                amount: 0,
                script_public_key: BLANK_OUTPUT.script_public_key,
                covenant: None,
                derivations: &[],
            };
            no
        ];
        // Room for the longest document: per input its fields, scripts and
        // a group's keys; per output its fields, script and, for an own
        // output, its key; the change and the sweep, and a group's keys on
        // the change.
        let member = 72 + DERIVATION_MAX;
        let doc_len = 1024
            + n * (1024 + 2 * MAX_REDEEM + HINT_KEYS * member)
            + pays
                .iter()
                .map(|pay| 512 + 2 * pay.script.len() + pay.own.map_or(0, |_| member))
                .sum::<usize>()
            + 2 * (512 + 2 * PAY_TO_SCRIPT_HASH_LEN)
            + HINT_KEYS * member;
        let mut doc = vec![0u8; doc_len];
        let mut writing = BundleScratch {
            keys: &mut keys,
            values: &mut values,
            lens: &mut lens,
            members: &mut members,
            ranges: &mut ranges,
            inputs: &mut inputs,
            outputs: &mut outputs,
            doc: &mut doc,
        };
        let mut out = vec![0u8; 4 + 2 * doc_len];
        let r = request::bundle(
            &coins,
            &details,
            self.payment(&pays, &bindings),
            self.terms(fee_rate, rates, profile),
            &mut scratch,
            &mut writing,
            &mut out,
        )
        .map_err(Fault::of)?;
        out.truncate(r.len);
        Ok(Request::of(out, &r))
    }

    /// Build the request in rusty-kaspa's WASM SDK safe JSON
    /// (`serializeToSafeJSON`) for a wallet to sign: the transaction
    /// [`build`](Self::build) makes, every coin with its whole entry, the
    /// storage mass committed.
    ///
    /// # Errors
    ///
    /// `NoEntry { coin }` as [`build_bundle`](Self::build_bundle);
    /// `CardInSafeJson { coin }` for a card's UTXO; otherwise as
    /// [`build`](Self::build) but never `Kspt(..)` or `TooLong`.
    pub fn build_safe_json(
        &self,
        fee_rate: u64,
        rates: &Rates,
        profile: &Profile,
    ) -> Result<Request, Fault> {
        self.matured()?;
        let details = self.details()?;
        let coins = self.sdk_coins();
        let pays = self.sdk_pays();
        let bindings = self.sdk_bindings();
        let mut room = Room::new(coins.len(), pays.len() + 1);
        let mut scratch = request_scratch!(room);
        // Room for the longest text: per input and output its fields and
        // script, a bound output's binding, and the change and the sweep.
        let len = 1024
            + coins.len() * (1024 + 4 * PAY_TO_SCRIPT_HASH_LEN)
            + pays
                .iter()
                .map(|pay| 512 + 2 * pay.script.len())
                .sum::<usize>()
            + 2 * (256 + 2 * PAY_TO_SCRIPT_HASH_LEN);
        let mut out = vec![0u8; len];
        let r = request::safe_json(
            &coins,
            &details,
            self.payment(&pays, &bindings),
            self.terms(fee_rate, rates, profile),
            &mut scratch,
            &mut out,
        )
        .map_err(Fault::of)?;
        out.truncate(r.len);
        Ok(Request::of(out, &r))
    }

    /// `ImmatureCoinbase { coin }` for the first coin not matured at the
    /// DAA score given, if any.
    fn matured(&self) -> Result<(), Fault> {
        let Some(daa_score) = self.daa_score else {
            return Ok(());
        };
        match self
            .coins
            .iter()
            .position(|(c, _)| c.spendable_at(daa_score) == Some(false))
        {
            Some(coin) => Err(Fault(format!("ImmatureCoinbase {{ coin: {coin} }}"))),
            None => Ok(()),
        }
    }

    /// Every coin's entry with its covenant; `NoEntry { coin }` for one
    /// made without.
    fn details(&self) -> Result<Vec<EntryDetails>, Fault> {
        self.coins
            .iter()
            .enumerate()
            .map(|(coin, (c, _))| {
                c.entry
                    .map(|e| EntryDetails {
                        covenant_id: c.covenant_id,
                        ..e
                    })
                    .ok_or_else(|| Fault(format!("NoEntry {{ coin: {coin} }}")))
            })
            .collect()
    }

    /// The SDK's coins over the builder's.
    fn sdk_coins(&self) -> Vec<request::Coin<'_>> {
        self.coins
            .iter()
            .map(|(coin, spent)| request::Coin {
                outpoint: coin.outpoint,
                amount: coin.amount,
                covenant_id: coin.covenant_id,
                source: match spent {
                    Spent::Account {
                        account,
                        chain,
                        index,
                    } => Source::Account {
                        account,
                        chain: *chain,
                        index: *index,
                    },
                    Spent::Group {
                        group,
                        cosigner,
                        chain,
                        index,
                    } => Source::Group {
                        group,
                        cosigner: *cosigner,
                        chain: *chain,
                        index: *index,
                    },
                    Spent::Kcc3 { address, hint } => Source::Kcc3 {
                        address,
                        hint: *hint,
                    },
                    Spent::Card { card, signer } => Source::Card {
                        card,
                        signer: signer.as_ref().map(|(account, index)| (account, *index)),
                    },
                },
            })
            .collect()
    }

    /// The SDK's outputs over the builder's.
    fn sdk_pays(&self) -> Vec<Pay<'_>> {
        self.pays
            .iter()
            .map(|p| Pay {
                script: &p.script,
                value: p.value,
                own: p.own.as_ref().map(|(account, index)| Own {
                    account,
                    index: *index,
                }),
            })
            .collect()
    }

    /// Each output's binding, in the outputs' order.
    fn sdk_bindings(&self) -> Vec<Binding> {
        self.pays.iter().map(|p| p.binding).collect()
    }

    /// What the request pays: the sweep, or `pays` and the change, with
    /// `bindings` where an output is bound to a covenant.
    fn payment<'a>(&'a self, pays: &'a [Pay<'a>], bindings: &'a [Binding]) -> Payment<'a> {
        let change = Self::place(&self.change);
        match &self.sweep {
            Some((to, own)) => Payment::Sweep {
                to,
                own: Self::place(own),
            },
            None if bindings.iter().any(|b| *b != Binding::None) => Payment::Covenant {
                outputs: pays,
                bindings,
                change,
            },
            None => Payment::Outputs {
                outputs: pays,
                change,
            },
        }
    }

    /// The terms the request is built under.
    fn terms<'a>(&self, fee_rate: u64, rates: &'a Rates, profile: &'a Profile) -> Terms<'a> {
        Terms {
            rate: FeeRate {
                sompi_per_gram: fee_rate,
            },
            rates: rates.inner(),
            profile: profile.inner(),
            lock_time: self.lock_time,
            end_covenants: self.end_covenants,
        }
    }

    /// The SDK's place over the builder's: the change's, or a sweep's own.
    fn place(to: &ChangeTo) -> Change<'_> {
        match to {
            ChangeTo::None => Change::None,
            ChangeTo::Account {
                account,
                chain,
                index,
            } => Change::Account {
                account,
                chain: *chain,
                index: *index,
            },
            ChangeTo::Group {
                group,
                cosigner,
                chain,
                index,
            } => Change::Group {
                group,
                cosigner: *cosigner,
                chain: *chain,
                index: *index,
            },
        }
    }
}

impl Default for RequestBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// What a build made: the request's bytes and what it pays.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    /// The KSPT, the bundle's envelope or the safe JSON, which the reply is
    /// read against.
    pub bytes: Vec<u8>,
    /// The fee the transaction pays, sompi.
    pub fee: u64,
    /// The mass the fee was computed over, grams.
    pub mass: u64,
    /// The change output's value, when there is one.
    pub change: Option<u64>,
    /// Signatures the reply must carry in all.
    pub signatures: u32,
}

impl Request {
    /// The bytes as text: the bundle's envelope, or the safe JSON.
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.bytes).into_owned()
    }

    /// The SDK's request over `bytes`, which it wrote.
    fn of(bytes: Vec<u8>, r: &request::Request) -> Request {
        Request {
            bytes,
            fee: r.fee,
            mass: r.mass,
            change: r.change,
            signatures: r.signatures as u32,
        }
    }
}

/// One output of a request, as [`summary`] reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputSummary {
    /// The address the output pays, if it has one.
    pub address: Option<String>,
    /// The locking script.
    pub script: Vec<u8>,
    /// Sompi.
    pub value: u64,
    /// The covenant it is bound to, hex: a continued covenant's, or the
    /// new one's the output starts.
    pub covenant_id: Option<String>,
    /// The input that authorizes the binding, by its place.
    pub authorizing_input: Option<u32>,
}

impl OutputSummary {
    /// The output paying `value` to `script`, with its address.
    pub(crate) fn of(script: &[u8], value: u64) -> OutputSummary {
        let mut text = [0u8; kassigner_kaspa::address::MAX_ADDRESS_LEN];
        let address = watch::address_of_script(script, &mut text)
            .ok()
            .map(|n| crate::watch::text(&text[..n]));
        OutputSummary {
            address,
            script: script.to_vec(),
            value,
            covenant_id: None,
            authorizing_input: None,
        }
    }
}

/// What a request or a reply carries, read back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Summary {
    /// Inputs.
    pub inputs: u32,
    /// Each input's outpoint, `txId:index`.
    pub outpoints: Vec<String>,
    /// Sompi the inputs hold.
    pub total_in: u64,
    /// The outputs.
    pub outputs: Vec<OutputSummary>,
    /// Sompi the outputs pay.
    pub total_out: u64,
    /// Signatures the bytes carry: none on a request.
    pub signatures: u32,
    /// The lock time, zero for none, as the unit's LOCK TIME page shows it.
    pub lock_time: u64,
    /// The transaction's version: 1 with an output bound to a covenant.
    pub version: u32,
}

impl Summary {
    /// The fee: in less out.
    pub fn fee(&self) -> u64 {
        self.total_in.saturating_sub(self.total_out)
    }
}

/// Read `kspt_bytes`, a request or a reply, for what it carries. Nothing
/// is verified; [`crate::reply::read_reply`] does that.
///
/// # Errors
///
/// The SDK's `KsptError` for bytes that are not a KSPT within `profile`.
pub fn summary(kspt_bytes: &[u8], profile: &Profile) -> Result<Summary, Fault> {
    let k = kspt::parse(kspt_bytes, profile.inner()).map_err(Fault::of)?;
    let mut total_in = 0u64;
    let mut outpoints = Vec::new();
    let mut signatures = 0u32;
    for input in k.inputs() {
        total_in = total_in.saturating_add(input.amount);
        outpoints.push(format!("{}:{}", hex(&input.prev_tx_id), input.prev_index));
        signatures += input.signatures().count() as u32;
    }
    let mut total_out = 0u64;
    let mut outputs = Vec::new();
    for output in k.outputs() {
        total_out = total_out.saturating_add(output.value);
        outputs.push(OutputSummary::of(output.spk, output.value));
    }
    // Each bound output's covenant, from its record.
    for record in k.records() {
        if let kspt::Record::Covenant {
            output_index,
            authorizing_input,
            covenant_id,
        } = record
        {
            if let Some(output) = outputs.get_mut(usize::from(output_index)) {
                output.covenant_id = Some(hex(covenant_id));
                output.authorizing_input = Some(u32::from(authorizing_input));
            }
        }
    }
    Ok(Summary {
        inputs: k.num_inputs as u32,
        outpoints,
        total_in,
        outputs,
        total_out,
        signatures,
        lock_time: k.lock_time,
        version: u32::from(k.tx_version),
    })
}
