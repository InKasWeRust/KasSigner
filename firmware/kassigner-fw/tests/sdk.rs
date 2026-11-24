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

//! Both sides of the air gap in one process: the SDK builds a request, the
//! unit plans, reviews and signs it, and the SDK checks and finishes the
//! reply. abandon 12 and zoo 12 sign; abandon 24's kpub is the 2-of-3's
//! third key.

use kassigner_crypto::bip39;
use kassigner_crypto::slot::Slot;
use kassigner_crypto::wallet::Wallet;
use kassigner_fw::keyring::Keyring;
use kassigner_fw::reply::{self, Plan};
use kassigner_fw::session::{Decision, Session};
use kassigner_hal::entropy::{self, Entropy};
use kassigner_kaspa::address::{encode, Version, MAX_ADDRESS_LEN};
use kassigner_kaspa::derivation::Path;
use kassigner_kaspa::mass::{minimum_relay_fee, MassRates};
use kassigner_kaspa::pskb::signature::{Derivation, PartialSig};
use kassigner_kaspa::pskb::write::{Input as BundleInput, Member, Output as BundleOutput};
use kassigner_kaspa::pskb::{decode_envelope, Splice};
use kassigner_kaspa::script::unlock;
use kassigner_kaspa::script::unlock::PositionedSignature;
use kassigner_kaspa::script::{kcc3_script_hash, PAY_TO_SCRIPT_HASH_LEN};
use kassigner_kaspa::tx::{EntryDetails, Outpoint, TransactionInput, TransactionOutput};
use kassigner_protocol::check::{verify_kspt, CHANGE_DEPTH, RECEIVE_DEPTH, SEARCH_DEPTH};
use kassigner_protocol::frame::Format;
use kassigner_protocol::kspt::transaction as kspt_tx;
use kassigner_protocol::kspt::{
    self, AccountHint, CoinCovenant, Hint, InputSignature, Kcc3Hint, Record,
};
use kassigner_protocol::profile::Profile;
use kassigner_sdk::bundle::{self, BundleError, SuppliedRedeem, DERIVATION_MAX, HINT_KEYS};
use kassigner_sdk::card::{self, Entry, Savings};
use kassigner_sdk::reply::{
    self as sdk_reply, Checked, FinalScratch, Finalized, ReplyError, Shape,
};
use kassigner_sdk::request::{
    build, bundle as build_bundle, safe_json as build_safe_json, Binding, BundleScratch, Change,
    Coin, FeeRate, Own, Pay, Payment, Request, RequestError, Scratch, Source, Terms,
};
use kassigner_sdk::transport::{Codes, Progress, Reader, ReaderBuffers, CODE_MAX, FRAME_BUF};
use kassigner_sdk::watch::{Account, Group, Kcc3Address, CHANGE, MAX_REDEEM, RECEIVE};
use kassigner_sdk::Network;

#[path = "../../../testkit/hex.rs"]
pub mod hex;
use hex::hex;

const P: Profile = Profile::ESP32S3;

const ABANDON12: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const ZOO12: &str = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong";

/// abandon 12's `m/44'/111111'/0'` kpub, and the three cosigners'
/// `m/45'/111111'/0'`.
const ABANDON12_KPUB44: &str = "kpub2JXpdok4yzBUdLiywgMbE36ixpEnffDhG31kJpRextvhpBQgBJVPcQJ7A99JryUvi8JNBcnzGoiu4qbGcvCfpY1T2RWndCaUjJqhwDSUNw8";
const ABANDON12_KPUB45: &str = "kpub2JKepGqGb3usUsEfD7JgwbFZav8Nu2z4dBZQ42hg8JUGnCbLUb9phbpZW2TQuk2DmayefGMiVzCK7EL9hPbr2K2vVzSk8SpuUwwqTLq8y14";
const ABANDON24_KPUB45: &str = "kpub2JG8myov28wfetFRquaJtuTJpL3jhYnBhu2V6ZuwHnDqPBAoyqgJKkQiba4wLfU9JcsNBBoBTm7zPtk1Nv4Nn36tUkoZWGUXjWn1aJCajdW";
const ZOO12_KPUB45: &str = "kpub2HgQUMVzkWe8YCDJDEg5zdMAiKnFE3inHgrv7VRUCxKanfXpGnPpSut8MQUHYBcSFKxDhNJKCFJTy6BSdUhXKd1VbrFdFRrJ2thq3ZJfPUU";

const KAS: u64 = 100_000_000;

struct Live;

impl Entropy for Live {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), entropy::Error> {
        for (i, b) in out.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(37).wrapping_add(11);
        }
        Ok(())
    }
}

fn wallet(words: &str) -> Wallet {
    let m = bip39::from_words(words.split(' ')).expect("words");
    let mut scratch = vec![0u8; bip39::scratch_for(0)];
    Wallet::open(&Slot::mnemonic(m, b"").expect("slot"), &mut scratch).expect("wallet")
}

fn account() -> Account {
    Account::new(kassigner_protocol::kpub::read(ABANDON12_KPUB44.as_bytes()).unwrap())
}

fn group() -> Group {
    let line = format!("multi_hd45(2,{ABANDON12_KPUB45},{ABANDON24_KPUB45},{ZOO12_KPUB45})");
    Group::from_descriptor(&line).expect("the bench's group")
}

/// abandon 12's KCC-3 receive 0, as the unit shows it: the address alone.
fn kcc3_address() -> Kcc3Address {
    let w = wallet(ABANDON12);
    let keys = Keyring::new(&w).expect("keyring");
    let key = keys
        .kcc3_address_key(Path::kcc3_receive(0))
        .expect("the 22' key");
    let mut text = [0u8; MAX_ADDRESS_LEN];
    let n = encode(
        Network::Mainnet,
        Version::ScriptHash,
        &kcc3_script_hash(&key),
        &mut text,
    )
    .unwrap();
    Kcc3Address::read(&text[..n]).unwrap()
}

fn outpoint(n: u8) -> Outpoint {
    Outpoint {
        transaction_id: [n; 32],
        index: u32::from(n),
    }
}

/// A blank single-key hint, to fill.
const ACCOUNT_HINT: AccountHint = AccountHint {
    index: 0,
    chain: 0,
    addr_index: 0,
};

/// Everything a request is built in, for up to eight coins and outputs.
struct Buffers<'a> {
    inputs: [TransactionInput<'a>; 8],
    outputs: [TransactionOutput<'a>; 8],
    redeems: [[u8; MAX_REDEEM]; 8],
    redeem_lens: [usize; 8],
    redeem_slices: [&'a [u8]; 8],
    change_script: [u8; PAY_TO_SCRIPT_HASH_LEN],
    scripts: [[u8; PAY_TO_SCRIPT_HASH_LEN]; 8],
    script_lens: [usize; 8],
    input_hints: [Hint; 8],
    kcc3_hints: [Kcc3Hint; 8],
    account_hints: [AccountHint; 8],
    output_hints: [Hint; 1],
    account_output_hints: [AccountHint; 8],
    cells_in: [kassigner_kaspa::mass::Cell; 8],
    cells_out: [kassigner_kaspa::mass::Cell; 8],
    coin_covenants: [CoinCovenant; 8],
}

impl<'a> Buffers<'a> {
    fn new() -> Self {
        let input = TransactionInput {
            previous_outpoint: outpoint(0),
            sequence: 0,
            sig_op_count: 0,
            compute_budget: 0,
            signature_script: &[],
            utxo_entry: kassigner_kaspa::tx::UtxoEntry {
                amount: 0,
                script_public_key: kassigner_kaspa::tx::ScriptPublicKey {
                    version: 0,
                    script: &[],
                },
            },
        };
        let output = TransactionOutput {
            value: 0,
            script_public_key: kassigner_kaspa::tx::ScriptPublicKey {
                version: 0,
                script: &[],
            },
            covenant: None,
        };
        let hint = Hint {
            index: 0,
            cosigner: 0,
            chain: 0,
            addr_index: 0,
        };
        Buffers {
            inputs: [input; 8],
            outputs: [output; 8],
            redeems: [[0; MAX_REDEEM]; 8],
            redeem_lens: [0; 8],
            redeem_slices: [&[]; 8],
            change_script: [0; PAY_TO_SCRIPT_HASH_LEN],
            scripts: [[0; PAY_TO_SCRIPT_HASH_LEN]; 8],
            script_lens: [0; 8],
            input_hints: [hint; 8],
            kcc3_hints: [Kcc3Hint {
                index: 0,
                chain: 0,
                addr_index: 0,
            }; 8],
            account_hints: [ACCOUNT_HINT; 8],
            output_hints: [hint; 1],
            account_output_hints: [ACCOUNT_HINT; 8],
            cells_in: [kassigner_kaspa::mass::Cell {
                plurality: 0,
                amount: 0,
            }; 8],
            cells_out: [kassigner_kaspa::mass::Cell {
                plurality: 0,
                amount: 0,
            }; 8],
            coin_covenants: [CoinCovenant {
                index: 0,
                covenant_id: [0; 32],
            }; 8],
        }
    }
}

/// The terms an app builds under: the minimum rate, mainnet's mass rates,
/// the bench's profile, and `lock_time`.
fn terms(lock_time: u64) -> Terms<'static> {
    Terms {
        rate: FeeRate::MINIMUM,
        rates: &MassRates::MAINNET,
        profile: &P,
        lock_time,
        end_covenants: ENDING.with(std::cell::Cell::get),
    }
}

std::thread_local! {
    /// Whether [`terms`] say a request may end a covenant; a test's own, as
    /// each runs on its own thread.
    static ENDING: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// `f` with the terms saying a request may end a covenant.
fn ending<T>(f: impl FnOnce() -> T) -> T {
    ENDING.with(|e| e.set(true));
    let r = f();
    ENDING.with(|e| e.set(false));
    r
}

/// Build a request as an app would: the KSPT bytes and what was made.
fn request(coins: &[Coin<'_>], payment: Payment<'_>) -> Result<(Request, Vec<u8>), RequestError> {
    request_locked(coins, payment, 0)
}

/// [`request`] under `lock_time`.
fn request_locked(
    coins: &[Coin<'_>],
    payment: Payment<'_>,
    lock_time: u64,
) -> Result<(Request, Vec<u8>), RequestError> {
    let mut b = Buffers::new();
    let mut scratch = Scratch {
        inputs: &mut b.inputs,
        outputs: &mut b.outputs,
        redeems: &mut b.redeems,
        redeem_lens: &mut b.redeem_lens,
        redeem_slices: &mut b.redeem_slices,
        change_script: &mut b.change_script,
        scripts: &mut b.scripts,
        script_lens: &mut b.script_lens,
        input_hints: &mut b.input_hints,
        kcc3_hints: &mut b.kcc3_hints,
        account_hints: &mut b.account_hints,
        output_hints: &mut b.output_hints,
        account_output_hints: &mut b.account_output_hints,
        cells_in: &mut b.cells_in,
        cells_out: &mut b.cells_out,
        coin_covenants: &mut b.coin_covenants,
    };
    let terms = terms(lock_time);
    let mut out = vec![0u8; 4096];
    let r = build(coins, payment, terms, &mut scratch, &mut out)?;
    out.truncate(r.len);
    Ok((r, out))
}

/// What a node lists of a coin past its value and script, coin `n`'s.
fn entry_details(n: u32) -> EntryDetails {
    EntryDetails {
        block_daa_score: 90_000_000 + u64::from(n),
        is_coinbase: false,
        covenant_id: None,
    }
}

/// Each coin's entry as a node lists it, with the covenant it is bound to.
fn details_of(coins: &[Coin<'_>]) -> Vec<EntryDetails> {
    coins
        .iter()
        .map(|c| EntryDetails {
            covenant_id: c.covenant_id,
            ..entry_details(c.outpoint.index)
        })
        .collect()
}

/// [`request`] as a bundle, each coin's entry as a node lists it: the
/// envelope and what was made.
fn bundle_request(
    coins: &[Coin<'_>],
    payment: Payment<'_>,
) -> Result<(Request, Vec<u8>), RequestError> {
    bundle_request_with(coins, &details_of(coins), payment, 0)
}

/// [`bundle_request`] with the coins' entries `details`, under `lock_time`.
fn bundle_request_with(
    coins: &[Coin<'_>],
    details: &[EntryDetails],
    payment: Payment<'_>,
    lock_time: u64,
) -> Result<(Request, Vec<u8>), RequestError> {
    let mut b = Buffers::new();
    let mut scratch = Scratch {
        inputs: &mut b.inputs,
        outputs: &mut b.outputs,
        redeems: &mut b.redeems,
        redeem_lens: &mut b.redeem_lens,
        redeem_slices: &mut b.redeem_slices,
        change_script: &mut b.change_script,
        scripts: &mut b.scripts,
        script_lens: &mut b.script_lens,
        input_hints: &mut b.input_hints,
        kcc3_hints: &mut b.kcc3_hints,
        account_hints: &mut b.account_hints,
        output_hints: &mut b.output_hints,
        account_output_hints: &mut b.account_output_hints,
        cells_in: &mut b.cells_in,
        cells_out: &mut b.cells_out,
        coin_covenants: &mut b.coin_covenants,
    };
    let terms = terms(lock_time);
    let room = (coins.len() + 1) * HINT_KEYS + 8;
    let mut keys = vec![[0u8; 33]; room];
    let mut values = vec![[0u8; DERIVATION_MAX]; room];
    let mut lens = vec![0usize; room];
    let mut members = vec![
        Member {
            public_key: &[0; 33],
            value: &[],
        };
        room
    ];
    let mut ranges = vec![(0usize, 0usize); coins.len() + 8];
    let blank = Buffers::new();
    let mut inputs = vec![
        BundleInput {
            previous_outpoint: outpoint(0),
            utxo_entry: blank.inputs[0].utxo_entry,
            details: entry_details(0),
            sequence: None,
            min_time: None,
            sighash_type: 0,
            redeem_script: None,
            sig_op_count: None,
            derivations: &[],
        };
        8
    ];
    let mut outputs = vec![
        BundleOutput {
            amount: 0,
            script_public_key: blank.outputs[0].script_public_key,
            covenant: None,
            derivations: &[],
        };
        8
    ];
    let mut doc = vec![0u8; 32_768];
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
    let mut out = vec![0u8; 4 + 2 * 32_768];
    let r = build_bundle(
        coins,
        details,
        payment,
        terms,
        &mut scratch,
        &mut writing,
        &mut out,
    )?;
    out.truncate(r.len);
    Ok((r, out))
}

/// [`request`] in the WASM SDK's safe JSON, each coin's entry as a node
/// lists it: the text and what was made.
fn safe_request(
    coins: &[Coin<'_>],
    payment: Payment<'_>,
) -> Result<(Request, Vec<u8>), RequestError> {
    safe_request_with(coins, &details_of(coins), payment, 0)
}

/// [`safe_request`] with the coins' entries `details`, under `lock_time`.
fn safe_request_with(
    coins: &[Coin<'_>],
    details: &[EntryDetails],
    payment: Payment<'_>,
    lock_time: u64,
) -> Result<(Request, Vec<u8>), RequestError> {
    let mut b = Buffers::new();
    let mut scratch = Scratch {
        inputs: &mut b.inputs,
        outputs: &mut b.outputs,
        redeems: &mut b.redeems,
        redeem_lens: &mut b.redeem_lens,
        redeem_slices: &mut b.redeem_slices,
        change_script: &mut b.change_script,
        scripts: &mut b.scripts,
        script_lens: &mut b.script_lens,
        input_hints: &mut b.input_hints,
        kcc3_hints: &mut b.kcc3_hints,
        account_hints: &mut b.account_hints,
        output_hints: &mut b.output_hints,
        account_output_hints: &mut b.account_output_hints,
        cells_in: &mut b.cells_in,
        cells_out: &mut b.cells_out,
        coin_covenants: &mut b.coin_covenants,
    };
    let terms = terms(lock_time);
    let mut out = vec![0u8; 16_384];
    let r = build_safe_json(coins, details, payment, terms, &mut scratch, &mut out)?;
    out.truncate(r.len);
    Ok((r, out))
}

/// What a wallet that signs the safe JSON hands back: `request` with
/// `scripts` as its inputs' unlocking scripts, written as upstream writes
/// it.
fn wallet_signs_safe_json(request: &[u8], scripts: &[Vec<u8>]) -> Vec<u8> {
    let (mut ins, mut outs) = (Buffers::new().inputs, Buffers::new().outputs);
    let mut details = [entry_details(0); 8];
    let mut bytes = vec![0u8; request.len() / 2];
    let f =
        kassigner_kaspa::safe_json::fill(request, &mut ins, &mut details, &mut outs, &mut bytes)
            .expect("the request reads");
    assert_eq!(f.inputs, scripts.len());
    for (input, script) in ins.iter_mut().zip(scripts) {
        input.signature_script = script;
    }
    let tx = kassigner_kaspa::safe_json::build(&f.header, &ins[..f.inputs], &outs[..f.outputs]);
    let details = &details[..f.inputs];
    let mut out =
        vec![0u8; kassigner_kaspa::safe_json::written_len(&tx, details, f.storage_mass).unwrap()];
    kassigner_kaspa::safe_json::write(&tx, details, f.storage_mass, &mut out).unwrap();
    out
}

/// The unit's side: parse, map, review every page, confirm, plan and sign
/// with `w`. The plan, the reply's bytes, and how many signatures the
/// reply verified with.
fn unit_signs(bytes: &[u8], w: &Wallet) -> (Plan, Vec<u8>, usize) {
    let k = kspt::parse(bytes, &P).expect("the unit parses it");
    let mut ins = Buffers::new().inputs;
    let mut outs = Buffers::new().outputs;
    let (ni, no) = kspt_tx::fill(&k, &mut ins, &mut outs).expect("fill");
    let tx = kspt_tx::build(&k, &ins[..ni], &outs[..no]);
    // The spent coins' covenant ids, as the unit's flow reads them.
    let mut coins = [None; 8];
    kspt_tx::coins(&k, &mut coins);
    let mut s = Session::with_coins(tx, |_| None, &coins[..ni]).expect("session");
    let keys = Keyring::new(w).expect("keyring");
    let mut sigs = [InputSignature::EMPTY; 8];
    let plan = reply::plan_kspt(&s, &k, &keys, &P, 14_400, &mut sigs).expect("the unit plans it");
    while let Some((i, _)) = s.next_page() {
        s.page_shown(i).expect("mark");
    }
    s.decide(Decision::Confirm).expect("confirm");
    let mut out = vec![0u8; 4096];
    let r = reply::kspt(&s, &k, &keys, &P, &mut Live, &mut sigs, &mut out).expect("the unit signs");
    out.truncate(r.len);
    let verified = verify_kspt(&out, s.transaction(), &P).expect("the reply verifies");
    (plan, out, verified)
}

fn records(bytes: &[u8]) -> Vec<Record<'_>> {
    kspt::parse(bytes, &P).unwrap().records().collect()
}

fn sum_out(bytes: &[u8]) -> u64 {
    kspt::parse(bytes, &P)
        .unwrap()
        .outputs()
        .map(|o| o.value)
        .sum()
}

/// A `44'` spend of two coins with change back needs no hint: the unit
/// finds both keys in its bank, the fee is the minimum relay fee, and the
/// values balance.
#[test]
fn a_single_key_spend_goes_through_the_unit() {
    let a = account();
    let zoo = wallet(ZOO12);
    let pay_to = kassigner_kaspa::script::pay_to_pubkey(
        &zoo.signing_key(Path::receive(0)).unwrap().x_only(),
    );
    let coins = [
        Coin {
            outpoint: outpoint(1),
            amount: 3 * KAS,
            covenant_id: None,
            source: Source::Account {
                account: &a,
                chain: RECEIVE,
                index: 0,
            },
        },
        Coin {
            outpoint: outpoint(2),
            amount: 2 * KAS,
            covenant_id: None,
            source: Source::Account {
                account: &a,
                chain: CHANGE,
                index: 3,
            },
        },
    ];
    let (r, bytes) = request(
        &coins,
        Payment::Outputs {
            outputs: &[Pay {
                script: &pay_to,
                value: 4 * KAS,
                own: None,
            }],
            change: Change::Account {
                account: &a,
                chain: CHANGE,
                index: 4,
            },
        },
    )
    .expect("built");
    assert_eq!(r.signatures, 2);
    assert_eq!(r.fee, minimum_relay_fee(r.mass), "the minimum rate");
    assert_eq!(r.change, Some(5 * KAS - 4 * KAS - r.fee));
    assert_eq!(sum_out(&bytes) + r.fee, 5 * KAS, "the values balance");
    assert!(records(&bytes).is_empty(), "no hint for a single key");

    let (plan, reply, verified) = unit_signs(&bytes, &wallet(ABANDON12));
    assert_eq!((plan.signatures, plan.inputs, plan.group), (2, 2, None));
    assert_eq!(verified, 2);
    assert_eq!(
        reply::kspt_signers(&reply, &P),
        None,
        "a single key's count"
    );
}

/// A `44'` coin past the unit's search and a change past its bank travel
/// with their paths (a `0x47` and a `0x48`, or bundle derivations) so the
/// unit can sign; within the bank nothing travels.
#[test]
fn a_deep_single_key_spend_goes_through_the_unit() {
    let a = account();
    let zoo = wallet(ZOO12);
    let pay_to = kassigner_kaspa::script::pay_to_pubkey(
        &zoo.signing_key(Path::receive(0)).unwrap().x_only(),
    );
    let paid = [Pay {
        script: &pay_to,
        value: KAS,
        own: None,
    }];
    let spend = |coin: u32, change: u32| {
        let coins = [Coin {
            outpoint: outpoint(1),
            amount: 3 * KAS,
            covenant_id: None,
            source: Source::Account {
                account: &a,
                chain: RECEIVE,
                index: coin,
            },
        }];
        let payment = Payment::Outputs {
            outputs: &paid,
            change: Change::Account {
                account: &a,
                chain: CHANGE,
                index: change,
            },
        };
        let (_, kspt) = request(&coins, payment).expect("built");
        let (_, envelope) = bundle_request(&coins, payment).expect("bundled");
        (kspt, envelope)
    };

    let (bytes, envelope) = spend(1500, 560);
    assert_eq!(
        records(&bytes),
        [
            Record::AccountInputHint(AccountHint {
                index: 0,
                chain: RECEIVE,
                addr_index: 1500
            }),
            Record::AccountOutputHint(AccountHint {
                index: 1,
                chain: CHANGE,
                addr_index: 560
            }),
        ]
    );
    let (plan, _, verified) = unit_signs(&bytes, &wallet(ABANDON12));
    assert_eq!((plan.signatures, plan.inputs), (1, 1));
    assert_eq!(verified, 1);
    let doc = String::from_utf8(unwrap(&envelope)).unwrap();
    for path in ["m/44'/111111'/0'/0/1500", "m/44'/111111'/0'/1/560"] {
        assert!(
            doc.contains(&format!("\"derivationPath\":\"{path}\"")),
            "{path}"
        );
    }
    assert!(!unit_signs_bundle(&envelope, &wallet(ABANDON12)).is_empty());

    let (bytes, _) = spend(RECEIVE_DEPTH - 1, CHANGE_DEPTH - 1);
    assert!(records(&bytes).is_empty(), "the bank's: no hint");
}

/// A payment named with [`Own`] to the seed's receive address past the bank
/// travels with its path, so the unit knows it as its own; within the bank
/// nothing travels. A wrong or hardened index in [`Own`] is refused.
#[test]
fn a_payment_to_the_seeds_own_receive_address_is_marked() {
    let a = account();
    let coins = [Coin {
        outpoint: outpoint(1),
        amount: 3 * KAS,
        covenant_id: None,
        source: Source::Account {
            account: &a,
            chain: RECEIVE,
            index: 0,
        },
    }];
    let (deep, near) = (
        a.script(RECEIVE, 777).unwrap(),
        a.script(RECEIVE, 3).unwrap(),
    );
    let own = |script, index| {
        [Pay {
            script,
            value: KAS,
            own: Some(Own { account: &a, index }),
        }]
    };
    let change = |chain, index| Change::Account {
        account: &a,
        chain,
        index,
    };

    let paid = own(&deep[..], 777);
    let payment = Payment::Outputs {
        outputs: &paid,
        change: change(CHANGE, 560),
    };
    let (_, bytes) = request(&coins, payment).expect("built");
    assert_eq!(
        records(&bytes),
        [
            Record::AccountOutputHint(AccountHint {
                index: 0,
                chain: RECEIVE,
                addr_index: 777
            }),
            Record::AccountOutputHint(AccountHint {
                index: 1,
                chain: CHANGE,
                addr_index: 560
            }),
        ]
    );
    let (plan, _, verified) = unit_signs(&bytes, &wallet(ABANDON12));
    assert_eq!((plan.signatures, verified), (1, 1));
    let (_, envelope) = bundle_request(&coins, payment).expect("bundled");
    let doc = String::from_utf8(unwrap(&envelope)).unwrap();
    for path in ["m/44'/111111'/0'/0/777", "m/44'/111111'/0'/1/560"] {
        assert!(
            doc.contains(&format!("\"derivationPath\":\"{path}\"")),
            "{path}"
        );
    }
    assert!(!unit_signs_bundle(&envelope, &wallet(ABANDON12)).is_empty());

    let paid = own(&near[..], 3);
    let (_, bytes) = request(
        &coins,
        Payment::Outputs {
            outputs: &paid,
            change: change(CHANGE, 2),
        },
    )
    .expect("built");
    assert!(records(&bytes).is_empty(), "the bank's: no hint");

    for (index, why) in [(4, "another index"), (3 | 0x8000_0000, "hardened")] {
        let paid = own(&near[..], index);
        let refused = request(
            &coins,
            Payment::Outputs {
                outputs: &paid,
                change: Change::None,
            },
        );
        assert_eq!(
            refused.map(|(r, _)| r),
            Err(RequestError::BadOwn { output: 0 }),
            "{why}"
        );
    }

    let theirs = [Pay {
        script: &near,
        value: KAS,
        own: None,
    }];
    let (_, bytes) = request(
        &coins,
        Payment::Outputs {
            outputs: &theirs,
            change: change(RECEIVE, 900),
        },
    )
    .expect("built");
    assert_eq!(
        records(&bytes),
        [Record::AccountOutputHint(AccountHint {
            index: 1,
            chain: RECEIVE,
            addr_index: 900
        })],
        "a change on the receive chain"
    );
}

/// A sweep to the wallet's own address is marked as a change is: a `0x48`
/// and bundle path past the bank, nothing within it, a group's `0x45`
/// always; a place that is not the script's is refused.
#[test]
fn a_sweep_to_the_wallets_own_address_is_marked() {
    let a = account();
    let g = group();
    let coins = [
        Coin {
            outpoint: outpoint(1),
            amount: 3 * KAS,
            covenant_id: None,
            source: Source::Account {
                account: &a,
                chain: RECEIVE,
                index: 0,
            },
        },
        Coin {
            outpoint: outpoint(2),
            amount: 2 * KAS,
            covenant_id: None,
            source: Source::Account {
                account: &a,
                chain: CHANGE,
                index: 1,
            },
        },
    ];
    let own = |chain, index| Change::Account {
        account: &a,
        chain,
        index,
    };
    for (chain, index) in [(CHANGE, 560), (RECEIVE, 777)] {
        let to = a.script(chain, index).unwrap();
        let payment = Payment::Sweep {
            to: &to,
            own: own(chain, index),
        };
        let (r, bytes) = request(&coins, payment).expect("built");
        assert_eq!(r.change, None);
        assert_eq!(
            records(&bytes),
            [Record::AccountOutputHint(AccountHint {
                index: 0,
                chain,
                addr_index: index
            })],
            "{chain}/{index}"
        );
        let (plan, _, verified) = unit_signs(&bytes, &wallet(ABANDON12));
        assert_eq!((plan.signatures, verified), (2, 2));
        let (_, envelope) = bundle_request(&coins, payment).expect("bundled");
        let doc = String::from_utf8(unwrap(&envelope)).unwrap();
        let path = format!("m/44'/111111'/0'/{chain}/{index}");
        assert!(
            doc.contains(&format!("\"derivationPath\":\"{path}\"")),
            "{path}"
        );
        assert!(!unit_signs_bundle(&envelope, &wallet(ABANDON12)).is_empty());
    }

    let near = a.script(CHANGE, 2).unwrap();
    let (_, bytes) = request(
        &coins,
        Payment::Sweep {
            to: &near,
            own: own(CHANGE, 2),
        },
    )
    .expect("built");
    assert!(records(&bytes).is_empty(), "the bank's: no hint");
    for (place, why) in [
        (own(CHANGE, 3), "another index"),
        (own(RECEIVE, 2), "the other chain"),
        (own(CHANGE, 2 | 0x8000_0000), "hardened"),
    ] {
        assert_eq!(
            request(
                &coins,
                Payment::Sweep {
                    to: &near,
                    own: place
                }
            )
            .map(|(r, _)| r),
            Err(RequestError::BadOwn { output: 0 }),
            "{why}"
        );
    }

    let gathered = kassigner_sdk::watch::group_script(&g, 0, CHANGE, 7).unwrap();
    let (_, bytes) = request(
        &[Coin {
            outpoint: outpoint(3),
            amount: 10 * KAS,
            covenant_id: None,
            source: Source::Group {
                group: &g,
                cosigner: 0,
                chain: RECEIVE,
                index: 0,
            },
        }],
        Payment::Sweep {
            to: &gathered,
            own: Change::Group {
                group: &g,
                cosigner: 0,
                chain: CHANGE,
                index: 7,
            },
        },
    )
    .expect("built");
    assert!(records(&bytes).contains(&Record::OutputHint(Hint {
        index: 0,
        cosigner: 0,
        chain: CHANGE,
        addr_index: 7
    })));
}

/// The fee is found as rusty-kaspa's wallet finds it, at the minimum rate,
/// the storage mass estimated with the change before the fee; a change
/// worth less than its fee goes to the fee. A payment whose KIP-9 storage
/// mass no node takes is refused.
#[test]
fn the_fee_is_found_as_the_wallet_finds_it() {
    let a = account();
    let coin = |n: u8, amount: u64, chain: u32, index: u32| Coin {
        outpoint: outpoint(n),
        amount,
        covenant_id: None,
        source: Source::Account {
            account: &a,
            chain,
            index,
        },
    };
    let coins = [
        coin(1, 1_751_116_133, CHANGE, 78),
        coin(2, 100_000_000, RECEIVE, 27),
        coin(3, 70_000_000, RECEIVE, 26),
        coin(4, 50_000_000, RECEIVE, 27),
        coin(5, 39_684_600, CHANGE, 76),
    ];
    let to = a.script(RECEIVE, 28).unwrap();
    let paid = [Pay {
        script: &to,
        value: 1_990_000_000,
        own: Some(Own {
            account: &a,
            index: 28,
        }),
    }];
    let (r, bytes) = request(
        &coins,
        Payment::Outputs {
            outputs: &paid,
            change: Change::Account {
                account: &a,
                chain: CHANGE,
                index: 79,
            },
        },
    )
    .expect("built");
    assert_eq!((r.mass, r.fee), (36_147, 3_614_700));
    assert_eq!(r.change, Some(20_800_733 - 3_614_700));
    let (_, reply, verified) = unit_signs(&bytes, &wallet(ABANDON12));
    assert_eq!(verified, 5);
    let f = app_finalizes(&bytes, &reply).expect("finished");
    assert_eq!(f.fee, 3_614_700);

    let one = [coin(1, KAS, RECEIVE, 0)];
    let theirs = kassigner_kaspa::script::pay_to_pubkey(&[0x42; 32]);
    let pay = |value| {
        [Pay {
            script: &theirs,
            value,
            own: None,
        }]
    };
    let with_change = |outputs| Payment::Outputs {
        outputs,
        change: Change::Account {
            account: &a,
            chain: CHANGE,
            index: 0,
        },
    };
    let most = pay(92_000_000);
    let (r, bytes) = request(&one, with_change(&most)).expect("built");
    assert_eq!(
        (r.change, r.fee),
        (None, 8_000_000),
        "the change in the fee"
    );
    assert_eq!(sum_out(&bytes), 92_000_000);
    let tiny = pay(500_000);
    assert!(matches!(
        request(&one, with_change(&tiny)).err(),
        Some(RequestError::StorageMass { mass }) if mass > 1_000_000
    ));
    let small = pay(5_000_000);
    let (r, _) = request(&one, with_change(&small)).expect("built");
    assert!((100_000..500_000).contains(&r.mass), "{}", r.mass);
}

/// A `45'` group spend carries its cosigner hints; the unit finds its key
/// by them, the review says 2-of-3, and abandon 12 and zoo 12 each sign
/// their own position.
#[test]
fn a_group_spend_goes_through_two_cosigners() {
    let g = group();
    let a = account();
    let pay_to = a.script(RECEIVE, 1).unwrap();
    let coins = [Coin {
        outpoint: outpoint(3),
        amount: 10 * KAS,
        covenant_id: None,
        source: Source::Group {
            group: &g,
            cosigner: 0,
            chain: RECEIVE,
            index: 0,
        },
    }];
    let (r, bytes) = request(
        &coins,
        Payment::Outputs {
            outputs: &[Pay {
                script: &pay_to,
                value: 7 * KAS,
                own: None,
            }],
            change: Change::Group {
                group: &g,
                cosigner: 0,
                chain: CHANGE,
                index: 0,
            },
        },
    )
    .expect("built");
    assert_eq!(r.signatures, 2, "a 2-of-3 needs two");
    let recs = records(&bytes);
    assert!(recs.contains(&Record::InputHint(Hint {
        index: 0,
        cosigner: 0,
        chain: 0,
        addr_index: 0
    })));
    assert!(recs.contains(&Record::OutputHint(Hint {
        index: 1,
        cosigner: 0,
        chain: 1,
        addr_index: 0
    })));

    let (plan, first, verified) = unit_signs(&bytes, &wallet(ABANDON12));
    assert_eq!((plan.signatures, plan.group), (1, Some((2, 3))));
    assert_eq!(verified, 1);
    let (_, second, verified) = unit_signs(&first, &wallet(ZOO12));
    assert_eq!(verified, 2, "both cosigners' signatures verify");
    assert_eq!(
        reply::kspt_signers(&second, &P),
        Some(reply::Signers {
            present: 2,
            required: 2
        })
    );
}

/// A `22'` sweep from the address alone: the unit finds the key in its
/// `22'` bank and supplies the redeem script.
#[test]
fn a_kcc3_sweep_goes_through_the_unit() {
    let addr = kcc3_address();
    let a = account();
    let to = a.script(RECEIVE, 0).unwrap();
    let coins = [
        Coin {
            outpoint: outpoint(4),
            amount: 5 * KAS,
            covenant_id: None,
            source: Source::Kcc3 {
                address: &addr,
                hint: None,
            },
        },
        Coin {
            outpoint: outpoint(5),
            amount: KAS / 2,
            covenant_id: None,
            source: Source::Kcc3 {
                address: &addr,
                hint: Some((RECEIVE, 0)),
            },
        },
    ];
    let (r, bytes) = request(
        &coins,
        Payment::Sweep {
            to: &to,
            own: Change::None,
        },
    )
    .expect("built");
    assert_eq!(r.change, None);
    assert_eq!(sum_out(&bytes), 5 * KAS + KAS / 2 - r.fee);
    assert_eq!(
        records(&bytes),
        vec![Record::Kcc3InputHint(Kcc3Hint {
            index: 1,
            chain: 0,
            addr_index: 0
        })]
    );
    let (plan, reply, verified) = unit_signs(&bytes, &wallet(ABANDON12));
    assert_eq!((plan.signatures, plan.inputs), (2, 2));
    assert_eq!(verified, 2);
    let k = kspt::parse(&reply, &P).unwrap();
    assert!(
        k.inputs().all(|i| i.redeem.len() == 34),
        "the unit supplied `<P> OP_CHECKSIG` on both"
    );
}

/// The SDK refuses before the unit would: a dust output, coins short of the
/// fee, a sweep left with dust, a hardened index, nothing to spend. A `44'`
/// coin past the search depth is built, with its hint.
#[test]
fn the_sdk_refuses_what_the_unit_would() {
    let a = account();
    let to = a.script(RECEIVE, 0).unwrap();
    let coin = |index: u32, amount: u64| Coin {
        outpoint: outpoint(9),
        amount,
        covenant_id: None,
        source: Source::Account {
            account: &a,
            chain: RECEIVE,
            index,
        },
    };
    let half = [Pay {
        script: &to,
        value: KAS / 2,
        own: None,
    }];
    let dust = [Pay {
        script: &to,
        value: 50_000,
        own: None,
    }];
    let all = [Pay {
        script: &to,
        value: KAS,
        own: None,
    }];
    let pay = |outputs| Payment::Outputs {
        outputs,
        change: Change::None,
    };
    assert!(request(&[coin(SEARCH_DEPTH, KAS)], pay(&half)).is_ok());
    assert_eq!(
        request(&[coin(0, KAS)], pay(&dust)).err(),
        Some(RequestError::Dust { output: 0 })
    );
    assert!(matches!(
        request(&[coin(0, KAS)], pay(&all)).err(),
        Some(RequestError::Insufficient { have, .. }) if have == KAS
    ));
    assert_eq!(
        request(
            &[coin(0, 200_000)],
            Payment::Sweep {
                to: &to,
                own: Change::None,
            }
        )
        .err(),
        Some(RequestError::SweepDust)
    );
    assert_eq!(
        request(&[coin(0x8000_0000, KAS)], pay(&half)).err(),
        Some(RequestError::BadHint { coin: 0 })
    );
    assert_eq!(request(&[], pay(&half)).err(), Some(RequestError::Empty));
    // Change that would be dust goes to the fee, and no change output is
    // written.
    let (r, bytes) = request(
        &[coin(0, KAS)],
        Payment::Outputs {
            outputs: &[Pay {
                script: &to,
                value: KAS - 220_000,
                own: None,
            }],
            change: Change::Account {
                account: &a,
                chain: CHANGE,
                index: 0,
            },
        },
    )
    .expect("built");
    assert_eq!(r.change, None);
    assert_eq!(kspt::parse(&bytes, &P).unwrap().num_outputs, 1);
    assert_eq!(r.fee, 220_000);
    // Change above dust stays and the fee is the mass's: a 0.5 KAS change
    // beside a 10 KAS input has a large KIP-9 storage mass, about 0.02 KAS.
    let (r, bytes) = request(
        &[coin(0, 10 * KAS)],
        Payment::Outputs {
            outputs: &[Pay {
                script: &to,
                value: 9 * KAS + KAS / 2,
                own: None,
            }],
            change: Change::Account {
                account: &a,
                chain: CHANGE,
                index: 0,
            },
        },
    )
    .expect("built");
    assert_eq!(r.change, Some(KAS / 2 - r.fee));
    assert_eq!(r.fee, minimum_relay_fee(r.mass));
    assert!(r.fee > 1_000_000 && r.fee < 3_000_000, "{}", r.fee);
    assert_eq!(kspt::parse(&bytes, &P).unwrap().num_outputs, 2);
}

/// A coin bound to a covenant is refused by name, as a KSPT, a bundle, the
/// safe JSON or a sweep, unless the terms say the request may end a
/// covenant; the same coins unbound build either way. A coin and its entry
/// must name the same covenant.
#[test]
fn a_coin_bound_to_a_covenant_is_left_alone() {
    let a = account();
    let to = a.script(RECEIVE, 0).unwrap();
    let coin = |n: u8, covenant_id| Coin {
        outpoint: outpoint(n),
        amount: 3 * KAS,
        covenant_id,
        source: Source::Account {
            account: &a,
            chain: RECEIVE,
            index: u32::from(n),
        },
    };
    let pays = [Pay {
        script: &to,
        value: 4 * KAS,
        own: None,
    }];
    let payment = Payment::Outputs {
        outputs: &pays,
        change: Change::Account {
            account: &a,
            chain: CHANGE,
            index: 0,
        },
    };
    let free = [coin(1, None), coin(2, None)];
    let bound = [coin(1, None), coin(2, Some([0x5a; 32]))];
    let refused = Some(RequestError::CovenantBound { coin: 1 });
    assert!(request(&free, payment).is_ok());
    assert!(bundle_request(&free, payment).is_ok());
    assert!(safe_request(&free, payment).is_ok());
    assert_eq!(request(&bound, payment).err(), refused);
    assert_eq!(bundle_request(&bound, payment).err(), refused);
    assert_eq!(safe_request(&bound, payment).err(), refused);
    let sweep = Payment::Sweep {
        to: &to,
        own: Change::None,
    };
    assert!(request(&free, sweep).is_ok());
    assert_eq!(request(&bound, sweep).err(), refused);
    // With the terms' word, all four build.
    ending(|| {
        assert!(request(&free, payment).is_ok());
        assert!(request(&bound, payment).is_ok());
        assert!(bundle_request(&bound, payment).is_ok());
        assert!(safe_request(&bound, payment).is_ok());
        assert!(request(&bound, sweep).is_ok());
    });
    // The coin and its entry name the same covenant, or none: an entry
    // bound where the coin is not, the reverse, and another covenant's.
    let mismatch = Some(RequestError::CovenantEntry { coin: 1 });
    let mut other = details_of(&bound);
    other[1].covenant_id = Some([0x5b; 32]);
    let cases: [(&[Coin<'_>], Vec<EntryDetails>); 3] = [
        (&free, details_of(&bound)),
        (&bound, details_of(&free)),
        (&bound, other),
    ];
    for (coins, details) in &cases {
        for end in [false, true] {
            let build = || {
                (
                    bundle_request_with(coins, details, payment, 0).err(),
                    safe_request_with(coins, details, payment, 0).err(),
                )
            };
            let got = if end { ending(build) } else { build() };
            assert_eq!(got, (mismatch, mismatch), "ending: {end}");
        }
    }
}

/// With the terms' word a request ends a covenant: it spends the coin bound
/// to it with no output continuing it. The request names the coin's
/// covenant, the unit shows the covenant ending on a page of its own and
/// signs, the reply names it too, and the finished transaction's storage
/// mass counts the coin as bound, as a node does: as a KSPT, a bundle and
/// the safe JSON, all one transaction.
#[test]
fn a_request_ends_a_covenant_when_the_terms_say_so() {
    use kassigner_fw::review::Page;
    use kassigner_kaspa::mass::transaction_storage_mass;
    let a = account();
    let w = wallet(ABANDON12);
    let to = a.script(RECEIVE, 0).unwrap();
    let id = [0x5a; 32];
    let coin = |n: u8, covenant_id| Coin {
        outpoint: outpoint(n),
        amount: 3 * KAS,
        covenant_id,
        source: Source::Account {
            account: &a,
            chain: RECEIVE,
            index: u32::from(n),
        },
    };
    // An output small enough for the storage mass to show: 0.05 KAS.
    let pays = [Pay {
        script: &to,
        value: KAS / 20,
        own: None,
    }];
    let payment = Payment::Outputs {
        outputs: &pays,
        change: Change::Account {
            account: &a,
            chain: CHANGE,
            index: 0,
        },
    };
    let free = [coin(1, None), coin(2, None)];
    let bound = [coin(1, None), coin(2, Some(id))];
    let named = |bytes: &[u8]| -> Vec<(u8, [u8; 32])> {
        records(bytes)
            .into_iter()
            .filter_map(|r| match r {
                Record::CoinCovenant {
                    input_index,
                    covenant_id,
                } => Some((input_index, *covenant_id)),
                _ => None,
            })
            .collect()
    };
    ending(|| {
        // The same coins unbound, for what the binding changes.
        let (_, plain) = request(&free, payment).expect("built");
        assert_eq!(named(&plain), []);
        let (_, plain_reply, _) = unit_signs(&plain, &w);
        let unbound = app_finalizes(&plain, &plain_reply).expect("finished");

        let (r, bytes) = request(&bound, payment).expect("built");
        assert_eq!(named(&bytes), [(1, id)], "the request names the covenant");

        // The unit: the covenant, one UTXO of it spent, no output
        // continuing it.
        let k = kspt::parse(&bytes, &P).expect("parses");
        let (mut ins, mut outs) = (Buffers::new().inputs, Buffers::new().outputs);
        let (ni, no) = kspt_tx::fill(&k, &mut ins, &mut outs).expect("fill");
        let tx = kspt_tx::build(&k, &ins[..ni], &outs[..no]);
        let mut coins = [None; 8];
        kspt_tx::coins(&k, &mut coins);
        assert_eq!(coins[..ni], [None, Some(id)]);
        let s = Session::with_coins(tx, |_| None, &coins[..ni]).expect("session");
        let ended = Page::Covenant {
            id,
            outputs: 0,
            spent: 1,
            from: None,
        };
        assert!((0..s.pages()).any(|i| s.page(i) == Ok(ended)));
        // What a node finds for it, the coin counted as bound.
        let exact =
            transaction_storage_mass(&tx, &coins[..ni], MassRates::MAINNET.storage_mass_parameter)
                .expect("storage mass");

        let (_, reply, verified) = unit_signs(&bytes, &w);
        assert_eq!(verified, 2);
        assert_eq!(named(&reply), [(1, id)], "the reply names the covenant");
        let f = app_finalizes(&bytes, &reply).expect("finished");
        assert_eq!(f.storage, exact, "the coin counts as bound");
        assert_ne!(f.storage, unbound.storage, "and weighs otherwise unbound");
        assert_eq!(f.fee, r.fee);

        // A reply that drops the coin's covenant, or names another, is not
        // the request's.
        let other = {
            let mut b = reply.clone();
            let at = b.windows(32).position(|w| w == id).expect("the id");
            b[at] ^= 1;
            b
        };
        assert_eq!(
            app_finalizes(&bytes, &other).err(),
            Some(ReplyError::NotTheRequest)
        );
        assert_eq!(
            app_finalizes(&bytes, &plain_reply).err(),
            Some(ReplyError::NotTheRequest)
        );

        // As a bundle: the input's entry carries the covenant.
        let (_, envelope) = bundle_request(&bound, payment).expect("bundle");
        let doc = unwrap(&envelope);
        let text = core::str::from_utf8(&doc).expect("text");
        let hex: String = id.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            text.matches(&format!("\"covenantId\":\"{hex}\"")).count(),
            1
        );
        let reply = unit_signs_bundle(&envelope, &w);
        let b = app_finalizes_bundle(&envelope, &reply).expect("finished");
        assert_eq!((b.id, b.storage), (f.id, exact), "the one transaction");

        // As the safe JSON, signed by a wallet with the same scripts.
        let (_, safe) = safe_request(&bound, payment).expect("safe JSON");
        let text = core::str::from_utf8(&safe).expect("text");
        assert_eq!(
            text.matches(&format!("\"covenantId\":\"{hex}\"")).count(),
            1
        );
        assert!(
            text.contains(&format!("\"storageMass\":\"{exact}\"")),
            "{text}"
        );
        let signed = wallet_signs_safe_json(&safe, &f.scripts);
        let j = app_finalizes_safe_json(&safe, &signed).expect("finished");
        assert_eq!((j.id, j.storage), (f.id, exact), "the one transaction");
    });
}

/// The script the bench's covenant outputs pay: a script hash, as a
/// covenant's program is locked.
fn covenant_script() -> [u8; PAY_TO_SCRIPT_HASH_LEN] {
    kassigner_kaspa::script::pay_to_script_hash(&[0x77; 32])
}

/// The covenant the bench's bound coin belongs to.
const BENCH_COVENANT: [u8; 32] = [0x5a; 32];

/// The bench's two covenant requests, as [`request`] builds them: one that
/// starts a covenant in its two first outputs, authorized by coin 0, and one
/// that continues coin 0's covenant in its first output. Each over two
/// `44'` coins of 1000 KAS, 100 KAS an output, change to change 0. `make`
/// builds one: as a KSPT, or the safe JSON.
fn covenant_requests<T>(mut make: impl FnMut(&[Coin<'_>], Payment<'_>) -> T) -> [T; 2] {
    let a = account();
    let to = covenant_script();
    let coin = |n: u8, covenant_id| Coin {
        outpoint: outpoint(n),
        amount: 1000 * KAS,
        covenant_id,
        source: Source::Account {
            account: &a,
            chain: RECEIVE,
            index: u32::from(n),
        },
    };
    let pay = Pay {
        script: &to,
        value: 100 * KAS,
        own: None,
    };
    let change = Change::Account {
        account: &a,
        chain: CHANGE,
        index: 0,
    };
    let start = make(
        &[coin(1, None), coin(2, None)],
        Payment::Covenant {
            outputs: &[pay, pay],
            bindings: &[Binding::Start { coin: 0 }, Binding::Start { coin: 0 }],
            change,
        },
    );
    let go_on = make(
        &[coin(1, Some(BENCH_COVENANT)), coin(2, None)],
        Payment::Covenant {
            outputs: &[pay],
            bindings: &[Binding::Continue { coin: 0 }],
            change,
        },
    );
    [start, go_on]
}

/// The covenant pages a unit shows for `bytes`, a KSPT request: each one's
/// id, outputs, spent coins and authorizing input.
fn covenant_pages(bytes: &[u8]) -> Vec<([u8; 32], u32, u16, Option<u16>)> {
    use kassigner_fw::review::Page;
    let k = kspt::parse(bytes, &P).expect("parses");
    let (mut ins, mut outs) = (Buffers::new().inputs, Buffers::new().outputs);
    let (ni, no) = kspt_tx::fill(&k, &mut ins, &mut outs).expect("fill");
    let tx = kspt_tx::build(&k, &ins[..ni], &outs[..no]);
    let mut coins = [None; 8];
    kspt_tx::coins(&k, &mut coins);
    let s = Session::with_coins(tx, |_| None, &coins[..ni]).expect("session");
    (0..s.pages())
        .filter_map(|i| match s.page(i) {
            Ok(Page::Covenant {
                id,
                outputs,
                spent,
                from,
            }) => Some((id, outputs, spent, from)),
            _ => None,
        })
        .collect()
}

/// A request starts a covenant: its outputs are bound under the id their
/// authorizing input makes, in a version 1 transaction whose inputs commit
/// no signature operations. The unit shows the new covenant and signs; the
/// finished transaction commits each input's compute budget and pays the
/// fee the request found, a little over the same payment unbound. As a KSPT
/// and the safe JSON, one transaction; a bundle cannot carry it.
#[test]
fn a_request_starts_a_covenant() {
    use kassigner_kaspa::sighash::covenant_id;
    use kassigner_kaspa::tx::CovenantBinding;
    let w = wallet(ABANDON12);
    let [(r, bytes), _] = covenant_requests(|c, p| request(c, p).expect("built"));
    let k = kspt::parse(&bytes, &P).expect("parses");
    assert_eq!(k.tx_version, 1, "a binding needs version 1");
    assert!(k.inputs().all(|i| i.sig_op_count == 0));
    let (mut ins, mut outs) = (Buffers::new().inputs, Buffers::new().outputs);
    let (ni, no) = kspt_tx::fill(&k, &mut ins, &mut outs).expect("fill");
    assert_eq!((ni, no), (2, 3));
    // The id the two outputs make with coin 0's outpoint, by the formula.
    let id = covenant_id(
        &outpoint(1),
        outs[..2].iter().enumerate().map(|(j, o)| (j as u32, o)),
    );
    let binding = Some(CovenantBinding {
        authorizing_input: 0,
        covenant_id: id,
    });
    assert_eq!(
        outs[..no].iter().map(|o| o.covenant).collect::<Vec<_>>(),
        [binding, binding, None],
        "the change is not bound"
    );
    // The unit: a new covenant in outputs 1 and 2, from input 1.
    assert_eq!(covenant_pages(&bytes), [(id, 0b11, 0, Some(0))]);

    let (_, reply, verified) = unit_signs(&bytes, &w);
    assert_eq!(verified, 2);
    let f = app_finalizes(&bytes, &reply).expect("finished");
    assert_eq!(f.fee, r.fee, "the fee the request found");
    assert_eq!(f.json.matches("\"sigOpCount\":0").count(), 2, "{}", f.json);
    assert_eq!(
        f.json.matches("\"computeBudget\":10").count(),
        2,
        "{}",
        f.json
    );
    assert!(f.json.contains("\"version\":1"), "{}", f.json);

    // The same payment unbound: version 0, lighter by the two inputs' budget
    // fields and the two bindings, 2 and 34 bytes each at a gram a byte.
    let [(plain, plain_bytes), _] = covenant_requests(|c, p| {
        let Payment::Covenant {
            outputs, change, ..
        } = p
        else {
            unreachable!()
        };
        let unbound: Vec<Coin<'_>> = c
            .iter()
            .map(|c| Coin {
                covenant_id: None,
                ..*c
            })
            .collect();
        request(&unbound, Payment::Outputs { outputs, change }).expect("built")
    });
    assert_eq!(kspt::parse(&plain_bytes, &P).unwrap().tx_version, 0);
    assert_eq!(r.mass - plain.mass, 2 * 2 + 2 * 34);
    assert_eq!(r.fee - plain.fee, (2 * 2 + 2 * 34) * 100);

    // A bundle has no field for a version 1 input's compute budget.
    let [bundled, _] = covenant_requests(|c, p| bundle_request(c, p).err());
    assert_eq!(bundled, Some(RequestError::CovenantInBundle));

    // The safe JSON, signed by a wallet with the same scripts.
    let [(_, safe), _] = covenant_requests(|c, p| safe_request(c, p).expect("safe JSON"));
    let text = core::str::from_utf8(&safe).expect("text");
    assert!(text.contains("\"version\":1"), "{text}");
    assert_eq!(text.matches("\"computeBudget\":10").count(), 2, "{text}");
    let signed = wallet_signs_safe_json(&safe, &f.scripts);
    let j = app_finalizes_safe_json(&safe, &signed).expect("finished");
    assert_eq!((j.id, j.fee, j.storage), (f.id, f.fee, f.storage));
}

/// A request continues a covenant: the output is bound under the id of the
/// coin whose input authorizes it, so the covenant does not end and the
/// terms need not say it may. The unit shows it continuing and signs; the
/// storage mass counts the bound coin and the bound output as a node does.
#[test]
fn a_request_continues_a_covenant() {
    use kassigner_kaspa::mass::transaction_storage_mass;
    use kassigner_kaspa::tx::CovenantBinding;
    let w = wallet(ABANDON12);
    let [_, (r, bytes)] = covenant_requests(|c, p| request(c, p).expect("built"));
    let k = kspt::parse(&bytes, &P).expect("parses");
    assert_eq!(k.tx_version, 1);
    let (mut ins, mut outs) = (Buffers::new().inputs, Buffers::new().outputs);
    let (ni, no) = kspt_tx::fill(&k, &mut ins, &mut outs).expect("fill");
    let tx = kspt_tx::build(&k, &ins[..ni], &outs[..no]);
    assert_eq!(
        outs[..no].iter().map(|o| o.covenant).collect::<Vec<_>>(),
        [
            Some(CovenantBinding {
                authorizing_input: 0,
                covenant_id: BENCH_COVENANT,
            }),
            None
        ]
    );
    let mut coins = [None; 8];
    kspt_tx::coins(&k, &mut coins);
    assert_eq!(coins[..ni], [Some(BENCH_COVENANT), None]);
    // The unit: the covenant, one UTXO of it spent, continued in output 1.
    assert_eq!(covenant_pages(&bytes), [(BENCH_COVENANT, 0b1, 1, None)]);
    let exact =
        transaction_storage_mass(&tx, &coins[..ni], MassRates::MAINNET.storage_mass_parameter)
            .expect("storage mass");

    let (_, reply, verified) = unit_signs(&bytes, &w);
    assert_eq!(verified, 2);
    let f = app_finalizes(&bytes, &reply).expect("finished");
    assert_eq!((f.fee, f.storage), (r.fee, exact));
    assert_eq!(
        f.json.matches("\"computeBudget\":10").count(),
        2,
        "{}",
        f.json
    );

    let [_, (_, safe)] = covenant_requests(|c, p| safe_request(c, p).expect("safe JSON"));
    let signed = wallet_signs_safe_json(&safe, &f.scripts);
    let j = app_finalizes_safe_json(&safe, &signed).expect("finished");
    assert_eq!((j.id, j.fee, j.storage), (f.id, f.fee, exact));
}

/// What the builder refuses of bindings: not one per output, a coin the
/// request does not spend, a continuation of a coin bound to nothing; and a
/// bound coin whose covenant no output continues, unless the terms say a
/// request may end one. A continuation of another coin's covenant does not
/// keep this coin's.
#[test]
fn the_builder_refuses_bindings_that_name_no_covenant() {
    let a = account();
    let to = covenant_script();
    let coin = |n: u8, covenant_id| Coin {
        outpoint: outpoint(n),
        amount: 1000 * KAS,
        covenant_id,
        source: Source::Account {
            account: &a,
            chain: RECEIVE,
            index: u32::from(n),
        },
    };
    let pay = Pay {
        script: &to,
        value: 100 * KAS,
        own: None,
    };
    let change = Change::Account {
        account: &a,
        chain: CHANGE,
        index: 0,
    };
    let (x, y) = ([0x5a; 32], [0x5b; 32]);
    let build = |coins: &[Coin<'_>], outputs: &[Pay<'_>], bindings: &[Binding]| {
        request(
            coins,
            Payment::Covenant {
                outputs,
                bindings,
                change,
            },
        )
        .map(|(_, bytes)| kspt::parse(&bytes, &P).unwrap().tx_version)
    };
    let free = [coin(1, None), coin(2, None)];
    let one = [coin(1, Some(x)), coin(2, None)];
    let two = [coin(1, Some(x)), coin(2, Some(y))];
    use Binding::{Continue, None as Unbound, Start};
    // No output bound: the plain payment, version 0.
    assert_eq!(build(&free, &[pay], &[Unbound]), Ok(0));
    // Not one binding an output.
    let count = Err(RequestError::BadBinding { output: 2 });
    assert_eq!(build(&free, &[pay, pay], &[Start { coin: 0 }]), count);
    assert_eq!(build(&free, &[pay, pay], &[]), count);
    // A coin the request does not spend.
    let bad = |output| Err(RequestError::BadBinding { output });
    assert_eq!(build(&free, &[pay], &[Start { coin: 2 }]), bad(0));
    assert_eq!(
        build(&one, &[pay, pay], &[Unbound, Continue { coin: 9 }]),
        bad(1)
    );
    // A continuation of a coin bound to nothing.
    assert_eq!(build(&one, &[pay], &[Continue { coin: 1 }]), bad(0));
    assert_eq!(build(&free, &[pay], &[Continue { coin: 0 }]), bad(0));
    // A covenant no output continues ends: the terms must say so, whether
    // the request starts another, or continues another coin's.
    let ends = |coin| Err(RequestError::CovenantBound { coin });
    assert_eq!(build(&one, &[pay], &[Unbound]), ends(0));
    assert_eq!(build(&one, &[pay], &[Start { coin: 0 }]), ends(0));
    assert_eq!(build(&two, &[pay], &[Continue { coin: 0 }]), ends(1));
    assert_eq!(build(&two, &[pay], &[Continue { coin: 1 }]), ends(0));
    ending(|| {
        assert_eq!(build(&one, &[pay], &[Start { coin: 0 }]), Ok(1));
        assert_eq!(build(&two, &[pay], &[Continue { coin: 0 }]), Ok(1));
        assert_eq!(build(&one, &[pay], &[Unbound]), Ok(0));
    });
    // Both continued, each by its own coin's input: nothing ends.
    assert_eq!(
        build(
            &two,
            &[pay, pay],
            &[Continue { coin: 1 }, Continue { coin: 0 }]
        ),
        Ok(1)
    );
    // A coin can start one covenant and continue its own.
    assert_eq!(
        build(
            &one,
            &[pay, pay],
            &[Start { coin: 0 }, Continue { coin: 0 }]
        ),
        Ok(1)
    );
}

/// The bench's group starting a covenant: its cosigner 0 receive 0 coin of
/// 1000 KAS, 100 KAS to the covenant's script as a new covenant's one
/// output, change to the group. And the same payment unbound.
fn group_covenant_requests() -> [(Request, Vec<u8>); 2] {
    let g = group();
    let to = covenant_script();
    let coins = [Coin {
        outpoint: outpoint(3),
        amount: 1000 * KAS,
        covenant_id: None,
        source: Source::Group {
            group: &g,
            cosigner: 0,
            chain: RECEIVE,
            index: 0,
        },
    }];
    let pays = [Pay {
        script: &to,
        value: 100 * KAS,
        own: None,
    }];
    let change = Change::Group {
        group: &g,
        cosigner: 0,
        chain: CHANGE,
        index: 0,
    };
    let bound = request(
        &coins,
        Payment::Covenant {
            outputs: &pays,
            bindings: &[Binding::Start { coin: 0 }],
            change,
        },
    )
    .expect("built");
    let plain = request(
        &coins,
        Payment::Outputs {
            outputs: &pays,
            change,
        },
    )
    .expect("built");
    [bound, plain]
}

/// A group starts a covenant: each cosigner signs the version 1 request,
/// and the finished input commits the budget of a signature operation a
/// key, as version 0 commits a count of one a key.
#[test]
fn a_group_starts_a_covenant() {
    let [(r, bytes), (plain, _)] = group_covenant_requests();
    assert_eq!(r.signatures, 2);
    assert_eq!(r.mass - plain.mass, 2 + 34);
    let pages = covenant_pages(&bytes);
    assert_eq!(pages.len(), 1);
    assert_eq!((pages[0].1, pages[0].2, pages[0].3), (0b1, 0, Some(0)));

    let (_, first, _) = unit_signs(&bytes, &wallet(ABANDON12));
    let (_, second, verified) = unit_signs(&first, &wallet(ZOO12));
    assert_eq!(verified, 2);
    let f = app_finalizes(&bytes, &second).expect("finished");
    assert_eq!(f.fee, r.fee);
    assert!(f.json.contains("\"sigOpCount\":0"), "{}", f.json);
    assert!(f.json.contains("\"computeBudget\":30"), "{}", f.json);
}

/// The bench's `22'` coin and its card's UTXO, each starting a covenant
/// with 1 KAS of its own and the rest as change to the account: the two
/// other scripts a unit signs. The card's under its unlock time.
fn other_covenant_requests() -> [(&'static str, Request, Vec<u8>, &'static str); 2] {
    let a = account();
    let to = covenant_script();
    let pays = [Pay {
        script: &to,
        value: KAS,
        own: None,
    }];
    let payment = Payment::Covenant {
        outputs: &pays,
        bindings: &[Binding::Start { coin: 0 }],
        change: Change::Account {
            account: &a,
            chain: CHANGE,
            index: 0,
        },
    };
    let addr = kcc3_address();
    let kcc3 = [Coin {
        outpoint: outpoint(5),
        amount: 5 * KAS,
        covenant_id: None,
        source: Source::Kcc3 {
            address: &addr,
            hint: Some((RECEIVE, 0)),
        },
    }];
    let (r, bytes) = request(&kcc3, payment).expect("built");
    let savings = bench_card();
    let [card, _] = card_coins(&savings, Some((&a, 0)));
    let (c, card_bytes) = request_locked(&[card], payment, savings.unlock().ms()).expect("built");
    [
        ("kcc3", r, bytes, ABANDON12),
        ("card", c, card_bytes, ABANDON12),
    ]
}

/// A `22'` coin and a card's UTXO start a covenant too: each finished input
/// commits the budget of the signature operations its script commits in
/// version 0, one and the card's, and pays the fee the request found.
#[test]
fn a_kcc3_coin_and_a_card_start_a_covenant() {
    for (name, r, bytes, seed) in other_covenant_requests() {
        assert_eq!(kspt::parse(&bytes, &P).unwrap().tx_version, 1, "{name}");
        let (_, reply, verified) = unit_signs(&bytes, &wallet(seed));
        assert_eq!(verified, 1, "{name}");
        let f = app_finalizes(&bytes, &reply).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_eq!(f.fee, r.fee, "{name}: the fee the request found");
        let budget = match name {
            "kcc3" => 10,
            _ => 10 * u16::from(card::SIG_OP_COUNT),
        };
        assert!(
            f.json.contains(&format!("\"computeBudget\":{budget}}}")),
            "{name}: {}",
            f.json
        );
    }
}

/// A request carries the app's lock time, a DAA score or a time, as a KSPT,
/// a bundle and the safe JSON at no cost in fee or mass; the unit shows it
/// and signs, and all three finish to the same transaction.
#[test]
fn a_request_carries_the_lock_time_the_app_sets() {
    use kassigner_fw::review::Page;
    let a = account();
    let w = wallet(ABANDON12);
    let to = a.script(RECEIVE, 0).unwrap();
    let coin = |n: u8| Coin {
        outpoint: outpoint(n),
        amount: 3 * KAS,
        covenant_id: None,
        source: Source::Account {
            account: &a,
            chain: RECEIVE,
            index: u32::from(n),
        },
    };
    let coins = [coin(1), coin(2)];
    let pays = [Pay {
        script: &to,
        value: 4 * KAS,
        own: None,
    }];
    let payment = Payment::Outputs {
        outputs: &pays,
        change: Change::Account {
            account: &a,
            chain: CHANGE,
            index: 0,
        },
    };
    let (plain, _) = request(&coins, payment).expect("built");
    for lock in [412_345_678u64, 1_798_761_599_000] {
        let (r, bytes) = request_locked(&coins, payment, lock).expect("built");
        assert_eq!(
            (r.fee, r.mass, r.change),
            (plain.fee, plain.mass, plain.change),
            "a lock time weighs nothing"
        );
        let k = kspt::parse(&bytes, &P).expect("parses");
        assert_eq!(k.lock_time, lock);
        let mut ins = Buffers::new().inputs;
        let mut outs = Buffers::new().outputs;
        let (ni, no) = kspt_tx::fill(&k, &mut ins, &mut outs).expect("fill");
        let s = Session::new(kspt_tx::build(&k, &ins[..ni], &outs[..no])).expect("session");
        let shown = Page::LockTime {
            value: lock,
            ignored: false,
        };
        assert!((0..s.pages()).any(|i| s.page(i) == Ok(shown)), "{lock}");
        let (_, reply, _) = unit_signs(&bytes, &w);
        let f = app_finalizes(&bytes, &reply).expect("finished");
        assert!(
            f.json.contains(&format!("\"lockTime\":{lock},")),
            "{}",
            f.json
        );

        // As a bundle: each input's `minTime`, read back as the lock time.
        let (_, envelope) =
            bundle_request_with(&coins, &details_of(&coins), payment, lock).expect("bundle");
        let doc = unwrap(&envelope);
        let text = core::str::from_utf8(&doc).expect("text");
        assert_eq!(text.matches(&format!("\"minTime\":{lock}")).count(), 2);
        let reply = unit_signs_bundle(&envelope, &w);
        let b = app_finalizes_bundle(&envelope, &reply).expect("finished");
        assert_eq!(b.id, f.id, "the one transaction");

        // As the safe JSON, signed by a wallet with the same scripts.
        let (_, safe) =
            safe_request_with(&coins, &details_of(&coins), payment, lock).expect("safe JSON");
        let text = core::str::from_utf8(&safe).expect("text");
        assert!(text.contains(&format!("\"lockTime\":\"{lock}\"")), "{text}");
        let signed = wallet_signs_safe_json(&safe, &f.scripts);
        let j = app_finalizes_safe_json(&safe, &signed).expect("finished");
        assert_eq!(j.id, f.id, "the one transaction");
    }
}

/// The three requests, as an app builds them, for the bench page and the
/// frames test.
fn the_three_requests() -> Vec<(&'static str, Vec<u8>)> {
    let [single, multisig, sweep] =
        the_three(|coins, payment| request(coins, payment).expect("built").1);
    vec![
        ("44' spend, two coins, change back", single),
        ("2-of-3 group spend, change to the group", multisig),
        ("22' sweep, two coins, the address alone", sweep),
    ]
}

/// The three requests' coins and payments, each handed to `make`: the `44'`
/// spend, the group's and the `22'` sweep.
fn the_three<T>(mut make: impl FnMut(&[Coin<'_>], Payment<'_>) -> T) -> [T; 3] {
    let a = account();
    let g = group();
    let addr = kcc3_address();
    let zoo = wallet(ZOO12);
    let to_zoo = kassigner_kaspa::script::pay_to_pubkey(
        &zoo.signing_key(Path::receive(0)).unwrap().x_only(),
    );
    let to_a1 = a.script(RECEIVE, 1).unwrap();
    let to_a0 = a.script(RECEIVE, 0).unwrap();
    let single = make(
        &[
            Coin {
                outpoint: outpoint(1),
                amount: 3 * KAS,
                covenant_id: None,
                source: Source::Account {
                    account: &a,
                    chain: RECEIVE,
                    index: 0,
                },
            },
            Coin {
                outpoint: outpoint(2),
                amount: 2 * KAS,
                covenant_id: None,
                source: Source::Account {
                    account: &a,
                    chain: CHANGE,
                    index: 3,
                },
            },
        ],
        Payment::Outputs {
            outputs: &[Pay {
                script: &to_zoo,
                value: 4 * KAS,
                own: None,
            }],
            change: Change::Account {
                account: &a,
                chain: CHANGE,
                index: 4,
            },
        },
    );
    let multisig = make(
        &[Coin {
            outpoint: outpoint(3),
            amount: 10 * KAS,
            covenant_id: None,
            source: Source::Group {
                group: &g,
                cosigner: 0,
                chain: RECEIVE,
                index: 0,
            },
        }],
        Payment::Outputs {
            outputs: &[Pay {
                script: &to_a1,
                value: 7 * KAS,
                own: None,
            }],
            change: Change::Group {
                group: &g,
                cosigner: 0,
                chain: CHANGE,
                index: 0,
            },
        },
    );
    let sweep = make(
        &[
            Coin {
                outpoint: outpoint(4),
                amount: 5 * KAS,
                covenant_id: None,
                source: Source::Kcc3 {
                    address: &addr,
                    hint: None,
                },
            },
            Coin {
                outpoint: outpoint(5),
                amount: KAS / 2,
                covenant_id: None,
                source: Source::Kcc3 {
                    address: &addr,
                    hint: Some((RECEIVE, 0)),
                },
            },
        ],
        Payment::Sweep {
            to: &to_a0,
            own: Change::None,
        },
    );
    [single, multisig, sweep]
}

/// Each request goes out in at most five frames of version 6 to 9, or one
/// bare code, and the reader puts it back whole for the unit to parse.
#[test]
fn the_requests_round_trip_through_the_frames() {
    for (what, bytes) in the_three_requests() {
        let codes = Codes::plan(bytes.len(), &P).expect(what);
        assert!(
            codes.frames <= 5 && (6..=9).contains(&codes.version) || codes.bare,
            "{what}"
        );
        let mut payload = vec![0u8; P.max_reassembled];
        let mut seen = vec![false; P.max_frames];
        let mut sizes = vec![0u8; P.max_frames];
        let mut bare = vec![0u8; CODE_MAX];
        let mut reader = Reader::new(
            ReaderBuffers {
                payload: &mut payload,
                seen: &mut seen,
                sizes: &mut sizes,
                bare: &mut bare,
            },
            225,
        );
        let mut last = Progress::Nothing;
        for i in 0..codes.frames {
            let mut buf = [0u8; FRAME_BUF];
            let n = codes.bytes(Format::Kspt, &bytes, i, &mut buf).expect(what);
            last = reader.take(&buf[..n], P.max_frames).expect(what);
        }
        assert_eq!(last, Progress::Whole(bytes.len()), "{what}");
        let mut out = vec![0u8; bytes.len()];
        reader.collect(&mut out).expect(what);
        assert_eq!(out, bytes, "{what}");
        kspt::parse(&out, &P).expect(what);
    }
}

/// A code as an SVG: dark modules on a white quiet zone.
fn svg(qr: &kassigner_qr::QrMatrix) -> String {
    let n = qr.size as usize;
    let side = n + 8;
    let mut s = format!(
        "<svg viewBox=\"0 0 {side} {side}\" shape-rendering=\"crispEdges\"><rect width=\"{side}\" height=\"{side}\" fill=\"#fff\"/><path fill=\"#000\" d=\""
    );
    for y in 0..n {
        for x in 0..n {
            if qr.get(x as u8, y as u8) {
                s.push_str(&format!("M{} {}h1v1h-1z", x + 4, y + 4));
            }
        }
    }
    s.push_str("\"/></svg>");
    s
}

/// The bench page shows the three requests as a phone would, each one's
/// codes cycling at its period; with `KASSIGNER_SDK_BENCH` set it is
/// written there, for a unit to scan.
#[test]
fn the_bench_page_shows_the_three_requests() {
    let mut page = String::from(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>KasSigner SDK bench</title>\
<style>body{background:#111;color:#ddd;font:16px system-ui;margin:0;padding:24px}\
h1{font-size:20px}section{margin:32px 0}svg{width:360px;height:360px;display:none}\
svg.on{display:block}p{color:#999;font-size:14px}</style></head><body>\
<h1>KasSigner SDK bench: three requests, v1.1.0 frames</h1>",
    );
    for (k, (what, bytes)) in the_three_requests().iter().enumerate() {
        let codes = Codes::plan(bytes.len(), &P).unwrap();
        page.push_str(&format!(
            "<section id=\"r{k}\" data-ms=\"{}\"><h2>{what}</h2><p>{} bytes, {} code{} (version {}{})</p>",
            codes.period_ms(),
            bytes.len(),
            codes.frames,
            if codes.frames == 1 { "" } else { "s" },
            codes.version,
            if codes.bare { ", bare" } else { "" },
        ));
        for i in 0..codes.frames {
            let qr = codes.code(Format::Kspt, bytes, i).unwrap();
            page.push_str(&svg(&qr).replace(
                "<svg ",
                if i == 0 {
                    "<svg class=\"on\" "
                } else {
                    "<svg "
                },
            ));
        }
        page.push_str("</section>");
    }
    // Each request's codes at their own period, from the section's plan.
    page.push_str(
        "<script>for(const s of document.querySelectorAll('section')){const c=[...s.querySelectorAll('svg')];\
let i=0;if(c.length>1)setInterval(()=>{c[i].classList.remove('on');i=(i+1)%c.length;c[i].classList.add('on');},+s.dataset.ms);}</script></body></html>",
    );
    assert_eq!(page.matches("<section").count(), 3);
    if let Ok(path) = std::env::var("KASSIGNER_SDK_BENCH") {
        std::fs::write(&path, &page).expect("the bench page written");
    }
}

/// The app's reading of `reply` against `request`.
fn app_reads(request: &[u8], reply: &[u8]) -> Result<Checked, ReplyError> {
    let mut b = Buffers::new();
    let mut scratch = sdk_reply::Scratch {
        inputs: &mut b.inputs,
        outputs: &mut b.outputs,
    };
    sdk_reply::read(request, reply, &P, &mut scratch)
}

/// The app's merge of `replies` to `request`.
fn app_merges(request: &[u8], replies: &[&[u8]]) -> Result<Vec<u8>, ReplyError> {
    let mut b = Buffers::new();
    let mut scratch = sdk_reply::Scratch {
        inputs: &mut b.inputs,
        outputs: &mut b.outputs,
    };
    let mut sigs = [InputSignature::EMPTY; 16];
    let mut out = vec![0u8; 4096];
    let n = sdk_reply::merge(request, replies, &P, &mut scratch, &mut sigs, &mut out)?;
    out.truncate(n);
    Ok(out)
}

/// What the app's finalization gives: id, fee, compute and storage masses,
/// the submit request, each input's unlocking script, and the finished
/// transaction in the safe JSON for rusty-kaspa's engine to run.
struct Finished {
    id: kassigner_kaspa::sighash::Hash,
    fee: u64,
    compute: u64,
    storage: u64,
    json: String,
    scripts: Vec<Vec<u8>>,
    signed: String,
}

/// What `f` holds, as the tests read it.
fn finished(f: &Finalized<'_>) -> Finished {
    let mut json = vec![0u8; f.submit_json_len(false, Shape::Rpc)];
    let n = f.submit_json(false, Shape::Rpc, &mut json).unwrap();
    assert_eq!(n, json.len());
    let details: Vec<EntryDetails> = f
        .transaction
        .inputs
        .iter()
        .map(|i| entry_details(i.previous_outpoint.index))
        .collect();
    let mut signed =
        vec![
            0u8;
            kassigner_kaspa::safe_json::written_len(&f.transaction, &details, f.storage_mass)
                .unwrap()
        ];
    kassigner_kaspa::safe_json::write(&f.transaction, &details, f.storage_mass, &mut signed)
        .unwrap();
    Finished {
        id: f.id,
        fee: f.fee,
        compute: f.compute_mass,
        storage: f.storage_mass,
        json: String::from_utf8(json).unwrap(),
        scripts: f
            .transaction
            .inputs
            .iter()
            .map(|i| i.signature_script.to_vec())
            .collect(),
        signed: String::from_utf8(signed).unwrap(),
    }
}

/// The app's finalization of `reply`, against `request`.
fn app_finalizes(request: &[u8], reply: &[u8]) -> Result<Finished, ReplyError> {
    let mut b = Buffers::new();
    let mut unlocks = vec![0u8; 4096];
    let mut unlock_lens = [0usize; 8];
    let mut signatures = [PositionedSignature {
        position: 0,
        sighash_type: 0,
        signature: &[0; 64],
    }; 16];
    let mut ranges = [(0usize, 0usize); 8];
    let mut spends = [sdk_reply::Spend {
        need: 0,
        redeem: &[],
        signatures: &[],
        bound: false,
    }; 8];
    let mut scratch = FinalScratch {
        inputs: &mut b.inputs,
        outputs: &mut b.outputs,
        unlocks: &mut unlocks,
        unlock_lens: &mut unlock_lens,
        signatures: &mut signatures,
        ranges: &mut ranges,
        spends: &mut spends,
        cells_in: &mut b.cells_in,
        cells_out: &mut b.cells_out,
    };
    let f: Finalized<'_> =
        sdk_reply::finalize(request, reply, &P, &MassRates::MAINNET, &mut scratch)?;
    Ok(finished(&f))
}

/// The app's finish of `signed` against `request`, both in the safe JSON.
fn app_finalizes_safe_json(request: &[u8], signed: &[u8]) -> Result<Finished, ReplyError> {
    let (mut req_ins, mut req_outs) = (Buffers::new().inputs, Buffers::new().outputs);
    let (mut ins, mut outs) = (Buffers::new().inputs, Buffers::new().outputs);
    let mut req_details = [entry_details(0); 8];
    let mut details = [entry_details(0); 8];
    let mut req_bytes = vec![0u8; request.len() / 2];
    let mut bytes = vec![0u8; signed.len() / 2];
    let mut b = Buffers::new();
    let mut scratch = sdk_reply::SafeScratch {
        request_inputs: &mut req_ins,
        request_outputs: &mut req_outs,
        request_details: &mut req_details,
        request_bytes: &mut req_bytes,
        inputs: &mut ins,
        outputs: &mut outs,
        details: &mut details,
        bytes: &mut bytes,
        cells_in: &mut b.cells_in,
        cells_out: &mut b.cells_out,
    };
    let f = sdk_reply::finalize_safe_json(request, signed, &MassRates::MAINNET, &mut scratch)?;
    Ok(finished(&f))
}

/// The app reads, merges and finishes replies: the `44'` reply complete at
/// once, the group's only with two cosigners' merged, the `22'` sweep with
/// the redeem script the unit supplied. Each pays at least the minimum
/// relay fee and goes out as a submit request with its storage mass.
#[test]
fn replies_are_read_merged_and_finished_by_the_app() {
    let requests = the_three_requests();
    let (_, single) = &requests[0];
    let (_, multisig) = &requests[1];
    let (_, sweep) = &requests[2];

    let (plan, reply, _) = unit_signs(single, &wallet(ABANDON12));
    let c = app_reads(single, &reply).expect("read");
    assert_eq!((c.signatures, c.signers, c.complete), (2, None, true));
    assert_eq!(
        app_reads(multisig, &reply).err(),
        Some(ReplyError::NotTheRequest),
        "another request's reply"
    );
    assert_eq!(
        app_finalizes(multisig, &reply).err(),
        Some(ReplyError::NotTheRequest),
        "finished against another request"
    );
    let f = app_finalizes(single, &reply).expect("finished");
    assert!(f.fee >= minimum_relay_fee(f.compute));
    assert_eq!(plan.inputs, f.scripts.len());
    assert!(f
        .scripts
        .iter()
        .all(|s| s.len() == 66 && s[0] == 65 && s[65] == 1));
    assert!(f.json.contains(&format!("\"mass\":{}", f.storage)));
    assert!(f.json.starts_with("{\"transaction\":{\"version\":0,\"inputs\":[{\"previousOutpoint\":{\"transactionId\":\"0101"));
    assert_ne!(f.id, [0; 32]);

    let (_, first, _) = unit_signs(multisig, &wallet(ABANDON12));
    let c = app_reads(multisig, &first).expect("read");
    assert_eq!(c.signatures, 1);
    assert_eq!(
        c.signers,
        Some(reply::Signers {
            present: 1,
            required: 2
        })
    );
    assert!(!c.complete);
    assert!(matches!(
        app_finalizes(multisig, &first).err(),
        Some(ReplyError::Signatures {
            input: 0,
            have: 1,
            need: 2
        })
    ));
    let (_, second, _) = unit_signs(multisig, &wallet(ZOO12));
    let merged = app_merges(multisig, &[&first, &second]).expect("merged");
    let c = app_reads(multisig, &merged).expect("read");
    assert_eq!((c.signatures, c.complete), (2, true));
    assert_eq!(
        c.signers,
        Some(reply::Signers {
            present: 2,
            required: 2
        })
    );
    assert!(matches!(
        app_merges(multisig, &[&first, &first]).err(),
        Some(ReplyError::Merge(
            kspt::KsptError::DuplicateSignature { .. }
        ))
    ));
    let f = app_finalizes(multisig, &merged).expect("finished");
    assert_eq!(f.fee, minimum_relay_fee(f.compute.max(f.storage)));
    // Two signatures by position, then the 2-of-3's redeem script pushed.
    let unlock = &f.scripts[0];
    assert_eq!(unlock[0], 65);
    assert_eq!(unlock[66], 65);
    assert_eq!(unlock[132], 0x4c, "OP_PUSHDATA1 for the 104-byte redeem");
    assert_eq!(unlock.len(), 132 + 2 + unlock[133] as usize);

    let (_, reply, _) = unit_signs(sweep, &wallet(ABANDON12));
    let c = app_reads(sweep, &reply).expect("read");
    assert_eq!((c.signatures, c.complete), (2, true));
    let f = app_finalizes(sweep, &reply).expect("finished");
    assert_eq!(f.fee, minimum_relay_fee(f.compute.max(f.storage)));
    for s in &f.scripts {
        assert_eq!(s.len(), 66 + 35, "a signature and `<P> OP_CHECKSIG` pushed");
        assert_eq!(s[66], 34);
        assert_eq!(s[67], 0x20);
        assert_eq!(s[100], 0xac);
    }
}

// ── Bundles ─────────────────────────────────────────────────────────────────

macro_rules! vector {
    ($path:literal) => {
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../spec/vectors/v107/",
            $path
        ))
    };
}

/// The bench's bundles: abandon 12 pays 1 KAS to abandon 24, and the
/// 2-of-3 pays 2 KAS with change to itself.
const PSKB_SEND: &[u8] = vector!("site/pskb_send.bin");
const PSKB_MULTISIG: &[u8] = vector!("site/pskb_multisig.bin");

/// The document inside an envelope.
fn unwrap(env: &[u8]) -> Vec<u8> {
    let mut json = vec![0u8; env.len()];
    let n = decode_envelope(env, &mut json).expect("envelope");
    json.truncate(n);
    json
}

/// The unit's side of a bundle: parse, review, confirm, plan and sign with
/// `w`; the reply envelope.
fn unit_signs_bundle(envelope: &[u8], w: &Wallet) -> Vec<u8> {
    let doc = unwrap(envelope);
    let mut ins = Buffers::new().inputs;
    let mut outs = Buffers::new().outputs;
    let mut bytes = [0u8; 2048];
    let filled = kassigner_kaspa::pskb::transaction::fill(&doc, 0, &mut ins, &mut outs, &mut bytes)
        .expect("fill");
    let tx = kassigner_kaspa::pskb::transaction::build(
        &filled.header,
        &ins[..filled.inputs],
        &outs[..filled.outputs],
    );
    // The spent coins' covenant ids, as the unit's flow reads them.
    let checked = kassigner_kaspa::pskb::check(&doc).expect("a bundle");
    let coins: Vec<Option<[u8; 32]>> = (0..filled.inputs)
        .map(|i| {
            kassigner_kaspa::pskb::transaction::input_covenant_id(checked, 0, i).expect("entry")
        })
        .collect();
    let mut s = Session::with_coins(tx, |_| None, &coins).expect("session");
    let keys = Keyring::new(w).expect("keyring");
    let mut redeem = [0u8; 512];
    reply::plan_pskb(&s, &doc, &keys, 14_400, &mut redeem).expect("the unit plans it");
    while let Some((i, _)) = s.next_page() {
        s.page_shown(i).expect("mark");
    }
    s.decide(Decision::Confirm).expect("confirm");
    let (mut sins, mut souts) = (Buffers::new().inputs, Buffers::new().outputs);
    let mut sbytes = [0u8; 2048];
    let mut sredeem = [0u8; 512];
    let mut signatures = [[0u8; 64]; 8];
    let mut signed = [reply::Signed::EMPTY; 8];
    let mut partial = [PartialSig {
        input: 0,
        public_key: &[0; 33],
        signature: &[0; 64],
        derivation: Derivation::Null,
    }; 8];
    let mut splices = [Splice::insert_at(0, &[]); 24];
    let mut text = [0u8; 4096];
    let mut json = vec![0u8; doc.len() + 4096];
    let mut scratch = reply::Scratch {
        inputs: &mut sins,
        outputs: &mut souts,
        bytes: &mut sbytes,
        redeem: &mut sredeem,
        signatures: &mut signatures,
        signed: &mut signed,
        partial: &mut partial,
        splices: &mut splices,
        text: &mut text,
        json: &mut json,
    };
    let mut out = vec![0u8; 4 + 2 * (doc.len() + 4096)];
    let r =
        reply::pskb(&s, &doc, &keys, &mut Live, &mut scratch, &mut out).expect("the unit signs");
    out.truncate(r.len);
    out
}

/// Everything the app's bundle side works in, for one envelope.
struct BundleRoom<'a> {
    doc: Vec<u8>,
    inputs: [TransactionInput<'a>; 8],
    outputs: [TransactionOutput<'a>; 8],
    bytes: Vec<u8>,
    redeem: Vec<u8>,
    text: Vec<u8>,
    splices: [Splice<'a>; 32],
    json: Vec<u8>,
}

/// The app's bundle scratch over a room, built where the room lives.
macro_rules! bundle_scratch {
    ($room:expr) => {
        bundle::Scratch {
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

impl<'a> BundleRoom<'a> {
    fn new(envelope: &[u8]) -> Self {
        BundleRoom {
            doc: vec![0u8; envelope.len()],
            inputs: Buffers::new().inputs,
            outputs: Buffers::new().outputs,
            bytes: vec![0u8; envelope.len()],
            redeem: vec![0u8; P.max_redeem],
            text: vec![0u8; 8192],
            splices: [Splice::insert_at(0, &[]); 32],
            json: vec![0u8; 2 * envelope.len() + 8192],
        }
    }
}

fn app_prepares(
    envelope: &[u8],
    hints: &[(usize, bundle::Hint<'_>)],
) -> Result<(bundle::Prepared, Vec<u8>), BundleError> {
    let mut room = BundleRoom::new(envelope);
    let mut scratch = bundle_scratch!(room);
    let mut out = vec![0u8; 2 * envelope.len() + 16384];
    let p = bundle::prepare(envelope, hints, &P, &mut scratch, &mut out)?;
    out.truncate(p.len);
    Ok((p, out))
}

fn app_reads_bundle(request: &[u8], reply: &[u8]) -> Result<bundle::Checked, BundleError> {
    let mut req = BundleRoom::new(request);
    let mut rep = BundleRoom::new(reply);
    let mut scratch = bundle::ReadScratch {
        request: bundle_scratch!(req),
        doc: &mut rep.doc,
        inputs: &mut rep.inputs,
        outputs: &mut rep.outputs,
        bytes: &mut rep.bytes,
        redeem: &mut rep.redeem,
    };
    bundle::read(request, reply, &P, &mut scratch)
}

fn app_merges_bundles(request: &[u8], replies: &[&[u8]]) -> Result<Vec<u8>, BundleError> {
    let longest = replies
        .iter()
        .map(|r| r.len())
        .max()
        .unwrap_or(0)
        .max(request.len());
    let mut req = BundleRoom::new(request);
    let mut rep = BundleRoom::new(&vec![0u8; longest]);
    let mut scratch = bundle::ReadScratch {
        request: bundle_scratch!(req),
        doc: &mut rep.doc,
        inputs: &mut rep.inputs,
        outputs: &mut rep.outputs,
        bytes: &mut rep.bytes,
        redeem: &mut rep.redeem,
    };
    let mut keys = [[0u8; 33]; 16];
    let mut signatures = [[0u8; 64]; 16];
    let mut partial = [PartialSig {
        input: 0,
        public_key: &[0; 33],
        signature: &[0; 64],
        derivation: Derivation::Null,
    }; 16];
    let mut redeems = [SuppliedRedeem::EMPTY; 8];
    let mut merging = bundle::MergeScratch {
        keys: &mut keys,
        signatures: &mut signatures,
        partial: &mut partial,
        redeems: &mut redeems,
    };
    let mut out = vec![0u8; 4 * longest + 16384];
    let n = bundle::merge(request, replies, &P, &mut scratch, &mut merging, &mut out)?;
    out.truncate(n);
    Ok(out)
}

fn app_finalizes_bundle(request: &[u8], reply: &[u8]) -> Result<Finished, BundleError> {
    let mut asked = BundleRoom::new(request);
    let mut room = BundleRoom::new(reply);
    let mut redeems = vec![0u8; 8 * P.max_redeem];
    let mut redeem_lens = [0usize; 8];
    let mut sighash = [0u8; 8];
    let mut keys = [[0u8; 33]; 16];
    let mut signature_bytes = [[0u8; 64]; 16];
    let mut signatures = [PositionedSignature {
        position: 0,
        sighash_type: 0,
        signature: &[0; 64],
    }; 16];
    let mut ranges = [(0usize, 0usize); 8];
    let mut spends = [sdk_reply::Spend {
        need: 0,
        redeem: &[],
        signatures: &[],
        bound: false,
    }; 8];
    let mut unlocks = vec![0u8; 4096];
    let mut unlock_lens = [0usize; 8];
    let mut cells_in = [kassigner_kaspa::mass::Cell {
        plurality: 0,
        amount: 0,
    }; 8];
    let mut cells_out = cells_in;
    let mut scratch = bundle::FinalScratch {
        request_doc: &mut asked.doc,
        request_inputs: &mut asked.inputs,
        request_outputs: &mut asked.outputs,
        request_bytes: &mut asked.bytes,
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
        finish: sdk_reply::FinishScratch {
            unlocks: &mut unlocks,
            unlock_lens: &mut unlock_lens,
            cells_in: &mut cells_in,
            cells_out: &mut cells_out,
        },
    };
    let f = bundle::finalize(request, reply, &P, &MassRates::MAINNET, &mut scratch)?;
    Ok(finished(&f))
}

/// An envelope over `doc`.
fn envelope(doc: &[u8]) -> Vec<u8> {
    let mut env = b"PSKB".to_vec();
    env.extend(doc.iter().flat_map(|&b| {
        let h = b"0123456789abcdef";
        [h[usize::from(b >> 4)], h[usize::from(b & 0x0f)]]
    }));
    env
}

/// `prepare` refuses a bundle the unit would refuse as a whole, by the same
/// rule, so a wallet learns before the unit scans it; the bench's send is
/// broken one rule at a time.
#[test]
fn prepare_refuses_what_the_unit_refuses() {
    use kassigner_kaspa::tx::{NonStandardError, TxRuleError};
    use kassigner_protocol::check::TransactionError;
    let doc = String::from_utf8(unwrap(PSKB_SEND)).unwrap();
    let input = &doc[doc
        .find("{\"bip32Derivations\":{},\"finalScriptSig\"")
        .unwrap()..doc.find("],\"outputs\"").unwrap()];
    let edit = |from: &str, to: &str| {
        assert_eq!(doc.matches(from).count(), 1, "{from}");
        doc.replacen(from, to, 1)
    };
    let twice = edit(input, &format!("{input},{input}")).replacen(
        "\"inputCount\":1",
        "\"inputCount\":2",
        1,
    );
    let bound = edit("\"txVersion\":0", "\"txVersion\":1").replacen(
        "\"redeemScript\":null,\"scriptPublicKey\":\"00002094",
        &format!(
            "\"covenant\":{{\"authorizingInput\":5,\"covenantId\":\"{}\"}},\"redeemScript\":null,\"scriptPublicKey\":\"00002094",
            "cc".repeat(32)
        ),
        1,
    );
    // A binding naming the bundle's one input, under an id no new covenant
    // of that input makes: the rule that needs the spent coins.
    let unmade = bound.replacen("\"authorizingInput\":5", "\"authorizingInput\":0", 1);
    assert_ne!(unmade, bound);
    // A case: what is broken, the bundle's document, and the rule refusing it.
    type Case = (&'static str, String, fn(&TransactionError) -> bool);
    // No outputs at all: everything the input holds would go to the fee.
    let none = format!(
        "{}\"outputs\":[]}}]",
        &doc[..doc.find("\"outputs\":[").unwrap()]
    )
    .replacen("\"outputCount\":2", "\"outputCount\":0", 1);
    let cases: [Case; 8] = [
        ("no outputs", none, |e| {
            matches!(e, TransactionError::NoOutputs)
        }),
        (
            "an output worth nothing",
            edit("\"amount\":100000000", "\"amount\":0"),
            |e| matches!(e, TransactionError::Consensus(TxRuleError::TxOutZero(0))),
        ),
        ("an outpoint spent twice", twice, |e| {
            matches!(
                e,
                TransactionError::Consensus(TxRuleError::TxDuplicateInputs)
            )
        }),
        (
            "outputs above the inputs",
            edit("\"amount\":399000000", "\"amount\":499000000"),
            |e| {
                matches!(
                    e,
                    TransactionError::Consensus(TxRuleError::SpendTooHigh(..))
                )
            },
        ),
        (
            "an output of no standard form",
            edit(
                "\"000020276222b7bf62ffce4482c3c40aaa25e21ef06d27cc91c217b464982d042d33feac\"",
                "\"000051\"",
            ),
            |e| {
                matches!(
                    e,
                    TransactionError::NonStandard(NonStandardError::RejectOutputScriptClass(1))
                )
            },
        ),
        (
            "a version consensus does not know",
            edit("\"txVersion\":0", "\"txVersion\":9"),
            |e| {
                matches!(
                    e,
                    TransactionError::Consensus(TxRuleError::UnknownTxVersion(9))
                )
            },
        ),
        ("a binding naming no input of the transaction", bound, |e| {
            matches!(
                e,
                TransactionError::Consensus(TxRuleError::AuthInputOutOfBounds(0, 5))
            )
        }),
        (
            "a new covenant under an id it does not make",
            unmade.clone(),
            |e| {
                matches!(
                    e,
                    TransactionError::Consensus(TxRuleError::WrongGenesisCovenantId(0, id))
                        if *id == [0xcc; 32]
                )
            },
        ),
    ];
    for (what, doc, rule) in cases {
        let env = envelope(doc.as_bytes());
        match app_prepares(&env, &[]) {
            Err(BundleError::Transaction(e)) => assert!(rule(&e), "{what}: prepare refused {e:?}"),
            Ok((p, _)) => panic!("{what}: prepare passed it: {p:?}"),
            Err(e) => panic!("{what}: prepare refused it otherwise: {e:?}"),
        }
        let mut room = BundleRoom::new(&env);
        let (_, tx) = bundle::transaction_of(
            &env,
            &mut room.doc,
            &mut room.inputs,
            &mut room.outputs,
            &mut room.bytes,
        )
        .unwrap_or_else(|e| panic!("{what}: {e:?}"));
        let unit = match Session::new(tx) {
            Err(kassigner_fw::session::Error::Consensus(r)) => TransactionError::Consensus(r),
            Err(kassigner_fw::session::Error::NonStandard(r)) => TransactionError::NonStandard(r),
            Err(kassigner_fw::session::Error::NoOutputs) => TransactionError::NoOutputs,
            other => panic!("{what}: the unit gave {:?}", other.err()),
        };
        assert!(rule(&unit), "{what}: the unit refused {unit:?}");
    }
    // The same binding continues the covenant when the input's coin is bound
    // to it: `prepare` reads the coin's entry, and the rule passes.
    assert_eq!(unmade.matches("\"covenantId\":null").count(), 1);
    let continued = unmade.replacen(
        "\"covenantId\":null",
        &format!("\"covenantId\":\"{}\"", "cc".repeat(32)),
        1,
    );
    let env = envelope(continued.as_bytes());
    assert!(
        app_prepares(&env, &[]).is_ok(),
        "{:?}",
        app_prepares(&env, &[]).err()
    );
}

/// A wallet's bundle, prepared with abandon 12's hint, goes through the
/// unit and finishes with one signature; its 0.01 KAS fee, under its
/// storage mass but over the relay fee for its compute mass, finishes as a
/// node takes it.
#[test]
fn a_bundle_goes_through_the_unit() {
    let a = account();
    let hint = bundle::Hint::Account {
        account: &a,
        chain: RECEIVE,
        index: 0,
        fingerprint: [0x73, 0xc5, 0xda, 0x0a],
    };
    let (_, prepared) = app_prepares(PSKB_SEND, &[(0, hint)]).expect("prepared");
    let reply = unit_signs_bundle(&prepared, &wallet(ABANDON12));
    let f = app_finalizes_bundle(&prepared, &reply).expect("a node takes it");
    assert_eq!(f.fee, 1_000_000);
    assert!(f.fee < minimum_relay_fee(f.storage) && f.fee >= minimum_relay_fee(f.compute));

    let doc = String::from_utf8(unwrap(PSKB_SEND)).unwrap();
    let paid = envelope(
        doc.replace("\"amount\":399000000", "\"amount\":390000000")
            .as_bytes(),
    );
    let (p, prepared) = app_prepares(
        &paid,
        &[(
            0,
            bundle::Hint::Account {
                account: &a,
                chain: RECEIVE,
                index: 0,
                fingerprint: [0x73, 0xc5, 0xda, 0x0a],
            },
        )],
    )
    .expect("prepared");
    assert_eq!((p.inputs, p.signatures), (1, 1));
    let doc = String::from_utf8(unwrap(&prepared)).unwrap();
    assert!(
        doc.contains("\"keyFingerprint\":\"73c5da0a\",\"derivationPath\":\"m/44'/111111'/0'/0/0\"")
    );
    assert!(
        doc.contains("\"bip32Derivations\":{\"02") || doc.contains("\"bip32Derivations\":{\"03")
    );

    let reply = unit_signs_bundle(&prepared, &wallet(ABANDON12));
    let c = app_reads_bundle(&prepared, &reply).expect("read");
    assert_eq!((c.signatures, c.signers, c.complete), (1, None, true));
    assert_eq!(
        app_reads_bundle(PSKB_MULTISIG, &reply).err(),
        Some(BundleError::NotTheRequest)
    );
    assert_eq!(
        app_finalizes_bundle(PSKB_MULTISIG, &reply).err(),
        Some(BundleError::NotTheRequest)
    );
    let f = app_finalizes_bundle(&prepared, &reply).expect("finished");
    assert_eq!(f.fee, 10_000_000);
    assert!(f.fee >= minimum_relay_fee(f.compute.max(f.storage)));
    assert_eq!(f.scripts.len(), 1);
    assert_eq!(f.scripts[0].len(), 66);
    assert!(f.json.contains(&format!("\"mass\":{}", f.storage)));
    assert_ne!(f.id, [0; 32]);
}

/// The 2-of-3's bundle, prepared with a hint for its three keys, is
/// answered by abandon 12 and zoo 12; merged, it is complete and finishes
/// with both signatures by position and the redeem script.
#[test]
fn a_group_bundle_is_merged_from_two_replies() {
    let g = group();
    let (p, prepared) = app_prepares(
        PSKB_MULTISIG,
        &[(
            0,
            bundle::Hint::Group {
                group: &g,
                cosigner: 0,
                chain: RECEIVE,
                index: 0,
                fingerprints: &[],
            },
        )],
    )
    .expect("prepared");
    assert_eq!((p.inputs, p.signatures), (1, 2));
    let doc = String::from_utf8(unwrap(&prepared)).unwrap();
    assert_eq!(
        doc.matches("\"derivationPath\":\"m/45'/111111'/0'/0/0/0\"")
            .count(),
        3
    );
    assert_eq!(doc.matches("\"keyFingerprint\":\"00000000\"").count(), 3);

    let first = unit_signs_bundle(&prepared, &wallet(ABANDON12));
    let c = app_reads_bundle(&prepared, &first).expect("read");
    assert_eq!(c.signatures, 1);
    assert_eq!(
        c.signers,
        Some(reply::Signers {
            present: 1,
            required: 2
        })
    );
    assert!(!c.complete);
    assert!(matches!(
        app_finalizes_bundle(&prepared, &first).err(),
        Some(BundleError::Finish(ReplyError::Signatures {
            input: 0,
            have: 1,
            need: 2
        }))
    ));
    let second = unit_signs_bundle(&prepared, &wallet(ZOO12));
    let merged = app_merges_bundles(&prepared, &[&first, &second]).expect("merged");
    let c = app_reads_bundle(&prepared, &merged).expect("read");
    assert_eq!((c.signatures, c.complete), (2, true));
    assert_eq!(
        c.signers,
        Some(reply::Signers {
            present: 2,
            required: 2
        })
    );
    assert!(matches!(
        app_merges_bundles(&prepared, &[&first, &first]).err(),
        Some(BundleError::Edit(_))
    ));
    let f = app_finalizes_bundle(&prepared, &merged).expect("finished");
    let s = &f.scripts[0];
    assert_eq!(s[0], 65);
    assert_eq!(s[66], 65);
    assert_eq!(s[132], 0x4c);
    assert_eq!(s.len(), unlock::script_hash_len(2, s[133] as usize));
    assert!(f.fee >= minimum_relay_fee(f.compute.max(f.storage)));
}

/// `prepare` refuses a bundle the unit would: two transactions in one
/// envelope, a sighash type other than `ALL`, a hint for an input it lacks.
#[test]
fn the_app_refuses_what_the_unit_refuses_in_a_bundle() {
    let doc = unwrap(PSKB_SEND);
    let text = String::from_utf8(doc).unwrap();
    let inner = &text[1..text.len() - 1];
    let two = envelope(format!("[{inner},{inner}]").as_bytes());
    assert_eq!(
        app_prepares(&two, &[]).err(),
        Some(BundleError::NotOneTransaction { count: 2 })
    );
    let none = envelope(
        text.replace("\"sighashType\":1", "\"sighashType\":2")
            .as_bytes(),
    );
    assert_eq!(
        app_prepares(&none, &[]).err(),
        Some(BundleError::Check(
            kassigner_protocol::check::Error::SighashNotAll { input: 0 }
        ))
    );
    let a = account();
    assert_eq!(
        app_prepares(
            PSKB_SEND,
            &[(
                3,
                bundle::Hint::Account {
                    account: &a,
                    chain: RECEIVE,
                    index: 0,
                    fingerprint: [0; 4],
                },
            )],
        )
        .err(),
        Some(BundleError::Hint { input: 3 })
    );
}

/// A reply supplying another redeem script than the coin commits to is
/// refused, even one holding the same key (`<P> OP_CHECKSIGVERIFY` for
/// `<P> OP_CHECKSIG`): by the KSPT's merge and finish before a key is read
/// from it, and by the bundle's merge with or without the signature.
#[test]
fn a_reply_supplying_another_script_is_refused() {
    let requests = the_three_requests();
    let (_, sweep) = &requests[2];
    let (_, reply, _) = unit_signs(sweep, &wallet(ABANDON12));
    let script = kspt::parse(&reply, &P)
        .unwrap()
        .inputs()
        .next()
        .unwrap()
        .redeem
        .to_vec();
    assert_eq!((script.len(), script[33]), (34, 0xac));
    let at = reply
        .windows(34)
        .position(|w| w == script.as_slice())
        .expect("the supplied script");
    let mut other = reply.clone();
    other[at + 33] = 0xad;
    let refused = Some(ReplyError::Unverified(reply::Unverified::NoKeyAt {
        input: 0,
        position: 0,
    }));
    assert_eq!(app_merges(sweep, &[&other]).err(), refused);
    assert_eq!(app_finalizes(sweep, &other).err(), refused);
    assert!(app_merges(sweep, &[&reply]).is_ok());

    let [_, _, kcc3] = the_three(bundle_request);
    let request = kcc3.expect("built as a bundle").1;
    let reply = unit_signs_bundle(&request, &wallet(ABANDON12));
    let doc = String::from_utf8(unwrap(&reply)).unwrap();
    let held = format!("\"redeemScript\":\"{}\"", kassigner_sdk_host::hex(&script));
    assert_eq!(doc.matches(&held).count(), 2, "both inputs");
    let mut changed = kassigner_sdk_host::hex(&script);
    changed.replace_range(66.., "ad");
    let doc = doc.replacen(&held, &format!("\"redeemScript\":\"{changed}\""), 1);
    assert_eq!(
        app_merges_bundles(&request, &[&envelope(doc.as_bytes())]).err(),
        Some(BundleError::Check(
            kassigner_protocol::check::Error::BadSignature { input: 0 }
        ))
    );
    let members = doc.find("\"partialSigs\":{\"").expect("input 0's members");
    let end = members + doc[members..].find("}}").expect("their end") + 2;
    let unsigned = format!("{}\"partialSigs\":{{}}{}", &doc[..members], &doc[end..]);
    assert_eq!(
        app_merges_bundles(&request, &[&envelope(unsigned.as_bytes())]).err(),
        Some(BundleError::Redeem { input: 0 })
    );
}

/// A request built as a bundle is the KSPT's transaction: same fee, mass
/// and change, and signed it finishes to the same id and submit request. It
/// carries each coin's node entry and every key's path, the group's change
/// keys included, where the unit reads a bundle's change from.
#[test]
fn a_request_built_as_a_bundle_is_the_kspts_transaction() {
    let [kspt_single, kspt_multisig, _] = the_three(request);
    let [bundle_single, bundle_multisig, _] = the_three(bundle_request);

    let (rk, kspt) = kspt_single.expect("built");
    let (rb, pskb) = bundle_single.expect("built as a bundle");
    assert_eq!(
        (rb.fee, rb.mass, rb.change, rb.signatures),
        (rk.fee, rk.mass, rk.change, rk.signatures)
    );
    let doc = String::from_utf8(unwrap(&pskb)).unwrap();
    assert!(doc.starts_with("[{\"global\":{\"version\":0,\"txVersion\":0,"));
    assert!(doc.contains("\"blockDaaScore\":90000001,\"isCoinbase\":false"));
    assert!(doc.contains("\"sequence\":0,\"minTime\":null"));
    for path in ["m/44'/111111'/0'/0/0", "m/44'/111111'/0'/1/3"] {
        assert!(
            doc.contains(&format!(
                "{{\"keyFingerprint\":\"00000000\",\"derivationPath\":\"{path}\"}}"
            )),
            "{path}"
        );
    }
    let reply = unit_signs_bundle(&pskb, &wallet(ABANDON12));
    let c = app_reads_bundle(&pskb, &reply).expect("read");
    assert_eq!((c.signatures, c.complete), (2, true));
    let fb = app_finalizes_bundle(&pskb, &reply).expect("finished");
    let fk = app_finalizes(&kspt, &unit_signs(&kspt, &wallet(ABANDON12)).1).expect("finished");
    assert_eq!(fb.id, fk.id, "the same transaction");
    assert_eq!(fb.json, fk.json, "the same submit request");
    assert_eq!(fb.fee, rk.fee);

    let (rk, kspt) = kspt_multisig.expect("built");
    let (rb, pskb) = bundle_multisig.expect("built as a bundle");
    assert_eq!(
        (rb.fee, rb.mass, rb.change, rb.signatures),
        (rk.fee, rk.mass, rk.change, rk.signatures)
    );
    let doc = String::from_utf8(unwrap(&pskb)).unwrap();
    assert_eq!(
        doc.matches("\"derivationPath\":\"m/45'/111111'/0'/0/0/0\"")
            .count(),
        3,
        "the coin's three keys"
    );
    assert_eq!(
        doc.matches("\"derivationPath\":\"m/45'/111111'/0'/0/1/0\"")
            .count(),
        3,
        "the change's three keys"
    );
    let change_at = doc.find("\"outputs\":").expect("outputs");
    assert!(doc[change_at..].contains("\"m/45'/111111'/0'/0/1/0\""));
    assert!(!doc.contains("\"redeemScript\":null,\"sigOpCount\":3"));
    let replies = [
        unit_signs_bundle(&pskb, &wallet(ABANDON12)),
        unit_signs_bundle(&pskb, &wallet(ZOO12)),
    ];
    let merged = app_merges_bundles(&pskb, &[&replies[0], &replies[1]]).expect("merged");
    assert!(app_reads_bundle(&pskb, &merged).expect("read").complete);
    let fb = app_finalizes_bundle(&pskb, &merged).expect("finished");
    let kspt_replies = [
        unit_signs(&kspt, &wallet(ABANDON12)).1,
        unit_signs(&kspt, &wallet(ZOO12)).1,
    ];
    let fk = app_finalizes(
        &kspt,
        &app_merges(&kspt, &[&kspt_replies[0], &kspt_replies[1]]).unwrap(),
    )
    .expect("finished");
    assert_eq!(fb.id, fk.id, "the same transaction");
    assert_eq!(fb.json, fk.json, "the same submit request");
}

/// A request in the safe JSON is the KSPT's transaction and, signed with
/// the unit's unlocking scripts, finishes to the same id and submit
/// request; handed back unsigned, altered or with a wrong id it is refused.
#[test]
fn a_request_written_as_safe_json_is_the_kspts_transaction() {
    let [kspt_single, kspt_multisig, _] = the_three(request);
    let [safe_single, safe_multisig, _] = the_three(safe_request);

    let (rk, kspt) = kspt_single.expect("built");
    let (rs, text) = safe_single.expect("built as safe JSON");
    assert_eq!(
        (rs.fee, rs.mass, rs.change, rs.signatures),
        (rk.fee, rk.mass, rk.change, rk.signatures)
    );
    let doc = String::from_utf8(text.clone()).unwrap();
    assert!(doc.contains("\"version\":0,\"inputs\":[{\"transactionId\":"));
    assert!(doc.contains("\"blockDaaScore\":\"90000001\",\"isCoinbase\":false"));
    assert!(doc.contains("\"signatureScript\":\"\""));
    let fk = app_finalizes(&kspt, &unit_signs(&kspt, &wallet(ABANDON12)).1).expect("finished");
    assert!(doc.contains(&format!("\"storageMass\":\"{}\"", fk.storage)));
    let signed = wallet_signs_safe_json(&text, &fk.scripts);
    let fs = app_finalizes_safe_json(&text, &signed).expect("finished");
    assert_eq!(fs.id, fk.id, "the same transaction");
    assert_eq!(fs.json, fk.json, "the same submit request");
    assert_eq!(fs.fee, rk.fee);

    assert_eq!(
        app_finalizes_safe_json(&text, &text).err(),
        Some(ReplyError::Unsigned { input: 0 })
    );
    let signed_text = String::from_utf8(signed.clone()).unwrap();
    let paid = signed_text.replacen("\"value\":\"400000000\"", "\"value\":\"390000000\"", 1);
    assert_ne!(paid, signed_text);
    assert_eq!(
        app_finalizes_safe_json(&text, paid.as_bytes()).err(),
        Some(ReplyError::NotTheRequest)
    );
    let later = signed_text.replacen(
        "\"blockDaaScore\":\"90000001\"",
        "\"blockDaaScore\":\"90000002\"",
        1,
    );
    assert_ne!(later, signed_text);
    assert_eq!(
        app_finalizes_safe_json(&text, later.as_bytes()).err(),
        Some(ReplyError::NotTheRequest)
    );
    let id_at = signed_text.find("\"id\":\"").unwrap() + 6;
    let mut other = signed_text.clone().into_bytes();
    other[id_at] = if other[id_at] == b'0' { b'1' } else { b'0' };
    assert_eq!(
        app_finalizes_safe_json(&text, &other).err(),
        Some(ReplyError::WrongId)
    );

    let (rk, kspt) = kspt_multisig.expect("built");
    let (rs, text) = safe_multisig.expect("built as safe JSON");
    assert_eq!(
        (rs.fee, rs.mass, rs.change, rs.signatures),
        (rk.fee, rk.mass, rk.change, rk.signatures)
    );
    let replies = [
        unit_signs(&kspt, &wallet(ABANDON12)).1,
        unit_signs(&kspt, &wallet(ZOO12)).1,
    ];
    let fk = app_finalizes(
        &kspt,
        &app_merges(&kspt, &[&replies[0], &replies[1]]).unwrap(),
    )
    .expect("finished");
    let signed = wallet_signs_safe_json(&text, &fk.scripts);
    let fs = app_finalizes_safe_json(&text, &signed).expect("finished");
    assert_eq!(fs.id, fk.id, "the same transaction");
    assert_eq!(fs.json, fk.json, "the same submit request");
}

// ── Messages ────────────────────────────────────────────────────────────────

/// What the unit's Sign Message does with `text` and `w`'s receive 0: the
/// record it shows, as `Flow::sign_message` and `message_frame` make it.
fn unit_signs_message(text: &[u8], w: &Wallet) -> Vec<u8> {
    let key = w.signing_key(Path::receive(0)).expect("key");
    let hash = kassigner_kaspa::sighash::personal_message_hash(text);
    let mut aux = [0u8; 32];
    Live.fill(&mut aux).unwrap();
    let signature = kassigner_crypto::sign::sign(key.private_key(), &hash, &aux).expect("signed");
    let mut address = [0u8; MAX_ADDRESS_LEN];
    let n = encode(
        Network::Mainnet,
        Version::PubKey,
        &key.x_only(),
        &mut address,
    )
    .unwrap();
    let mut sig_hex = [0u8; 128];
    kassigner_fw::text::write_hex(signature.as_bytes(), &mut sig_hex);
    let mut out = vec![0u8; 4096];
    let m = kassigner_protocol::message::write(text, &address[..n], &sig_hex, &mut out).unwrap();
    out.truncate(m);
    out
}

/// A message the unit signs verifies in the app against its address's key
/// and the text and address expected; a changed text, another address, a
/// damaged signature or a text the unit refuses are each refused by name.
#[test]
fn a_signed_message_is_verified_by_the_app() {
    use kassigner_sdk::message::{self, MessageError};

    let text = b"Hello Kaspa!\nSigned on a unit.";
    let codes = message::codes(text, &P).expect("shown");
    assert!(codes.bare);
    assert_eq!(
        message::codes(b"tab\there", &P).err(),
        Some(MessageError::NotText)
    );
    assert_eq!(message::codes(b"", &P).err(), Some(MessageError::NotText));
    for text in [&b"Hello Kaspa! "[..], b"Hello \nKaspa!", b"Hello Kaspa!\n"] {
        assert_eq!(
            message::codes(text, &P).err(),
            Some(MessageError::TrailingWhitespace)
        );
    }
    let long = vec![b'x'; 300];
    assert_eq!(message::codes(&long, &P).unwrap().frames, 3);

    let w = wallet(ABANDON12);
    let record = unit_signs_message(text, &w);
    let v = message::verify(&record).expect("verifies");
    assert_eq!(v.key, w.signing_key(Path::receive(0)).unwrap().x_only());
    assert_eq!(&record[v.parts.text.clone()], text);
    let address = record[v.parts.address.clone()].to_vec();
    assert!(address.starts_with(b"kaspa:q"));
    message::verify_against(&record, text, &address).expect("the expected text and address");
    assert_eq!(
        message::verify_against(&record, b"Hello Kaspa!", &address).err(),
        Some(MessageError::OtherText)
    );
    let other = unit_signs_message(text, &wallet(ZOO12));
    let other_address = {
        let v = message::verify(&other).unwrap();
        other[v.parts.address.clone()].to_vec()
    };
    assert_eq!(
        message::verify_against(&record, text, &other_address).err(),
        Some(MessageError::OtherAddress)
    );
    assert!(matches!(
        kassigner_sdk::import::read(&record),
        Ok(kassigner_sdk::import::Import::SignedMessage(_))
    ));

    // The text changed under the signature.
    let mut changed = record.clone();
    changed[v.parts.text.start] ^= 0x01;
    assert_eq!(message::verify(&changed).err(), Some(MessageError::Fails));
    // A hex digit of the signature changed.
    let mut damaged = record.clone();
    let at = v.parts.signature.start;
    damaged[at] = if damaged[at] == b'0' { b'1' } else { b'0' };
    assert_eq!(message::verify(&damaged).err(), Some(MessageError::Fails));
    damaged[at] = b'g';
    assert_eq!(
        message::verify(&damaged).err(),
        Some(MessageError::NotARecord)
    );
    // Another unit's address on this record.
    let mut swapped = record[..v.parts.address.start].to_vec();
    swapped.extend_from_slice(&other_address);
    swapped.extend_from_slice(&record[v.parts.address.end..]);
    assert_eq!(message::verify(&swapped).err(), Some(MessageError::Fails));
    // A script-hash address has no key to check against.
    let mut p2sh = record[..v.parts.address.start].to_vec();
    p2sh.extend_from_slice(kcc3_address().text());
    p2sh.extend_from_slice(&record[v.parts.address.end..]);
    assert_eq!(
        message::verify(&p2sh).err(),
        Some(MessageError::NotAKeyAddress)
    );
    // The same key's testnet address: the signature holds, but the record
    // is refused, mainnet only.
    let mut elsewhere = [0u8; MAX_ADDRESS_LEN];
    let t = encode(Network::Testnet, Version::PubKey, &v.key, &mut elsewhere).unwrap();
    let mut testnet = record[..v.parts.address.start].to_vec();
    testnet.extend_from_slice(&elsewhere[..t]);
    testnet.extend_from_slice(&record[v.parts.address.end..]);
    assert_eq!(
        message::verify(&testnet).err(),
        Some(MessageError::NotMainnet(Network::Testnet))
    );
    assert_eq!(
        message::verify(b"hello").err(),
        Some(MessageError::NotARecord)
    );
}

// ── The host layer, which every binding wraps ───────────────────────────────

/// The host layer every binding wraps gives what the SDK gives:
/// `RequestBuilder` builds the same three requests, and the unit's replies,
/// the bundles and a signed record read, merge and finish through it as
/// through the SDK, every refusal by the SDK's name.
#[test]
fn the_host_layer_goes_the_whole_round() {
    use kassigner_sdk_host::bundle::{
        finalize_bundle, merge_bundles, prepare_bundle, read_bundle, Hints,
    };
    use kassigner_sdk_host::message::{verify_message, verify_message_against};
    use kassigner_sdk_host::reply::{finalize_reply, merge_replies, read_reply};
    use kassigner_sdk_host::request::{summary, Coin as GlueCoin, RequestBuilder};
    use kassigner_sdk_host::transport::{codes, Reader};
    use kassigner_sdk_host::watch::{
        Account as GlueAccount, Group as GlueGroup, Kcc3Address as GlueKcc3,
    };
    use kassigner_sdk_host::{hex, Fault, Profile as GlueProfile, Rates};

    let p = GlueProfile::esp32s3();
    let rates = Rates::mainnet();
    let a = GlueAccount::from_kpub(ABANDON12_KPUB44).unwrap();
    let g = GlueGroup::from_descriptor(&format!(
        "multi_hd45(2,{ABANDON12_KPUB45},{ABANDON24_KPUB45},{ZOO12_KPUB45})"
    ))
    .unwrap();
    let k = GlueKcc3::read(core::str::from_utf8(kcc3_address().text()).unwrap()).unwrap();
    let coin = |n: u8, amount: u64| GlueCoin::new(&hex(&[n; 32]), u32::from(n), amount).unwrap();
    let zoo = wallet(ZOO12);
    let to_zoo = kassigner_kaspa::script::pay_to_pubkey(
        &zoo.signing_key(Path::receive(0)).unwrap().x_only(),
    );

    let mut single = RequestBuilder::new();
    single.spend_account(&a, RECEIVE, 0, &coin(1, 3 * KAS));
    single.spend_account(&a, CHANGE, 3, &coin(2, 2 * KAS));
    single.pay_script(&to_zoo, 4 * KAS);
    single.change_to_account(&a, CHANGE, 4);
    let mut multisig = RequestBuilder::new();
    multisig.spend_group(&g, 0, RECEIVE, 0, &coin(3, 10 * KAS));
    multisig.pay_script(&a.script(RECEIVE, 1).unwrap(), 7 * KAS);
    multisig.change_to_group(&g, 0, CHANGE, 0);
    let mut sweep = RequestBuilder::new();
    sweep.spend_kcc3(&k, &coin(4, 5 * KAS), None, None).unwrap();
    sweep
        .spend_kcc3(&k, &coin(5, KAS / 2), Some(RECEIVE), Some(0))
        .unwrap();
    sweep.sweep_to(&a.address(RECEIVE, 0).unwrap()).unwrap();
    let built: Vec<Vec<u8>> = [&single, &multisig, &sweep]
        .iter()
        .map(|b| b.build(100, &rates, &p).unwrap().bytes)
        .collect();
    let sdk_built: Vec<Vec<u8>> = the_three_requests().into_iter().map(|(_, b)| b).collect();
    assert_eq!(built, sdk_built, "the builder builds what the SDK builds");

    // The 44' spend through the reader, signed, checked and finished as the
    // SDK does.
    let req = &built[0];
    let c = codes(req, "kspt", &p).unwrap();
    let mut reader = Reader::new(&p, 225);
    for i in 0..c.frames() {
        reader.take(&c.bytes(i).unwrap()).unwrap();
    }
    assert_eq!(reader.collect().unwrap(), *req);
    let (_, reply, _) = unit_signs(req, &wallet(ABANDON12));
    let checked = read_reply(req, &reply, &p).unwrap();
    assert_eq!(
        (checked.signatures, checked.present, checked.complete),
        (2, None, true)
    );
    assert_eq!(
        read_reply(&built[1], &reply, &p).unwrap_err(),
        Fault("NotTheRequest".to_string())
    );
    let s = summary(&reply, &p).unwrap();
    assert_eq!(s.signatures, 2);
    let f = finalize_reply(req, &reply, false, &rates, &p).unwrap();
    let theirs = app_finalizes(req, &reply).unwrap();
    assert_eq!(f.id, hex(&theirs.id));
    assert_eq!(f.submit_json, theirs.json);
    assert!(f.rest_json.contains(
        "\"outputs\":[{\"amount\":400000000,\"scriptPublicKey\":{\"version\":0,\"scriptPublicKey\":\"20"
    ));
    assert!(!f.rest_json.contains("\"mass\""));
    assert_eq!(
        (f.fee, f.storage_mass, f.compute_mass),
        (theirs.fee, theirs.storage, theirs.compute)
    );
    assert_eq!(
        f.unlocks,
        theirs.scripts.iter().map(|u| hex(u)).collect::<Vec<_>>()
    );
    assert!(finalize_reply(req, &reply, true, &rates, &p)
        .unwrap()
        .submit_json
        .ends_with("\"allowOrphan\":true}"));

    // The group's: one reply is incomplete, two merge and finish.
    let req = &built[1];
    let (_, first, _) = unit_signs(req, &wallet(ABANDON12));
    let (_, second, _) = unit_signs(req, &wallet(ZOO12));
    let checked = read_reply(req, &first, &p).unwrap();
    assert_eq!(
        (checked.present, checked.required, checked.complete),
        (Some(1), Some(2), false)
    );
    assert_eq!(
        finalize_reply(req, &first, false, &rates, &p).unwrap_err(),
        Fault("Signatures { input: 0, have: 1, need: 2 }".to_string())
    );
    let merged = merge_replies(req, &[&first, &second], &p).unwrap();
    assert_eq!(merged, app_merges(req, &[&first, &second]).unwrap());
    let checked = read_reply(req, &merged, &p).unwrap();
    assert_eq!((checked.present, checked.complete), (Some(2), true));
    assert!(merge_replies(req, &[&first, &first], &p)
        .unwrap_err()
        .0
        .starts_with("Merge(DuplicateSignature"));
    let f = finalize_reply(req, &merged, false, &rates, &p).unwrap();
    assert_eq!(f.submit_json, app_finalizes(req, &merged).unwrap().json);

    // The 22' sweep.
    let req = &built[2];
    let (_, reply, _) = unit_signs(req, &wallet(ABANDON12));
    assert!(read_reply(req, &reply, &p).unwrap().complete);
    let f = finalize_reply(req, &reply, false, &rates, &p).unwrap();
    assert_eq!(f.submit_json, app_finalizes(req, &reply).unwrap().json);

    // The group's bundle: prepared, two replies merged, finished as the SDK
    // does.
    let mut hints = Hints::new();
    hints.group(0, &g, 0, RECEIVE, 0, vec![]).unwrap();
    let prepared = prepare_bundle(PSKB_MULTISIG, &hints, &p).unwrap();
    let sdk_prepared = app_prepares(
        PSKB_MULTISIG,
        &[(
            0,
            bundle::Hint::Group {
                group: &group(),
                cosigner: 0,
                chain: RECEIVE,
                index: 0,
                fingerprints: &[],
            },
        )],
    )
    .unwrap()
    .1;
    assert_eq!(prepared.bytes, sdk_prepared);
    assert_eq!((prepared.inputs, prepared.signatures), (1, 2));
    let first = unit_signs_bundle(&prepared.bytes, &wallet(ABANDON12));
    let second = unit_signs_bundle(&prepared.bytes, &wallet(ZOO12));
    let checked = read_bundle(&prepared.bytes, &first, &p).unwrap();
    assert_eq!(
        (checked.present, checked.required, checked.complete),
        (Some(1), Some(2), false)
    );
    assert_eq!(
        finalize_bundle(&prepared.bytes, &first, false, &rates, &p).unwrap_err(),
        Fault("Finish(Signatures { input: 0, have: 1, need: 2 })".to_string())
    );
    let merged = merge_bundles(&prepared.bytes, &[&first, &second], &p).unwrap();
    assert_eq!(
        merged,
        app_merges_bundles(&prepared.bytes, &[&first, &second]).unwrap()
    );
    assert!(read_bundle(&prepared.bytes, &merged, &p).unwrap().complete);
    let f = finalize_bundle(&prepared.bytes, &merged, false, &rates, &p).unwrap();
    assert_eq!(
        f.submit_json,
        app_finalizes_bundle(&prepared.bytes, &merged).unwrap().json
    );
    assert_eq!(
        read_bundle(PSKB_SEND, &merged, &p).unwrap_err(),
        Fault("NotTheRequest".to_string())
    );

    // A signed record.
    let w = wallet(ABANDON12);
    let record = unit_signs_message(b"login", &w);
    let v = verify_message(&record).unwrap();
    assert_eq!(
        v.key,
        hex(&w.signing_key(Path::receive(0)).unwrap().x_only())
    );
    assert_eq!(v.record.text, "login");
    let address = v.record.address.clone();
    assert!(address.starts_with("kaspa:q"));
    verify_message_against(&record, "login", &address).unwrap();
    assert_eq!(
        verify_message_against(&record, "logout", &address).unwrap_err(),
        Fault("OtherText".to_string())
    );
    let i = kassigner_sdk_host::watch::read_import(&record).unwrap();
    assert_eq!(i.kind, "signedMessage");
    assert_eq!(i.signed_message.unwrap().address, address);
}

// ── Time-Locked Savings cards ───────────────────────────────────────────────

/// A key's mainnet address.
fn key_address(key: &[u8; 32]) -> String {
    let mut out = [0u8; MAX_ADDRESS_LEN];
    let n = encode(Network::Mainnet, Version::PubKey, key, &mut out).unwrap();
    String::from_utf8(out[..n].to_vec()).unwrap()
}

/// The bench's card: abandon 12's receive 0 the owner, zoo 12's receive 0
/// the recovery wallet, unlocking on 01/01/2027.
fn bench_card() -> Savings {
    let owner = key_address(&account().public_key(RECEIVE, 0).unwrap());
    let recovery = key_address(
        &wallet(ZOO12)
            .signing_key(Path::receive(0))
            .unwrap()
            .x_only(),
    );
    card::savings(
        owner.as_bytes(),
        Some(recovery.as_bytes()),
        1,
        1,
        2027,
        0,
        0,
    )
    .unwrap()
}

/// Two UTXOs of `savings`: coin 1 of 5 KAS, its key named as `named` says,
/// and coin 2 of 3 KAS, its key not named.
fn card_coins<'a>(savings: &'a Savings, named: Option<(&'a Account, u32)>) -> [Coin<'a>; 2] {
    [
        Coin {
            outpoint: outpoint(1),
            amount: 5 * KAS,
            covenant_id: None,
            source: Source::Card {
                card: savings,
                signer: named,
            },
        },
        Coin {
            outpoint: outpoint(2),
            amount: 3 * KAS,
            covenant_id: None,
            source: Source::Card {
                card: savings,
                signer: None,
            },
        },
    ]
}

/// zoo 12's receive 1, which a card's claim sweeps to.
fn zoo_receive_1() -> [u8; 34] {
    kassigner_kaspa::script::pay_to_pubkey(
        &wallet(ZOO12)
            .signing_key(Path::receive(1))
            .unwrap()
            .x_only(),
    )
}

/// The claim of [`bench_card`]'s two UTXOs, swept to [`zoo_receive_1`] on
/// the card's day, as a KSPT and as a bundle, abandon 12's key named.
fn card_requests() -> ((Request, Vec<u8>), (Request, Vec<u8>)) {
    let savings = bench_card();
    let a = account();
    let coins = card_coins(&savings, Some((&a, 0)));
    let to = zoo_receive_1();
    let pay = Payment::Sweep {
        to: &to,
        own: Change::None,
    };
    let day = savings.unlock().ms();
    let kspt = request_locked(&coins, pay, day).expect("built");
    let bundle = bundle_request_with(&coins, &details_of(&coins), pay, day).expect("built");
    (kspt, bundle)
}

/// A card made from its keys' addresses and an unlock time to the minute
/// backs up and reads back, and an account finds its key in it as owner (a
/// claim) or recovery wallet. An address that is not a mainnet Schnorr
/// key's, or an impossible day or time, makes no card.
#[test]
fn a_card_is_made_backed_up_and_found_in_an_account() {
    let savings = bench_card();
    let a = account();
    let mut text = [0u8; MAX_ADDRESS_LEN];
    let n = card::address(&savings, &mut text).unwrap();
    assert!(text[..n].starts_with(b"kaspa:p"), "a script's address");
    let mut line = [0u8; card::BACKUP_MAX_LEN];
    let n = card::backup(&savings, &mut line).unwrap();
    assert!(line[..n].starts_with(b"savings_v1(kaspa:q"));
    assert!(line[..n].ends_with(b")"));
    assert_eq!(card::read_backup(&line[..n]), Ok(savings));
    assert_eq!(card::signer(&a, &savings, 20), Ok(Some((0, Entry::Claim))));

    // abandon 12's receive 7 as another card's recovery wallet.
    let owner = key_address(
        &wallet(ZOO12)
            .signing_key(Path::receive(0))
            .unwrap()
            .x_only(),
    );
    let seventh = key_address(&a.public_key(RECEIVE, 7).unwrap());
    let theirs = card::savings(
        owner.as_bytes(),
        Some(seventh.as_bytes()),
        31,
        12,
        2026,
        23,
        59,
    )
    .unwrap();
    assert_eq!(theirs.unlock().time(), (23, 59));
    assert_eq!(card::signer(&a, &theirs, 20), Ok(Some((7, Entry::Recover))));
    assert_eq!(
        card::signer(&a, &theirs, 7),
        Ok(None),
        "not in the first seven"
    );
    let alone = card::savings(owner.as_bytes(), None, 1, 1, 2027, 0, 0).unwrap();
    assert_eq!(card::signer(&a, &alone, 20), Ok(None));
    // Both keys the account's: the owner's, a claim, wherever it lies.
    let third = key_address(&a.public_key(RECEIVE, 3).unwrap());
    let first = key_address(&a.public_key(RECEIVE, 1).unwrap());
    let both = card::savings(third.as_bytes(), Some(first.as_bytes()), 1, 1, 2027, 0, 0).unwrap();
    assert_eq!(card::signer(&a, &both, 20), Ok(Some((3, Entry::Claim))));

    let mut p2sh = [0u8; MAX_ADDRESS_LEN];
    let n = card::address(&alone, &mut p2sh).unwrap();
    assert_eq!(
        card::savings(&p2sh[..n], None, 1, 1, 2027, 0, 0),
        Err(card::MakeError::Owner(card::KeyError::NotAKey))
    );
    let mut testnet = [0u8; MAX_ADDRESS_LEN];
    let zoo = wallet(ZOO12)
        .signing_key(Path::receive(0))
        .unwrap()
        .x_only();
    let n = encode(Network::Testnet, Version::PubKey, &zoo, &mut testnet).unwrap();
    assert_eq!(
        card::savings(owner.as_bytes(), Some(&testnet[..n]), 1, 1, 2027, 0, 0),
        Err(card::MakeError::Recovery(card::KeyError::NotMainnet(
            Network::Testnet
        )))
    );
    assert_eq!(
        card::savings(owner.as_bytes(), None, 29, 2, 2027, 0, 0),
        Err(card::MakeError::Date),
        "no 29 February in 2027"
    );
    for (hour, minute) in [(24, 0), (0, 60)] {
        assert_eq!(
            card::savings(owner.as_bytes(), None, 1, 1, 2027, hour, minute),
            Err(card::MakeError::Date),
            "{hour}:{minute}"
        );
    }
}

/// A card's claim (abandon 12) and recovery (zoo 12) go through the unit as
/// a KSPT and a bundle under the card's day as lock time, and the app
/// finishes each to the card's claim or recover script.
#[test]
fn a_card_claim_and_recovery_go_through_the_unit() {
    let savings = bench_card();
    let ((r, kspt), (rb, bundle)) = card_requests();
    assert_eq!((r.signatures, r.change), (2, None));
    assert_eq!((rb.fee, rb.mass), (r.fee, r.mass));
    let k = kspt::parse(&kspt, &P).unwrap();
    assert_eq!((k.tx_version, k.lock_time), (0, savings.unlock().ms()));
    for input in k.inputs() {
        assert_eq!(input.redeem, &savings.program()[..]);
        assert_eq!((input.sequence, input.sig_op_count), (0, 1));
    }
    assert!(records(&kspt).is_empty(), "the owner's key is in the bank");
    let doc = String::from_utf8(unwrap(&bundle)).unwrap();
    let program = hex(&savings.program());
    assert_eq!(
        doc.matches(&format!("\"redeemScript\":\"{program}\""))
            .count(),
        2
    );
    assert_eq!(doc.matches("\"sequence\":0,").count(), 2);
    assert_eq!(
        doc.matches(&format!("\"minTime\":{},", savings.unlock().ms()))
            .count(),
        2
    );
    assert_eq!(
        doc.matches("m/44'/111111'/0'/0/0").count(),
        1,
        "coin 1's key"
    );

    for (seed, entry, second) in [(ABANDON12, Entry::Claim, 0), (ZOO12, Entry::Recover, 0b11)] {
        let w = wallet(seed);
        let (plan, reply, verified) = unit_signs(&kspt, &w);
        assert_eq!((plan.signatures, plan.inputs, plan.second), (2, 2, second));
        assert_eq!(verified, 2);
        let f = app_finalizes(&kspt, &reply).expect("finished");
        assert!(f.compute <= r.mass, "the estimate covers the compute mass");
        assert_eq!(f.fee, r.fee);
        let rep = kspt::parse(&reply, &P).unwrap();
        for (script, input) in f.scripts.iter().zip(rep.inputs()) {
            let s = input.signatures().next().unwrap();
            let mut sig = [0u8; card::SIG_LEN];
            sig[..64].copy_from_slice(s.bytes);
            sig[64] = s.sighash_type;
            assert_eq!(script[..], savings.signature_script(entry, &sig)[..]);
        }
        let fb = app_finalizes_bundle(&bundle, &unit_signs_bundle(&bundle, &w)).expect("finished");
        assert_eq!((fb.id, fb.fee, &fb.scripts), (f.id, f.fee, &f.scripts));
    }
    // Both keys' replies merged: the owner's signature is the one spent, a
    // claim.
    let (_, owners, _) = unit_signs(&kspt, &wallet(ABANDON12));
    let (_, recoverys, _) = unit_signs(&kspt, &wallet(ZOO12));
    let merged = app_merges(&kspt, &[&recoverys, &owners]).expect("merged");
    let claimed = app_finalizes(&kspt, &owners).unwrap();
    assert_eq!(
        app_finalizes(&kspt, &merged).unwrap().scripts,
        claimed.scripts
    );
}

/// The SDK refuses a card spend the unit would: a lock time before the
/// card's day or none, a named key that is not the card's or is at a
/// hardened index, the safe JSON (which cannot carry the program), and a
/// bundle whose card input states no sequence (read as final) or a
/// relative one.
#[test]
fn the_sdk_refuses_a_card_spend_the_unit_would() {
    let savings = bench_card();
    let a = account();
    let to = zoo_receive_1();
    let pay = Payment::Sweep {
        to: &to,
        own: Change::None,
    };
    let day = savings.unlock().ms();
    let coins = card_coins(&savings, None);
    for lock_time in [day - 1, 0, 400_000_000] {
        assert_eq!(
            request_locked(&coins, pay, lock_time).err(),
            Some(RequestError::CardLocked { coin: 0 }),
            "{lock_time}"
        );
    }
    assert!(request_locked(&coins, pay, day + 1).is_ok());
    let wrong = card_coins(&savings, Some((&a, 3)));
    assert_eq!(
        request_locked(&wrong, pay, day).err(),
        Some(RequestError::NotTheCardsKey { coin: 0 })
    );
    // abandon 12's receive 7 named as another card's recovery wallet: its
    // key, so the request is built.
    let owner = key_address(
        &wallet(ZOO12)
            .signing_key(Path::receive(0))
            .unwrap()
            .x_only(),
    );
    let seventh = key_address(&a.public_key(RECEIVE, 7).unwrap());
    let theirs =
        card::savings(owner.as_bytes(), Some(seventh.as_bytes()), 1, 1, 2027, 0, 0).unwrap();
    assert!(request_locked(&card_coins(&theirs, Some((&a, 7))), pay, day).is_ok());
    let hardened = card_coins(&savings, Some((&a, 0x8000_0000)));
    assert_eq!(
        request_locked(&hardened, pay, day).err(),
        Some(RequestError::BadHint { coin: 0 })
    );
    assert_eq!(
        safe_request_with(&coins, &details_of(&coins), pay, day).err(),
        Some(RequestError::CardInSafeJson { coin: 0 })
    );
    let (_, (_, bundle)) = card_requests();
    let doc = String::from_utf8(unwrap(&bundle)).unwrap();
    let unstated = envelope(
        doc.replacen("\"sequence\":0,", "\"sequence\":null,", 1)
            .as_bytes(),
    );
    assert_eq!(
        app_prepares(&unstated, &[]).err(),
        Some(BundleError::Check(
            kassigner_protocol::check::Error::CardFinal { input: 0 }
        ))
    );
    let relative = envelope(
        doc.replacen("\"sequence\":0,", "\"sequence\":5,", 1)
            .as_bytes(),
    );
    assert_eq!(
        app_prepares(&relative, &[]).err(),
        Some(BundleError::Check(
            kassigner_protocol::check::Error::Sequence { input: 0 }
        ))
    );
    assert!(app_prepares(&bundle, &[]).is_ok());
}

// ── The SDK's vectors ───────────────────────────────────────────────────────

/// Where the SDK's vectors live: what the SDK built and the unit answered,
/// for the tests of the layers that cannot sign (`kassigner-sdk-host`,
/// the bindings' checks).
const VECTORS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../spec/vectors/v110/sdk/");

/// The committed vectors in `spec/vectors/v110/sdk/` are, byte for byte,
/// what the SDK builds and the unit signs now, the unit's aux randomness
/// being fixed; `KASSIGNER_SDK_VECTORS=write` writes them instead.
#[test]
fn the_sdk_vectors_are_current() {
    let write = std::env::var("KASSIGNER_SDK_VECTORS").as_deref() == Ok("write");
    let mut files: Vec<(String, Vec<u8>)> = Vec::new();
    let names = ["single", "multisig", "sweep"];
    for ((_, request), name) in the_three_requests().into_iter().zip(names) {
        let (_, abandon, _) = unit_signs(&request, &wallet(ABANDON12));
        files.push((format!("{name}.request"), request.clone()));
        files.push((format!("{name}.reply.abandon12"), abandon));
        if name == "multisig" {
            let (_, zoo, _) = unit_signs(&request, &wallet(ZOO12));
            files.push(("multisig.reply.zoo12".into(), zoo));
        }
    }
    let a = account();
    let g = group();
    let doc = String::from_utf8(unwrap(PSKB_SEND)).unwrap();
    let paid = envelope(
        doc.replace("\"amount\":399000000", "\"amount\":390000000")
            .as_bytes(),
    );
    let (_, send) = app_prepares(
        &paid,
        &[(
            0,
            bundle::Hint::Account {
                account: &a,
                chain: RECEIVE,
                index: 0,
                fingerprint: [0x73, 0xc5, 0xda, 0x0a],
            },
        )],
    )
    .unwrap();
    files.push((
        "pskb_send.reply.abandon12".into(),
        unit_signs_bundle(&send, &wallet(ABANDON12)),
    ));
    files.push(("pskb_send.request".into(), send));
    let (_, multi) = app_prepares(
        PSKB_MULTISIG,
        &[(
            0,
            bundle::Hint::Group {
                group: &g,
                cosigner: 0,
                chain: RECEIVE,
                index: 0,
                fingerprints: &[],
            },
        )],
    )
    .unwrap();
    files.push((
        "pskb_multisig.reply.abandon12".into(),
        unit_signs_bundle(&multi, &wallet(ABANDON12)),
    ));
    files.push((
        "pskb_multisig.reply.zoo12".into(),
        unit_signs_bundle(&multi, &wallet(ZOO12)),
    ));
    files.push(("pskb_multisig.request".into(), multi));
    let [single, multisig, _] = the_three(bundle_request);
    let single = single.expect("built as a bundle").1;
    files.push((
        "single.bundle.reply.abandon12".into(),
        unit_signs_bundle(&single, &wallet(ABANDON12)),
    ));
    files.push(("single.bundle".into(), single));
    let multisig = multisig.expect("built as a bundle").1;
    files.push((
        "multisig.bundle.reply.abandon12".into(),
        unit_signs_bundle(&multisig, &wallet(ABANDON12)),
    ));
    files.push((
        "multisig.bundle.reply.zoo12".into(),
        unit_signs_bundle(&multisig, &wallet(ZOO12)),
    ));
    files.push(("multisig.bundle".into(), multisig));
    let [single, multisig, _] = the_three(safe_request);
    let single = single.expect("built as safe JSON").1;
    let kspt_file = |name: &str| &files.iter().find(|(n, _)| n == name).unwrap().1;
    let scripts = app_finalizes(
        kspt_file("single.request"),
        kspt_file("single.reply.abandon12"),
    )
    .unwrap()
    .scripts;
    files.push((
        "single.safe.signed.json".into(),
        wallet_signs_safe_json(&single, &scripts),
    ));
    files.push(("single.safe.json".into(), single));
    let multisig = multisig.expect("built as safe JSON").1;
    let kspt_multisig = |name: &str| {
        files
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, b)| b.clone())
            .unwrap()
    };
    let merged = app_merges(
        &kspt_multisig("multisig.request"),
        &[
            &kspt_multisig("multisig.reply.abandon12"),
            &kspt_multisig("multisig.reply.zoo12"),
        ],
    )
    .unwrap();
    let scripts = app_finalizes(&kspt_multisig("multisig.request"), &merged)
        .unwrap()
        .scripts;
    files.push((
        "multisig.safe.signed.json".into(),
        wallet_signs_safe_json(&multisig, &scripts),
    ));
    files.push(("multisig.safe.json".into(), multisig));
    files.push((
        "message.record".into(),
        unit_signs_message(b"kassigner.org login", &wallet(ABANDON12)),
    ));
    let savings = bench_card();
    let mut line = [0u8; card::BACKUP_MAX_LEN];
    let n = card::backup(&savings, &mut line).unwrap();
    files.push(("savings.backup".into(), line[..n].to_vec()));
    let ((_, kspt), (_, bundle)) = card_requests();
    for (seed, name, entry) in [
        (ABANDON12, "abandon12", "claim"),
        (ZOO12, "zoo12", "recover"),
    ] {
        let w = wallet(seed);
        let (_, reply, _) = unit_signs(&kspt, &w);
        let f = app_finalizes(&kspt, &reply).unwrap();
        files.push((
            format!("savings.{entry}.signed.json"),
            f.signed.into_bytes(),
        ));
        files.push((format!("savings.reply.{name}"), reply));
        files.push((
            format!("savings.bundle.reply.{name}"),
            unit_signs_bundle(&bundle, &w),
        ));
    }
    files.push(("savings.request".into(), kspt));
    files.push(("savings.bundle".into(), bundle));
    // The covenant requests, version 1: each with the unit's reply and the
    // finished transaction in the safe JSON, its coins' entries as the
    // request's, for the engine.
    let w = wallet(ABANDON12);
    let safe = covenant_requests(|c, p| safe_request(c, p).expect("safe JSON").1);
    let kspts = covenant_requests(|c, p| request(c, p).expect("built").1);
    for ((name, kspt), safe) in ["start", "continue"].into_iter().zip(kspts).zip(safe) {
        let (_, reply, _) = unit_signs(&kspt, &w);
        let f = app_finalizes(&kspt, &reply).unwrap();
        files.push((
            format!("covenant.{name}.signed.json"),
            wallet_signs_safe_json(&safe, &f.scripts),
        ));
        files.push((format!("covenant.{name}.reply.abandon12"), reply));
        files.push((format!("covenant.{name}.request"), kspt));
    }
    let [(_, kspt), _] = group_covenant_requests();
    let (_, abandon, _) = unit_signs(&kspt, &w);
    let (_, both, _) = unit_signs(&abandon, &wallet(ZOO12));
    let f = app_finalizes(&kspt, &both).unwrap();
    files.push(("covenant.group.signed.json".into(), f.signed.into_bytes()));
    files.push(("covenant.group.reply.abandon12".into(), abandon));
    files.push(("covenant.group.reply.both".into(), both));
    files.push(("covenant.group.request".into(), kspt));
    for (name, _, kspt, seed) in other_covenant_requests() {
        let (_, reply, _) = unit_signs(&kspt, &wallet(seed));
        let f = app_finalizes(&kspt, &reply).unwrap();
        files.push((
            format!("covenant.{name}.signed.json"),
            f.signed.into_bytes(),
        ));
    }

    for (name, bytes) in &files {
        let path = format!("{VECTORS}{name}");
        if write {
            std::fs::create_dir_all(VECTORS).unwrap();
            std::fs::write(&path, bytes).expect("vector written");
        } else {
            let committed = std::fs::read(&path).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(
                &committed, bytes,
                "{name} differs from the committed vector"
            );
        }
    }
}
