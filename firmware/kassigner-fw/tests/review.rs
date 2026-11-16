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

//! Reviewing a transaction: pure logic with no display, touch or board, so the
//! rule is checked exactly.

use kassigner_fw::review::{Error, Page, Review, MAX_PAGES};
use kassigner_kaspa::constants::SOMPI_PER_KASPA as KAS;
use kassigner_kaspa::tx::{
    CovenantBinding, Outpoint, ScriptPublicKey, TransactionInput, TransactionOutput, UtxoEntry,
};

#[path = "../../../testkit/transaction.rs"]
pub mod transaction;
use transaction::tx;

const SPK: &[u8] = &[0x20u8; 34];

fn output(value: u64, covenant: Option<CovenantBinding>) -> TransactionOutput<'static> {
    TransactionOutput {
        value,
        script_public_key: ScriptPublicKey {
            version: 0,
            script: SPK,
        },
        covenant,
    }
}

/// An input spending `amount`, carried in its UTXO, so the review takes the fee
/// from the transaction and it cannot be passed wrongly.
fn input(amount: u64) -> TransactionInput<'static> {
    TransactionInput {
        previous_outpoint: Outpoint {
            transaction_id: [0u8; 32],
            index: 0,
        },
        sequence: 0,
        sig_op_count: 1,
        compute_budget: 0,
        signature_script: &[],
        utxo_entry: UtxoEntry {
            amount,
            script_public_key: ScriptPublicKey {
                version: 0,
                script: SPK,
            },
        },
    }
}

/// Confirming is refused until every page has been seen: the rule the
/// module exists for.
#[test]
fn confirming_needs_every_page() {
    let ins = [input(3_500 * KAS)];
    let outs = [output(1_000 * KAS, None), output(2_000 * KAS, None)];
    let t = tx(&ins, &outs);

    let mut r = Review::new(&t).expect("review");
    assert!(!r.may_confirm(), "nothing has been shown yet");

    // Step through everything except the last page.
    while r.remaining() > 1 {
        let i = r.next_unseen().expect("more to show");
        r.mark_seen(i).expect("mark");
        assert!(!r.may_confirm(), "one page still unshown");
    }

    let last = r.next_unseen().expect("one left");
    r.mark_seen(last).expect("mark");
    assert!(r.may_confirm(), "and now every page has been shown");
}

/// Every covenant the transaction touches gets one page, and every binding
/// is on one: the signature hash commits to each. A binding continues the
/// covenant its authorizing input's UTXO is bound to; any other id starts
/// one (upstream's `CovenantsContext::from_tx`). The pages come after the
/// outputs and the lock time: first the covenants the inputs' UTXOs are bound
/// to, in the inputs' order, then those that start here, in the outputs'.
#[test]
fn every_covenant_gets_its_own_page() {
    const A: [u8; 32] = [0xA1; 32];
    const B: [u8; 32] = [0xB2; 32];
    const C: [u8; 32] = [0xC3; 32];
    const D: [u8; 32] = [0xD4; 32];
    let bound = |authorizing_input: u16, covenant_id: [u8; 32]| {
        output(
            1_000 * KAS,
            Some(CovenantBinding {
                authorizing_input,
                covenant_id,
            }),
        )
    };
    fn covenants<'a>(r: &Review<'a>) -> Vec<(usize, Page<'a>)> {
        (0..r.len())
            .map(|i| (i, r.page(i).unwrap()))
            .filter(|(_, p)| matches!(p, Page::Covenant { .. }))
            .collect()
    }

    // Inputs 0 and 1 spend UTXOs bound to A, input 2 one bound to D, input
    // 3 an unbound one.
    let ins = [
        input(2_000 * KAS),
        input(2_000 * KAS),
        input(2_000 * KAS),
        input(2_000 * KAS),
    ];
    let coins = [Some(A), Some(A), Some(D), None];
    let outs = [
        bound(0, A),               // continues A
        bound(3, B),               // starts B
        output(1_000 * KAS, None), // no covenant
        bound(1, A),               // continues A
        bound(3, B),               // B again, the same input: the same page
        bound(0, C),               // starts C: input 0's UTXO is bound to A
        bound(2, B),               // B from another input: its own page
    ];
    let mut t = tx(&ins, &outs);
    t.lock_time = 500_000_000_000;
    let r = Review::with_coins(&t, |_| None, &coins).expect("review");

    let found = covenants(&r);
    let pages: Vec<Page<'_>> = found.iter().map(|(_, p)| *p).collect();
    assert_eq!(
        pages,
        [
            Page::Covenant {
                id: A,
                outputs: 0b000_1001,
                spent: 2,
                from: None,
            },
            // Nothing continues D: it ends here.
            Page::Covenant {
                id: D,
                outputs: 0,
                spent: 1,
                from: None,
            },
            Page::Covenant {
                id: B,
                outputs: 0b001_0010,
                spent: 0,
                from: Some(3),
            },
            Page::Covenant {
                id: C,
                outputs: 0b010_0000,
                spent: 0,
                from: Some(0),
            },
            Page::Covenant {
                id: B,
                outputs: 0b100_0000,
                spent: 0,
                from: Some(2),
            },
        ]
    );
    // Every bound output is on exactly one page.
    let shown = pages.iter().fold(0u32, |all, p| match p {
        Page::Covenant { outputs, .. } => {
            assert_eq!(all & outputs, 0, "an output on two pages");
            all | outputs
        }
        _ => all,
    });
    assert_eq!(shown, 0b111_1011);
    // After the outputs and the lock time, the last pages of all.
    let lock = (0..r.len())
        .find(|&i| matches!(r.page(i).unwrap(), Page::LockTime { .. }))
        .expect("the lock time's page");
    assert_eq!(found[0].0, lock + 1);
    assert_eq!(found[4].0, r.len() - 1);

    // With the UTXOs' covenants not given, every UTXO counts as unbound and
    // every binding starts a covenant.
    let r = Review::new(&t).expect("review");
    let pages: Vec<Page<'_>> = covenants(&r).iter().map(|(_, p)| *p).collect();
    assert_eq!(pages.len(), 5);
    assert_eq!(
        pages[0],
        Page::Covenant {
            id: A,
            outputs: 0b1,
            spent: 0,
            from: Some(0),
        }
    );
    assert!(pages.iter().all(|p| matches!(
        p,
        Page::Covenant {
            spent: 0,
            from: Some(_),
            ..
        }
    )));

    // No binding and no bound UTXO: no covenant page.
    let plain = [output(1_000 * KAS, None)];
    let r = Review::with_coins(&tx(&ins[..1], &plain), |_| None, &[None]).expect("review");
    assert!(covenants(&r).is_empty());
}

/// The summary states the right fee outright, not inside an output page: an
/// inflated fee is the classic way to take value from a transaction whose
/// outputs look correct.
#[test]
fn the_fee_is_shown_and_is_correct() {
    let ins = [input(100_000 * KAS)];
    let outs = [output(70_000 * KAS, None), output(25_000 * KAS, None)];
    let t = tx(&ins, &outs);

    let r = Review::new(&t).expect("review");
    match r.page(0).expect("summary") {
        Page::Summary {
            spending,
            receiving,
            fee,
            inputs,
            outputs,
        } => {
            assert_eq!(inputs, 1);
            assert_eq!(outputs, 2);
            assert_eq!(spending, 100_000 * KAS);
            assert_eq!(receiving, 95_000 * KAS);
            assert_eq!(fee, 5_000 * KAS);
        }
        other => panic!("the first page should be the summary, got {other:?}"),
    }
}

/// Outputs worth more than the inputs are refused, not shown: a negative fee
/// drawn as a huge positive one is the display bug that gets something signed.
#[test]
fn a_transaction_that_cannot_have_a_fee_is_refused() {
    let ins = [input(100_000)];
    let outs = [output(200_000, None)];
    let t = tx(&ins, &outs);

    assert_eq!(Review::new(&t).err(), Some(Error::ValueOverflow));

    // Output values that overflow on their own: caught before the fee
    // subtraction, not wrapped into a plausible one.
    let big_ins = [input(u64::MAX)];
    let huge = [output(u64::MAX, None), output(2, None)];
    let t2 = tx(&big_ins, &huge);
    assert_eq!(Review::new(&t2).err(), Some(Error::ValueOverflow));

    // Inputs that overflow each other too.
    let two_max = [input(u64::MAX), input(1)];
    let one = [output(1, None)];
    let t3 = tx(&two_max, &one);
    assert_eq!(Review::new(&t3).err(), Some(Error::ValueOverflow));
}

/// A storage mass over the block limit is refused, not paged: a node's
/// mempool refuses the transaction (upstream's
/// `validate_transaction_limits_in_context`, `RejectStorageMass`), so there is
/// nothing to ask a person to confirm. KIP-9: the mass grows as an output's
/// value shrinks.
#[test]
fn a_storage_mass_over_the_block_limit_is_refused() {
    use kassigner_kaspa::mass::BLOCK_STORAGE_MASS_LIMIT;

    // One KAS in; half a KAS and a thousand sompi out. The outputs weigh
    // 10^12 / 50,000,000 + 10^12 / 1,000 grams and the input takes off
    // 10^12 / 100,000,000.
    let ins = [input(KAS)];
    let outs = [output(KAS / 2, None), output(1_000, None)];
    assert_eq!(
        Review::new(&tx(&ins, &outs)).err(),
        Some(Error::StorageMass {
            mass: 1_000_010_000
        })
    );

    // The limit itself is let through and one gram more is not. An input
    // large enough to take nothing off leaves the output's own weight:
    // 10^12 / 2,000,000 is the limit, 10^12 / 1,999,996 one gram over.
    assert_eq!(BLOCK_STORAGE_MASS_LIMIT, 500_000);
    let ins = [input(100_000 * KAS)];
    assert!(Review::new(&tx(&ins, &[output(2_000_000, None)])).is_ok());
    assert_eq!(
        Review::new(&tx(&ins, &[output(1_999_996, None)])).err(),
        Some(Error::StorageMass { mass: 500_001 })
    );
}

/// A coin bound to a covenant is counted as a node counts it: 32 bytes more
/// of storage, here two storage units for one (upstream's `utxo_plurality`),
/// so it takes four times as much off the outputs' weight. The same
/// transaction is over the limit spending an unbound coin and under it
/// spending a bound one.
#[test]
fn a_coin_bound_to_a_covenant_frees_more_storage() {
    let ins = [input(100_000)];
    let outs = [output(90_000, None)];
    let t = tx(&ins, &outs);

    // Unbound: 10^12 / 90,000 less 10^12 / 100,000.
    assert_eq!(
        Review::new(&t).err(),
        Some(Error::StorageMass { mass: 1_111_111 })
    );
    assert_eq!(
        Review::with_coins(&t, |_| None, &[None]).err(),
        Some(Error::StorageMass { mass: 1_111_111 })
    );
    // Bound: four times the relief, more than the output weighs.
    assert!(Review::with_coins(&t, |_| None, &[Some([7; 32])]).is_ok());
}

/// A zero fee is legal and shown as zero.
#[test]
fn a_zero_fee_is_not_an_error() {
    let ins = [input(1_000)];
    let outs = [output(1_000, None)];
    let t = tx(&ins, &outs);

    let r = Review::new(&t).expect("review");
    assert!(matches!(r.page(0), Ok(Page::Summary { fee: 0, .. })));
}

/// Marking a page twice changes nothing: redrawing a page already shown must
/// not satisfy the rule for one that was not.
#[test]
fn marking_twice_does_not_count_twice() {
    let ins = [input(100 * KAS)];
    let outs = [output(10 * KAS, None), output(20 * KAS, None)];
    let t = tx(&ins, &outs);

    let mut r = Review::new(&t).expect("review");
    let total = r.len();
    assert_eq!(total, 3, "summary plus two outputs");

    for _ in 0..10 {
        r.mark_seen(0).expect("mark");
    }
    assert_eq!(r.remaining(), total - 1, "still two to go");
    assert!(!r.may_confirm());
}

/// A page index past the end is refused, to read and to mark: marking a page
/// that does not exist could satisfy the rule without showing anything.
#[test]
fn a_page_that_does_not_exist_cannot_be_marked() {
    let ins = [input(100 * KAS)];
    let outs = [output(10 * KAS, None)];
    let t = tx(&ins, &outs);

    let mut r = Review::new(&t).expect("review");
    let past = r.len();

    assert_eq!(r.page(past).err(), Some(Error::NoSuchPage { index: past }));
    assert_eq!(
        r.mark_seen(past).err(),
        Some(Error::NoSuchPage { index: past })
    );
    assert_eq!(
        r.mark_seen(999).err(),
        Some(Error::NoSuchPage { index: 999 })
    );

    assert!(!r.may_confirm(), "and none of that satisfied the rule");
}

/// Too many pages are refused, not truncated: a dropped page would be signed
/// and not shown.
#[test]
fn too_many_pages_is_refused_rather_than_truncated() {
    let ins = [input(1_000 * KAS)];
    // Eight outputs each with a binding: summary + 8 + 8 = 17, which fits.
    // With a lock time and a payload it would be 19, still inside MAX_PAGES.
    let fits: Vec<TransactionOutput> = (0..8u8)
        .map(|i| {
            output(
                KAS,
                Some(CovenantBinding {
                    authorizing_input: 0,
                    covenant_id: [i; 32],
                }),
            )
        })
        .collect();
    let t = tx(&ins, &fits);
    let r = Review::new(&t).expect("seventeen pages fit");
    assert_eq!(r.len(), 17);
    assert!(r.len() <= MAX_PAGES);

    // The widest transaction the profile allows: every output covenanted, a
    // lock time and a payload.
    let mut widest = tx(&ins, &fits);
    widest.lock_time = 1;
    widest.payload = &[0xAB];
    let r = Review::new(&widest).expect("the widest transaction still fits");
    assert_eq!(r.len(), 19);
    assert_eq!(MAX_PAGES, 20, "the widest transaction fits");

    // Ten outputs, each covenanted, tips it over. Nine is 1 + 9 + 9 = 19, which
    // the profile would not allow anyway but the review still holds.
    let over: Vec<TransactionOutput> = (0..10u8)
        .map(|i| {
            output(
                KAS,
                Some(CovenantBinding {
                    authorizing_input: 0,
                    covenant_id: [i; 32],
                }),
            )
        })
        .collect();
    let t2 = tx(&ins, &over);
    assert_eq!(
        Review::new(&t2).err(),
        Some(Error::TooManyPages { needed: 21 })
    );
}

/// Stepping through pages reaches every one exactly once.
#[test]
fn stepping_reaches_every_page() {
    let ins = [input(100 * KAS)];
    let outs = [
        output(
            KAS,
            Some(CovenantBinding {
                authorizing_input: 3,
                covenant_id: [7; 32],
            }),
        ),
        output(2 * KAS, None),
        output(
            3 * KAS,
            Some(CovenantBinding {
                authorizing_input: 0,
                covenant_id: [9; 32],
            }),
        ),
    ];
    let t = tx(&ins, &outs);

    let mut r = Review::new(&t).expect("review");
    let expected = r.len();
    assert_eq!(expected, 6, "summary + 3 outputs + 2 covenants");

    let mut visited = Vec::new();
    while let Some(i) = r.next_unseen() {
        assert!(!visited.contains(&i), "page {i} came round twice");
        visited.push(i);
        r.page(i).expect("every index it hands out is readable");
        r.mark_seen(i).expect("mark");
    }

    assert_eq!(visited.len(), expected);
    assert!(r.may_confirm());
}

/// The output page carries the script, not only the amount: the destination is
/// what an output review exists for, so it must be part of what is seen.
#[test]
fn an_output_page_carries_its_script() {
    let spk_a: &[u8] = &[0xAA; 34];
    let spk_b: &[u8] = &[0xBB; 34];
    let ins = [input(100_000 * KAS)];
    let outs = [
        TransactionOutput {
            value: 60_000 * KAS,
            script_public_key: ScriptPublicKey {
                version: 0,
                script: spk_a,
            },
            covenant: None,
        },
        TransactionOutput {
            value: 30_000 * KAS,
            script_public_key: ScriptPublicKey {
                version: 1,
                script: spk_b,
            },
            covenant: None,
        },
    ];
    let t = tx(&ins, &outs);
    let r = Review::new(&t).expect("review");

    match r.page(1).expect("first output") {
        Page::Output {
            index,
            value,
            script_version,
            script,
        } => {
            assert_eq!(index, 0);
            assert_eq!(value, 60_000 * KAS);
            assert_eq!(script_version, 0);
            assert_eq!(script, spk_a);
        }
        other => panic!("{other:?}"),
    }
    match r.page(2).expect("second output") {
        Page::Output {
            script_version,
            script,
            ..
        } => {
            assert_eq!(script_version, 1, "the version travels with the script");
            assert_eq!(script, spk_b);
        }
        other => panic!("{other:?}"),
    }
}

/// A lock time and a payload are pages, as the signature commits to them: only
/// when set, and appended, so the summary and outputs keep their indices.
#[test]
fn a_lock_time_and_a_payload_each_get_a_page() {
    let ins = [input(100_000 * KAS)];
    let outs = [output(90_000 * KAS, None)];

    // Neither set: two pages.
    let plain = tx(&ins, &outs);
    assert_eq!(Review::new(&plain).expect("review").len(), 2);

    let mut t = tx(&ins, &outs);
    t.lock_time = 12_345;
    t.payload = &[1, 2, 3, 4];
    let r = Review::new(&t).expect("review");
    assert_eq!(r.len(), 4);
    assert!(matches!(r.page(0), Ok(Page::Summary { .. })), "unmoved");
    assert!(
        matches!(r.page(1), Ok(Page::Output { index: 0, .. })),
        "unmoved"
    );
    assert_eq!(
        r.page(2),
        Ok(Page::LockTime {
            value: 12_345,
            ignored: false
        })
    );
    assert_eq!(
        r.page(3),
        Ok(Page::Payload {
            bytes: &[1, 2, 3, 4]
        })
    );

    // And both have to be seen before the review is finished.
    let mut r = Review::new(&t).expect("review");
    for i in 0..3 {
        r.mark_seen(i).expect("seen");
    }
    assert!(!r.may_confirm(), "the payload page is still unshown");
    r.mark_seen(3).expect("seen");
    assert!(r.may_confirm());

    // Every input final: consensus ignores the lock time, which the
    // signature still covers, so it is still a page.
    let finals = [TransactionInput {
        sequence: u64::MAX,
        ..input(100_000 * KAS)
    }];
    let mut t = tx(&finals, &outs);
    t.lock_time = 12_345;
    let r = Review::new(&t).expect("review");
    assert_eq!(
        r.page(2),
        Ok(Page::LockTime {
            value: 12_345,
            ignored: true
        })
    );
}

/// Fields nobody can check are refused, not paged: a twenty-byte subnetwork
/// identifier, and gas, which consensus refuses on the native subnetwork. A
/// page for either trains a person to press through.
#[test]
fn a_transaction_that_cannot_be_shown_is_refused() {
    let ins = [input(100_000)];
    let outs = [output(90_000, None)];

    let mut t = tx(&ins, &outs);
    t.subnetwork_id = [0x42; 20];
    assert_eq!(Review::new(&t).err(), Some(Error::NonNativeSubnetwork));

    let mut t = tx(&ins, &outs);
    t.gas = 7;
    assert_eq!(Review::new(&t).err(), Some(Error::GasNotZero { gas: 7 }));
}

// ── Time-Locked Savings cards ───────────────────────────────────────────────

/// Each card an input spends is a page, after the summary and before the
/// outputs, in first-spend order, with how many inputs spend it. Only
/// script-hash inputs are asked, and a card its input does not lock to is no
/// page.
#[test]
fn each_card_is_a_page_after_the_summary() {
    use core::cell::RefCell;
    use kassigner_protocol::card::savings::{Savings, UnlockAt};

    let key = |seed: u8| {
        use kassigner_crypto::slot::{RawKey, Slot};
        use kassigner_crypto::wallet::Wallet;
        let w = Wallet::open(&Slot::RawKey(RawKey::new(&[seed; 32]).unwrap()), &mut []).unwrap();
        w.signing_key(kassigner_kaspa::derivation::Path::receive(0))
            .unwrap()
            .x_only()
    };
    let at = |m: u32| UnlockAt::new(m).unwrap();
    let a = Savings::new(key(1), Some(key(2)), at(20_819 * 1_440)).unwrap();
    let b = Savings::new(key(1), None, at(21_000 * 1_440 + 870)).unwrap();
    let (la, lb) = (a.locking_script(), b.locking_script());
    let spend = |lock: &'static [u8], amount: u64| TransactionInput {
        utxo_entry: UtxoEntry {
            amount,
            script_public_key: ScriptPublicKey {
                version: 0,
                script: lock,
            },
        },
        ..input(amount)
    };
    let (la, lb): (&'static [u8], &'static [u8]) =
        (Box::leak(Box::new(la)), Box::leak(Box::new(lb)));
    let inputs = [spend(la, 300), input(200), spend(lb, 100), spend(la, 400)];
    let outputs = [output(900, None)];
    let t = tx(&inputs, &outputs);
    let asked = RefCell::new(Vec::new());
    let cards = |i: usize| {
        asked.borrow_mut().push(i);
        match i {
            0 | 3 => Some(a),
            2 => Some(b),
            // A key's input said to be a card: never asked.
            1 => Some(a),
            _ => None,
        }
    };
    let mut r = Review::with_cards(&t, cards).unwrap();
    assert_eq!(*asked.borrow(), [0, 2, 3], "script-hash inputs only");
    assert_eq!(r.len(), 4, "summary, two cards, one output");
    assert!(matches!(r.page(0), Ok(Page::Summary { inputs: 4, .. })));
    assert_eq!(r.page(1), Ok(Page::Card { first: 0, count: 2 }));
    assert_eq!(r.page(2), Ok(Page::Card { first: 2, count: 1 }));
    assert!(matches!(r.page(3), Ok(Page::Output { index: 0, .. })));

    // Seen like any page: CONFIRM waits for both cards.
    for i in [0, 3, 1] {
        r.mark_seen(i).unwrap();
    }
    assert!(!r.may_confirm());
    r.mark_seen(2).unwrap();
    assert!(r.may_confirm());

    // A card its input's script does not lock to: no page.
    let wrong = Review::with_cards(&t, |i| (i == 2).then_some(a)).unwrap();
    assert_eq!(wrong.len(), 2);
    assert_eq!(Review::new(&t).unwrap().len(), 2);
}
