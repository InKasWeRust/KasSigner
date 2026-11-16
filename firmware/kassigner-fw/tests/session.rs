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

//! The signing flow, end to end, with no hardware.
//!
//! A transaction and its signature hash from level 0, signing from level 2,
//! an entropy source behind a level 3 trait: no board needed.
//!
//! Most tests are about what the session *refuses*, the point of the type:
//! each is a way a signature could be made for something nobody agreed to.

use kassigner_fw::review::Page;
use kassigner_fw::session::{Decision, Error, Session, Stage};
use kassigner_hal::entropy::{self, Entropy};
use kassigner_kaspa::constants::SOMPI_PER_KASPA as KAS;
use kassigner_kaspa::sighash::SIG_HASH_ALL;
use kassigner_kaspa::tx::{
    CovenantBinding, Outpoint, ScriptPublicKey, TransactionInput, TransactionOutput, UtxoEntry,
};

#[path = "../../../testkit/transaction.rs"]
pub mod transaction;
use transaction::tx;

/// Pay to a public key of 0x20 bytes: a standard form, as an output must be
/// to be reviewed.
const SPK: &[u8] = &{
    let mut s = [0x20u8; 34];
    s[33] = 0xac;
    s
};
const KEY: [u8; 32] = [0x11; 32];

/// A source that works.
struct Live(u8);

impl Entropy for Live {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), entropy::Error> {
        for (i, b) in out.iter_mut().enumerate() {
            *b = self.0.wrapping_add(i as u8);
        }
        Ok(())
    }
}

/// A source that is not there.
struct Dead;

impl Entropy for Dead {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), entropy::Error> {
        out.fill(0);
        Err(entropy::Error::Unavailable)
    }
}

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

fn input(amount: u64) -> TransactionInput<'static> {
    input_at(0, amount)
}

/// An input spending `amount` from output `index` of the one transaction
/// every input here spends: two inputs at one index spend one outpoint
/// twice, which consensus refuses.
fn input_at(index: u32, amount: u64) -> TransactionInput<'static> {
    TransactionInput {
        previous_outpoint: Outpoint {
            transaction_id: [0u8; 32],
            index,
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

/// Walk a session through its whole review.
fn review_everything(s: &mut Session<'_>) {
    while let Some((i, _page)) = s.next_page() {
        s.page_shown(i).expect("mark");
    }
}

/// The whole flow, and the signature verifies.
#[test]
fn a_reviewed_and_confirmed_transaction_signs() {
    let ins = [input(100_000 * KAS)];
    let outs = [output(95_000 * KAS, None)];
    let t = tx(&ins, &outs);

    let mut s = Session::new(t).expect("session");
    assert_eq!(s.stage(), Stage::Reviewing);

    review_everything(&mut s);
    assert_eq!(s.stage(), Stage::AwaitingDecision, "it moved on by itself");

    s.decide(Decision::Confirm).expect("confirm");
    assert_eq!(s.stage(), Stage::Confirmed);

    let sig = s.sign_input(0, &KEY, &mut Live(7)).expect("signature");

    // It verifies against the key that made it. `kassigner_crypto::sign`
    // checks this before returning; asserting it names the property.
    let pk = kassigner_crypto::sign::public_key(&KEY).expect("public key");
    let digest = kassigner_kaspa::sighash::schnorr_signature_hash(s.transaction(), 0, SIG_HASH_ALL)
        .expect("an input");
    assert!(kassigner_kaspa::bip340::verify(
        &pk,
        &digest,
        sig.as_bytes()
    ));
}

/// Signing before the review finishes is refused: the property the type
/// exists for, as such a signature would authorise something nobody saw.
#[test]
fn signing_before_the_review_finishes_is_refused() {
    let ins = [input(100_000 * KAS)];
    let outs = [output(50_000 * KAS, None), output(40_000 * KAS, None)];
    let t = tx(&ins, &outs);

    let mut s = Session::new(t).expect("session");

    // Not a single page shown.
    assert!(matches!(
        s.sign_input(0, &KEY, &mut Live(1)),
        Err(Error::NotReviewed { .. })
    ));

    // Some shown, not all.
    let (i, _) = s.next_page().expect("a page");
    s.page_shown(i).expect("mark");
    assert!(matches!(
        s.sign_input(0, &KEY, &mut Live(1)),
        Err(Error::NotReviewed { unseen: 2 })
    ));
}

/// Deciding before the review finishes is refused too: otherwise a
/// confirmation taken early could be honoured later.
#[test]
fn deciding_before_the_review_finishes_is_refused() {
    let ins = [input(100_000 * KAS)];
    let outs = [output(90_000 * KAS, None)];
    let t = tx(&ins, &outs);

    let mut s = Session::new(t).expect("session");
    assert!(matches!(
        s.decide(Decision::Confirm),
        Err(Error::NotReviewed { .. })
    ));
    assert_eq!(s.stage(), Stage::Reviewing, "and the stage did not move");

    // The refusal is not remembered: after the review, a fresh decision.
    review_everything(&mut s);
    assert_eq!(s.stage(), Stage::AwaitingDecision);
    assert!(matches!(
        s.sign_input(0, &KEY, &mut Live(1)),
        Err(Error::NotConfirmed)
    ));
}

/// A reviewed but unconfirmed transaction does not sign.
#[test]
fn a_reviewed_transaction_still_needs_a_confirmation() {
    let ins = [input(10_000 * KAS)];
    let outs = [output(9_000 * KAS, None)];
    let t = tx(&ins, &outs);

    let mut s = Session::new(t).expect("session");
    review_everything(&mut s);

    assert!(matches!(
        s.sign_input(0, &KEY, &mut Live(1)),
        Err(Error::NotConfirmed)
    ));
}

/// A decline is final.
#[test]
fn a_decline_cannot_be_walked_back() {
    let ins = [input(10_000 * KAS)];
    let outs = [output(9_000 * KAS, None)];
    let t = tx(&ins, &outs);

    let mut s = Session::new(t).expect("session");
    review_everything(&mut s);
    s.decide(Decision::Decline).expect("decline");
    assert_eq!(s.stage(), Stage::Declined);

    assert!(matches!(
        s.sign_input(0, &KEY, &mut Live(1)),
        Err(Error::Declined)
    ));

    // A second decision is refused: were a `Confirm` taken, it would
    // overwrite the stage `sign_input` reads, and the session would sign.
    assert_eq!(
        s.decide(Decision::Confirm),
        Err(Error::AlreadyDecided {
            stage: Stage::Declined
        })
    );
    assert_eq!(s.stage(), Stage::Declined, "the decision that stands");
    assert!(matches!(
        s.sign_input(0, &KEY, &mut Live(1)),
        Err(Error::Declined)
    ));

    // And a decline repeated is refused too, rather than quietly re-declining.
    assert_eq!(
        s.decide(Decision::Decline),
        Err(Error::AlreadyDecided {
            stage: Stage::Declined
        })
    );
}

/// A confirmation is spent once: a caller that could re-decide could turn a
/// confirmation into a decline after signing, or hand a second `Confirm` on a
/// stray press and learn nothing from the result.
#[test]
fn a_confirmation_cannot_be_changed() {
    let ins = [input(10_000 * KAS)];
    let outs = [output(9_000 * KAS, None)];
    let t = tx(&ins, &outs);

    let mut s = Session::new(t).expect("session");
    review_everything(&mut s);
    s.decide(Decision::Confirm).expect("confirm");
    assert_eq!(s.stage(), Stage::Confirmed);

    for d in [Decision::Decline, Decision::Confirm] {
        assert_eq!(
            s.decide(d),
            Err(Error::AlreadyDecided {
                stage: Stage::Confirmed
            })
        );
        assert_eq!(s.stage(), Stage::Confirmed);
    }

    // Still signs, because nothing about the confirmation changed.
    assert!(s.sign_input(0, &KEY, &mut Live(1)).is_ok());
}

/// Every signature commits to every output that was reviewed: the session's
/// digest is the one `SIG_HASH_ALL` produces, not any other type's, such as
/// `SIGHASH_NONE`, which commits to no output.
#[test]
fn the_signature_commits_to_everything_shown() {
    use kassigner_kaspa::sighash::{SIG_HASH_NONE, SIG_HASH_SINGLE};

    assert_eq!(Session::HASH_TYPE, SIG_HASH_ALL);

    let ins = [input(10_000 * KAS)];
    let outs = [output(6_000 * KAS, None), output(3_000 * KAS, None)];
    let t = tx(&ins, &outs);

    let mut s = Session::new(t).expect("session");
    review_everything(&mut s);
    s.decide(Decision::Confirm).expect("confirm");
    let sig = s.sign_input(0, &KEY, &mut Live(7)).expect("sign");

    let all = kassigner_kaspa::sighash::schnorr_signature_hash(s.transaction(), 0, SIG_HASH_ALL)
        .expect("an input");
    let pk = kassigner_crypto::sign::public_key(&KEY).expect("public key");
    assert!(kassigner_kaspa::bip340::verify(&pk, &all, sig.as_bytes()));

    for other in [SIG_HASH_NONE, SIG_HASH_SINGLE] {
        let d = kassigner_kaspa::sighash::schnorr_signature_hash(s.transaction(), 0, other)
            .expect("an input");
        assert_ne!(d, all, "the types differ on this transaction");
        assert!(
            !kassigner_kaspa::bip340::verify(&pk, &d, sig.as_bytes()),
            "the signature is not over {other:?}"
        );
    }
}

/// A dead entropy source refuses the signature rather than producing one: a
/// BIP340 signer falling back to a deterministic nonce is the
/// differential-fault case, where two signatures over one message on a
/// glitched device yield the key.
#[test]
fn a_dead_entropy_source_refuses_to_sign() {
    let ins = [input(10_000 * KAS)];
    let outs = [output(9_000 * KAS, None)];
    let t = tx(&ins, &outs);

    let mut s = Session::new(t).expect("session");
    review_everything(&mut s);
    s.decide(Decision::Confirm).expect("confirm");

    assert!(matches!(
        s.sign_input(0, &KEY, &mut Dead),
        Err(Error::NoEntropy(entropy::Error::Unavailable))
    ));
}

/// Different randomness gives different signatures, both valid: what makes
/// fault attacks expensive, and why the aux is drawn per signature, not per
/// session.
#[test]
fn each_signature_draws_its_own_randomness() {
    let ins = [input(10_000 * KAS)];
    let outs = [output(9_000 * KAS, None)];
    let t = tx(&ins, &outs);

    let mut s = Session::new(t).expect("session");
    review_everything(&mut s);
    s.decide(Decision::Confirm).expect("confirm");

    let a = s.sign_input(0, &KEY, &mut Live(1)).unwrap();
    let b = s.sign_input(0, &KEY, &mut Live(2)).unwrap();
    assert_ne!(
        a.as_bytes(),
        b.as_bytes(),
        "different aux, different signature"
    );

    let pk = kassigner_crypto::sign::public_key(&KEY).unwrap();
    let digest = kassigner_kaspa::sighash::schnorr_signature_hash(s.transaction(), 0, SIG_HASH_ALL)
        .expect("an input");
    for sig in [a, b] {
        assert!(kassigner_kaspa::bip340::verify(
            &pk,
            &digest,
            sig.as_bytes()
        ));
    }
}

/// An input that is not there is refused before any key is touched.
#[test]
fn an_input_that_does_not_exist_is_refused() {
    let ins = [input(10_000 * KAS)];
    let outs = [output(9_000 * KAS, None)];
    let t = tx(&ins, &outs);

    let mut s = Session::new(t).expect("session");
    review_everything(&mut s);
    s.decide(Decision::Confirm).expect("confirm");

    assert_eq!(
        s.sign_input(5, &KEY, &mut Live(1)).err(),
        Some(Error::NoSuchInput { index: 5 })
    );
}

/// Every covenant binding is on a page before a confirmation is possible:
/// not that the screen shows them, but that the session takes no
/// confirmation until they have been shown.
#[test]
fn covenant_bindings_gate_the_confirmation() {
    let ins = [input(100_000 * KAS)];
    let outs = [
        output(
            30_000 * KAS,
            Some(CovenantBinding {
                authorizing_input: 0,
                covenant_id: [1; 32],
            }),
        ),
        output(
            30_000 * KAS,
            Some(CovenantBinding {
                authorizing_input: 0,
                covenant_id: [1; 32],
            }),
        ),
        output(
            30_000 * KAS,
            Some(CovenantBinding {
                authorizing_input: 0,
                covenant_id: [1; 32],
            }),
        ),
    ];
    let t = tx(&ins, &outs);

    // The coin is bound to the covenant its outputs continue.
    let mut s = Session::with_coins(t, |_| None, &[Some([1; 32])]).expect("session");

    // Show pages up to the first covenant one, and leave it unmarked:
    // `next_page` hands back the first unseen, so the review cannot pass it.
    let mut shown = 0;
    while let Some((index, page)) = s.next_page() {
        if matches!(page, Page::Covenant { .. }) {
            break;
        }
        s.page_shown(index).expect("mark");
        shown += 1;
    }

    assert!(shown > 0, "the summary and an output were shown");
    assert!(s.remaining() > 0, "and a covenant page was not");
    assert!(
        matches!(s.decide(Decision::Confirm), Err(Error::NotReviewed { .. })),
        "so a confirmation is refused"
    );
}

/// A binding on a version-0 transaction is refused before any review:
/// consensus refuses it, and a version-0 signature does not commit to
/// bindings, so a page would show what the signature does not cover.
#[test]
fn a_binding_on_version_zero_is_refused() {
    let ins = [input(100_000 * KAS)];
    let outs = [output(
        30_000 * KAS,
        Some(CovenantBinding {
            authorizing_input: 0,
            covenant_id: [1; 32],
        }),
    )];
    let mut t = tx(&ins, &outs);
    t.version = 0;
    assert_eq!(
        Session::new(t).err(),
        Some(Error::Consensus(
            kassigner_kaspa::tx::TxRuleError::CovenantBindingInV0(0)
        ))
    );

    // The same binding at version 1, continuing its coin's covenant, is a
    // transaction to review.
    t.version = 1;
    assert!(Session::with_coins(t, |_| None, &[Some([1; 32])]).is_ok());
}

/// An output bound to a covenant either continues the covenant its
/// authorizing input's coin is bound to, or starts one whose id is what the
/// outpoint and the outputs make (upstream's `CovenantsContext::from_tx`,
/// `WrongGenesisCovenantId`). Any other id is refused before any review, as
/// a node refuses it. The coin's covenant is what the request says of it.
#[test]
fn a_binding_continues_its_coins_covenant_or_starts_its_own() {
    use kassigner_kaspa::sighash::covenant_id;
    use kassigner_kaspa::tx::TxRuleError as R;

    let ins = [input(100_000 * KAS)];
    let bound = |id: [u8; 32]| {
        [output(
            30_000 * KAS,
            Some(CovenantBinding {
                authorizing_input: 0,
                covenant_id: id,
            }),
        )]
    };
    let with = |outs: &[TransactionOutput<'static>; 1], coin: Option<[u8; 32]>| {
        let mut t = tx(&ins, outs);
        t.version = 1;
        Session::with_coins(t, |_| None, &[coin]).err()
    };

    // An id nothing makes, over a coin bound to nothing or to another
    // covenant: refused.
    let made_up = bound([7; 32]);
    let wrong = Some(Error::Consensus(R::WrongGenesisCovenantId(0, [7; 32])));
    assert_eq!(with(&made_up, None), wrong);
    assert_eq!(with(&made_up, Some([8; 32])), wrong);
    // The coin bound to that covenant: the output continues it.
    assert_eq!(with(&made_up, Some([7; 32])), None);

    // A new covenant under the id its outpoint and output make.
    let plain = bound([0; 32]);
    let id = covenant_id(&ins[0].previous_outpoint, [(0u32, &plain[0])].into_iter());
    let genesis = bound(id);
    assert_eq!(with(&genesis, None), None);
    assert_eq!(with(&genesis, Some([8; 32])), None);
}

/// A transaction version consensus does not know, above version 1 (cov++'s),
/// is refused before any review, as upstream's `UnknownTxVersion`.
#[test]
fn an_unknown_transaction_version_is_refused() {
    let ins = [input(100_000 * KAS)];
    let outs = [output(30_000 * KAS, None)];
    let mut t = tx(&ins, &outs);
    for version in [0, 1] {
        t.version = version;
        assert!(Session::new(t).is_ok(), "version {version}");
    }
    for version in [2, u16::MAX] {
        t.version = version;
        assert_eq!(
            Session::new(t).err(),
            Some(Error::Consensus(
                kassigner_kaspa::tx::TxRuleError::UnknownTxVersion(version)
            ))
        );
    }
}

/// Amounts above Kaspa's supply, and an output worth nothing, are refused
/// before any review, as upstream's `check_transaction_output_value_ranges`
/// and `check_transaction_input_amounts` refuse them: each output and both
/// totals held to `MAX_SOMPI`, the supply itself let through.
#[test]
fn amounts_past_the_supply_and_empty_outputs_are_refused() {
    use kassigner_kaspa::constants::MAX_SOMPI;
    use kassigner_kaspa::tx::TxRuleError as R;
    let refused = |ins: &[TransactionInput<'_>], outs: &[TransactionOutput<'_>]| {
        Session::new(tx(ins, outs)).err()
    };

    // The supply itself, in and out: a transaction to review.
    let all = [input(MAX_SOMPI)];
    assert_eq!(refused(&all, &[output(MAX_SOMPI - 1, None)]), None);
    // Spread over two inputs and two outputs, the same.
    let halves = [input(MAX_SOMPI / 2), input_at(1, MAX_SOMPI / 2)];
    let outs = [output(MAX_SOMPI / 2, None), output(MAX_SOMPI / 2 - 1, None)];
    assert_eq!(refused(&halves, &outs), None);

    // An output worth nothing, whichever it is.
    let ins = [input(100_000)];
    let outs = [output(30_000, None), output(0, None)];
    assert_eq!(
        refused(&ins, &outs),
        Some(Error::Consensus(R::TxOutZero(1)))
    );

    // One output past the supply.
    let outs = [output(1, None), output(MAX_SOMPI + 1, None)];
    assert_eq!(
        refused(&all, &outs),
        Some(Error::Consensus(R::TxOutTooHigh(1)))
    );
    // Outputs each within it, their total past it.
    let outs = [output(MAX_SOMPI, None), output(1, None)];
    assert_eq!(
        refused(&all, &outs),
        Some(Error::Consensus(R::TotalTxOutTooHigh))
    );

    // Inputs whose total is past the supply, or past a u64. As upstream, the
    // total is held to the supply input by input, so it overflows only where
    // the input after a legal one does.
    let outs = [output(30_000, None)];
    let past = [input(MAX_SOMPI), input_at(1, 1)];
    assert_eq!(
        refused(&past, &outs),
        Some(Error::Consensus(R::InputAmountTooHigh))
    );
    let over = [input(1), input_at(1, u64::MAX)];
    assert_eq!(
        refused(&over, &outs),
        Some(Error::Consensus(R::InputAmountOverflow))
    );
    let one = [input(u64::MAX)];
    assert_eq!(
        refused(&one, &outs),
        Some(Error::Consensus(R::InputAmountTooHigh))
    );

    // Outputs worth one sompi more than the inputs: upstream's
    // `SpendTooHigh` (outputs' total first), from the consensus rule, not
    // the review. Worth exactly the inputs: a zero fee, to review.
    let ins = [input(100_000 * KAS)];
    let outs = [output(60_000 * KAS, None), output(40_000 * KAS + 1, None)];
    assert_eq!(
        refused(&ins, &outs),
        Some(Error::Consensus(R::SpendTooHigh(
            100_000 * KAS + 1,
            100_000 * KAS
        )))
    );
    let outs = [output(60_000 * KAS, None), output(40_000 * KAS, None)];
    assert_eq!(refused(&ins, &outs), None);
}

/// An outpoint spent twice is refused before any review (upstream's
/// `TxDuplicateInputs`, right after the outputs' values): reviewed, its
/// amount would count twice in the inputs and the fee. Two outputs of one
/// transaction are two outpoints.
#[test]
fn an_outpoint_spent_twice_is_refused() {
    use kassigner_kaspa::tx::TxRuleError as R;
    let outs = [output(90_000, None)];
    let twice = [input(50_000), input(50_000)];
    assert_eq!(
        Session::new(tx(&twice, &outs)).err(),
        Some(Error::Consensus(R::TxDuplicateInputs))
    );
    // Not next to each other: the third input spends the first's outpoint.
    let apart = [input(30_000), input_at(1, 30_000), input(40_000)];
    assert_eq!(
        Session::new(tx(&apart, &outs)).err(),
        Some(Error::Consensus(R::TxDuplicateInputs))
    );
    let two = [input(50_000), input_at(1, 50_000)];
    assert!(Session::new(tx(&two, &outs)).is_ok(), "two outpoints");

    // The outputs' values are checked first, as upstream checks them.
    let empty = [output(0, None)];
    assert_eq!(
        Session::new(tx(&twice, &empty)).err(),
        Some(Error::Consensus(R::TxOutZero(0)))
    );
}

/// A covenant binding naming an input the transaction does not have is
/// refused before any review (upstream's `AuthInputOutOfBounds`).
#[test]
fn a_binding_naming_a_missing_input_is_refused() {
    let ins = [input(100_000 * KAS)];
    let mut outs = [output(
        30_000 * KAS,
        Some(CovenantBinding {
            authorizing_input: 0,
            covenant_id: [1; 32],
        }),
    )];
    assert!(
        Session::with_coins(tx(&ins, &outs), |_| None, &[Some([1; 32])]).is_ok(),
        "input 0 is there"
    );
    outs[0].covenant = Some(CovenantBinding {
        authorizing_input: 1,
        covenant_id: [1; 32],
    });
    assert_eq!(
        Session::new(tx(&ins, &outs)).err(),
        Some(Error::Consensus(
            kassigner_kaspa::tx::TxRuleError::AuthInputOutOfBounds(0, 1)
        ))
    );
}

/// An output under a script version consensus does not run is refused
/// before any review: a node's mempool refuses it (upstream's
/// `RejectScriptPublicKeyVersion`), anyone can spend it, and it has no
/// address to show.
#[test]
fn an_output_under_an_unknown_script_version_is_refused() {
    let ins = [input(100_000 * KAS)];
    let mut outs = [output(30_000 * KAS, None), output(30_000 * KAS, None)];
    outs[1].script_public_key.version = 1;
    assert_eq!(
        Session::new(tx(&ins, &outs)).err(),
        Some(Error::NonStandard(
            kassigner_kaspa::tx::NonStandardError::RejectScriptPublicKeyVersion(1)
        ))
    );

    outs[1].script_public_key.version = 0;
    assert!(Session::new(tx(&ins, &outs)).is_ok());
}

/// An output whose script is none of the standard forms is refused before
/// any review, as a node's mempool refuses it (upstream's
/// `RejectOutputScriptClass`). Pay to public key, Schnorr or ECDSA, and pay
/// to script hash, a covenant's form, are reviewed; an output under an
/// unknown version is refused for its version first, as upstream checks.
#[test]
fn an_output_that_is_no_standard_form_is_refused() {
    use kassigner_kaspa::tx::NonStandardError::{
        RejectOutputScriptClass, RejectScriptPublicKeyVersion,
    };
    let ins = [input(100_000 * KAS)];
    let mut ecdsa = vec![0x21];
    ecdsa.extend_from_slice(&[0x02; 33]);
    ecdsa.push(0xab);
    let mut p2sh = vec![0xaa, 0x20];
    p2sh.extend_from_slice(&[0x33; 32]);
    p2sh.push(0x87);
    for standard in [SPK, &ecdsa[..], &p2sh[..]] {
        let mut outs = [output(30_000 * KAS, None), output(30_000 * KAS, None)];
        outs[1].script_public_key.script = standard;
        assert!(Session::new(tx(&ins, &outs)).is_ok(), "{standard:02x?}");
    }

    let mut outs = [output(30_000 * KAS, None), output(30_000 * KAS, None)];
    outs[1].script_public_key.script = &[0x51];
    assert_eq!(
        Session::new(tx(&ins, &outs)).err(),
        Some(Error::NonStandard(RejectOutputScriptClass(1)))
    );
    outs[1].script_public_key.version = 1;
    assert_eq!(
        Session::new(tx(&ins, &outs)).err(),
        Some(Error::NonStandard(RejectScriptPublicKeyVersion(1)))
    );
}
