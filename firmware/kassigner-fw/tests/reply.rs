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

//! A confirmed session answered: the request back out with the device's
//! signatures in it.

use kassigner_crypto::slot::{RawKey, Slot};
use kassigner_crypto::wallet::Wallet;
use kassigner_fw::keyring::{self, Keyring};
use kassigner_fw::reply::{self, Error, Scratch};
use kassigner_fw::session::{self, Decision, Session};
use kassigner_hal::entropy::{self, Entropy};
use kassigner_kaspa::bip340;
use kassigner_kaspa::constants::SOMPI_PER_KASPA as KAS;
use kassigner_kaspa::multisig::redeem_script;
use kassigner_kaspa::pskb::signature::{Derivation, PartialSig};
use kassigner_kaspa::pskb::transaction as pskb_tx;
use kassigner_kaspa::pskb::{decode_envelope, Splice};
use kassigner_kaspa::script::redeem_hash;
use kassigner_kaspa::sighash::{schnorr_signature_hash, SIG_HASH_ALL};
use kassigner_kaspa::tx::ScriptPublicKey;
use kassigner_protocol::kspt::transaction as kspt_tx;
use kassigner_protocol::kspt::{self, InputSignature, MAGIC, VERSION};
use kassigner_protocol::profile::Profile;

#[path = "../../../testkit/hex.rs"]
pub mod hex;
use hex::{hex, unhex, unhex_array};
#[path = "../../../testkit/kspt_bytes.rs"]
pub mod kspt_bytes;
use kspt_bytes::spk_len;
#[path = "../../../testkit/transaction.rs"]
pub mod transaction;
use transaction::{arrays, p2pk};

const P: Profile = Profile::ESP32S3;

struct Live;

impl Entropy for Live {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), entropy::Error> {
        for (i, b) in out.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(37).wrapping_add(11);
        }
        Ok(())
    }
}

/// A raw-key wallet: one key, so the bank is that key everywhere.
fn key(seed: u8) -> Wallet {
    Wallet::open(&Slot::RawKey(RawKey::new(&[seed; 32]).unwrap()), &mut []).expect("wallet")
}

fn x_only(w: &Wallet) -> [u8; 32] {
    w.signing_key(kassigner_kaspa::derivation::Path::receive(0))
        .unwrap()
        .x_only()
}

fn public(w: &Wallet) -> [u8; 33] {
    *w.signing_key(kassigner_kaspa::derivation::Path::receive(0))
        .unwrap()
        .public_key()
}

/// A pay-to-script-hash lock for `redeem` as upstream builds it, over its
/// Blake2b-256. The device checks it before signing, so any other hash tests
/// the refusal.
fn p2sh(redeem: &[u8]) -> Vec<u8> {
    let mut v = vec![0xaa, 0x20];
    v.extend_from_slice(&redeem_hash(redeem));
    v.push(0x87);
    v
}

/// A covenant redeem script: some program, the keys it names as 32-byte
/// pushes, and a check. Nothing recognises it, which is the point.
fn covenant(keys: &[[u8; 32]]) -> Vec<u8> {
    let mut v = vec![0x63, 0xb1, 0x75];
    for k in keys {
        v.push(0x20);
        v.extend_from_slice(k);
        v.push(0xad);
    }
    v.push(0x68);
    v
}

/// A redeem script over each wallet's `45'` key at `at`, in the order given:
/// the key a seed signs a multisig with.
fn multisig(m: usize, keys: &[&Wallet], at: Path) -> Vec<u8> {
    let xs: Vec<[u8; 32]> = keys
        .iter()
        .map(|k| k.signing_key(at).unwrap().x_only())
        .collect();
    let mut out = vec![0u8; 256];
    let n = redeem_script(m, &xs, &mut out).expect("redeem");
    out.truncate(n);
    out
}

/// Every cosigner's first receive key: the same cosigner index under every
/// key, as Kaspa derives a group's address.
const FIRST: Path = Path::Multisig {
    cosigner: 0,
    chain: 0,
    index: 0,
};

/// A signature by `w`'s key at `at` over `digest`, an input's hash, which
/// leaves out a request's own signatures.
fn signed_by(digest: [u8; 32], w: &Wallet, at: Path) -> [u8; 64] {
    let key = w.signing_key(at).unwrap();
    *kassigner_crypto::sign::sign(key.private_key(), &digest, &[0; 32])
        .expect("sign")
        .as_bytes()
}

/// The hash input `i` of a KSPT request is signed over.
fn kspt_digest(req: &[u8], i: usize) -> [u8; 32] {
    with_kspt(req, false, |s, _| {
        schnorr_signature_hash(s.transaction(), i, SIG_HASH_ALL).expect("an input")
    })
}

/// The hash input `i` of a bundle's transaction is signed over.
fn pskb_digest(doc: &[u8], i: usize) -> [u8; 32] {
    with_pskb(doc, |s| {
        schnorr_signature_hash(s.transaction(), i, SIG_HASH_ALL).expect("an input")
    })
}

/// A KSPT `0x44` input hint: the input, then cosigner, chain and index below
/// the `45'` account.
fn input_hint(input: u8, cosigner: u32, chain: u32, index: u32) -> Vec<u8> {
    let mut r = vec![0x44u8, input];
    r.extend_from_slice(&cosigner.to_le_bytes());
    r.extend_from_slice(&chain.to_le_bytes());
    r.extend_from_slice(&index.to_le_bytes());
    r
}

// ── KSPT requests, built by hand ────────────────────────────────────────────

#[derive(Clone, Copy)]
struct In<'a> {
    amount: u64,
    spk: &'a [u8],
    redeem: &'a [u8],
    /// (position, sighash, signature) already present.
    sigs: &'a [(u8, u8, [u8; 64])],
}

fn request(inputs: &[In<'_>], outputs: &[(u64, &[u8])]) -> Vec<u8> {
    request_at(1, 1, inputs, outputs)
}

/// [`request`] at transaction version `tx_version`, every input committing
/// `sig_ops` signature operations.
fn request_at(
    tx_version: u16,
    sig_ops: u8,
    inputs: &[In<'_>],
    outputs: &[(u64, &[u8])],
) -> Vec<u8> {
    request_timed(tx_version, 0, 0, sig_ops, inputs, outputs)
}

/// [`request_at`] with the transaction's lock time `lock_time` and every
/// input's sequence `sequence`.
fn request_timed(
    tx_version: u16,
    lock_time: u64,
    sequence: u64,
    sig_ops: u8,
    inputs: &[In<'_>],
    outputs: &[(u64, &[u8])],
) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&MAGIC);
    b.push(VERSION);
    b.push(0);
    b.extend_from_slice(&tx_version.to_le_bytes());
    b.push(inputs.len() as u8);
    b.push(outputs.len() as u8);
    b.extend_from_slice(&lock_time.to_le_bytes());
    b.extend_from_slice(&[0u8; 20]);
    b.extend_from_slice(&0u64.to_le_bytes());
    b.extend_from_slice(&0u16.to_le_bytes());
    for (i, inp) in inputs.iter().enumerate() {
        b.extend_from_slice(&[0x11u8; 32]);
        b.extend_from_slice(&(i as u32).to_le_bytes());
        b.extend_from_slice(&inp.amount.to_le_bytes());
        b.extend_from_slice(&sequence.to_le_bytes());
        b.push(sig_ops);
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&spk_len(inp.spk.len()));
        b.extend_from_slice(inp.spk);
        b.push(inp.sigs.len() as u8);
        for (pos, ty, sig) in inp.sigs {
            b.push(*pos);
            b.push(*ty);
            b.extend_from_slice(sig);
        }
        b.extend_from_slice(&(inp.redeem.len() as u16).to_le_bytes());
        b.extend_from_slice(inp.redeem);
    }
    for (value, spk) in outputs {
        b.extend_from_slice(&value.to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&spk_len(spk.len()));
        b.extend_from_slice(spk);
    }
    b
}

/// Review every page and confirm.
fn confirm(s: &mut Session<'_>) {
    while let Some((i, _)) = s.next_page() {
        s.page_shown(i).expect("mark");
    }
    s.decide(Decision::Confirm).expect("confirm");
}

/// Parse a request, map it, and build a confirmed session over it, then run
/// `f` with the session and the source.
fn with_kspt<R>(
    bytes: &[u8],
    confirmed: bool,
    f: impl FnOnce(&Session<'_>, &kspt::Kspt<'_>) -> R,
) -> R {
    let k = kspt::parse(bytes, &P).expect("parse");
    let (mut ins, mut outs) = arrays();
    let (ni, no) = kspt_tx::fill(&k, &mut ins, &mut outs).expect("fill");
    let tx = kspt_tx::build(&k, &ins[..ni], &outs[..no]);
    let mut s = Session::new(tx).expect("session");
    if confirmed {
        confirm(&mut s);
    }
    f(&s, &k)
}

fn kspt_reply(
    s: &Session<'_>,
    k: &kspt::Kspt<'_>,
    w: &Wallet,
) -> Result<(reply::Reply, Vec<u8>), Error> {
    let keys = Keyring::new(w).expect("keyring");
    let mut sigs = [InputSignature::EMPTY; 8];
    let mut out = vec![0u8; 4096];
    let r = reply::kspt(s, k, &keys, &P, &mut Live, &mut sigs, &mut out)?;
    out.truncate(r.len);
    Ok((r, out))
}

/// The signatures on input `i` of a payload, as (position, type, bytes).
fn sigs_on(bytes: &[u8], i: usize) -> Vec<(u8, u8, Vec<u8>)> {
    let k = kspt::parse(bytes, &P).expect("reply parses");
    k.inputs()
        .nth(i)
        .expect("input")
        .signatures()
        .map(|s| (s.pubkey_pos, s.sighash_type, s.bytes.to_vec()))
        .collect()
}

/// A reply is read back and verified before it leaves; a flipped signature
/// byte, a sighash type other than `ALL` on a signature that verifies, a
/// body changed where no signature looks, a payload that is no KSPT, a reply
/// with no signature, and another transaction are each refused.
#[test]
fn a_reply_is_read_back_and_verified_against_the_request() {
    let me = key(1);
    let spk = p2pk(&x_only(&me));
    let req = request(
        &[In {
            amount: 100_000 * KAS,
            spk: &spk,
            redeem: &[],
            sigs: &[],
        }],
        &[(90_000 * KAS, &spk)],
    );
    let (_, out) = with_kspt(&req, true, |s, k| kspt_reply(s, k, &me)).expect("reply");

    with_kspt(&req, true, |s, _| {
        assert_eq!(reply::verify_kspt(&out, s.transaction(), &P), Ok(1));

        // One bit of the signature, found where it sits in the reply.
        let sig = sigs_on(&out, 0).remove(0).2;
        let sig_at = out
            .windows(sig.len())
            .position(|w| w == sig.as_slice())
            .expect("the signature is in the reply");
        let mut bad = out.clone();
        bad[sig_at + 10] ^= 0x01;
        assert_eq!(
            reply::verify_kspt(&bad, s.transaction(), &P),
            Err(reply::Unverified::Fails {
                input: 0,
                position: 0
            })
        );

        // The record's sighash byte, just before its signature: the
        // signature still verifies over `ALL`'s hash, but says another type.
        assert_eq!(sigs_on(&out, 0)[0].1, 0x01, "written as ALL");
        assert_eq!(out[sig_at - 1], 0x01, "the record's sighash byte");
        for other in [0x00, 0x02, 0x03, 0x81] {
            let mut bad = out.clone();
            bad[sig_at - 1] = other;
            assert_eq!(sigs_on(&bad, 0)[0].1, other);
            assert_eq!(
                reply::verify_kspt(&bad, s.transaction(), &P),
                Err(reply::Unverified::SighashNotAll { input: 0 }),
                "{other:#04x}"
            );
        }

        // The body changed where no signature looks: a byte of the key the
        // output pays. The signature still verifies over the reviewed
        // transaction's hash, so only the body says it is another payment.
        let paid = kspt::parse(&out, &P)
            .expect("reply parses")
            .outputs()
            .next()
            .expect("an output")
            .spk;
        let key_at = paid.as_ptr() as usize - out.as_ptr() as usize + 1;
        let mut bad = out.clone();
        bad[key_at] ^= 0x01;
        assert_eq!(
            reply::verify_kspt(&bad, s.transaction(), &P),
            Err(reply::Unverified::NotTheTransaction)
        );

        // Not a KSPT at all.
        assert_eq!(
            reply::verify_kspt(b"nope", s.transaction(), &P),
            Err(reply::Unverified::DoesNotParse)
        );

        // The request itself: parses, carries no signature.
        assert_eq!(
            reply::verify_kspt(&req, s.transaction(), &P),
            Err(reply::Unverified::Nothing)
        );
    });

    // The same reply against a transaction that pays a different amount:
    // not its body, refused before the signature is read.
    let other = request(
        &[In {
            amount: 100_000 * KAS,
            spk: &spk,
            redeem: &[],
            sigs: &[],
        }],
        &[(80_000 * KAS, &spk)],
    );
    with_kspt(&other, true, |s, _| {
        assert_eq!(
            reply::verify_kspt(&out, s.transaction(), &P),
            Err(reply::Unverified::NotTheTransaction)
        );
    });
}

/// A reply with fewer inputs or more outputs is not the transaction, though a
/// reply cut to its first input still verifies over that input's hash.
#[test]
fn a_reply_with_fewer_inputs_is_not_the_transaction() {
    let me = key(1);
    let spk = p2pk(&x_only(&me));
    let both = [
        In {
            amount: 100_000 * KAS,
            spk: &spk,
            redeem: &[],
            sigs: &[],
        },
        In {
            amount: 50_000 * KAS,
            spk: &spk,
            redeem: &[],
            sigs: &[],
        },
    ];
    let req = request(&both, &[(140_000 * KAS, &spk)]);
    let (_, out) = with_kspt(&req, true, |s, k| kspt_reply(s, k, &me)).expect("reply");
    let (pos, ty, sig) = sigs_on(&out, 0).remove(0);
    let sig: [u8; 64] = sig.try_into().expect("64 bytes");
    let first = [(pos, ty, sig)];
    let short = request(
        &[In {
            sigs: &first,
            ..both[0]
        }],
        &[(140_000 * KAS, &spk)],
    );
    let more_outputs = request(&both, &[(70_000 * KAS, &spk), (70_000 * KAS, &spk)]);
    with_kspt(&req, true, |s, _| {
        assert_eq!(reply::verify_kspt(&out, s.transaction(), &P), Ok(2));
        assert_eq!(
            reply::verify_kspt(&short, s.transaction(), &P),
            Err(reply::Unverified::NotTheTransaction)
        );
        assert_eq!(
            reply::verify_kspt(&more_outputs, s.transaction(), &P),
            Err(reply::Unverified::NotTheTransaction)
        );
    });
}

/// A single-key input is signed at position zero, the reply is canonical and
/// parses, and the signature verifies over what the session hashed.
#[test]
fn a_single_key_input_is_signed_and_the_reply_parses() {
    let me = key(1);
    let spk = p2pk(&x_only(&me));
    let req = request(
        &[In {
            amount: 100_000 * KAS,
            spk: &spk,
            redeem: &[],
            sigs: &[],
        }],
        &[(90_000 * KAS, &spk)],
    );
    let (r, out) = with_kspt(&req, true, |s, k| kspt_reply(s, k, &me)).expect("reply");
    assert_eq!(r.signed, 1);
    assert_eq!(out[MAGIC.len()], VERSION, "answered as 0x06");

    let sigs = sigs_on(&out, 0);
    assert_eq!(sigs.len(), 1);
    let (pos, ty, sig) = &sigs[0];
    assert_eq!((*pos, *ty), (0, SIG_HASH_ALL.to_u8()));

    with_kspt(&req, true, |s, _| {
        let digest = schnorr_signature_hash(s.transaction(), 0, SIG_HASH_ALL).expect("an input");
        assert!(bip340::verify(
            &x_only(&me),
            &digest,
            sig.as_slice().try_into().unwrap()
        ));
    });
}

/// An unconfirmed session is refused before the request is looked at.
#[test]
fn an_unconfirmed_session_is_refused_first() {
    let me = key(1);
    let spk = p2pk(&x_only(&me));
    let req = request(
        &[In {
            amount: 100_000 * KAS,
            spk: &spk,
            redeem: &[],
            sigs: &[],
        }],
        &[(90_000 * KAS, &spk)],
    );
    let err = with_kspt(&req, false, |s, k| kspt_reply(s, k, &me)).err();
    assert!(matches!(
        err,
        Some(Error::Session(session::Error::NotReviewed { .. }))
    ));
}

/// A key the script does not name signs nothing, and nothing signed is
/// refused rather than written.
#[test]
fn a_key_the_script_does_not_name_is_refused() {
    let me = key(1);
    let other = key(2);
    let spk = p2pk(&x_only(&other));
    let req = request(
        &[In {
            amount: 100_000 * KAS,
            spk: &spk,
            redeem: &[],
            sigs: &[],
        }],
        &[(90_000 * KAS, &spk)],
    );
    assert_eq!(
        with_kspt(&req, true, |s, k| kspt_reply(s, k, &me)).err(),
        Some(Error::NothingSigned)
    );
}

/// An input under a script version consensus does not run is not signed,
/// though its script holds this key: the request has no input of ours.
#[test]
fn an_input_under_an_unknown_script_version_is_not_signed() {
    let me = key(1);
    let spk = p2pk(&x_only(&me));
    let mut req = request(
        &[In {
            amount: 100_000 * KAS,
            spk: &spk,
            redeem: &[],
            sigs: &[],
        }],
        &[(90_000 * KAS, &spk)],
    );
    // The input's script version: past the 48-byte header, the outpoint,
    // the amount, the sequence and the signature-operation count.
    req[101..103].copy_from_slice(&1u16.to_le_bytes());
    let parsed = kspt::parse(&req, &P).expect("parse");
    assert_eq!(parsed.inputs().next().expect("input").spk_version, 1);
    assert_eq!(
        with_kspt(&req, true, |s, k| kspt_reply(s, k, &me)).err(),
        Some(Error::NothingSigned)
    );
}

/// An input this key already signed is refused as `AlreadySigned`, not skipped;
/// a made-up signature at that position is refused as a bad one.
#[test]
fn an_input_already_signed_is_refused_as_such() {
    let me = key(1);
    let spk = p2pk(&x_only(&me));
    let with = |sig: [u8; 64]| {
        request(
            &[In {
                amount: 100_000 * KAS,
                spk: &spk,
                redeem: &[],
                sigs: &[(0, SIG_HASH_ALL.to_u8(), sig)],
            }],
            &[(90_000 * KAS, &spk)],
        )
    };
    let made_up = with([7u8; 64]);
    let req = with(signed_by(kspt_digest(&made_up, 0), &me, Path::receive(0)));
    assert_eq!(
        with_kspt(&req, true, |s, k| kspt_reply(s, k, &me)).err(),
        Some(Error::AlreadySigned {
            input: 0,
            position: 0
        })
    );
    assert_eq!(
        with_kspt(&made_up, true, |s, k| kspt_reply(s, k, &me)).err(),
        Some(Error::BadSignature { input: 0 })
    );
}

/// In a 2-of-3 the device signs at its own key's position, a cosigner's
/// signature already there stays, and the two come out in position order.
#[test]
fn a_multisig_input_is_signed_at_the_keys_position() {
    let (a, b, c) = (hd(1), hd(2), hd(3));
    let redeem = multisig(2, &[&a, &b, &c], FIRST);
    let spk = p2sh(&redeem);
    let with = |sigs: &[(u8, u8, [u8; 64])]| {
        let mut req = request(
            &[In {
                amount: 100_000 * KAS,
                spk: &spk,
                redeem: &redeem,
                sigs,
            }],
            &[(90_000 * KAS, &spk)],
        );
        req.extend_from_slice(&input_hint(0, 0, 0, 0));
        req
    };
    let theirs = signed_by(kspt_digest(&with(&[]), 0), &a, FIRST);
    let req = with(&[(0, SIG_HASH_ALL.to_u8(), theirs)]);
    let (r, out) = with_kspt(&req, true, |s, k| kspt_reply(s, k, &c)).expect("reply");
    assert_eq!(r.signed, 1);
    let sigs = sigs_on(&out, 0);
    assert_eq!(sigs.len(), 2);
    assert_eq!(sigs[0].0, 0, "the cosigner's, first");
    assert_eq!(sigs[0].2, theirs.to_vec());
    assert_eq!(sigs[1].0, 2, "ours, at our position");

    // A key not in the script signs nothing.
    assert_eq!(
        with_kspt(&req, true, |s, k| kspt_reply(s, k, &hd(9))).err(),
        Some(Error::NothingSigned)
    );
}

/// A KSPT reply's signature count, as v1.0.7 showed it beside the frames: none
/// for a single signature; a multisig's signatures up to its threshold, plus
/// one per other input.
#[test]
fn a_kspt_replys_signatures_are_counted_as_v107_counted_them() {
    let (a, b, c) = (hd(1), hd(2), hd(3));
    let mine = p2pk(&x_only(&c));
    let single = request(
        &[In {
            amount: 100_000 * KAS,
            spk: &mine,
            redeem: &[],
            sigs: &[],
        }],
        &[(90_000 * KAS, &mine)],
    );
    let (_, out) = with_kspt(&single, true, |s, k| kspt_reply(s, k, &c)).expect("reply");
    assert_eq!(reply::kspt_signers(&out, &P), None, "a single signature's");

    let redeem = multisig(2, &[&a, &b, &c], FIRST);
    let spk = p2sh(&redeem);
    let count = |sigs: &[(u8, u8, [u8; 64])]| {
        let mut req = request(
            &[In {
                amount: 100_000 * KAS,
                spk: &spk,
                redeem: &redeem,
                sigs,
            }],
            &[(90_000 * KAS, &spk)],
        );
        req.extend_from_slice(&input_hint(0, 0, 0, 0));
        let (_, out) = with_kspt(&req, true, |s, k| kspt_reply(s, k, &c)).expect("reply");
        reply::kspt_signers(&out, &P).expect("a multisig's")
    };
    let theirs = {
        let mut req = request(
            &[In {
                amount: 100_000 * KAS,
                spk: &spk,
                redeem: &redeem,
                sigs: &[],
            }],
            &[(90_000 * KAS, &spk)],
        );
        req.extend_from_slice(&input_hint(0, 0, 0, 0));
        signed_by(kspt_digest(&req, 0), &a, FIRST)
    };
    let first = count(&[]);
    assert_eq!(
        first,
        reply::Signers {
            present: 1,
            required: 2
        }
    );
    let last = count(&[(0, SIG_HASH_ALL.to_u8(), theirs)]);
    assert_eq!(
        last,
        reply::Signers {
            present: 2,
            required: 2
        }
    );

    // Summed over the inputs: a multisig's two, and one for a single key's.
    let mut both = request(
        &[
            In {
                amount: 100_000 * KAS,
                spk: &spk,
                redeem: &redeem,
                sigs: &[],
            },
            In {
                amount: 50_000 * KAS,
                spk: &mine,
                redeem: &[],
                sigs: &[],
            },
        ],
        &[(140_000 * KAS, &mine)],
    );
    both.extend_from_slice(&input_hint(0, 0, 0, 0));
    let (_, out) = with_kspt(&both, true, |s, k| kspt_reply(s, k, &c)).expect("reply");
    assert_eq!(
        reply::kspt_signers(&out, &P),
        Some(reply::Signers {
            present: 2,
            required: 3
        })
    );
}

/// A pay-to-script-hash input without its redeem script cannot be signed.
#[test]
fn a_script_hash_input_needs_its_redeem() {
    let me = key(1);
    let spk = p2sh(&[]);
    let req = request(
        &[In {
            amount: 100_000 * KAS,
            spk: &spk,
            redeem: &[],
            sigs: &[],
        }],
        &[(90_000 * KAS, &spk)],
    );
    assert_eq!(
        with_kspt(&req, true, |s, k| kspt_reply(s, k, &me)).err(),
        Some(Error::Keyring {
            input: 0,
            error: keyring::Error::NoRedeemScript
        })
    );
}

// ── PSKB requests, built by hand ────────────────────────────────────────────

/// A `bip32Derivations` member: `key` at `path`, as a coordinator records it.
fn derivation(key: &[u8], path: &str) -> String {
    format!(
        "\"{}\":{{\"keyFingerprint\":\"00000000\",\"derivationPath\":\"{path}\"}}",
        hex(key)
    )
}

/// The `bip32Derivations` path of [`FIRST`].
const FIRST_PATH: &str = "m/45'/111111'/0'/0/0/0";

struct PIn<'a> {
    amount: u64,
    spk: &'a [u8],
    redeem: Option<&'a [u8]>,
    sighash: Option<u64>,
    /// Members already in `partialSigs`, as raw JSON.
    partial: &'a str,
    /// Members already in `bip32Derivations`, as raw JSON.
    derivations: &'a str,
}

fn bundle_tx(inputs: &[PIn<'_>], outputs: &[(u64, &[u8])]) -> String {
    bundle_tx_at(1, 1, inputs, outputs)
}

/// [`bundle_tx`] at transaction version `tx_version`, every input committing
/// `sig_ops` signature operations.
fn bundle_tx_at(
    tx_version: u16,
    sig_ops: u8,
    inputs: &[PIn<'_>],
    outputs: &[(u64, &[u8])],
) -> String {
    let ins: Vec<String> = inputs
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let mut s = format!(
                "{{\"utxoEntry\":{{\"amount\":{},\"scriptPublicKey\":\"0000{}\",\"blockDaaScore\":0,\"isCoinbase\":false}},\
                 \"previousOutpoint\":{{\"transactionId\":\"{}\",\"index\":{}}},\
                 \"sequence\":null,\"minTime\":null,\"partialSigs\":{{{}}},\"sighashType\":{},\
                 \"redeemScript\":{},\"sigOpCount\":{},\"bip32Derivations\":{{{}}},\"finalScriptSig\":null,\
                 \"proprietaries\":{{}}}}",
                p.amount,
                hex(p.spk),
                "11".repeat(32),
                i,
                p.partial,
                p.sighash.map_or("null".to_string(), |t| t.to_string()),
                p.redeem.map_or("null".to_string(), |r| format!("\"{}\"", hex(r))),
                sig_ops,
                p.derivations,
            );
            s.shrink_to_fit();
            s
        })
        .collect();
    let outs: Vec<String> = outputs
        .iter()
        .map(|(v, spk)| {
            format!(
                "{{\"amount\":{v},\"scriptPublicKey\":\"0000{}\",\"covenant\":null,\"redeemScript\":null,\"bip32Derivations\":{{}},\"proprietaries\":{{}}}}",
                hex(spk)
            )
        })
        .collect();
    format!(
        "{{\"global\":{{\"version\":0,\"txVersion\":{},\"fallbackLockTime\":null,\"inputsModifiable\":false,\
         \"outputsModifiable\":false,\"inputCount\":{},\"outputCount\":{},\"xpubs\":{{}},\"id\":null,\
         \"proprietaries\":{{}},\"payload\":null}},\"inputs\":[{}],\"outputs\":[{}]}}",
        tx_version,
        inputs.len(),
        outputs.len(),
        ins.join(","),
        outs.join(",")
    )
}

fn bundle(txs: &[String]) -> Vec<u8> {
    format!("[{}]", txs.join(",")).into_bytes()
}

/// Build a confirmed session over the bundle's first transaction and run `f`.
fn with_pskb<R>(doc: &[u8], f: impl FnOnce(&Session<'_>) -> R) -> R {
    let (mut ins, mut outs) = arrays();
    let mut bytes = [0u8; 2048];
    let filled = pskb_tx::fill(doc, 0, &mut ins, &mut outs, &mut bytes).expect("fill");
    let tx = pskb_tx::build(
        &filled.header,
        &ins[..filled.inputs],
        &outs[..filled.outputs],
    );
    let mut s = Session::new(tx).expect("session");
    confirm(&mut s);
    f(&s)
}

fn pskb_reply(s: &Session<'_>, doc: &[u8], w: &Wallet) -> Result<(reply::Reply, Vec<u8>), Error> {
    let keys = Keyring::new(w).expect("keyring");
    let (mut ins, mut outs) = arrays();
    let mut bytes = [0u8; 2048];
    let mut redeem = [0u8; 512];
    let mut signatures = [[0u8; 64]; 8];
    let mut signed = [reply::Signed::EMPTY; 8];
    let mut partial = [PartialSig {
        input: 0,
        public_key: &[0; 33],
        signature: &[0; 64],
        derivation: Derivation::Null,
    }; 8];
    let mut splices = [Splice::insert_at(0, &[]); 16];
    let mut text = [0u8; 4096];
    let mut json = vec![0u8; doc.len() + 4096];
    let mut scratch = Scratch {
        inputs: &mut ins,
        outputs: &mut outs,
        bytes: &mut bytes,
        redeem: &mut redeem,
        signatures: &mut signatures,
        signed: &mut signed,
        partial: &mut partial,
        splices: &mut splices,
        text: &mut text,
        json: &mut json,
    };
    let mut out = vec![0u8; 4 + 2 * (doc.len() + 4096)];
    let r = reply::pskb(s, doc, &keys, &mut Live, &mut scratch, &mut out)?;
    out.truncate(r.len);
    Ok((r, out))
}

/// The document inside a reply envelope, as text.
fn unwrap(env: &[u8]) -> String {
    let mut json = vec![0u8; env.len()];
    let n = decode_envelope(env, &mut json).expect("envelope");
    String::from_utf8(json[..n].to_vec()).unwrap()
}

/// A single-key bundle input is signed: the reply holds the same bundle with
/// our `partialSigs` member and a `null` derivation, and the signature
/// verifies.
#[test]
fn a_pskb_input_is_signed_and_spliced() {
    let me = key(1);
    let spk = p2pk(&x_only(&me));
    let doc = bundle(&[bundle_tx(
        &[PIn {
            amount: 100_000 * KAS,
            spk: &spk,
            redeem: None,
            sighash: Some(1),
            partial: "",
            derivations: "",
        }],
        &[(90_000 * KAS, &spk)],
    )]);
    let (r, out) = with_pskb(&doc, |s| pskb_reply(s, &doc, &me)).expect("reply");
    assert_eq!(r.signed, 1);
    assert!(out.starts_with(b"PSKB"));

    let text = unwrap(&out);
    let pk = hex(&public(&me));
    let member = format!("\"partialSigs\":{{\"{pk}\":{{\"schnorr\":\"");
    let at = text.find(&member).expect("our member") + member.len();
    let sig_hex = &text[at..at + 128];
    let sig = unhex(sig_hex);
    assert!(text.contains(&format!("\"bip32Derivations\":{{\"{pk}\":null}}")));

    with_pskb(&doc, |s| {
        let digest = schnorr_signature_hash(s.transaction(), 0, SIG_HASH_ALL).expect("an input");
        assert!(bip340::verify(
            &x_only(&me),
            &digest,
            sig.as_slice().try_into().unwrap()
        ));
    });

    // Everything else is the byte string that arrived.
    let original = String::from_utf8(doc.clone()).unwrap();
    let stripped = text
        .replace(&format!("\"{pk}\":{{\"schnorr\":\"{sig_hex}\"}}"), "")
        .replace(&format!("\"{pk}\":null"), "");
    assert_eq!(stripped, original);
}

/// A key source the coordinator recorded for us is passed back as it was.
#[test]
fn a_recorded_key_source_is_kept() {
    let me = key(1);
    let spk = p2pk(&x_only(&me));
    let pk = hex(&public(&me));
    let source = format!(
        "\"{pk}\":{{\"keyFingerprint\":\"abcdef01\",\"derivationPath\":\"m/45'/111111'/0'/0/3\"}}"
    );
    let doc = bundle(&[bundle_tx(
        &[PIn {
            amount: 100_000 * KAS,
            spk: &spk,
            redeem: None,
            sighash: Some(1),
            partial: "",
            derivations: &source,
        }],
        &[(90_000 * KAS, &spk)],
    )]);
    let (_, out) = with_pskb(&doc, |s| pskb_reply(s, &doc, &me)).expect("reply");
    let text = unwrap(&out);
    assert!(text.contains(&format!("\"bip32Derivations\":{{{source}}}")));
}

/// What a PSKB reply refuses.
#[test]
fn the_pskb_reply_refuses() {
    let me = key(1);
    let spk = p2pk(&x_only(&me));
    let one = |sighash: Option<u64>, partial: &str| {
        bundle_tx(
            &[PIn {
                amount: 100_000 * KAS,
                spk: &spk,
                redeem: None,
                sighash,
                partial,
                derivations: "",
            }],
            &[(90_000 * KAS, &spk)],
        )
    };

    // Two transactions.
    let two = bundle(&[one(Some(1), ""), one(Some(1), "")]);
    assert_eq!(
        with_pskb(&two, |s| pskb_reply(s, &two, &me)).err(),
        Some(Error::NotOneTransaction { count: 2 })
    );

    // A sighash type other than ALL.
    let single = bundle(&[one(Some(2), "")]);
    assert_eq!(
        with_pskb(&single, |s| pskb_reply(s, &single, &me)).err(),
        Some(Error::SighashNotAll { input: 0 })
    );

    // Already signed by us.
    let unsigned = bundle(&[one(Some(1), "")]);
    let mine = format!(
        "\"{}\":{{\"schnorr\":\"{}\"}}",
        hex(&public(&me)),
        hex(&signed_by(pskb_digest(&unsigned, 0), &me, Path::receive(0)))
    );
    let signed = bundle(&[one(Some(1), &mine)]);
    assert_eq!(
        with_pskb(&signed, |s| pskb_reply(s, &signed, &me)).err(),
        Some(Error::AlreadySigned {
            input: 0,
            position: 0
        })
    );

    // Not the transaction the session reviewed.
    let reviewed = bundle(&[one(Some(1), "")]);
    let other_spk = p2pk(&x_only(&key(2)));
    let other = bundle(&[bundle_tx(
        &[PIn {
            amount: 100_000 * KAS,
            spk: &spk,
            redeem: None,
            sighash: Some(1),
            partial: "",
            derivations: "",
        }],
        &[(90_000 * KAS, &other_spk)],
    )]);
    assert_eq!(
        with_pskb(&reviewed, |s| pskb_reply(s, &other, &me)).err(),
        Some(Error::NotTheReviewedTransaction)
    );

    // Not ours.
    let theirs = bundle(&[one(Some(1), "")]);
    assert_eq!(
        with_pskb(&theirs, |s| pskb_reply(s, &theirs, &key(2))).err(),
        Some(Error::NothingSigned)
    );
}

/// A multisig bundle input is signed with the redeem script read from the
/// bundle, at the device's position.
#[test]
fn a_pskb_multisig_input_uses_the_bundles_redeem() {
    let (a, b, c) = (hd(1), hd(2), hd(3));
    let redeem = multisig(2, &[&a, &b, &c], FIRST);
    let spk = p2sh(&redeem);
    let kb = b.signing_key(FIRST).unwrap();
    let recorded = derivation(kb.public_key(), FIRST_PATH);
    let doc = bundle(&[bundle_tx(
        &[PIn {
            amount: 100_000 * KAS,
            spk: &spk,
            redeem: Some(&redeem),
            sighash: Some(1),
            partial: "",
            derivations: &recorded,
        }],
        &[(90_000 * KAS, &spk)],
    )]);
    let (r, out) = with_pskb(&doc, |s| pskb_reply(s, &doc, &b)).expect("reply");
    assert_eq!(r.signed, 1);
    assert!(unwrap(&out).contains(&format!("\"{}\":{{\"schnorr\"", hex(kb.public_key()))));
    assert_eq!(
        with_pskb(&doc, |s| pskb_reply(s, &doc, &hd(9))).err(),
        Some(Error::NothingSigned)
    );
}

/// A bundle reply's signature count comes with its read back: a cosigner's
/// member counts by the script's key; a single key's reply has none.
#[test]
fn a_pskb_replys_signatures_are_counted_with_its_read_back() {
    fn counted(doc: &[u8], w: &Wallet) -> Option<reply::Signers> {
        with_pskb(doc, |s| {
            let (r, out) = pskb_reply(s, doc, w).expect("reply");
            let keys = Keyring::new(w).expect("keyring");
            let mut document = vec![0u8; out.len()];
            let mut scripts = [0u8; 2048];
            let mut redeem = [0u8; 512];
            let (mut ins, mut outs) = arrays();
            reply::verify_pskb(
                &out,
                s.transaction(),
                &keys,
                r.signed,
                reply::ReadBack {
                    document: &mut document,
                    scripts: &mut scripts,
                    redeem: &mut redeem,
                    inputs: &mut ins,
                    outputs: &mut outs,
                },
            )
            .expect("verifies")
        })
    }

    let (a, b, c) = (hd(1), hd(2), hd(3));
    let redeem = multisig(2, &[&a, &b, &c], FIRST);
    let spk = p2sh(&redeem);
    let recorded = derivation(b.signing_key(FIRST).unwrap().public_key(), FIRST_PATH);
    let with = |partial: &str| {
        bundle(&[bundle_tx(
            &[PIn {
                amount: 100_000 * KAS,
                spk: &spk,
                redeem: Some(&redeem),
                sighash: Some(1),
                partial,
                derivations: &recorded,
            }],
            &[(90_000 * KAS, &spk)],
        )])
    };
    assert_eq!(
        counted(&with(""), &b),
        Some(reply::Signers {
            present: 1,
            required: 2
        })
    );
    let cosigner = format!(
        "\"{}\":{{\"schnorr\":\"{}\"}}",
        hex(a.signing_key(FIRST).unwrap().public_key()),
        hex(&signed_by(pskb_digest(&with(""), 0), &a, FIRST))
    );
    assert_eq!(
        counted(&with(&cosigner), &b),
        Some(reply::Signers {
            present: 2,
            required: 2
        })
    );

    let mine = p2pk(&x_only(&b));
    let single = bundle(&[bundle_tx(
        &[PIn {
            amount: 100_000 * KAS,
            spk: &mine,
            redeem: None,
            sighash: Some(1),
            partial: "",
            derivations: "",
        }],
        &[(90_000 * KAS, &mine)],
    )]);
    assert_eq!(counted(&single, &b), None, "a single signature's");
}

/// A bundle's document back in its envelope.
fn envelope_of(json: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; 4 + 2 * json.len()];
    let n = kassigner_kaspa::pskb::encode_envelope(json, &mut out).expect("envelope");
    out.truncate(n);
    out
}

/// A bundle reply's signatures are verified on read back, not only found, as a
/// KSPT reply's are: one altered after it was written is refused at its input
/// and position.
#[test]
fn a_pskb_replys_signatures_are_verified_on_read_back() {
    let me = key(1);
    let spk = p2pk(&x_only(&me));
    let doc = bundle(&[bundle_tx(
        &[PIn {
            amount: 100_000 * KAS,
            spk: &spk,
            redeem: None,
            sighash: Some(1),
            partial: "",
            derivations: "",
        }],
        &[(90_000 * KAS, &spk)],
    )]);
    with_pskb(&doc, |s| {
        let (r, out) = pskb_reply(s, &doc, &me).expect("reply");
        let read = |reply: &[u8]| {
            let keys = Keyring::new(&me).expect("keyring");
            let mut document = vec![0u8; reply.len()];
            let mut scripts = [0u8; 2048];
            let mut redeem = [0u8; 512];
            let (mut ins, mut outs) = arrays();
            reply::verify_pskb(
                reply,
                s.transaction(),
                &keys,
                r.signed,
                reply::ReadBack {
                    document: &mut document,
                    scripts: &mut scripts,
                    redeem: &mut redeem,
                    inputs: &mut ins,
                    outputs: &mut outs,
                },
            )
            .map(|_| ())
        };
        assert_eq!(read(&out), Ok(()));

        // The signature's last byte changed, and the bundle sealed again.
        let text = unwrap(&out);
        let member = format!("\"{}\":{{\"schnorr\":\"", hex(&public(&me)));
        let at = text.find(&member).expect("our member") + member.len() + 126;
        let mut bent = text.clone();
        let flipped = if &text[at..at + 2] == "00" {
            "01"
        } else {
            "00"
        };
        bent.replace_range(at..at + 2, flipped);
        assert_eq!(
            read(&envelope_of(bent.as_bytes())),
            Err(reply::Unverified::Fails {
                input: 0,
                position: 0
            })
        );
    });
}

// ── Keyring over a real tree ────────────────────────────────────────────────

use kassigner_crypto::bip39;
use kassigner_fw::keyring::path_of_hint;
use kassigner_fw::limits::{CHANGE_DEPTH, RECEIVE_DEPTH, SEARCH_BATCH, SEARCH_DEPTH};
use kassigner_kaspa::derivation::Path;
use kassigner_protocol::kspt::Hint;

/// A locking script under version 0, the one version consensus runs.
fn v0(script: &[u8]) -> ScriptPublicKey<'_> {
    ScriptPublicKey { version: 0, script }
}

fn hd(fill: u8) -> Wallet {
    let m = bip39::from_entropy(&[fill; 16]).unwrap();
    let mut scratch = vec![0u8; bip39::scratch_for(0)];
    Wallet::open(&Slot::mnemonic(m, b"").unwrap(), &mut scratch).unwrap()
}

/// The bank finds a single-key input at its path on either chain, the search
/// finds one past the bank out to its depth, and one past that is not ours.
#[test]
fn the_bank_finds_receive_and_change_keys() {
    let w = hd(1);
    let ring = Keyring::new(&w).unwrap();
    for path in [
        Path::receive(0),
        Path::receive(RECEIVE_DEPTH - 1),
        Path::change(CHANGE_DEPTH - 1),
    ] {
        let x = w.signing_key(path).unwrap().x_only();
        let m = ring
            .resolve(v0(&p2pk(&x)), &[], None)
            .unwrap()
            .expect("ours");
        assert_eq!(m.position, 0);
        assert_eq!(m.key.x_only(), x);
    }
    // Past the bank, found on demand: the first key the bank lacks, one deep
    // in the second batch on each chain, and the last key of the search.
    for path in [
        Path::receive(RECEIVE_DEPTH),
        Path::change(CHANGE_DEPTH),
        Path::receive(SEARCH_BATCH + 50),
        Path::change(SEARCH_BATCH + 50),
        Path::receive(SEARCH_DEPTH - 1),
        Path::change(SEARCH_DEPTH - 1),
    ] {
        let x = w.signing_key(path).unwrap().x_only();
        let m = ring
            .resolve(v0(&p2pk(&x)), &[], None)
            .unwrap()
            .expect("ours");
        assert_eq!(m.position, 0);
        assert_eq!(m.key.x_only(), x);
    }
    // Past the search: not ours.
    for path in [Path::receive(SEARCH_DEPTH), Path::change(SEARCH_DEPTH)] {
        let x = w.signing_key(path).unwrap().x_only();
        assert!(ring.resolve(v0(&p2pk(&x)), &[], None).unwrap().is_none());
    }
    // ECDSA and non-standard scripts are not ours.
    let mut ecdsa = vec![0x21];
    ecdsa.extend_from_slice(&[0x02; 33]);
    ecdsa.push(0xab);
    assert!(ring.resolve(v0(&ecdsa), &[], None).unwrap().is_none());
    assert!(ring.resolve(v0(&[0x51]), &[], None).unwrap().is_none());
}

/// No key resolves under a script version consensus does not run, hint or none,
/// not even through a script hash: the engine accepts such a spend without
/// running it (upstream's `AcceptedUnknownVersion`), so its key guards nothing.
#[test]
fn no_key_resolves_under_an_unknown_script_version() {
    let w = hd(1);
    let ring = Keyring::new(&w).unwrap();
    let x = w.signing_key(Path::receive(0)).unwrap().x_only();
    let spk = p2pk(&x);
    assert!(ring.resolve(v0(&spk), &[], None).unwrap().is_some());
    let v1 = |script| ScriptPublicKey { version: 1, script };
    assert!(ring.resolve(v1(&spk), &[], None).unwrap().is_none());
    assert!(ring
        .resolve(v1(&spk), &[], Some(Path::receive(0)))
        .unwrap()
        .is_none());
    let redeem = [0x51u8];
    assert!(ring
        .resolve(v1(&p2sh(&redeem)), &[], None)
        .unwrap()
        .is_none());
    assert_eq!(
        ring.resolve(v0(&p2sh(&redeem)), &[], None).err(),
        Some(keyring::Error::NoRedeemScript),
        "under version 0 the same script asks for its redeem"
    );
}

/// The search past the bank runs only for a request with no hint; a wrong hint
/// stops at the bank, so a lying PSKB with many derivations per input cannot
/// burn minutes searching after each.
#[test]
fn the_search_past_the_bank_needs_no_hint() {
    let w = hd(1);
    let ring = Keyring::new(&w).unwrap();
    let deep = Path::receive(RECEIVE_DEPTH + 30);
    let x = w.signing_key(deep).unwrap().x_only();
    let spk = p2pk(&x);
    assert!(ring.resolve(v0(&spk), &[], None).unwrap().is_some());
    assert!(ring
        .resolve(v0(&spk), &[], Some(Path::receive(0)))
        .unwrap()
        .is_none());
    // The right hint still wins outright, at no search cost.
    assert!(ring.resolve(v0(&spk), &[], Some(deep)).unwrap().is_some());
}

/// A multisig is matched only through its `45'` hint: a `44'` key of ours in
/// one is not ours (a v1.0.5 multisig, not recognised here). A covenant redeem
/// is searched like a single key, then refused as unshown; KCC-3's is never
/// searched under `44'`.
#[test]
fn a_multisig_is_matched_only_through_its_hint() {
    let (a, b) = (hd(1), hd(2));
    let deep = Path::receive(RECEIVE_DEPTH + 7);
    let xs = [
        a.signing_key(Path::receive(0)).unwrap().x_only(),
        b.signing_key(deep).unwrap().x_only(),
    ];
    let mut redeem = vec![0u8; 256];
    let n = redeem_script(2, &xs, &mut redeem).unwrap();
    redeem.truncate(n);
    let spk = p2sh(&redeem);

    // Past the bank: not ours in the script, ours as a single key.
    let ring = Keyring::new(&b).unwrap();
    assert!(ring.resolve(v0(&spk), &redeem, None).unwrap().is_none());
    assert!(ring
        .resolve(v0(&p2pk(&xs[1])), &[], None)
        .unwrap()
        .is_some());
    // In the bank: still not ours in a multisig script.
    let ring = Keyring::new(&a).unwrap();
    assert!(ring.resolve(v0(&spk), &redeem, None).unwrap().is_none());
    assert!(ring
        .resolve(v0(&p2pk(&xs[0])), &[], None)
        .unwrap()
        .is_some());
    // Even named by a `44'` path, as a bundle's derivations can, not ours: a
    // v1.0.5 multisig.
    assert!(ring
        .resolve(v0(&spk), &redeem, Some(Path::receive(0)))
        .unwrap()
        .is_none());

    // A covenant redeem holding the deep key: found by the search, then
    // refused, its script having no page.
    let ring = Keyring::new(&b).unwrap();
    let held = covenant(&[xs[1]]);
    assert_eq!(
        ring.resolve(v0(&p2sh(&held)), &held, None).err(),
        Some(keyring::Error::ScriptUnshown)
    );
    // KCC-3's script over that deep `44'` key: only the `22'` sweep searches
    // for KCC-3's, so not ours.
    let kcc3 = kcc3_redeem(&xs[1]);
    assert!(ring
        .resolve(v0(&p2sh(&kcc3)), &kcc3, None)
        .unwrap()
        .is_none());
}

/// A bank key whose private key at its path disagrees with it is refused: the
/// bank comes from the chains' public keys, the signing key from the seed's
/// private ones, and a signature by the wrong key spends nothing. A
/// stranger's first bank key stands in for the disagreement.
#[test]
fn a_bank_key_its_private_key_disagrees_with_is_refused() {
    let w = hd(1);
    let chains = keyring::chain_keys(&w).unwrap();
    let mut bank: [(Path, [u8; 32]); keyring::BANK] =
        core::array::from_fn(|k| keyring::bank_key(&w, chains.as_ref(), k).unwrap());
    let stranger = hd(2).signing_key(Path::receive(0)).unwrap().x_only();
    assert_eq!(bank[0].0, Path::receive(0));
    bank[0].1 = stranger;
    let ring = Keyring::from_bank(&w, bank, chains);

    assert_eq!(
        ring.resolve(v0(&p2pk(&stranger)), &[], None).err(),
        Some(keyring::Error::KeyMismatch)
    );
    // The bank's other keys still sign.
    let x = w.signing_key(Path::receive(1)).unwrap().x_only();
    assert_eq!(
        ring.resolve(v0(&p2pk(&x)), &[], None)
            .unwrap()
            .expect("ours")
            .key
            .x_only(),
        x
    );
}

/// A raw key signs no multisig, hint or none, having no child for a `45'`
/// address; its single-key script is still its own.
#[test]
fn a_raw_key_signs_no_multisig() {
    let me = key(1);
    let x = x_only(&me);
    let ring = Keyring::new(&me).unwrap();
    let mut redeem = vec![0u8; 256];
    let n = redeem_script(1, &[x, x_only(&key(3))], &mut redeem).unwrap();
    redeem.truncate(n);
    let spk = p2sh(&redeem);
    for hint in [None, Some(Path::receive(0)), Some(FIRST)] {
        assert!(ring.resolve(v0(&spk), &redeem, hint).unwrap().is_none());
    }
    assert!(ring.resolve_in_bank(v0(&spk), &redeem).unwrap().is_none());
    assert!(ring.resolve(v0(&p2pk(&x)), &[], None).unwrap().is_some());
}

/// A multisig input is signed at the hinted `45'` key's position; a hint naming
/// a key the script lacks is ignored, leaving the input not ours.
#[test]
fn a_hint_names_the_multisig_key_and_a_wrong_one_is_ignored() {
    let (a, b, c) = (hd(1), hd(2), hd(3));
    let path = |cosigner| Path::Multisig {
        cosigner,
        chain: 0,
        index: 4,
    };
    // A 2-of-3 over the three wallets' 45' keys, each at its cosigner index.
    let xs: Vec<[u8; 32]> = [&a, &b, &c]
        .iter()
        .enumerate()
        .map(|(i, w)| w.signing_key(path(i as u32)).unwrap().x_only())
        .collect();
    let mut redeem = vec![0u8; 256];
    let n = redeem_script(2, &xs, &mut redeem).unwrap();
    redeem.truncate(n);
    let spk = p2sh(&redeem);

    let right = Hint {
        index: 0,
        cosigner: 1,
        chain: 0,
        addr_index: 4,
    };
    let ring = Keyring::new(&b).unwrap();
    let m = ring
        .resolve(v0(&spk), &redeem, path_of_hint(right))
        .unwrap()
        .expect("ours");
    assert_eq!(m.position, 1);
    assert_eq!(m.key.x_only(), xs[1]);

    // The wrong address index: the hinted key is not in the script, and the
    // bank holds no 45' key, so the input is not ours.
    let wrong = Hint {
        addr_index: 5,
        ..right
    };
    assert!(ring
        .resolve(v0(&spk), &redeem, path_of_hint(wrong))
        .unwrap()
        .is_none());
    assert!(ring.resolve(v0(&spk), &redeem, None).unwrap().is_none());

    // A wallet that is not a cosigner, hint or no hint.
    let nine = hd(9);
    let other = Keyring::new(&nine).unwrap();
    assert!(other
        .resolve(v0(&spk), &redeem, path_of_hint(right))
        .unwrap()
        .is_none());
}

/// A hint's branch is a cosigner's place among the script's keys, as
/// rusty-kaspa sets it, so one at or past their count names no address of
/// the group: it counts as no hint, and the input is not ours even when the
/// script holds the key it names. At the last branch below the count it
/// signs.
#[test]
fn a_hint_past_the_key_count_is_no_hint() {
    let (a, b, c) = (hd(1), hd(2), hd(3));
    let path = |cosigner| Path::Multisig {
        cosigner,
        chain: 0,
        index: 4,
    };
    let ring = Keyring::new(&b).unwrap();
    for (branch, ours) in [(2, true), (3, false), (1 << 20, false)] {
        // A 2-of-3 whose third key is this wallet's at `branch`.
        let xs = [
            a.signing_key(path(0)).unwrap().x_only(),
            c.signing_key(path(1)).unwrap().x_only(),
            b.signing_key(path(branch)).unwrap().x_only(),
        ];
        let mut redeem = vec![0u8; 256];
        let n = redeem_script(2, &xs, &mut redeem).unwrap();
        redeem.truncate(n);
        let spk = p2sh(&redeem);
        let found = ring.resolve(v0(&spk), &redeem, Some(path(branch))).unwrap();
        assert_eq!(found.is_some(), ours, "branch {branch}");
        if let Some(m) = found {
            assert_eq!(m.position, 2);
        }
    }
}

/// A KSPT hint reaches the reply: a 45' multisig input is signed at the
/// hinted position with the hinted key.
#[test]
fn a_kspt_hint_reaches_the_reply() {
    let (a, b) = (hd(1), hd(2));
    let path = |cosigner| Path::Multisig {
        cosigner,
        chain: 0,
        index: 0,
    };
    let xs = [
        a.signing_key(path(0)).unwrap().x_only(),
        b.signing_key(path(1)).unwrap().x_only(),
    ];
    let mut redeem = vec![0u8; 256];
    let n = redeem_script(2, &xs, &mut redeem).unwrap();
    redeem.truncate(n);
    let spk = p2sh(&redeem);
    let mut req = request(
        &[In {
            amount: 100_000 * KAS,
            spk: &spk,
            redeem: &redeem,
            sigs: &[],
        }],
        &[(90_000 * KAS, &spk)],
    );
    // Input 0, cosigner 1, chain 0, address 0.
    req.extend_from_slice(&input_hint(0, 1, 0, 0));

    let (r, out) = with_kspt(&req, true, |s, k| kspt_reply(s, k, &b)).expect("reply");
    assert_eq!(r.signed, 1);
    let sigs = sigs_on(&out, 0);
    assert_eq!(sigs.len(), 1);
    assert_eq!(sigs[0].0, 1, "at the hinted cosigner's position");
    let sig: [u8; 64] = sigs[0].2.as_slice().try_into().unwrap();
    with_kspt(&req, true, |s, _| {
        let digest = schnorr_signature_hash(s.transaction(), 0, SIG_HASH_ALL).expect("an input");
        assert!(bip340::verify(&xs[1], &digest, &sig), "with the hinted key");
    });
}

/// A hint off the receive and change chains, or with a hardened number, is no
/// hint: a multisig key on chain 7, at no address the wallet shows, is not this
/// seed's, and a hardened hint falls to the bank instead of failing the
/// request.
#[test]
fn a_hint_off_the_wallets_chains_is_no_hint() {
    use kassigner_crypto::wallet::WalletError;
    use kassigner_kaspa::bip32_public::ChildNumber;
    use kassigner_kaspa::derivation::MULTISIG_ACCOUNT;

    let hint = |cosigner, chain, addr_index| input_hint(0, cosigner, chain, addr_index);

    // Chain 7.
    let (a, b) = (hd(1), hd(2));
    let on = |chain| Path::Multisig {
        cosigner: 1,
        chain,
        index: 0,
    };
    // The key on chain 7, from the seed itself: the wallet refuses a chain
    // no address of it is on.
    let off_chain = {
        let m = bip39::from_entropy(&[2; 16]).unwrap();
        let mut scratch = vec![0u8; bip39::scratch_for(0)];
        let seed = bip39::to_seed(&m, "", &mut scratch).unwrap();
        let key = ExtendedPrivateKey::from_seed(seed.as_bytes())
            .unwrap()
            .derive_path(&MULTISIG_ACCOUNT)
            .unwrap()
            .derive_path(&[ChildNumber(1), ChildNumber(7), ChildNumber(0)])
            .unwrap()
            .public_key();
        <[u8; 32]>::try_from(&key[1..]).unwrap()
    };
    assert_eq!(
        b.signing_key(on(7)).err(),
        Some(WalletError::Chain { chain: 7 })
    );
    let xs = [a.signing_key(on(0)).unwrap().x_only(), off_chain];
    let mut redeem = vec![0u8; 256];
    let n = redeem_script(2, &xs, &mut redeem).unwrap();
    redeem.truncate(n);
    let spk = p2sh(&redeem);
    let mut req = request(
        &[In {
            amount: 100_000 * KAS,
            spk: &spk,
            redeem: &redeem,
            sigs: &[],
        }],
        &[(90_000 * KAS, &spk)],
    );
    req.extend_from_slice(&hint(1, 7, 0));
    assert_eq!(
        with_kspt(&req, true, |s, k| kspt_reply(s, k, &b)).err(),
        Some(Error::NothingSigned)
    );

    // Hardened numbers, on a key of the bank's.
    let mine = b.signing_key(Path::receive(0)).unwrap().x_only();
    let spk = p2pk(&mine);
    for bad in [
        hint(1 << 31, 0, 0),
        hint(1, 1 << 31, 0),
        hint(1, 0, 1 << 31),
    ] {
        let mut req = request(
            &[In {
                amount: 100_000 * KAS,
                spk: &spk,
                redeem: &[],
                sigs: &[],
            }],
            &[(90_000 * KAS, &spk)],
        );
        req.extend_from_slice(&bad);
        let (r, _) = with_kspt(&req, true, |s, k| kspt_reply(s, k, &b)).expect("signed");
        assert_eq!(r.signed, 1);
    }

    // The paths themselves.
    use kassigner_protocol::kspt::Hint;
    let h = |cosigner, chain, addr_index| Hint {
        index: 0,
        cosigner,
        chain,
        addr_index,
    };
    for chain in [0, 1] {
        assert_eq!(
            path_of_hint(h(1, chain, 4)),
            Some(Path::Multisig {
                cosigner: 1,
                chain,
                index: 4
            })
        );
    }
    assert_eq!(path_of_hint(h(1, 2, 4)), None);
    assert_eq!(path_of_hint(h(1, 7, 4)), None);
    assert_eq!(path_of_hint(h(1 << 31, 0, 4)), None);
    assert_eq!(path_of_hint(h(1, 0, u32::MAX)), None);
    assert_eq!(
        keyring::path_of(b"m/44'/111111'/0'/1/3"),
        Some(Path::Single { chain: 1, index: 3 })
    );
    assert_eq!(keyring::path_of(b"m/44'/111111'/0'/2/3"), None);
    assert_eq!(keyring::path_of(b"m/44'/111111'/0'/7/0"), None);
    assert_eq!(
        keyring::path_of(b"m/45'/111111'/0'/1/0/4"),
        Some(Path::Multisig {
            cosigner: 1,
            chain: 0,
            index: 4
        })
    );
    assert_eq!(keyring::path_of(b"m/45'/111111'/0'/1/7/4"), None);
}

/// A `45'` multisig bundle input is signed through the derivation path naming
/// our cosigner key, which the bank lacks; without it, the input is not ours.
#[test]
fn a_pskb_derivation_names_the_multisig_key() {
    let (a, b) = (hd(1), hd(2));
    let path = |cosigner| Path::Multisig {
        cosigner,
        chain: 0,
        index: 4,
    };
    let kb = b.signing_key(path(1)).unwrap();
    let xs = [a.signing_key(path(0)).unwrap().x_only(), kb.x_only()];
    let mut redeem = vec![0u8; 256];
    let n = redeem_script(2, &xs, &mut redeem).unwrap();
    redeem.truncate(n);
    let spk = p2sh(&redeem);
    let source = derivation(kb.public_key(), "m/45'/111111'/0'/1/0/4");
    let one = |derivations: &str| {
        bundle(&[bundle_tx(
            &[PIn {
                amount: 100_000 * KAS,
                spk: &spk,
                redeem: Some(&redeem),
                sighash: Some(1),
                partial: "",
                derivations,
            }],
            &[(90_000 * KAS, &spk)],
        )])
    };
    let with = one(&source);
    let (r, out) = with_pskb(&with, |s| pskb_reply(s, &with, &b)).expect("reply");
    assert_eq!(r.signed, 1);
    let text = unwrap(&out);
    assert!(text.contains(&format!("\"{}\":{{\"schnorr\"", hex(kb.public_key()))));
    assert!(text.contains(&source), "the coordinator's entry survives");

    let without = one("");
    assert_eq!(
        with_pskb(&without, |s| pskb_reply(s, &without, &b)).err(),
        Some(Error::NothingSigned)
    );
}

/// A bundle's `44'` derivation path is no multisig hint (a KSPT's cosigner hint
/// is always `45'`): a multisig over `44'` keys is v1.0.5's, not recognised
/// here.
#[test]
fn a_44_path_in_a_bundle_is_no_multisig_hint() {
    let (a, b) = (hd(1), hd(2));
    let kb = b.signing_key(Path::receive(0)).unwrap();
    let xs = [x_only(&a), kb.x_only()];
    let mut redeem = vec![0u8; 256];
    let n = redeem_script(2, &xs, &mut redeem).unwrap();
    redeem.truncate(n);
    let spk = p2sh(&redeem);
    let recorded = derivation(kb.public_key(), "m/44'/111111'/0'/0/0");
    let doc = bundle(&[bundle_tx(
        &[PIn {
            amount: 100_000 * KAS,
            spk: &spk,
            redeem: Some(&redeem),
            sighash: Some(1),
            partial: "",
            derivations: &recorded,
        }],
        &[(90_000 * KAS, &spk)],
    )]);
    assert_eq!(
        with_pskb(&doc, |s| pskb_reply(s, &doc, &b)).err(),
        Some(Error::NothingSigned)
    );
}

// ── Plans ───────────────────────────────────────────────────────────────────

use kassigner_fw::reply::Plan;

fn with_kspt_unconfirmed<R>(
    bytes: &[u8],
    f: impl FnOnce(&mut Session<'_>, &kspt::Kspt<'_>) -> R,
) -> R {
    let k = kspt::parse(bytes, &P).expect("parse");
    let (mut ins, mut outs) = arrays();
    let (ni, no) = kspt_tx::fill(&k, &mut ins, &mut outs).expect("fill");
    let tx = kspt_tx::build(&k, &ins[..ni], &outs[..no]);
    let mut s = Session::new(tx).expect("session");
    f(&mut s, &k)
}

fn with_pskb_unconfirmed<R>(doc: &[u8], f: impl FnOnce(&mut Session<'_>) -> R) -> R {
    let (mut ins, mut outs) = arrays();
    let mut bytes = [0u8; 2048];
    let filled = pskb_tx::fill(doc, 0, &mut ins, &mut outs, &mut bytes).expect("fill");
    let tx = pskb_tx::build(
        &filled.header,
        &ins[..filled.inputs],
        &outs[..filled.outputs],
    );
    let mut s = Session::new(tx).expect("session");
    f(&mut s)
}

fn kspt_plan(
    s: &Session<'_>,
    k: &kspt::Kspt<'_>,
    w: &Wallet,
    ceiling: usize,
) -> Result<Plan, Error> {
    let keys = Keyring::new(w).expect("keyring");
    let mut scratch = [InputSignature::EMPTY; 8];
    reply::plan_kspt(s, k, &keys, &P, ceiling, &mut scratch)
}

fn pskb_plan(s: &Session<'_>, doc: &[u8], w: &Wallet, ceiling: usize) -> Result<Plan, Error> {
    let keys = Keyring::new(w).expect("keyring");
    let mut redeem = [0u8; 512];
    reply::plan_pskb(s, doc, &keys, ceiling, &mut redeem)
}

/// **A KSPT plan, made before the review, is the reply exactly, and a
/// ceiling one byte short refuses it.**
#[test]
fn a_kspt_plan_is_the_reply_before_the_review() {
    let me = key(1);
    let spk = p2pk(&x_only(&me));
    let one = In {
        amount: 100_000 * KAS,
        spk: &spk,
        redeem: &[],
        sigs: &[],
    };
    let req = request(
        &[
            one,
            In {
                amount: 50_000 * KAS,
                ..one
            },
        ],
        &[(140_000 * KAS, &spk)],
    );
    with_kspt_unconfirmed(&req, |s, k| {
        let plan = kspt_plan(s, k, &me, 14_528).expect("plan before the review");
        assert_eq!(plan.signatures, 2);
        assert!(matches!(
            kspt_reply(s, k, &me),
            Err(Error::Session(session::Error::NotReviewed { .. }))
        ));

        confirm(s);
        let (r, out) = kspt_reply(s, k, &me).expect("reply");
        assert_eq!((r.signed, r.len), (plan.signatures, plan.len));
        assert_eq!(out.len(), plan.len);

        assert_eq!(
            kspt_plan(s, k, &me, plan.len - 1),
            Err(Error::TooLargeToShow {
                needed: plan.len,
                ceiling: plan.len - 1
            })
        );
        assert_eq!(kspt_plan(s, k, &me, plan.len), Ok(plan));
    });
}

/// **A KSPT plan refuses what the reply refuses.**
#[test]
fn a_kspt_plan_refuses_what_the_reply_refuses() {
    let me = key(1);
    let mine = p2pk(&x_only(&me));
    let theirs = p2pk(&x_only(&key(2)));
    let not_ours = request(
        &[In {
            amount: 100_000 * KAS,
            spk: &theirs,
            redeem: &[],
            sigs: &[],
        }],
        &[(90_000 * KAS, &theirs)],
    );
    assert_eq!(
        with_kspt_unconfirmed(&not_ours, |s, k| kspt_plan(s, k, &me, 14_528)).err(),
        Some(Error::NothingSigned)
    );
    let signed_with = |sig: [u8; 64]| {
        request(
            &[In {
                amount: 100_000 * KAS,
                spk: &mine,
                redeem: &[],
                sigs: &[(0, SIG_HASH_ALL.to_u8(), sig)],
            }],
            &[(90_000 * KAS, &mine)],
        )
    };
    let signed = signed_with(signed_by(
        kspt_digest(&signed_with([0; 64]), 0),
        &me,
        Path::receive(0),
    ));
    assert_eq!(
        with_kspt_unconfirmed(&signed, |s, k| kspt_plan(s, k, &me, 14_528)).err(),
        Some(Error::AlreadySigned {
            input: 0,
            position: 0
        })
    );
}

/// Every signature a KSPT request holds is checked in the plan, before any
/// page: a failing one, one at a keyless position, one of another sighash type,
/// or a made-up one at ours is refused; a cosigner's valid one, checked by the
/// script's key alone, stays beside ours.
#[test]
fn a_kspt_requests_signatures_are_checked_on_arrival() {
    let (a, b, c) = (hd(1), hd(2), hd(3));
    let redeem = multisig(2, &[&a, &b, &c], FIRST);
    let spk = p2sh(&redeem);
    let with = |sigs: &[(u8, u8, [u8; 64])]| {
        let mut req = request(
            &[In {
                amount: 100_000 * KAS,
                spk: &spk,
                redeem: &redeem,
                sigs,
            }],
            &[(90_000 * KAS, &spk)],
        );
        req.extend_from_slice(&input_hint(0, 0, 0, 0));
        req
    };
    let digest = kspt_digest(&with(&[]), 0);
    let theirs = signed_by(digest, &a, FIRST);
    let all = SIG_HASH_ALL.to_u8();
    let plan = |req: &[u8]| with_kspt_unconfirmed(req, |s, k| kspt_plan(s, k, &c, 14_528));

    assert!(
        plan(&with(&[(0, all, theirs)])).is_ok(),
        "a cosigner's that verifies"
    );
    let mut bent = theirs;
    bent[10] ^= 1;
    for sigs in [
        [(0, all, bent)],
        [(0, all, [0xaa; 64])],
        [(1, all, theirs)],
        [(5, all, theirs)],
        [(2, all, [7u8; 64])],
    ] {
        assert_eq!(
            plan(&with(&sigs)).err(),
            Some(Error::BadSignature { input: 0 }),
            "position {}",
            sigs[0].0
        );
    }
    assert_eq!(
        plan(&with(&[(0, 0x81, theirs)])).err(),
        Some(Error::SighashNotAll { input: 0 })
    );
    // Ours, already, at our position: `AlreadySigned`.
    let ours = signed_by(digest, &c, FIRST);
    assert_eq!(
        plan(&with(&[(2, all, ours)])).err(),
        Some(Error::AlreadySigned {
            input: 0,
            position: 2
        })
    );
}

/// **Every member of a bundle's `partialSigs` is checked in the plan,** as a
/// KSPT's are: a key not in the script, a failing Schnorr signature, and an
/// ECDSA one, which this device cannot check, are refused.
#[test]
fn a_bundles_signatures_are_checked_on_arrival() {
    let (a, b, c) = (hd(1), hd(2), hd(3));
    let redeem = multisig(2, &[&a, &b, &c], FIRST);
    let spk = p2sh(&redeem);
    let recorded = derivation(c.signing_key(FIRST).unwrap().public_key(), FIRST_PATH);
    let with = |partial: &str| {
        bundle(&[bundle_tx(
            &[PIn {
                amount: 100_000 * KAS,
                spk: &spk,
                redeem: Some(&redeem),
                sighash: Some(1),
                partial,
                derivations: &recorded,
            }],
            &[(90_000 * KAS, &spk)],
        )])
    };
    let digest = pskb_digest(&with(""), 0);
    let ka = a.signing_key(FIRST).unwrap();
    let member = |key: &[u8], value: String| format!("\"{}\":{}", hex(key), value);
    let schnorr = |sig: &[u8; 64]| format!("{{\"schnorr\":\"{}\"}}", hex(sig));
    let theirs = signed_by(digest, &a, FIRST);
    let plan = |doc: &[u8]| with_pskb_unconfirmed(doc, |s| pskb_plan(s, doc, &c, 1 << 20));

    assert!(
        plan(&with(&member(ka.public_key(), schnorr(&theirs)))).is_ok(),
        "a cosigner's that verifies"
    );
    let mut bent = theirs;
    bent[10] ^= 1;
    let stranger = hd(9).signing_key(FIRST).unwrap();
    for partial in [
        member(ka.public_key(), schnorr(&bent)),
        member(
            stranger.public_key(),
            schnorr(&signed_by(digest, &hd(9), FIRST)),
        ),
        member(
            ka.public_key(),
            "{\"eCDSA\":\"3006020101020101\"}".to_string(),
        ),
    ] {
        assert_eq!(
            plan(&with(&partial)).err(),
            Some(Error::BadSignature { input: 0 }),
            "{partial}"
        );
    }
}

/// A version 0 multisig input committing fewer signature operations than keys
/// is refused on arrival: some cosigner sets could never spend it, and every
/// cosigner's hash fixes the count. More is the fee's business; from version 1
/// a compute budget outside the hash replaces it.
#[test]
fn a_v0_multisig_input_commits_an_operation_per_key() {
    let (a, b, c) = (hd(1), hd(2), hd(3));
    let redeem = multisig(2, &[&a, &b, &c], FIRST);
    let spk = p2sh(&redeem);
    let kspt_at = |version: u16, ops: u8| {
        let mut req = request_at(
            version,
            ops,
            &[In {
                amount: 100_000 * KAS,
                spk: &spk,
                redeem: &redeem,
                sigs: &[],
            }],
            &[(90_000 * KAS, &spk)],
        );
        req.extend_from_slice(&input_hint(0, 0, 0, 0));
        req
    };
    let kspt_plan_of = |req: &[u8]| with_kspt_unconfirmed(req, |s, k| kspt_plan(s, k, &a, 14_528));
    let too_few = Some(Error::TooFewSigOps {
        input: 0,
        count: 2,
        keys: 3,
    });
    assert!(kspt_plan_of(&kspt_at(0, 3)).is_ok());
    assert!(kspt_plan_of(&kspt_at(0, 4)).is_ok(), "more than its keys");
    assert_eq!(kspt_plan_of(&kspt_at(0, 2)).err(), too_few);
    assert!(kspt_plan_of(&kspt_at(1, 2)).is_ok(), "version 1");

    let recorded = derivation(a.signing_key(FIRST).unwrap().public_key(), FIRST_PATH);
    let bundle_at = |version: u16, ops: u8| {
        bundle(&[bundle_tx_at(
            version,
            ops,
            &[PIn {
                amount: 100_000 * KAS,
                spk: &spk,
                redeem: Some(&redeem),
                sighash: Some(1),
                partial: "",
                derivations: &recorded,
            }],
            &[(90_000 * KAS, &spk)],
        )])
    };
    let pskb_plan_of = |doc: &[u8]| with_pskb_unconfirmed(doc, |s| pskb_plan(s, doc, &a, 1 << 20));
    assert!(pskb_plan_of(&bundle_at(0, 3)).is_ok());
    assert_eq!(pskb_plan_of(&bundle_at(0, 2)).err(), too_few);
    assert!(pskb_plan_of(&bundle_at(1, 2)).is_ok(), "version 1");

    // A single key at version 0, one operation: planned.
    let mine = p2pk(&x_only(&a));
    let single = request_at(
        0,
        1,
        &[In {
            amount: 100_000 * KAS,
            spk: &mine,
            redeem: &[],
            sigs: &[],
        }],
        &[(90_000 * KAS, &mine)],
    );
    assert!(kspt_plan_of(&single).is_ok());
}

/// A version 0 single-key input committing no signature operation is refused on
/// arrival, Schnorr or ECDSA: with only the free allowance, a tenth of one
/// check, it can never be spent. From version 1 nothing is refused.
#[test]
fn a_v0_single_key_input_commits_an_operation() {
    let a = hd(1);
    let mine = p2pk(&x_only(&a));
    let mut ecdsa = vec![0x21];
    ecdsa.extend_from_slice(&public(&hd(2)));
    ecdsa.push(0xab);
    let none = Some(Error::NoSigOp { input: 0 });

    let kspt_at = |version: u16, ops: u8, first: &[u8]| {
        let input = |spk| In {
            amount: 100_000 * KAS,
            spk,
            redeem: &[],
            sigs: &[],
        };
        request_at(
            version,
            ops,
            &[input(first), input(&mine)],
            &[(190_000 * KAS, &mine)],
        )
    };
    let kspt_plan_of = |req: &[u8]| with_kspt_unconfirmed(req, |s, k| kspt_plan(s, k, &a, 14_528));
    for first in [&mine, &ecdsa] {
        assert_eq!(kspt_plan_of(&kspt_at(0, 0, first)).err(), none);
        assert!(kspt_plan_of(&kspt_at(0, 1, first)).is_ok());
        assert!(kspt_plan_of(&kspt_at(0, 2, first)).is_ok(), "more than one");
        assert!(kspt_plan_of(&kspt_at(1, 0, first)).is_ok(), "version 1");
    }

    let bundle_at = |version: u16, ops: u8, first: &[u8]| {
        let input = |spk| PIn {
            amount: 100_000 * KAS,
            spk,
            redeem: None,
            sighash: Some(1),
            partial: "",
            derivations: "",
        };
        bundle(&[bundle_tx_at(
            version,
            ops,
            &[input(first), input(&mine)],
            &[(190_000 * KAS, &mine)],
        )])
    };
    let pskb_plan_of = |doc: &[u8]| with_pskb_unconfirmed(doc, |s| pskb_plan(s, doc, &a, 1 << 20));
    for first in [&mine, &ecdsa] {
        assert_eq!(pskb_plan_of(&bundle_at(0, 0, first)).err(), none);
        assert!(pskb_plan_of(&bundle_at(0, 1, first)).is_ok());
        assert!(pskb_plan_of(&bundle_at(1, 0, first)).is_ok(), "version 1");
    }
}

/// **A PSKB plan, made before the review, bounds the reply from above, with
/// and without a recorded key source, and refuses what the reply refuses.**
#[test]
fn a_pskb_plan_bounds_the_reply_before_the_review() {
    let me = key(1);
    let spk = p2pk(&x_only(&me));
    let pk = hex(&public(&me));
    let recorded = format!(
        "\"{pk}\":{{\"keyFingerprint\":\"abcdef01\",\"derivationPath\":\"m/44'/111111'/0'/0/0\"}}"
    );
    for derivations in [String::new(), recorded] {
        let input = |amount| PIn {
            amount,
            spk: &spk,
            redeem: None,
            sighash: Some(1),
            partial: "",
            derivations: &derivations,
        };
        let doc = bundle(&[bundle_tx(
            &[input(100_000 * KAS), input(50_000 * KAS)],
            &[(140_000 * KAS, &spk)],
        )]);
        with_pskb_unconfirmed(&doc, |s| {
            let plan = pskb_plan(s, &doc, &me, 1 << 20).expect("plan before the review");
            assert_eq!(plan.signatures, 2);
            confirm(s);
            let (r, out) = pskb_reply(s, &doc, &me).expect("reply");
            assert_eq!(r.signed, plan.signatures);
            assert_eq!(out.len(), r.len);
            assert!(r.len <= plan.len, "{} over the bound {}", r.len, plan.len);
            assert_eq!(
                pskb_plan(s, &doc, &me, plan.len - 1),
                Err(Error::TooLargeToShow {
                    needed: plan.len,
                    ceiling: plan.len - 1
                })
            );
        });
    }

    let one = bundle_tx(
        &[PIn {
            amount: 100_000 * KAS,
            spk: &spk,
            redeem: None,
            sighash: Some(1),
            partial: "",
            derivations: "",
        }],
        &[(90_000 * KAS, &spk)],
    );
    let two = bundle(&[one.clone(), one]);
    assert_eq!(
        with_pskb_unconfirmed(&two, |s| pskb_plan(s, &two, &me, 1 << 20)).err(),
        Some(Error::NotOneTransaction { count: 2 })
    );
    let not_ours = bundle(&[bundle_tx(
        &[PIn {
            amount: 100_000 * KAS,
            spk: &p2pk(&x_only(&key(2))),
            redeem: None,
            sighash: Some(1),
            partial: "",
            derivations: "",
        }],
        &[(90_000 * KAS, &spk)],
    )]);
    assert_eq!(
        with_pskb_unconfirmed(&not_ours, |s| pskb_plan(s, &not_ours, &me, 1 << 20)).err(),
        Some(Error::NothingSigned)
    );
}

/// A multisig past the device's limit, or with no threshold, is refused as
/// unsupported, not read as some other script with keys in it.
#[test]
fn a_multisig_past_the_device_limit_is_refused() {
    use kassigner_fw::limits::MAX_MULTISIG_KEYS;
    let w = hd(1);
    let ring = Keyring::new(&w).unwrap();
    let mine = w.signing_key(FIRST).unwrap().x_only();
    let group = |m: usize, n: usize| {
        let mut xs: Vec<[u8; 32]> = (1..n).map(|i| [i as u8; 32]).collect();
        xs.insert(0, mine);
        let mut out = vec![0u8; kassigner_kaspa::multisig::redeem_script_len(m, n)];
        let len = redeem_script(m, &xs, &mut out).unwrap();
        out.truncate(len);
        out
    };
    // Each redeem gets the script that locks to it, since a mismatch is
    // refused before anything about the multisig is read.
    let five = group(2, MAX_MULTISIG_KEYS);
    let hint = Some(FIRST);
    assert!(ring
        .resolve(v0(&p2sh(&five)), &five, hint)
        .unwrap()
        .is_some());
    let six = group(2, MAX_MULTISIG_KEYS + 1);
    assert_eq!(
        ring.resolve(v0(&p2sh(&six)), &six, hint).err(),
        Some(keyring::Error::UnsupportedMultisig {
            required: 2,
            keys: 6
        })
    );
    let none_required = group(0, 3);
    assert_eq!(
        ring.resolve(v0(&p2sh(&none_required)), &none_required, hint)
            .err(),
        Some(keyring::Error::UnsupportedMultisig {
            required: 0,
            keys: 3
        })
    );
}

/// A multisig that repeats a key is refused, ours or not, hint or none: our key
/// twice is spent by us alone while the review says 2-of-2, and a unit signs
/// its first place only, then is "already signed": no unit finishes the spend.
/// The same keys once each still resolve.
#[test]
fn a_multisig_that_repeats_a_key_is_refused() {
    let w = hd(1);
    let ring = Keyring::new(&w).unwrap();
    let mine = w.signing_key(FIRST).unwrap().x_only();
    let other = [7u8; 32];
    let script = |m: usize, keys: &[[u8; 32]]| {
        let mut out = vec![0u8; kassigner_kaspa::multisig::redeem_script_len(m, keys.len())];
        let len = redeem_script(m, keys, &mut out).unwrap();
        out.truncate(len);
        out
    };
    let once = script(2, &[mine, other]);
    assert!(ring
        .resolve(v0(&p2sh(&once)), &once, Some(FIRST))
        .unwrap()
        .is_some());
    for (m, keys, position) in [
        (2, &[mine, mine][..], 1),
        (2, &[mine, other, mine][..], 2),
        (2, &[other, mine, other][..], 2),
    ] {
        let redeem = script(m, keys);
        for hint in [Some(FIRST), None] {
            assert_eq!(
                ring.resolve(v0(&p2sh(&redeem)), &redeem, hint).err(),
                Some(keyring::Error::RepeatedKey { position }),
                "{keys:02x?} {hint:?}"
            );
        }
    }
}

/// A multisig in a non-standard form, such as a 2-of-3 with its threshold
/// pushed as a byte and a key repeated, is `ScriptUnshown`, hint or none,
/// whoever's keys it holds; in the standard form, its repeated key is what is
/// refused.
#[test]
fn a_multisig_in_another_form_is_refused_as_unshown() {
    let w = hd(1);
    let ring = Keyring::new(&w).unwrap();
    let mine = w.signing_key(FIRST).unwrap().x_only();
    let other = [7u8; 32];
    for keys in [[mine, other, other], [[8; 32], other, other]] {
        let mut standard = vec![0u8; kassigner_kaspa::multisig::redeem_script_len(2, 3)];
        let len = redeem_script(2, &keys, &mut standard).unwrap();
        standard.truncate(len);
        assert_eq!(standard[0], 0x52, "OP_2");
        let mut byte = vec![0x01, 0x02];
        byte.extend_from_slice(&standard[1..]);
        for hint in [Some(FIRST), None] {
            assert_eq!(
                ring.resolve(v0(&p2sh(&byte)), &byte, hint).err(),
                Some(keyring::Error::ScriptUnshown),
                "{hint:?}"
            );
        }
        assert_eq!(
            ring.resolve(v0(&p2sh(&standard)), &standard, Some(FIRST))
                .err(),
            Some(keyring::Error::RepeatedKey { position: 2 })
        );
    }
}

/// A key of ours under a covenant script is refused, by hint, bank or reply: no
/// page shows an input's script, so signing would agree to unseen terms.
/// `key_at` still places such a key, for when a page shows the script.
#[test]
fn a_covenant_input_of_ours_is_refused_as_unshown() {
    let me = key(1);
    let mine = x_only(&me);
    let redeem = covenant(&[[0x11; 32], mine, [0x22; 32]]);
    let spk = p2sh(&redeem);
    let ring = Keyring::new(&me).unwrap();
    for hint in [None, Some(Path::receive(0))] {
        assert_eq!(
            ring.resolve(v0(&spk), &redeem, hint).err(),
            Some(keyring::Error::ScriptUnshown),
            "{hint:?}"
        );
    }
    let req = request(
        &[In {
            amount: 100_000 * KAS,
            spk: &spk,
            redeem: &redeem,
            sigs: &[],
        }],
        &[(90_000 * KAS, &spk)],
    );
    assert_eq!(
        with_kspt(&req, true, |s, k| kspt_reply(s, k, &me)).err(),
        Some(Error::Keyring {
            input: 0,
            error: keyring::Error::ScriptUnshown
        })
    );
}

/// A covenant naming no key of ours signs nothing, rather than being signed
/// with whatever key the bank happens to start with.
#[test]
fn a_covenant_that_names_no_key_of_ours_is_not_ours() {
    let me = key(1);
    let redeem = covenant(&[[0x11; 32], [0x22; 32]]);
    let spk = p2sh(&redeem);
    let req = request(
        &[In {
            amount: 100_000 * KAS,
            spk: &spk,
            redeem: &redeem,
            sigs: &[],
        }],
        &[(90_000 * KAS, &spk)],
    );
    assert_eq!(
        with_kspt(&req, true, |s, k| kspt_reply(s, k, &me)).err(),
        Some(Error::NothingSigned)
    );
}

/// A redeem script that is not the one the input locks to fails the whole
/// request: the network would never run it, so whoever sent it is broken or
/// trying something.
#[test]
fn a_redeem_that_is_not_the_inputs_own_is_refused() {
    let me = key(1);
    let mine = x_only(&me);
    let redeem = covenant(&[mine]);
    let other = covenant(&[mine, [0x33; 32]]);
    let spk = p2sh(&other);
    let ring = Keyring::new(&me).unwrap();
    assert_eq!(
        ring.resolve(v0(&spk), &redeem, None).err(),
        Some(keyring::Error::RedeemMismatch)
    );
    let req = request(
        &[In {
            amount: 100_000 * KAS,
            spk: &spk,
            redeem: &redeem,
            sigs: &[],
        }],
        &[(90_000 * KAS, &spk)],
    );
    assert_eq!(
        with_kspt(&req, true, |s, k| kspt_reply(s, k, &me)).err(),
        Some(Error::Keyring {
            input: 0,
            error: keyring::Error::RedeemMismatch
        })
    );
}

/// The sweep's paths end with the sweep: each key once, past the bank on one
/// chain, and none past the end, rather than a walk until a count overflows.
#[test]
fn the_sweeps_paths_end_with_the_sweep() {
    use kassigner_fw::keyring::{sweep_path, SWEEP};
    let paths: Vec<Path> = (0..SWEEP)
        .map(|i| sweep_path(i).expect("inside the sweep"))
        .collect();
    for i in RECEIVE_DEPTH..SEARCH_DEPTH {
        assert!(paths.contains(&Path::receive(i)), "receive {i}");
    }
    for i in CHANGE_DEPTH..SEARCH_DEPTH {
        assert!(paths.contains(&Path::change(i)), "change {i}");
    }
    assert_eq!(
        paths.len(),
        (2 * SEARCH_DEPTH - RECEIVE_DEPTH - CHANGE_DEPTH) as usize
    );
    for i in [SWEEP, SWEEP + 1, usize::MAX] {
        assert_eq!(sweep_path(i), None, "{i}");
    }
}

/// A bundle's wrong paths stop at the bank, as a KSPT's wrong hint does: a key
/// the search finds for a silent bundle is not ours when every path names
/// another, so a lying bundle gets no wider search.
#[test]
fn a_bundles_wrong_paths_stop_at_the_bank() {
    let w = hd(1);
    let key = w.signing_key(Path::receive(RECEIVE_DEPTH + 3)).unwrap();
    let spk = p2pk(&key.x_only());
    let with = |derivations: &str| {
        bundle(&[bundle_tx(
            &[PIn {
                amount: 100_000 * KAS,
                spk: &spk,
                redeem: None,
                sighash: Some(1),
                partial: "",
                derivations,
            }],
            &[(90_000 * KAS, &spk)],
        )])
    };

    // Saying nothing of it, the search past the bank finds it.
    let silent = with("");
    assert_eq!(
        with_pskb(&silent, |s| pskb_reply(s, &silent, &w)).map(|(r, _)| r.signed),
        Ok(1)
    );

    // A path to another address: the bank only, which does not hold it.
    let wrong = with(&format!(
        "\"{}\":{{\"keyFingerprint\":\"abcdef01\",\"derivationPath\":\"m/44'/111111'/0'/0/5\"}}",
        hex(key.public_key())
    ));
    assert_eq!(
        with_pskb(&wrong, |s| pskb_reply(s, &wrong, &w)).err(),
        Some(Error::NothingSigned)
    );
}

/// A bundle path with escapes is the same hint, as serde_json decodes `m\/44'`
/// to `m/44'` before upstream reads it; read raw, a key past the search would
/// go unfound.
#[test]
fn a_path_written_with_escapes_is_the_same_hint() {
    let plain = keyring::path_of(b"m/44'/111111'/0'/0/999");
    assert_eq!(
        plain,
        Some(Path::Single {
            chain: 0,
            index: 999
        })
    );
    for written in [
        &br"m\/44'\/111111'\/0'\/0\/999"[..],
        br"\u006d/44'/111111'/0'/0/999",
        br"m/44\u0027/111111'/0'/0/9\u00399",
    ] {
        assert_eq!(
            keyring::path_of(written),
            plain,
            "{}",
            String::from_utf8_lossy(written)
        );
    }
    assert_eq!(keyring::path_of(br"m/44'/111111'/0'/0/\u00e9"), None);
}

// ── KCC-3 ───────────────────────────────────────────────────────────────────

use kassigner_crypto::bip32::ExtendedPrivateKey;
use kassigner_fw::keyring::{kcc3_bank_key, kcc3_bank_path, kcc3_chain_keys, KCC3_BANK};
use kassigner_kaspa::derivation::SINGLE_ACCOUNT;
use kassigner_kaspa::script::{kcc3_redeem, kcc3_script_hash};

/// `w`'s KCC-3 key at `path`, its redeem script, and the lock of its
/// address.
fn kcc3_input(w: &Wallet, path: Path) -> ([u8; 32], Vec<u8>, Vec<u8>) {
    let x = w.signing_key(path).unwrap().x_only();
    let redeem = kcc3_redeem(&x).to_vec();
    let spk = p2sh(&redeem);
    (x, redeem, spk)
}

/// The seed `fill` gives [`hd`], imported as its `44'` account xprv: no
/// `22'` tree above it.
fn account_xprv(fill: u8) -> Wallet {
    let m = bip39::from_entropy(&[fill; 16]).unwrap();
    let mut scratch = vec![0u8; bip39::scratch_for(0)];
    let seed = bip39::to_seed(&m, "", &mut scratch).unwrap();
    let account = ExtendedPrivateKey::from_seed(seed.as_bytes())
        .unwrap()
        .derive_path(&SINGLE_ACCOUNT)
        .unwrap();
    Wallet::open(&Slot::Xprv(account), &mut scratch).unwrap()
}

/// A KCC-3 input is signed by its bank key at position zero, receive or change;
/// a `22'` path finds one past the bank, and one naming another key is ignored.
#[test]
fn a_kcc3_input_is_signed_with_its_bank_key() {
    let w = hd(1);
    let ring = Keyring::new(&w).unwrap();
    for path in [
        Path::kcc3_receive(0),
        Path::kcc3_receive(RECEIVE_DEPTH - 1),
        Path::kcc3_change(0),
        Path::kcc3_change(CHANGE_DEPTH - 1),
    ] {
        let (x, redeem, spk) = kcc3_input(&w, path);
        let m = ring
            .resolve(v0(&spk), &redeem, None)
            .unwrap()
            .expect("ours");
        assert_eq!((m.position, m.shape), (0, None), "{path:?}");
        assert_eq!(m.key.x_only(), x, "{path:?}");
    }

    let past = Path::kcc3_receive(RECEIVE_DEPTH + 30);
    let (x, redeem, spk) = kcc3_input(&w, past);
    assert!(
        ring.resolve_in_bank(v0(&spk), &redeem).unwrap().is_none(),
        "past the bank"
    );
    let m = ring
        .resolve(v0(&spk), &redeem, Some(past))
        .unwrap()
        .expect("its path");
    assert_eq!(m.key.x_only(), x);

    let (x, redeem, spk) = kcc3_input(&w, Path::kcc3_receive(0));
    let m = ring
        .resolve(v0(&spk), &redeem, Some(past))
        .unwrap()
        .expect("the bank's");
    assert_eq!(m.key.x_only(), x);
}

/// **Only KCC-3's keys sign KCC-3's script:** the script over a `44'` key, a
/// KCC-3 key under another script, and a raw key's are refused as unshown, path
/// or none; an account xprv, with no `22'` tree, holds no KCC-3 key.
#[test]
fn only_kcc3_keys_sign_kcc3s_script() {
    let w = hd(1);
    let ring = Keyring::new(&w).unwrap();
    let unshown = Some(keyring::Error::ScriptUnshown);

    let x = x_only(&w);
    let redeem = kcc3_redeem(&x);
    let spk = p2sh(&redeem);
    for hint in [None, Some(Path::receive(0))] {
        assert_eq!(
            ring.resolve(v0(&spk), &redeem, hint).err(),
            unshown,
            "a 44' key, {hint:?}"
        );
    }

    let hidden = w.signing_key(Path::kcc3_receive(2)).unwrap().x_only();
    let redeem = covenant(&[[0x11; 32], hidden]);
    let spk = p2sh(&redeem);
    for hint in [None, Some(Path::kcc3_receive(2))] {
        assert_eq!(
            ring.resolve(v0(&spk), &redeem, hint).err(),
            unshown,
            "a KCC-3 key in a covenant, {hint:?}"
        );
    }

    let xprv = account_xprv(1);
    assert!(!xprv.has_kcc3());
    let ring = Keyring::new(&xprv).unwrap();
    let (_, redeem, spk) = kcc3_input(&w, Path::kcc3_receive(0));
    assert!(ring.resolve_in_bank(v0(&spk), &redeem).unwrap().is_none());
    assert!(ring
        .resolve(v0(&spk), &redeem, Some(Path::kcc3_receive(0)))
        .unwrap()
        .is_none());
    assert_eq!(
        ring.kcc3_change_index(&kcc3_script_hash(
            &w.signing_key(Path::kcc3_change(0)).unwrap().x_only()
        )),
        None
    );

    let raw = key(1);
    let ring = Keyring::new(&raw).unwrap();
    let redeem = kcc3_redeem(&x_only(&raw));
    let spk = p2sh(&redeem);
    assert_eq!(ring.resolve_in_bank(v0(&spk), &redeem).err(), unshown);
    assert_eq!(
        ring.resolve(v0(&spk), &redeem, Some(Path::kcc3_receive(0)))
            .err(),
        unshown
    );
}

/// The KCC-3 bank is the wallet's `22'` keys, and a bank key its private key
/// disagrees with is refused, as for the first bank (a stranger's first key
/// stands in).
#[test]
fn the_kcc3_bank_is_the_wallets_and_checked_against_it() {
    let w = hd(1);
    assert_eq!(KCC3_BANK, keyring::BANK);
    let chains = kcc3_chain_keys(&w).unwrap().expect("a seed has the tree");
    let mut keys: [[u8; 32]; KCC3_BANK] =
        core::array::from_fn(|k| kcc3_bank_key(&chains, k).unwrap());
    for (k, key) in keys.iter().enumerate() {
        let path = kcc3_bank_path(k);
        assert!(path.is_kcc3());
        assert_eq!(*key, w.signing_key(path).unwrap().x_only(), "{path:?}");
    }
    assert_eq!(kcc3_bank_path(0), Path::kcc3_receive(0));
    assert_eq!(kcc3_bank_path(RECEIVE_DEPTH as usize), Path::kcc3_change(0));
    assert!(kcc3_chain_keys(&account_xprv(1)).unwrap().is_none());
    assert!(kcc3_chain_keys(&key(1)).unwrap().is_none());

    let stranger = hd(2).signing_key(Path::kcc3_receive(0)).unwrap().x_only();
    keys[0] = stranger;
    let ring = Keyring::new(&w).unwrap().with_kcc3(keys, chains);
    let redeem = kcc3_redeem(&stranger);
    assert_eq!(
        ring.resolve(v0(&p2sh(&redeem)), &redeem, None).err(),
        Some(keyring::Error::KeyMismatch)
    );
    let (x, redeem, spk) = kcc3_input(&w, Path::kcc3_receive(1));
    assert_eq!(
        ring.resolve(v0(&spk), &redeem, None)
            .unwrap()
            .expect("the bank's other keys still sign")
            .key
            .x_only(),
        x
    );
}

/// **A KCC-3 change output is known by its script hash:** only the KCC-3 bank's
/// change keys match, each at its own index.
#[test]
fn a_kcc3_change_is_known_by_its_script_hash() {
    let w = hd(1);
    let ring = Keyring::new(&w).unwrap();
    let hash = |path| kcc3_script_hash(&w.signing_key(path).unwrap().x_only());
    for k in 0..CHANGE_DEPTH {
        assert_eq!(
            ring.kcc3_change_index(&hash(Path::kcc3_change(k))),
            Some(k),
            "{k}"
        );
    }
    for path in [
        Path::kcc3_receive(0),
        Path::kcc3_change(CHANGE_DEPTH),
        Path::change(0),
    ] {
        assert_eq!(ring.kcc3_change_index(&hash(path)), None, "{path:?}");
    }
    let hidden = w.signing_key(Path::kcc3_change(0)).unwrap().x_only();
    assert_eq!(
        ring.change_index(&hidden),
        None,
        "a KCC-3 key is no pay-to-key change"
    );
}

/// A KCC-3 input is signed at position zero in a KSPT, from the bank, read back
/// and verified; and in a bundle, past the bank too, through its `22'`
/// derivation path, which the reply keeps.
#[test]
fn a_kcc3_input_is_answered_in_a_kspt_and_a_bundle() {
    let w = hd(1);
    let (x, redeem, spk) = kcc3_input(&w, Path::kcc3_receive(4));
    let req = request(
        &[In {
            amount: 100_000 * KAS,
            spk: &spk,
            redeem: &redeem,
            sigs: &[],
        }],
        &[(90_000 * KAS, &spk)],
    );
    let (r, out) = with_kspt(&req, true, |s, k| kspt_reply(s, k, &w)).expect("reply");
    assert_eq!(r.signed, 1);
    with_kspt(&req, true, |s, _| {
        assert_eq!(reply::verify_kspt(&out, s.transaction(), &P), Ok(1));
    });
    let sigs = sigs_on(&out, 0);
    assert_eq!(sigs.len(), 1);
    assert_eq!((sigs[0].0, sigs[0].1), (0, SIG_HASH_ALL.to_u8()));
    let sig: [u8; 64] = sigs[0].2.clone().try_into().unwrap();
    assert!(bip340::verify(&x, &kspt_digest(&req, 0), &sig));

    let past = w.signing_key(Path::kcc3_receive(50)).unwrap();
    let redeem = kcc3_redeem(&past.x_only());
    let spk = p2sh(&redeem);
    let source = derivation(past.public_key(), "m/22'/111111'/0'/0/50");
    let doc = bundle(&[bundle_tx(
        &[PIn {
            amount: 100_000 * KAS,
            spk: &spk,
            redeem: Some(&redeem),
            sighash: Some(1),
            partial: "",
            derivations: &source,
        }],
        &[(90_000 * KAS, &spk)],
    )]);
    let (r, out) = with_pskb(&doc, |s| pskb_reply(s, &doc, &w)).expect("reply");
    assert_eq!(r.signed, 1);
    let text = unwrap(&out);
    assert!(text.contains(&format!("\"{}\":{{\"schnorr\"", hex(past.public_key()))));
    assert!(text.contains(&source), "the coordinator's entry survives");
}

/// **A version 0 KCC-3 input must commit its one signature operation,** as a
/// single key's must: its redeem makes one check, so with none it can never be
/// spent.
#[test]
fn a_v0_kcc3_input_commits_an_operation() {
    let w = hd(1);
    let (_, redeem, spk) = kcc3_input(&w, Path::kcc3_receive(0));
    let mine = p2pk(&x_only(&w));
    let none = Some(Error::NoSigOp { input: 0 });

    let kspt_at = |version: u16, ops: u8| {
        request_at(
            version,
            ops,
            &[
                In {
                    amount: 100_000 * KAS,
                    spk: &spk,
                    redeem: &redeem,
                    sigs: &[],
                },
                In {
                    amount: 100_000 * KAS,
                    spk: &mine,
                    redeem: &[],
                    sigs: &[],
                },
            ],
            &[(190_000 * KAS, &mine)],
        )
    };
    let plan = |req: &[u8]| with_kspt_unconfirmed(req, |s, k| kspt_plan(s, k, &w, 14_528));
    assert_eq!(plan(&kspt_at(0, 0)).err(), none);
    assert!(plan(&kspt_at(0, 1)).is_ok());
    assert!(plan(&kspt_at(1, 0)).is_ok(), "version 1");

    let bundle_at = |version: u16, ops: u8| {
        bundle(&[bundle_tx_at(
            version,
            ops,
            &[
                PIn {
                    amount: 100_000 * KAS,
                    spk: &spk,
                    redeem: Some(&redeem),
                    sighash: Some(1),
                    partial: "",
                    derivations: "",
                },
                PIn {
                    amount: 100_000 * KAS,
                    spk: &mine,
                    redeem: None,
                    sighash: Some(1),
                    partial: "",
                    derivations: "",
                },
            ],
            &[(190_000 * KAS, &mine)],
        )])
    };
    let plan = |doc: &[u8]| with_pskb_unconfirmed(doc, |s| pskb_plan(s, doc, &w, 1 << 20));
    assert_eq!(plan(&bundle_at(0, 0)).err(), none);
    assert!(plan(&bundle_at(0, 1)).is_ok());
    assert!(plan(&bundle_at(1, 0)).is_ok(), "version 1");
}

/// **A KSPT's KCC-3 hint is a KCC-3 path**, receive or change, soft below the
/// account; another chain or a hardened number is no hint.
#[test]
fn a_kcc3_hint_is_a_kcc3_path() {
    use kassigner_fw::keyring::path_of_kcc3_hint;
    use kassigner_protocol::kspt::Kcc3Hint;
    let hint = |chain, addr_index| Kcc3Hint {
        index: 0,
        chain,
        addr_index,
    };
    assert_eq!(path_of_kcc3_hint(hint(0, 57)), Some(Path::kcc3_receive(57)));
    assert_eq!(path_of_kcc3_hint(hint(1, 4)), Some(Path::kcc3_change(4)));
    assert_eq!(path_of_kcc3_hint(hint(2, 4)), None);
    assert_eq!(path_of_kcc3_hint(hint(0, 0x8000_0000)), None);
}

/// **A KSPT's single-key hint is a single-key path**, receive or change, soft
/// below the account at any depth; another chain or a hardened number is no
/// hint.
#[test]
fn a_single_key_hint_is_a_single_key_path() {
    use kassigner_fw::keyring::path_of_account_hint;
    use kassigner_protocol::kspt::AccountHint;
    let hint = |chain, addr_index| AccountHint {
        index: 0,
        chain,
        addr_index,
    };
    assert_eq!(
        path_of_account_hint(hint(0, 1500)),
        Some(Path::receive(1500))
    );
    assert_eq!(
        path_of_account_hint(hint(1, 0x7fff_ffff)),
        Some(Path::change(0x7fff_ffff))
    );
    assert_eq!(path_of_account_hint(hint(2, 4)), None);
    assert_eq!(path_of_account_hint(hint(0, 0x8000_0000)), None);
}

/// **A bundle's `22'` path is a KCC-3 path**, receive or change, soft below
/// account `0'`, and nothing else is.
#[test]
fn a_22_path_in_a_bundle_is_a_kcc3_path() {
    assert_eq!(
        keyring::path_of(b"m/22'/111111'/0'/1/7"),
        Some(Path::kcc3_change(7))
    );
    assert_eq!(
        keyring::path_of(b"m/22'/111111'/0'/0/0"),
        Some(Path::kcc3_receive(0))
    );
    for path in [
        &b"m/22'/111111'/0'/2/7"[..],
        b"m/22'/111111'/1'/0/0",
        b"m/22'/111111'/0'/0/7'",
        b"m/22'/111111'/0'/0/0/0",
        b"m/22'/111111/0'/0/0",
        b"m/22/111111'/0'/0/0",
    ] {
        assert_eq!(
            keyring::path_of(path),
            None,
            "{}",
            String::from_utf8_lossy(path)
        );
    }
}

/// An address-only KCC-3 input, known only by its hash, is signed by the key
/// whose script hashes to it (bank, `22'` path or search), with that script
/// supplied; any other hash without a redeem is still refused.
#[test]
fn an_address_only_kcc3_input_is_supplied_its_redeem() {
    let w = hd(1);
    let ring = Keyring::new(&w).unwrap();
    for path in [Path::kcc3_receive(3), Path::kcc3_change(CHANGE_DEPTH - 1)] {
        let (x, redeem, spk) = kcc3_input(&w, path);
        let m = ring.resolve(v0(&spk), &[], None).unwrap().expect("ours");
        assert_eq!((m.position, m.shape), (0, None), "{path:?}");
        assert_eq!(m.key.x_only(), x);
        assert_eq!(m.supplied.map(|r| r.to_vec()), Some(redeem), "{path:?}");
    }
    // A redeem the request does carry is not supplied again.
    let (_, redeem, spk) = kcc3_input(&w, Path::kcc3_receive(3));
    let m = ring
        .resolve(v0(&spk), &redeem, None)
        .unwrap()
        .expect("ours");
    assert_eq!(m.supplied, None);

    let none = Some(keyring::Error::NoRedeemScript);
    let past = Path::kcc3_receive(RECEIVE_DEPTH + 30);
    let (x, redeem, spk) = kcc3_input(&w, past);
    for hint in [None, Some(past)] {
        let m = ring
            .resolve(v0(&spk), &[], hint)
            .unwrap()
            .expect("searched for, or its path");
        assert_eq!(m.key.x_only(), x, "{hint:?}");
        assert_eq!(m.supplied.map(|r| r.to_vec()), Some(redeem.clone()));
    }
    let (_, _, beyond) = kcc3_input(&w, Path::kcc3_receive(SEARCH_DEPTH));
    assert_eq!(
        ring.resolve(v0(&beyond), &[], None).err(),
        none,
        "past the search"
    );

    let single = kcc3_redeem(&x_only(&w));
    assert_eq!(ring.resolve(v0(&p2sh(&single)), &[], None).err(), none);
    let group = multisig(1, &[&w], FIRST);
    assert_eq!(
        ring.resolve(v0(&p2sh(&group)), &[], Some(FIRST)).err(),
        none
    );
    let (_, _, spk) = kcc3_input(&w, Path::kcc3_receive(3));
    let xprv = account_xprv(1);
    assert_eq!(
        Keyring::new(&xprv)
            .unwrap()
            .resolve(v0(&spk), &[], Some(Path::kcc3_receive(3)))
            .err(),
        none
    );
    let raw = key(1);
    let (_, _, spk) = kcc3_input(&raw, Path::kcc3_receive(0));
    assert_eq!(
        Keyring::new(&raw)
            .unwrap()
            .resolve(v0(&spk), &[], None)
            .err(),
        none
    );
}

/// The flow's KCC-3 sweep is its own: a KCC-3 input the keyring cannot place
/// counts as a KCC-3 miss, never a single-signature one; the KCC-3 window's key
/// places it, kept once the window moves, and single-signature lookups never
/// see it. Once the sweep ends, an unfound address with no redeem is refused.
#[test]
fn the_kcc3_sweep_is_its_own() {
    use kassigner_fw::keyring::kcc3_sweep_path;
    let w = hd(1);
    let mut ring = Keyring::new(&w).unwrap();
    ring.set_search(false);
    let past = Path::kcc3_receive(RECEIVE_DEPTH + 30);
    let (x, redeem, spk) = kcc3_input(&w, past);
    let i = (0..keyring::SWEEP)
        .find(|&i| kcc3_sweep_path(i) == Some(past))
        .expect("on the sweep");
    assert_eq!(ring.kcc3_sweep_key(i).unwrap(), Some(x));

    for r in [&redeem[..], &[]] {
        ring.forget_found();
        assert!(ring.resolve(v0(&spk), r, None).unwrap().is_none());
        assert_eq!((ring.misses(), ring.kcc3_misses()), (0, 1), "{r:?}");
    }
    // Its own key's script in a pay-to-key lock is a single key's lookup:
    // the KCC-3 window is no part of it.
    assert!(ring.kcc3_window_push(i, x));
    assert!(ring.resolve(v0(&p2pk(&x)), &[], None).unwrap().is_none());
    assert_eq!(ring.misses(), 1);
    ring.clear_misses();
    let m = ring
        .resolve(v0(&spk), &[], None)
        .unwrap()
        .expect("the window's");
    assert_eq!(m.supplied.map(|r| r.to_vec()), Some(redeem.clone()));
    assert_eq!(ring.kcc3_misses(), 0);
    ring.keep_hits();
    assert_eq!(ring.window_len(), 0);
    let m = ring
        .resolve(v0(&spk), &redeem, None)
        .unwrap()
        .expect("kept");
    assert_eq!(m.key.x_only(), x);

    let (_, _, other) = kcc3_input(&w, Path::kcc3_receive(RECEIVE_DEPTH + 31));
    assert!(
        ring.resolve(v0(&other), &[], None).unwrap().is_none(),
        "pending"
    );
    ring.set_kcc3_swept(true);
    assert_eq!(
        ring.resolve(v0(&other), &[], None).err(),
        Some(keyring::Error::NoRedeemScript),
        "swept"
    );
    ring.forget_found();
    assert!(
        ring.resolve(v0(&other), &[], None).unwrap().is_none(),
        "a new request, pending again"
    );
}

/// **An address-only spend is answered with its redeem script in it,** in a
/// KSPT and a bundle, for whoever finishes the spend; the reply reads back and
/// verifies, and the plans bound it before the review, the KSPT's exactly.
#[test]
fn an_address_only_spend_is_answered_with_its_redeem() {
    let w = hd(1);
    let (x, redeem, spk) = kcc3_input(&w, Path::kcc3_receive(3));
    let req = request(
        &[In {
            amount: 100_000 * KAS,
            spk: &spk,
            redeem: &[],
            sigs: &[],
        }],
        &[(90_000 * KAS, &spk)],
    );
    let plan = with_kspt_unconfirmed(&req, |s, k| kspt_plan(s, k, &w, 14_528)).expect("plan");
    let (r, out) = with_kspt(&req, true, |s, k| kspt_reply(s, k, &w)).expect("reply");
    assert_eq!(r.signed, 1);
    assert_eq!(plan.len, out.len(), "the plan is the reply's length");
    with_kspt(&req, true, |s, _| {
        assert_eq!(reply::verify_kspt(&out, s.transaction(), &P), Ok(1));
    });
    let k = kspt::parse(&out, &P).expect("reply parses");
    assert_eq!(k.inputs().next().expect("input").redeem, &redeem[..]);
    let sigs = sigs_on(&out, 0);
    assert_eq!((sigs.len(), sigs[0].0), (1, 0));
    let sig: [u8; 64] = sigs[0].2.clone().try_into().unwrap();
    assert!(bip340::verify(&x, &kspt_digest(&req, 0), &sig));

    let doc = bundle(&[bundle_tx(
        &[PIn {
            amount: 100_000 * KAS,
            spk: &spk,
            redeem: None,
            sighash: Some(1),
            partial: "",
            derivations: "",
        }],
        &[(90_000 * KAS, &spk)],
    )]);
    let plan = with_pskb_unconfirmed(&doc, |s| pskb_plan(s, &doc, &w, 1 << 20)).expect("plan");
    with_pskb(&doc, |s| {
        let (r, out) = pskb_reply(s, &doc, &w).expect("reply");
        assert_eq!(r.signed, 1);
        assert!(out.len() <= plan.len, "the plan bounds the reply");
        let text = unwrap(&out);
        assert!(
            text.contains(&format!("\"redeemScript\":\"{}\"", hex(&redeem))),
            "{text}"
        );
        assert_eq!(
            text.matches("\"redeemScript\":null").count(),
            1,
            "the output's alone"
        );
        let keys = Keyring::new(&w).expect("keyring");
        let mut document = vec![0u8; out.len()];
        let mut scripts = [0u8; 2048];
        let mut scratch = [0u8; 512];
        let (mut ins, mut outs) = arrays();
        assert!(reply::verify_pskb(
            &out,
            s.transaction(),
            &keys,
            r.signed,
            reply::ReadBack {
                document: &mut document,
                scripts: &mut scripts,
                redeem: &mut scratch,
                inputs: &mut ins,
                outputs: &mut outs,
            },
        )
        .is_ok());
    });
}

/// **A version 0 address-only input must commit its one signature operation**
/// too: the supplied redeem makes the check.
#[test]
fn a_v0_address_only_input_commits_an_operation() {
    let w = hd(1);
    let (_, _, spk) = kcc3_input(&w, Path::kcc3_receive(0));
    let kspt_at = |ops: u8| {
        request_at(
            0,
            ops,
            &[In {
                amount: 100_000 * KAS,
                spk: &spk,
                redeem: &[],
                sigs: &[],
            }],
            &[(90_000 * KAS, &spk)],
        )
    };
    let plan = |req: &[u8]| with_kspt_unconfirmed(req, |s, k| kspt_plan(s, k, &w, 14_528));
    assert_eq!(plan(&kspt_at(0)).err(), Some(Error::NoSigOp { input: 0 }));
    assert!(plan(&kspt_at(1)).is_ok());
    let bundle_at = |ops: u8| {
        bundle(&[bundle_tx_at(
            0,
            ops,
            &[PIn {
                amount: 100_000 * KAS,
                spk: &spk,
                redeem: None,
                sighash: Some(1),
                partial: "",
                derivations: "",
            }],
            &[(90_000 * KAS, &spk)],
        )])
    };
    let plan = |doc: &[u8]| with_pskb_unconfirmed(doc, |s| pskb_plan(s, doc, &w, 1 << 20));
    assert_eq!(plan(&bundle_at(0)).err(), Some(Error::NoSigOp { input: 0 }));
    assert!(plan(&bundle_at(1)).is_ok());
}

// ── Time-Locked Savings cards ───────────────────────────────────────────────

use kassigner_protocol::card::savings::{Savings, UnlockAt};

/// 1 January 2027, 14:30 UTC, in minutes after 1970.
const CARD_AT: u32 = 20_819 * 1_440 + 14 * 60 + 30;

/// A card of `owner`, with `recovery` or none, unlocking on 1 January 2027
/// at 14:30 UTC.
fn card_of(owner: [u8; 32], recovery: Option<[u8; 32]>) -> Savings {
    Savings::new(owner, recovery, UnlockAt::new(CARD_AT).unwrap()).unwrap()
}

/// A version 0 request spending one UTXO of `card`, at `lock_time`, its
/// input at `sequence` committing `sig_ops`, paid to a stranger.
fn card_request(card: &Savings, lock_time: u64, sequence: u64, sig_ops: u8) -> Vec<u8> {
    let program = card.program();
    let spk = card.locking_script();
    let to = p2pk(&[0x42; 32]);
    let input = In {
        amount: 100_000 * KAS,
        spk: &spk,
        redeem: &program,
        sigs: &[],
    };
    request_timed(
        0,
        lock_time,
        sequence,
        sig_ops,
        &[input],
        &[(90_000 * KAS, &to)],
    )
}

/// The owner's seed and key, the recovery wallet's, and their card.
fn card_seeds() -> (Wallet, [u8; 32], Wallet, [u8; 32], Savings) {
    let (a, b) = (hd(1), hd(2));
    let owner = a.signing_key(Path::receive(3)).unwrap().x_only();
    let recovery = b.signing_key(Path::receive(0)).unwrap().x_only();
    (a, owner, b, recovery, card_of(owner, Some(recovery)))
}

/// **A card is signed by its owner at its program's first key, or by its
/// recovery wallet at the second** (by the owner at the first when it has
/// none), from the bank or a hint; not by a stranger, nor under a program not
/// the input's own.
#[test]
fn a_card_is_signed_as_its_owner_or_its_recovery_wallet() {
    let (a, owner, b, recovery, card) = card_seeds();
    let (program, spk) = (card.program(), card.locking_script());
    let ring = Keyring::new(&a).unwrap();
    for hint in [None, Some(Path::receive(3))] {
        let m = ring
            .resolve(v0(&spk), &program, hint)
            .unwrap()
            .expect("the owner's key");
        assert_eq!((m.position, m.shape, m.key.x_only()), (0, None, owner));
        assert!(m.supplied.is_none());
    }
    let m = Keyring::new(&b)
        .unwrap()
        .resolve(v0(&spk), &program, None)
        .unwrap()
        .expect("the recovery wallet's key");
    assert_eq!((m.position, m.key.x_only()), (1, recovery));
    assert!(Keyring::new(&hd(3))
        .unwrap()
        .resolve(v0(&spk), &program, None)
        .unwrap()
        .is_none());

    let alone = card_of(owner, None);
    let m = ring
        .resolve(v0(&alone.locking_script()), &alone.program(), None)
        .unwrap()
        .expect("the owner's key");
    assert_eq!((m.position, m.key.x_only()), (0, owner));
    assert_eq!(
        ring.resolve(v0(&spk), &alone.program(), None).err(),
        Some(keyring::Error::RedeemMismatch)
    );
}

/// **A card is signed by a `44'` key only:** its owner's change key is found in
/// the bank and by hint, but a hint naming its `45'` or `22'` key is no hint
/// for a card.
#[test]
fn a_card_is_signed_by_a_44_key_only() {
    let a = hd(1);
    let ring = Keyring::new(&a).unwrap();
    let change = Path::change(2);
    let owner = a.signing_key(change).unwrap().x_only();
    let card = card_of(owner, None);
    let (program, spk) = (card.program(), card.locking_script());
    for hint in [None, Some(change)] {
        let m = ring
            .resolve(v0(&spk), &program, hint)
            .unwrap()
            .expect("the change key");
        assert_eq!((m.position, m.key.x_only()), (0, owner));
    }
    let kcc3 = Path::Kcc3 { chain: 0, index: 0 };
    for path in [FIRST, kcc3] {
        let owner = a.signing_key(path).unwrap().x_only();
        let card = card_of(owner, None);
        let (program, spk) = (card.program(), card.locking_script());
        assert!(
            ring.resolve(v0(&spk), &program, Some(path))
                .unwrap()
                .is_none(),
            "{path:?}"
        );
    }
}

/// **A card's claim, by its owner or its recovery wallet, is planned, signed
/// and read back:** one `ALL` signature at the signer's place, which the plan
/// reports for the card's page.
#[test]
fn a_card_claim_is_planned_signed_and_read_back() {
    let (a, owner, b, recovery, card) = card_seeds();
    let req = card_request(&card, card.unlock().ms(), 0, 1);
    for (w, position, key) in [(&a, 0u8, owner), (&b, 1, recovery)] {
        with_kspt(&req, true, |s, k| {
            let plan = kspt_plan(s, k, w, 1 << 20).expect("planned");
            assert_eq!((plan.signatures, plan.inputs, plan.group), (1, 1, None));
            assert_eq!(plan.second, u32::from(position));
            let (_, out) = kspt_reply(s, k, w).expect("signed");
            let sigs = sigs_on(&out, 0);
            assert_eq!(sigs.len(), 1);
            assert_eq!((sigs[0].0, sigs[0].1), (position, SIG_HASH_ALL.to_u8()));
            let digest = schnorr_signature_hash(s.transaction(), 0, SIG_HASH_ALL).unwrap();
            let sig: &[u8; 64] = sigs[0].2.as_slice().try_into().unwrap();
            assert!(bip340::verify(&key, &digest, sig));
            assert!(reply::verify_kspt(&out, s.transaction(), &P).is_ok());
            // Read back by itself: one signature finishes a card's input.
            let found = with_kspt(&out, false, reply::kspt_itself).expect("read back");
            assert_eq!(
                (found.inputs, found.complete, found.group, found.second),
                (1, true, None, u32::from(position))
            );
        });
    }
}

/// **A card its program would refuse is refused on arrival,** whoever's it
/// is: a lock time before it opens, a millisecond or a minute, none, or a
/// DAA score; an input final.
#[test]
fn a_card_its_program_refuses_is_refused_on_arrival() {
    let (a, _, _, _, card) = card_seeds();
    let opens = card.unlock().ms();
    let stranger = hd(3);
    for (lock_time, sequence, why) in [
        (opens - 1, 0, Error::CardEarly { input: 0 }),
        (opens - 60_000, 0, Error::CardEarly { input: 0 }),
        (0, 0, Error::CardEarly { input: 0 }),
        (412_345_678, 0, Error::CardEarly { input: 0 }),
        (opens, u64::MAX, Error::CardFinal { input: 0 }),
    ] {
        let req = card_request(&card, lock_time, sequence, 1);
        with_kspt(&req, false, |s, k| {
            for w in [&a, &stranger] {
                assert_eq!(kspt_plan(s, k, w, 1 << 20).err(), Some(why), "{lock_time}");
            }
        });
    }
    // Its time, or after it, and not final: planned.
    for lock_time in [opens, opens + 1] {
        let req = card_request(&card, lock_time, 0, 1);
        with_kspt(&req, false, |s, k| {
            assert!(kspt_plan(s, k, &a, 1 << 20).is_ok())
        });
    }
}

/// **A card's input commits its one signature operation** under version 0.
#[test]
fn a_card_input_commits_its_signature_operation() {
    let (a, _, _, _, card) = card_seeds();
    let req = card_request(&card, card.unlock().ms(), 0, 0);
    with_kspt(&req, false, |s, k| {
        assert_eq!(
            kspt_plan(s, k, &a, 1 << 20).err(),
            Some(Error::NoSigOp { input: 0 })
        );
    });
}

/// **A relative lock is refused on arrival** on any input: a sequence other
/// than 0 or final. Final passes, as a PSKT writes it for an input naming none.
#[test]
fn a_relative_lock_is_refused_on_arrival() {
    let me = hd(1);
    let spk = p2pk(&x_only(&me));
    let input = In {
        amount: 100_000 * KAS,
        spk: &spk,
        redeem: &[],
        sigs: &[],
    };
    for (sequence, why) in [
        (5, Some(Error::Sequence { input: 0 })),
        (1 << 63, Some(Error::Sequence { input: 0 })),
        (u64::MAX - 1, Some(Error::Sequence { input: 0 })),
        (u64::MAX, None),
        (0, None),
    ] {
        let req = request_timed(0, 0, sequence, 1, &[input], &[(90_000 * KAS, &spk)]);
        with_kspt(&req, false, |s, k| {
            assert_eq!(kspt_plan(s, k, &me, 1 << 20).err(), why, "{sequence:#x}");
        });
    }
}

/// **A relative lock in a bundle is refused on arrival** as a KSPT's is:
/// a bundle's input states its sequence, or none, which is final.
#[test]
fn a_relative_lock_in_a_bundle_is_refused_on_arrival() {
    let me = hd(1);
    let spk = p2pk(&x_only(&me));
    let input = PIn {
        amount: 100_000 * KAS,
        spk: &spk,
        redeem: None,
        sighash: Some(1),
        partial: "",
        derivations: "",
    };
    let doc = String::from_utf8(bundle(&[bundle_tx(&[input], &[(90_000 * KAS, &spk)])])).unwrap();
    for (sequence, why) in [
        ("5", Some(Error::Sequence { input: 0 })),
        ("9223372036854775808", Some(Error::Sequence { input: 0 })),
        ("0", None),
        ("18446744073709551615", None),
        ("null", None),
    ] {
        let doc = doc
            .replacen("\"sequence\":null", &format!("\"sequence\":{sequence}"), 1)
            .into_bytes();
        let plan = with_pskb_unconfirmed(&doc, |s| pskb_plan(s, &doc, &me, 1 << 20));
        assert_eq!(plan.err(), why, "{sequence}");
    }
}

/// [`card_request`] as a bundle, `sequence` `null` for none (final), with the
/// key sources `derivations`.
fn card_bundle(
    card: &Savings,
    lock_time: u64,
    sequence: &str,
    sig_ops: u8,
    derivations: &str,
) -> Vec<u8> {
    let (program, spk) = (card.program(), card.locking_script());
    let to = p2pk(&[0x42; 32]);
    let input = PIn {
        amount: 100_000 * KAS,
        spk: &spk,
        redeem: Some(&program),
        sighash: Some(1),
        partial: "",
        derivations,
    };
    let tx = bundle_tx_at(0, sig_ops, &[input], &[(90_000 * KAS, &to)]).replacen(
        "\"sequence\":null,\"minTime\":null",
        &format!("\"sequence\":{sequence},\"minTime\":{lock_time}"),
        1,
    );
    bundle(&[tx])
}

/// **A card in a bundle is planned, signed and read back** as in a KSPT, by its
/// owner at the first place (by search or the bundle's path) or its recovery
/// wallet at the second; read by itself it is complete, a recovery said as one.
/// With no recovery wallet, the owner's key is there twice and its signature is
/// a claim.
#[test]
fn a_card_in_a_bundle_is_planned_signed_and_read_back() {
    let (a, owner, b, recovery, card) = card_seeds();
    let alone = card_of(owner, None);
    let owners = a.signing_key(Path::receive(3)).unwrap();
    let recoverys = b.signing_key(Path::receive(0)).unwrap();
    let hinted = derivation(owners.public_key(), "m/44'/111111'/0'/0/3");
    for (card, w, position, key, signer, sources) in [
        (&card, &a, 0u8, owner, owners.public_key(), ""),
        (&card, &a, 0, owner, owners.public_key(), hinted.as_str()),
        (&card, &b, 1, recovery, recoverys.public_key(), ""),
        (&alone, &a, 0, owner, owners.public_key(), ""),
    ] {
        let doc = card_bundle(card, card.unlock().ms(), "0", 1, sources);
        let plan =
            with_pskb_unconfirmed(&doc, |s| pskb_plan(s, &doc, w, 1 << 20)).expect("planned");
        assert_eq!(
            (plan.signatures, plan.inputs, plan.group, plan.second),
            (1, 1, None, u32::from(position))
        );
        let (r, out) = with_pskb(&doc, |s| pskb_reply(s, &doc, w)).expect("signed");
        assert_eq!(r.signed, 1);
        let text = unwrap(&out);
        let member = format!("\"{}\":{{\"schnorr\":\"", hex(signer));
        let at = text.find(&member).expect("the signer's member") + member.len();
        let sig: [u8; 64] = unhex_array(&text[at..at + 128]);
        assert!(bip340::verify(&key, &pskb_digest(&doc, 0), &sig));
        let mut redeem = [0u8; 512];
        let (found, _) = with_pskb(text.as_bytes(), |s| {
            reply::pskb_itself(s, text.as_bytes(), &mut redeem)
        })
        .expect("read by itself");
        assert_eq!(
            (found.inputs, found.complete, found.group, found.second),
            (1, true, None, u32::from(position))
        );
    }
}

/// **A card in a bundle its program would refuse is refused on arrival,** as in
/// a KSPT; read by itself, a card still locked is refused too.
#[test]
fn a_card_in_a_bundle_its_program_refuses_is_refused_on_arrival() {
    let (a, _, _, _, card) = card_seeds();
    let opens = card.unlock().ms();
    let stranger = hd(3);
    let early = Error::CardEarly { input: 0 };
    let last = Error::CardFinal { input: 0 };
    for (lock_time, sequence, sig_ops, why) in [
        (opens - 1, "0", 1, early),
        (0, "0", 1, early),
        (opens, "null", 1, last),
        (opens, "18446744073709551615", 1, last),
        (opens, "0", 0, Error::NoSigOp { input: 0 }),
    ] {
        let doc = card_bundle(&card, lock_time, sequence, sig_ops, "");
        // The card's own refusals come before any key is looked for; the
        // signature operation's after.
        let seeds = if sig_ops == 0 {
            vec![&a]
        } else {
            vec![&a, &stranger]
        };
        for w in seeds {
            let plan = with_pskb_unconfirmed(&doc, |s| pskb_plan(s, &doc, w, 1 << 20));
            assert_eq!(plan.err(), Some(why), "{lock_time} {sequence} {sig_ops}");
        }
    }
    let doc = card_bundle(&card, opens - 1, "0", 1, "");
    let mut redeem = [0u8; 512];
    let itself = with_pskb(&doc, |s| reply::pskb_itself(s, &doc, &mut redeem));
    assert_eq!(itself.err(), Some(early));
    // Its time, or after it, and not final: planned.
    for lock_time in [opens, opens + 1] {
        let doc = card_bundle(&card, lock_time, "0", 1, "");
        assert!(with_pskb_unconfirmed(&doc, |s| pskb_plan(s, &doc, &a, 1 << 20)).is_ok());
    }
}
