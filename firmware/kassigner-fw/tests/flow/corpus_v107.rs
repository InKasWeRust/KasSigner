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

//! The v1.0.7 corpus: SeedQRs a v1.0.7 unit shows and requests kassigner.org
//! 1.0.7 sends, taken as the units take them.

use super::*;

const ABANDON24: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
const ZOO12: &str = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong";

/// abandon 12's master fingerprint, as v1.0.7 wrote it into every bundle
/// it signed.
const ABANDON12_FINGERPRINT: [u8; 4] = [0x73, 0xc5, 0xda, 0x0a];

/// Scan a v1.0.7 SeedQR from the home grid and load it, standard or
/// compact: the unit ends on the home grid with it in use.
fn loaded_from<'b>(memory: &'b mut Memory, code: &[u8], words: usize) -> Flow<'b, 1> {
    let mut f = booted(memory, &[]);
    f.step(scan(), &mut Live);
    let out = f.step(Event::Code(code), &mut Live);
    assert_eq!(f.state(), State::Loading, "read, and waiting for Load");
    assert_eq!(out.screen, Screen::Loading { words });
    f.touch(answer(dialog::Target::Accept));
    f.step(no_passphrase(), &mut Live);
    opened(&mut f);
    f.step(home_button(), &mut Live);
    assert_eq!(f.state(), State::Home);
    f
}

/// A SeedQR a v1.0.7 unit shows loads its seed, standard or compact, 12
/// words or 24.
#[test]
fn a_seedqr_of_1_0_7_loads_its_seed() {
    let codes: [(&[u8], &str, usize); 6] = [
        (corpus!("seedqr/abandon12.standard"), ABANDON12, 12),
        (corpus!("seedqr/abandon12.compact"), ABANDON12, 12),
        (corpus!("seedqr/abandon24.standard"), ABANDON24, 24),
        (corpus!("seedqr/abandon24.compact"), ABANDON24, 24),
        (corpus!("seedqr/zoo12.standard"), ZOO12, 12),
        (corpus!("seedqr/zoo12.compact"), ZOO12, 12),
    ];
    assert_eq!(fingerprint_of(ABANDON12), ABANDON12_FINGERPRINT);
    for (code, words, count) in codes {
        let mut m = Memory::new();
        let f = loaded_from(&mut m, code, count);
        assert_eq!(f.fingerprint(), Some(fingerprint_of(words)), "{words}");
    }
}

/// A bundle's document as the device reads one: envelope opened,
/// kassigner.org 1.0.7's names put back to upstream's, a missing payload
/// filled.
fn bundle_doc(bytes: &[u8]) -> Vec<u8> {
    use kassigner_protocol::bundle;
    let mut doc = vec![0u8; bytes.len()];
    let n = kassigner_kaspa::pskb::decode_envelope(bytes, &mut doc).expect("envelope");
    bundle::upstream_names(&mut doc[..n]).expect("names");
    let n = bundle::fill_payload(&mut doc, n).expect("payload");
    doc.truncate(n);
    doc
}

/// The inputs of a bundle's one transaction.
fn bundle_spent(doc: &[u8]) -> Vec<Spent> {
    use kassigner_kaspa::pskb::{self, transaction as pskb_tx};
    let checked = pskb::check(doc).expect("checked");
    let mut ins = vec![blank_in(); 8];
    let mut outs = vec![blank_out(); 8];
    let mut scripts = vec![0u8; 4096];
    let filled = pskb_tx::fill(doc, 0, &mut ins, &mut outs, &mut scripts).expect("fill");
    let tx = pskb_tx::build(
        &filled.header,
        &ins[..filled.inputs],
        &outs[..filled.outputs],
    );
    (0..filled.inputs)
        .map(|i| {
            let mut buf = [0u8; 512];
            let redeem = pskb_tx::input_extras(checked, 0, i, &mut buf)
                .expect("extras")
                .redeem
                .to_vec();
            Spent {
                digest: schnorr_signature_hash(&tx, i, SIG_HASH_ALL).expect("an input"),
                script: tx.inputs[i].utxo_entry.script_public_key.script.to_vec(),
                redeem,
            }
        })
        .collect()
}

/// Who must have signed an input: a pay-to-key's own key, abandon 12's, or
/// under the 2-of-3 each of `cosigners` at address `index`, x-only.
fn signed_by(spent: &Spent, cosigners: &[&str], index: u32) -> Vec<[u8; 32]> {
    if spent.redeem.is_empty() {
        let s = &spent.script;
        assert_eq!((s.len(), s[0], s[33]), (34, 0x20, 0xac), "pay to a key");
        return vec![s[1..33].try_into().expect("a key")];
    }
    let keys = redeem_keys(&spent.redeem);
    cosigners
        .iter()
        .map(|kpub| {
            let x: [u8; 32] = cosigner_key(kpub, index)[1..].try_into().expect("x");
            assert!(keys.contains(&x), "a cosigner");
            x
        })
        .collect()
}

/// A KSPT reply: the transaction of `req`, and on every input a signature,
/// `SIGHASH_ALL`, from each key that must have signed it, at its place in a
/// redeem script, and from no other.
fn kspt_reply_holds(name: &str, req: &[u8], reply: &[u8], cosigners: &[&str], index: u32) {
    let asked = kspt_spent(&kspt::legacy::parse_any(req, &P).expect("request"));
    assert_eq!(reply[MAGIC.len()], VERSION, "{name}: answered as 0x06");
    let k = kspt::parse(reply, &P).unwrap_or_else(|e| panic!("{name}: {e:?}"));
    let signed = kspt_spent(&k);
    assert_eq!(signed.len(), asked.len(), "{name}: inputs");
    for (i, input) in k.inputs().enumerate() {
        let spent = &signed[i];
        assert_eq!(
            spent.digest, asked[i].digest,
            "{name}: input {i}: the request's"
        );
        let want = signed_by(spent, cosigners, index);
        let keys = if spent.redeem.is_empty() {
            want.clone()
        } else {
            redeem_keys(&spent.redeem)
        };
        let mut got = Vec::new();
        for sig in input.signatures() {
            assert_eq!(sig.sighash_type, SIG_HASH_ALL.to_u8(), "{name}: input {i}");
            let key = keys[usize::from(sig.pubkey_pos)];
            let bytes: &[u8; 64] = sig.bytes.try_into().expect("64 bytes");
            assert!(
                bip340::verify(&key, &spent.digest, bytes),
                "{name}: input {i}: the signature at {}",
                sig.pubkey_pos
            );
            got.push(key);
        }
        got.sort_unstable();
        let mut want = want;
        want.sort_unstable();
        assert_eq!(got, want, "{name}: input {i}: who signed");
    }
}

/// A bundle reply: the transaction of `req`, and on every input, in its
/// `partialSigs`, a signature from each key that must have signed it, and
/// from no other.
fn bundle_reply_holds(name: &str, req: &[u8], reply: &[u8], cosigners: &[&str], index: u32) {
    let asked = bundle_spent(&bundle_doc(req));
    let doc = bundle_doc(reply);
    let signed = bundle_spent(&doc);
    assert_eq!(signed.len(), asked.len(), "{name}: inputs");
    let checked = kassigner_kaspa::pskb::check(&doc).expect("checked");
    let text = core::str::from_utf8(&doc).expect("text");
    for (i, spent) in signed.iter().enumerate() {
        assert_eq!(
            spent.digest, asked[i].digest,
            "{name}: input {i}: the request's"
        );
        let mut want = signed_by(spent, cosigners, index);
        let mut got = Vec::new();
        kassigner_kaspa::pskb::signature::signers(checked, 0, i, |k| {
            got.push(k);
            true
        })
        .expect("signers");
        let mut xs: Vec<[u8; 32]> = got.iter().map(|k| k[1..].try_into().expect("x")).collect();
        xs.sort_unstable();
        want.sort_unstable();
        assert_eq!(xs, want, "{name}: input {i}: who signed");
        // Each signature is the value under its key; one written for another
        // input would be over another hash.
        for k in got {
            let key = hex(&k[..]);
            let open = format!("\"{key}\":{{\"schnorr\":\"");
            let verifies = text.match_indices(&open).any(|(at, _)| {
                let from = at + open.len();
                let sig: [u8; 64] = unhex_array(&text[from..from + 128]);
                let x: [u8; 32] = k[1..].try_into().expect("x");
                bip340::verify(&x, &spent.digest, &sig)
            });
            assert!(verifies, "{name}: input {i}: {key}'s signature");
        }
    }
}

/// Load `seed`, scan `req`, walk the review and sign: the reply.
fn signed_reply(
    seed: &[u8],
    words: usize,
    name: &str,
    req: &[u8],
) -> (Vec<u8>, kassigner_protocol::frame::Format) {
    let mut m = Memory::new();
    let mut f = loaded_from(&mut m, seed, words);
    f.step(scan(), &mut Live);
    deliver(&mut f, req);
    assert_eq!(f.state(), State::Reviewing, "{name}");
    let pages = match f.step(Event::Tick { now_us: 1 }, &mut Live).screen {
        Screen::Page { pages, .. } => pages,
        other => panic!("{name}: {other:?}"),
    };
    for _ in 1..pages {
        arrow(&mut f, RIGHT);
    }
    confirmed(&mut f);
    reply_shown(&mut f);
    (f.reply().to_vec(), f.reply_format())
}

/// The reply to `req` holds what it must, in the format `req` came in.
fn reply_holds(
    name: &str,
    req: &[u8],
    reply: (Vec<u8>, kassigner_protocol::frame::Format),
    cosigners: &[&str],
    index: u32,
) {
    let (reply, format) = reply;
    if req.starts_with(b"PSKB") {
        assert_eq!(format, kassigner_protocol::frame::Format::Pskb, "{name}");
        bundle_reply_holds(name, req, &reply, cosigners, index);
    } else {
        assert_eq!(format, kassigner_protocol::frame::Format::Kspt, "{name}");
        kspt_reply_holds(name, req, &reply, cosigners, index);
    }
}

/// Every request kassigner.org 1.0.7 sends is reviewed, signed and answered
/// by abandon 12, loaded from its v1.0.7 SeedQR: sends, many recipients, a
/// consolidation, and its part as the 2-of-3's first cosigner, from one
/// address and from three coins on another. A KSPT is answered in `0x06`, a
/// bundle in a bundle, each with the request's transaction and abandon
/// 12's signature on every input. A covenant's are refused (next test).
#[test]
fn every_request_kassigner_org_1_0_7_sends_is_signed() {
    let requests: [(&str, &[u8], u32); 12] = [
        ("kspt_send_1in", corpus!("site/kspt_send_1in.bin"), 0),
        ("kspt_send_3in", corpus!("site/kspt_send_3in.bin"), 0),
        ("kspt_compound", corpus!("site/kspt_compound.bin"), 0),
        ("kspt_consolidate", corpus!("site/kspt_consolidate.bin"), 0),
        ("kspt2_relay_send", corpus!("site/kspt2_relay_send.bin"), 0),
        (
            "kspt2_relay_multisig",
            corpus!("site/kspt2_relay_multisig.bin"),
            0,
        ),
        (
            "kspt2_relay_multisig_3in",
            corpus!("site/kspt2_relay_multisig_3in.bin"),
            1,
        ),
        ("pskb_send", corpus!("site/pskb_send.bin"), 0),
        ("pskb_send_utxos", corpus!("site/pskb_send_utxos.bin"), 0),
        ("pskb_compound", corpus!("site/pskb_compound.bin"), 0),
        ("pskb_multisig", corpus!("site/pskb_multisig.bin"), 0),
        (
            "pskb_multisig_3in",
            corpus!("site/pskb_multisig_3in.bin"),
            1,
        ),
    ];
    for (name, req, index) in requests {
        let reply = signed_reply(corpus!("seedqr/abandon12.compact"), 12, name, req);
        reply_holds(name, req, reply, &[ABANDON12_KPUB45], index);
    }
}

/// Load abandon 12, scan `req`, walk the review and sign: the flow at
/// SIGNED TX QR.
fn signed_flow<'b>(memory: &'b mut Memory, name: &str, req: &[u8]) -> Flow<'b, 1> {
    let mut f = loaded_from(memory, corpus!("seedqr/abandon12.compact"), 12);
    f.step(scan(), &mut Live);
    deliver(&mut f, req);
    assert_eq!(f.state(), State::Reviewing, "{name}");
    let pages = match f.step(Event::Tick { now_us: 1 }, &mut Live).screen {
        Screen::Page { pages, .. } => pages,
        other => panic!("{name}: {other:?}"),
    };
    for _ in 1..pages {
        arrow(&mut f, RIGHT);
    }
    let out = confirmed(&mut f);
    assert_eq!(out.screen, Screen::ReplyFormat, "{name}");
    f
}

/// A wallet built on v1.0.7 gets its answer in that release's form: for
/// each single-key request of kassigner.org 1.0.7, Wallet shows the reply
/// as a 1.0.7 unit wrote it, in as many codes, each a frame that release
/// reads, the signatures the very ones of the `0x06` reply. KasSigner still
/// shows the `0x06` reply in this version's frames, and Home wipes both.
#[test]
fn a_1_0_7_wallets_single_key_request_is_answered_as_1_0_7_answered() {
    use kassigner_protocol::frame;
    use kassigner_protocol::kspt::legacy;
    let requests: [(&str, &[u8], &[u8]); 3] = [
        (
            "kspt_send_1in",
            corpus!("site/kspt_send_1in.bin"),
            corpus!("device/kspt_send_1in.reply.bin"),
        ),
        (
            "kspt_send_3in",
            corpus!("site/kspt_send_3in.bin"),
            corpus!("device/kspt_send_3in.reply.bin"),
        ),
        (
            "kspt_consolidate",
            corpus!("site/kspt_consolidate.bin"),
            corpus!("device/kspt_consolidate.reply.bin"),
        ),
    ];
    for (name, req, unit) in requests {
        let mut m = Memory::new();
        let mut f = signed_flow(&mut m, name, req);

        // The reply as ever, and beside it the same signatures in 1.0.7's
        // form: the request's bytes, the signed flag, a signature an input.
        let canonical = f.reply().to_vec();
        kspt_reply_holds(name, req, &canonical, &[ABANDON12_KPUB45], 0);
        let signatures: Vec<[u8; 64]> = kspt::parse(&canonical, &P)
            .expect("the reply")
            .inputs()
            .map(|i| {
                let sig = i.signatures().next().expect("signed");
                sig.bytes.try_into().expect("64 bytes")
            })
            .collect();
        let old = f.reply_v107().to_vec();
        let mut want = vec![0u8; unit.len()];
        let n = legacy::write_signed(req, &P, &signatures, &mut want).expect("written");
        assert_eq!(old, &want[..n], "{name}: the request and these signatures");
        assert_eq!(&old[..6], b"KSPT\x01\x01", "{name}: signed, version 0x01");
        // The size and the layout of the unit's own reply: only the
        // signatures differ, each made with fresh randomness.
        assert_eq!(old.len(), unit.len(), "{name}");
        let (ours, theirs) = (
            legacy::parse(&old, &P).expect("reads as 1.0.7's"),
            legacy::parse(unit, &P).expect("the unit's"),
        );
        assert_eq!(ours.shape(), theirs.shape(), "{name}");
        let mut ins = vec![blank_in(); 8];
        let mut outs = vec![blank_out(); 8];
        let (ni, no) = kspt_tx::fill(&ours, &mut ins, &mut outs).expect("fill");
        let tx = kspt_tx::build(&ours, &ins[..ni], &outs[..no]);
        assert_eq!(
            kassigner_fw::reply::verify_kspt_v107(&old, &tx, &P),
            Ok(signatures.len()),
            "{name}: every signature verifies"
        );

        // Wallet: 1.0.7's codes, as many as its unit showed.
        let codes = frame::v107::codes(old.len());
        assert_eq!(f.reply_codes(true), codes, "{name}");
        assert!(f.reply_fits(true), "{name}");
        f.step(reply_card(Card::Wallet), &mut Live);
        assert_eq!(f.state(), State::ReplyMode, "{name}: frames ask first");
        f.touch(answer(dialog::Target::Accept));
        assert_eq!(f.state(), State::Showing { frame: 0 }, "{name}");
        assert_eq!(usize::from(f.reply_frames()), codes, "{name}");
        let mut back = Vec::new();
        for i in 0..f.reply_frames() {
            let code = f.reply_code(i).expect("a code");
            assert_eq!(code.size, 53, "{name}: frame {i} at version 9");
            let bytes = read_back(&code);
            assert_eq!(
                (bytes[0], usize::from(bytes[1])),
                (i, codes),
                "{name}: index and total"
            );
            assert_eq!(usize::from(bytes[2]), bytes.len() - 3, "{name}: its length");
            assert_ne!(bytes[0], frame::MAGIC, "{name}: not this version's frame");
            back.extend_from_slice(&bytes[3..]);
        }
        assert_eq!(back, old, "{name}: the frames put back");

        // KasSigner: the 0x06 reply in this version's frames, as before.
        for _ in 0..f.reply_frames() {
            f.step(LEFT, &mut Live);
        }
        assert_eq!(f.state(), State::ReplyDone, "{name}");
        f.touch(answer(dialog::Target::Nav(Nav::Back)));
        assert_eq!(f.state(), State::ReplyFormat, "{name}");
        f.step(reply_card(Card::KasSigner), &mut Live);
        if f.state() == State::ReplyMode {
            f.touch(answer(dialog::Target::Accept));
        }
        let first = read_back(&f.reply_code(0).expect("a code"));
        assert_eq!(first[0], frame::MAGIC, "{name}: this version's frame");
        assert_eq!(
            usize::from(f.reply_frames()),
            f.reply_codes(false),
            "{name}"
        );
        assert_eq!(
            f.reply(),
            &canonical[..],
            "{name}: the reply saved to the card"
        );

        // Home wipes both.
        for _ in 0..f.reply_frames() {
            f.step(LEFT, &mut Live);
        }
        assert_eq!(f.state(), State::ReplyDone, "{name}");
        f.touch(answer(dialog::Target::Nav(Nav::Home)));
        assert_eq!(f.state(), State::Home);
        assert!(f.reply().is_empty() && f.reply_v107().is_empty(), "{name}");
    }
}

/// Only that request has the old answer: a relay with hints, a multisig, a
/// bundle and a request of this version are answered as before, Wallet
/// showing this version's frames.
#[test]
fn no_other_request_is_answered_as_1_0_7_answered() {
    use kassigner_protocol::frame;
    let requests: [(&str, &[u8]); 4] = [
        ("kspt2_relay_send", corpus!("site/kspt2_relay_send.bin")),
        (
            "kspt2_relay_multisig",
            corpus!("site/kspt2_relay_multisig.bin"),
        ),
        ("pskb_send", corpus!("site/pskb_send.bin")),
        ("pskb_multisig", corpus!("site/pskb_multisig.bin")),
    ];
    for (name, req) in requests {
        let mut m = Memory::new();
        let mut f = signed_flow(&mut m, name, req);
        assert!(f.reply_v107().is_empty(), "{name}");
        f.step(reply_card(Card::Wallet), &mut Live);
        if f.state() == State::ReplyMode {
            f.touch(answer(dialog::Target::Accept));
        }
        let first = read_back(&f.reply_code(0).expect("a code"));
        if f.reply_frames() > 1 {
            assert_eq!(first[0], frame::MAGIC, "{name}: this version's frame");
        }
    }
}

/// A covenant's request is reviewed with its covenant on a page of its
/// own: kassigner.org 1.0.7's genesis, as a bundle and as a relay. Its id is
/// the one upstream's rule makes for a new covenant, or the request would
/// be refused as it arrived; NEW COVENANT says the output it starts in and
/// the input that authorizes it.
#[test]
fn a_covenant_request_of_1_0_7_is_reviewed_with_its_covenant_page() {
    let requests: [(&str, &[u8]); 2] = [
        (
            "kspt2_relay_covenant",
            corpus!("site/kspt2_relay_covenant.bin"),
        ),
        (
            "pskb_covenant_genesis",
            corpus!("site/pskb_covenant_genesis.bin"),
        ),
    ];
    let mut ids = Vec::new();
    for (name, req) in requests {
        let mut m = Memory::new();
        let mut f = loaded_from(&mut m, corpus!("seedqr/abandon12.compact"), 12);
        f.step(scan(), &mut Live);
        deliver(&mut f, req);
        assert_eq!(f.state(), State::Reviewing, "{name}");
        let pages = match f.step(Event::Tick { now_us: 1 }, &mut Live).screen {
            Screen::Page { pages, .. } => pages,
            other => panic!("{name}: {other:?}"),
        };
        let mut covenants = Vec::new();
        for page in 0..pages {
            let covenant = f.review(|s| match *s {
                review::Shown::Covenant {
                    id,
                    spent,
                    outputs,
                    from,
                } => Some((id, spent, outputs, from)),
                _ => None,
            });
            covenants.extend(covenant.flatten());
            if page + 1 < pages {
                arrow(&mut f, RIGHT);
            }
        }
        // One covenant, new: it starts in output 0, authorized by input 0.
        assert_eq!(covenants.len(), 1, "{name}: {covenants:?}");
        let (id, spent, outputs, from) = covenants[0];
        assert_eq!((spent, outputs, from), (0, 0b1, Some(0)), "{name}");
        ids.push(id);
    }
    assert_eq!(ids[0], ids[1], "the relay and the bundle name one covenant");
}

/// A 2-of-3 a v1.0.7 unit signed first is finished here by either other
/// cosigner, from its compact relay reply or its bundle; the reply carries
/// both signatures. The cosigner that signed it is refused, its signature
/// already there.
#[test]
fn a_2_of_3_a_1_0_7_unit_signed_first_is_finished_here() {
    let first: [(&str, &[u8], u32); 3] = [
        (
            "kspt2_relay_multisig.reply",
            corpus!("device/kspt2_relay_multisig.reply.bin"),
            0,
        ),
        (
            "kspt2_relay_multisig_3in.reply",
            corpus!("device/kspt2_relay_multisig_3in.reply.bin"),
            1,
        ),
        (
            "pskb_multisig.reply",
            corpus!("device/pskb_multisig.reply.bin"),
            0,
        ),
    ];
    let second: [(&[u8], usize, &str); 2] = [
        (corpus!("seedqr/abandon24.compact"), 24, ABANDON24_KPUB45),
        (corpus!("seedqr/zoo12.compact"), 12, ZOO12_KPUB45),
    ];
    for (name, req, index) in first {
        for (seed, words, kpub) in second {
            let reply = signed_reply(seed, words, name, req);
            reply_holds(name, req, reply, &[ABANDON12_KPUB45, kpub], index);
        }
        let mut m = Memory::new();
        let mut f = loaded_from(&mut m, corpus!("seedqr/abandon12.compact"), 12);
        f.step(scan(), &mut Live);
        deliver(&mut f, req);
        assert!(
            matches!(
                f.state(),
                State::Refused(Refusal::NotSigned(
                    kassigner_fw::reply::Error::AlreadySigned { .. }
                ))
            ),
            "{name}: {:?}",
            f.state()
        );
    }
}

/// A cosigner's bent signature is refused as the request arrives. The
/// 2-of-3 a v1.0.7 unit signed first, that unit's signature bent: abandon
/// 24 shows no page, signs nothing and writes no reply; "Bad signature in
/// request". The reply's read-back after CONFIRM stays as the last check,
/// but a request with a bad signature no longer reaches it.
#[test]
fn a_bent_cosigner_signature_is_refused_on_arrival() {
    let mut req = corpus!("device/kspt2_relay_multisig.reply.bin").to_vec();
    let at = {
        let k = kspt::legacy::parse_any(&req, &P).expect("parse");
        let input = k.inputs().next().expect("an input");
        let sig = input
            .signatures()
            .next()
            .expect("abandon 12's signature")
            .bytes;
        sig.as_ptr() as usize - req.as_ptr() as usize + sig.len() - 1
    };
    req[at] ^= 1;

    let mut m = Memory::new();
    {
        let mut f = loaded_from(&mut m, corpus!("seedqr/abandon24.compact"), 24);
        f.step(scan(), &mut Live);
        deliver(&mut f, &req);
        let why = Refusal::NotSigned(kassigner_fw::reply::Error::BadSignature { input: 0 });
        assert_eq!(f.state(), State::Refused(why));
        assert_eq!(why.words(), ("Signing failed", "Bad signature in request"));
        assert!(f.page(|_| ()).is_none(), "no review was started");
        assert!(f.reply().is_empty());
    }
    assert!(m.reply.iter().all(|&b| b == 0), "no reply written");
    assert!(
        m.signatures.iter().all(|s| *s == InputSignature::EMPTY),
        "no signature written"
    );
}

/// Every sighash type but ALL: the five others consensus allows, and two
/// bytes it does not, which a bundle's `u8` still carries.
const NOT_ALL: [u8; 7] = [0x02, 0x04, 0x81, 0x82, 0x84, 0x00, 0xFF];

/// `req`, a bundle from [`bundle_request`], with its input asking for `t`.
fn bundle_asking(req: &[u8], t: u8) -> Vec<u8> {
    let doc = unhex(core::str::from_utf8(&req[4..]).expect("hex"));
    let doc = String::from_utf8(doc).expect("text");
    let asking = doc.replacen("\"sighashType\":1,", &format!("\"sighashType\":{t},"), 1);
    assert_ne!(asking, doc, "it had one to change");
    format!("PSKB{}", hex(asking.as_bytes())).into_bytes()
}

/// An input asking for a sighash type other than ALL is refused as the
/// request arrives, as rusty-kaspa's signer refuses it since its PR #1135
/// (after 2.1.0): a type leaving outputs or inputs out of the hash lets
/// whoever holds the signature change them. The device signs
/// `SIG_HASH_ALL` only, with no opt-in.
///
/// A bundle states the type per input; a KSPT is signed under ALL, so there
/// the other type is on a cosigner's signature in the request. Neither
/// shows a page, signs or writes a reply: "Only SIGHASH_ALL is signed".
#[test]
fn a_sighash_type_other_than_all_is_refused_on_arrival() {
    let why = Refusal::NotSigned(kassigner_fw::reply::Error::SighashNotAll { input: 0 });
    assert_eq!(
        why.words(),
        ("Signing failed", "Only SIGHASH_ALL is signed")
    );

    // A bundle: the input is this seed's own, and ALL is reviewed.
    let spk = p2pk(&x_only(&wallet()));
    let req = bundle_request(100_000 * KAS, &spk, &[(90_000 * KAS, &spk)]);
    {
        let mut m = Memory::new();
        reviewing(&mut m, &req);
    }
    for t in NOT_ALL {
        let asking = bundle_asking(&req, t);
        let mut m = Memory::new();
        {
            let mut f: Flow<'_, 1> = seeded(&mut m);
            f.step(scan(), &mut Live);
            deliver(&mut f, &asking);
            assert_eq!(f.state(), State::Refused(why), "bundle, {t:#04x}");
            assert!(f.page(|_| ()).is_none(), "bundle, {t:#04x}: no review");
            assert!(f.reply().is_empty(), "bundle, {t:#04x}");
        }
        assert!(m.reply.iter().all(|&b| b == 0), "bundle, {t:#04x}");
        assert!(
            m.signatures.iter().all(|s| *s == InputSignature::EMPTY),
            "bundle, {t:#04x}"
        );
    }

    // A KSPT: the 2-of-3 abandon 12 signed first, its signature's type
    // changed. The type is checked before the signature, so it is the type
    // that is refused.
    let signed = corpus!("device/kspt2_relay_multisig.reply.bin");
    let at = {
        let k = kspt::legacy::parse_any(signed, &P).expect("parse");
        let input = k.inputs().next().expect("an input");
        let sig = input.signatures().next().expect("abandon 12's signature");
        assert_eq!(sig.sighash_type, SIG_HASH_ALL.to_u8());
        sig.bytes.as_ptr() as usize - signed.as_ptr() as usize - 1
    };
    for t in NOT_ALL {
        let mut req = signed.to_vec();
        req[at] = t;
        {
            let k = kspt::legacy::parse_any(&req, &P).expect("parse");
            let input = k.inputs().next().expect("an input");
            let sig = input.signatures().next().expect("a signature");
            assert_eq!(sig.sighash_type, t, "the byte is the type's");
        }
        let mut m = Memory::new();
        {
            let mut f = loaded_from(&mut m, corpus!("seedqr/abandon24.compact"), 24);
            f.step(scan(), &mut Live);
            deliver(&mut f, &req);
            assert_eq!(f.state(), State::Refused(why), "KSPT, {t:#04x}");
            assert!(f.page(|_| ()).is_none(), "KSPT, {t:#04x}: no review");
            assert!(f.reply().is_empty(), "KSPT, {t:#04x}");
        }
        assert!(m.reply.iter().all(|&b| b == 0), "KSPT, {t:#04x}");
        assert!(
            m.signatures.iter().all(|s| *s == InputSignature::EMPTY),
            "KSPT, {t:#04x}"
        );
    }
}

/// A KCC-3 input is reviewed and signed, and its change is CHANGE: the
/// seed's KCC-3 receive 3, spent to someone and back to its KCC-3 change 1.
/// Only the change output's page says CHANGE, and the reply carries the
/// KCC-3 key's signature at position zero, verifying over the input's hash.
#[test]
fn a_kcc3_input_is_reviewed_signed_and_its_change_known() {
    use kassigner_fw::ui::review::Shown;
    use kassigner_kaspa::script::{kcc3_redeem, kcc3_script_hash};
    let lock = |key: [u8; 32]| {
        let mut v = vec![0xaa, 0x20];
        v.extend_from_slice(&kcc3_script_hash(&key));
        v.push(0x87);
        v
    };
    let w = wallet();
    let hidden = w.signing_key(Path::kcc3_receive(3)).unwrap().x_only();
    let change = w.signing_key(Path::kcc3_change(1)).unwrap().x_only();
    let redeem = kcc3_redeem(&hidden);
    let mut tail = vec![0];
    tail.extend_from_slice(&(redeem.len() as u16).to_le_bytes());
    tail.extend_from_slice(&redeem);
    let theirs = p2pk(&[0x42; 32]);
    let req = request_as(
        VERSION,
        0,
        &tail,
        100_000 * KAS,
        &lock(hidden),
        &[(60_000 * KAS, &theirs), (30_000 * KAS, &lock(change))],
    );

    let mut m = Memory::new();
    let mut f = reviewing(&mut m, &req);
    let pages = match f.step(Event::Tick { now_us: 1 }, &mut Live).screen {
        Screen::Page { pages, .. } => pages,
        other => panic!("{other:?}"),
    };
    let mut changes = Vec::new();
    for _ in 1..pages {
        arrow(&mut f, RIGHT);
        if let Some(Some(c)) = f.review(|s| match *s {
            Shown::Output { change, .. } => Some(change),
            _ => None,
        }) {
            changes.push(c);
        }
    }
    assert_eq!(
        changes,
        [review::Change::No, review::Change::At(1)],
        "theirs, then the KCC-3 change"
    );
    confirmed(&mut f);
    reply_shown(&mut f);
    let k = kspt::legacy::parse_any(f.reply(), &P).expect("a KSPT");
    let sigs: Vec<_> = k.inputs().next().expect("input").signatures().collect();
    assert_eq!(sigs.len(), 1);
    assert_eq!(sigs[0].pubkey_pos, 0);
    let sig: &[u8; 64] = sigs[0].bytes.try_into().expect("64 bytes");
    assert!(bip340::verify(&hidden, &digest(&req), sig));
}

/// An address-only spend, as kassigner.org will send one, is reviewed,
/// signed and answered with its redeem script: the seed's KCC-3 receive 3
/// by its address alone, no redeem in the input. A KSPT and a bundle each
/// come back signed by that key, with `<P> OP_CHECKSIG` in the input for
/// whoever finishes the spend.
#[test]
fn an_address_only_spend_is_signed_with_its_redeem() {
    use kassigner_kaspa::script::{kcc3_redeem, kcc3_script_hash};
    let w = wallet();
    let hidden = w.signing_key(Path::kcc3_receive(3)).unwrap().x_only();
    let redeem = kcc3_redeem(&hidden);
    let mut lock = vec![0xaa, 0x20];
    lock.extend_from_slice(&kcc3_script_hash(&hidden));
    lock.push(0x87);
    let theirs = p2pk(&[0x42; 32]);
    let sign = |req: &[u8]| {
        let mut m = Memory::new();
        let mut f = reviewing(&mut m, req);
        let pages = match f.step(Event::Tick { now_us: 1 }, &mut Live).screen {
            Screen::Page { pages, .. } => pages,
            other => panic!("{other:?}"),
        };
        for _ in 1..pages {
            arrow(&mut f, RIGHT);
        }
        confirmed(&mut f);
        reply_shown(&mut f);
        f.reply().to_vec()
    };

    let req = request(100_000 * KAS, &lock, &[(90_000 * KAS, &theirs)]);
    let reply = sign(&req);
    let k = kspt::legacy::parse_any(&reply, &P).expect("a KSPT");
    let input = k.inputs().next().expect("input");
    assert_eq!(input.redeem, &redeem[..]);
    let sigs: Vec<_> = input.signatures().collect();
    assert_eq!((sigs.len(), sigs[0].pubkey_pos), (1, 0));
    let sig: &[u8; 64] = sigs[0].bytes.try_into().expect("64 bytes");
    assert!(bip340::verify(&hidden, &digest(&req), sig));

    let req = bundle_request(100_000 * KAS, &lock, &[(90_000 * KAS, &theirs)]);
    let reply = sign(&req);
    assert!(reply.starts_with(b"PSKB"), "answered as a bundle");
    let mut doc = vec![0u8; reply.len()];
    let n = kassigner_kaspa::pskb::decode_envelope(&reply, &mut doc).expect("an envelope");
    let doc = String::from_utf8(doc[..n].to_vec()).expect("text");
    let hexed = hex(&redeem);
    assert!(
        doc.contains(&format!("\"redeemScript\":\"{hexed}\"")),
        "{doc}"
    );
}

/// A KCC-3 address past the bank is asked about and searched for, as a
/// single key past the bank is. The seed's KCC-3 receive 30, address alone:
/// asked before the first batch, found in it, signed with its redeem
/// script supplied. Another seed's is swept to the end, asked before every
/// batch, and refused as an input with no redeem script.
#[test]
fn a_kcc3_address_past_the_bank_is_searched_for() {
    use kassigner_kaspa::script::{kcc3_redeem, kcc3_script_hash};
    let lock = |key: [u8; 32]| {
        let mut v = vec![0xaa, 0x20];
        v.extend_from_slice(&kcc3_script_hash(&key));
        v.push(0x87);
        v
    };
    let theirs = p2pk(&[0x42; 32]);
    let deep = wallet()
        .signing_key(Path::kcc3_receive(30))
        .unwrap()
        .x_only();
    let req = request(100_000 * KAS, &lock(deep), &[(90_000 * KAS, &theirs)]);
    let mut m = Memory::new();
    let mut f: Flow<'_, 1> = seeded(&mut m);
    f.step(scan(), &mut Live);
    deliver(&mut f, &req);
    assert_eq!(
        f.state(),
        State::Asking {
            next: 0,
            kcc3: true
        }
    );
    assert_eq!(
        f.step(
            Event::Tick {
                now_us: VERIFIED_US
            },
            &mut Live
        )
        .screen,
        Screen::Asking { checked: 25 }
    );
    assert_eq!(swept(&mut f), 1, "one batch");
    assert_eq!(f.state(), State::Reviewing);
    let pages = match f.step(Event::Tick { now_us: 1 }, &mut Live).screen {
        Screen::Page { pages, .. } => pages,
        other => panic!("{other:?}"),
    };
    for _ in 1..pages {
        arrow(&mut f, RIGHT);
    }
    confirmed(&mut f);
    reply_shown(&mut f);
    let k = kspt::legacy::parse_any(f.reply(), &P).expect("a KSPT");
    let input = k.inputs().next().expect("input");
    assert_eq!(input.redeem, &kcc3_redeem(&deep)[..]);
    let sig: &[u8; 64] = input
        .signatures()
        .next()
        .expect("signed")
        .bytes
        .try_into()
        .expect("64 bytes");
    assert!(bip340::verify(&deep, &digest(&req), sig));

    let other = {
        let m = bip39::from_entropy(&[9u8; 16]).unwrap();
        let mut scratch = vec![0u8; bip39::scratch_for(0)];
        Wallet::open(&Slot::mnemonic(m, b"").unwrap(), &mut scratch).unwrap()
    };
    let stranger = other.signing_key(Path::kcc3_receive(0)).unwrap().x_only();
    let req = request(100_000 * KAS, &lock(stranger), &[(90_000 * KAS, &theirs)]);
    let mut m = Memory::new();
    let mut f: Flow<'_, 1> = seeded(&mut m);
    f.step(scan(), &mut Live);
    deliver(&mut f, &req);
    assert_eq!(
        swept(&mut f),
        kassigner_fw::keyring::SWEEP.div_ceil(kassigner_fw::flow::BATCH),
        "asked before every batch"
    );
    assert_eq!(
        f.state(),
        State::Refused(Refusal::NotSigned(kassigner_fw::reply::Error::Keyring {
            input: 0,
            error: kassigner_fw::keyring::Error::NoRedeemScript
        }))
    );
    assert!(f.reply().is_empty());
}

/// A KSPT's KCC-3 input hint names the key at once: the seed's KCC-3
/// receive 60, address alone, with a `0x46` hint, is signed with its redeem
/// script supplied, with no question and no search. A hint naming another
/// address searches nothing either: refused at once as an input with no
/// redeem script.
#[test]
fn a_kcc3_hint_names_the_key_at_once() {
    use kassigner_kaspa::script::{kcc3_redeem, kcc3_script_hash};
    let w = wallet();
    let deep = w.signing_key(Path::kcc3_receive(60)).unwrap().x_only();
    let mut lock = vec![0xaa, 0x20];
    lock.extend_from_slice(&kcc3_script_hash(&deep));
    lock.push(0x87);
    let theirs = p2pk(&[0x42; 32]);
    let hinted = |index: u32| {
        let mut req = request(100_000 * KAS, &lock, &[(90_000 * KAS, &theirs)]);
        req.push(0x46);
        req.push(0);
        req.extend_from_slice(&0u32.to_le_bytes());
        req.extend_from_slice(&index.to_le_bytes());
        req
    };

    let req = hinted(60);
    let mut m = Memory::new();
    let mut f = reviewing(&mut m, &req);
    let pages = match f.step(Event::Tick { now_us: 1 }, &mut Live).screen {
        Screen::Page { pages, .. } => pages,
        other => panic!("{other:?}"),
    };
    for _ in 1..pages {
        arrow(&mut f, RIGHT);
    }
    confirmed(&mut f);
    reply_shown(&mut f);
    let k = kspt::legacy::parse_any(f.reply(), &P).expect("a KSPT");
    assert!(
        k.records()
            .any(|r| matches!(r, kspt::Record::Kcc3InputHint(h) if h.addr_index == 60)),
        "the hint written back"
    );
    let input = k.inputs().next().expect("input");
    assert_eq!(input.redeem, &kcc3_redeem(&deep)[..]);
    let sig: &[u8; 64] = input
        .signatures()
        .next()
        .expect("signed")
        .bytes
        .try_into()
        .expect("64 bytes");
    assert!(bip340::verify(&deep, &digest(&req), sig));

    let mut m = Memory::new();
    let mut f: Flow<'_, 1> = seeded(&mut m);
    f.step(scan(), &mut Live);
    deliver(&mut f, &hinted(61));
    assert_eq!(
        f.state(),
        State::Refused(Refusal::NotSigned(kassigner_fw::reply::Error::Keyring {
            input: 0,
            error: kassigner_fw::keyring::Error::NoRedeemScript
        })),
        "a wrong hint is not searched past"
    );
}

/// A request with an input placed and a KCC-3 input past the KCC-3 bank
/// asks, sweeps for the latter, and signs both: the seed's receive 0, and
/// its KCC-3 receive 30 by its address alone, with no hint.
#[test]
fn a_mixed_request_sweeps_for_its_kcc3_input() {
    use kassigner_kaspa::script::{kcc3_redeem, kcc3_script_hash};
    let w = wallet();
    let deep = w.signing_key(Path::kcc3_receive(30)).unwrap().x_only();
    let mut lock = vec![0xaa, 0x20];
    lock.extend_from_slice(&kcc3_script_hash(&deep));
    lock.push(0x87);
    let spk = p2pk(&x_only(&w));
    let theirs = p2pk(&[0x42; 32]);
    let req = request_of(
        VERSION,
        0,
        &[0, 0, 0],
        &[(100_000, &spk), (50_000, &lock)],
        &[(140_000, &theirs)],
    );
    let mut m = Memory::new();
    let mut f: Flow<'_, 1> = seeded(&mut m);
    f.step(scan(), &mut Live);
    deliver(&mut f, &req);
    assert!(
        matches!(f.state(), State::Asking { kcc3: true, .. }),
        "{:?}",
        f.state()
    );
    assert!(swept(&mut f) >= 1, "asked before the KCC-3 sweep");
    assert_eq!(f.state(), State::Reviewing);
    let pages = match f.step(Event::Tick { now_us: 1 }, &mut Live).screen {
        Screen::Page { pages, .. } => pages,
        other => panic!("{other:?}"),
    };
    for _ in 1..pages {
        arrow(&mut f, RIGHT);
    }
    confirmed(&mut f);
    reply_shown(&mut f);
    let k = kspt::legacy::parse_any(f.reply(), &P).expect("a KSPT");
    let inputs: Vec<_> = k.inputs().collect();
    assert_eq!(inputs.len(), 2);
    assert!(
        inputs.iter().all(|i| i.signatures().count() == 1),
        "both signed"
    );
    assert_eq!(inputs[1].redeem, &kcc3_redeem(&deep)[..]);
}

/// A single-key hint record, `0x47` for an input or `0x48` for an output:
/// which one, the chain and the index.
fn account_hint(marker: u8, index: u8, chain: u32, at: u32) -> Vec<u8> {
    let mut r = vec![marker, index];
    r.extend_from_slice(&chain.to_le_bytes());
    r.extend_from_slice(&at.to_le_bytes());
    r
}

/// A KSPT's single-key input hint names the key at once, however deep: the
/// seed's receive 1500, past the thousand the search reaches, with a `0x47`
/// hint, is signed with no question and no search, the hint written back.
/// A hint naming another key, on either chain, searches only the bank,
/// which does not hold it, and the request is refused at once.
#[test]
fn a_single_key_hint_names_the_key_at_once_however_deep() {
    let w = wallet();
    let deep = w.signing_key(Path::receive(1500)).unwrap().x_only();
    let theirs = p2pk(&[0x42; 32]);
    let hinted = |chain: u32, at: u32| {
        let mut req = request(100_000 * KAS, &p2pk(&deep), &[(90_000 * KAS, &theirs)]);
        req.extend_from_slice(&account_hint(0x47, 0, chain, at));
        req
    };

    let req = hinted(0, 1500);
    let mut m = Memory::new();
    let mut f = reviewing(&mut m, &req);
    let pages = match f.step(Event::Tick { now_us: 1 }, &mut Live).screen {
        Screen::Page { pages, .. } => pages,
        other => panic!("{other:?}"),
    };
    for _ in 1..pages {
        arrow(&mut f, RIGHT);
    }
    confirmed(&mut f);
    reply_shown(&mut f);
    let k = kspt::legacy::parse_any(f.reply(), &P).expect("a KSPT");
    assert!(
        k.records()
            .any(|r| matches!(r, kspt::Record::AccountInputHint(h) if h.addr_index == 1500)),
        "the hint written back"
    );
    let sig: &[u8; 64] = k
        .inputs()
        .next()
        .expect("input")
        .signatures()
        .next()
        .expect("signed")
        .bytes
        .try_into()
        .expect("64 bytes");
    assert!(bip340::verify(&deep, &digest(&req), sig));

    for (chain, at, why) in [(0, 1501, "another key"), (1, 1500, "the change chain")] {
        let mut m = Memory::new();
        let mut f: Flow<'_, 1> = seeded(&mut m);
        f.step(scan(), &mut Live);
        deliver(&mut f, &hinted(chain, at));
        assert_eq!(
            f.state(),
            State::Refused(Refusal::NotSigned(
                kassigner_fw::reply::Error::NothingSigned
            )),
            "{why}: not searched past"
        );
    }
}

/// A request may say where its change is, however deep: an output to the
/// seed's change 560, placed by a KSPT's `0x48` or a bundle's key path, is
/// CHANGE at 560, its key derived and compared, never taken on the
/// request's word. Placed one key off, on the receive chain, below a
/// hardened step or on another output, it is an ordinary output, as when
/// unplaced; a bank's change placed wrongly is still CHANGE at its own
/// index. A consolidation's one output is placed the same way, and so is
/// the change of a request whose input's key takes a search to find.
#[test]
fn a_request_may_say_where_its_change_is() {
    use kassigner_fw::ui::review::{Change, Shown};
    use kassigner_kaspa::pskb::{decode_envelope, encode_envelope};
    let w = wallet();
    let spk = p2pk(&x_only(&w));
    let key = w.signing_key(Path::change(560)).unwrap();
    let deep = p2pk(&key.x_only());
    let near = p2pk(&w.signing_key(Path::change(3)).unwrap().x_only());
    let theirs = p2pk(&[0x42; 32]);
    let walked = |f: &mut Flow<'_, 1>| {
        let pages = match f.step(Event::Tick { now_us: 1 }, &mut Live).screen {
            Screen::Page { pages, .. } => pages,
            other => panic!("{other:?}"),
        };
        let mut seen = Vec::new();
        for _ in 1..pages {
            arrow(f, RIGHT);
            seen.extend(
                f.review(|s| match *s {
                    Shown::Output { change, .. } => Some(change),
                    _ => None,
                })
                .flatten(),
            );
        }
        seen
    };
    let changes = |req: &[u8]| {
        let mut m = Memory::new();
        let mut f = reviewing(&mut m, req);
        walked(&mut f)
    };
    let kspt = |out: &[u8], record: &[u8]| {
        let mut req = request(
            100_000 * KAS,
            &spk,
            &[(60_000 * KAS, &theirs), (30_000 * KAS, out)],
        );
        req.extend_from_slice(record);
        req
    };

    assert_eq!(
        changes(&kspt(&deep, &account_hint(0x48, 1, 1, 560))),
        [Change::No, Change::At(560)]
    );
    for (record, why) in [
        (account_hint(0x48, 1, 1, 561), "one key off"),
        (account_hint(0x48, 1, 0, 560), "the receive chain"),
        (account_hint(0x48, 1, 1, 560 | 0x8000_0000), "hardened"),
        (account_hint(0x48, 0, 1, 560), "on the other output"),
        (Vec::new(), "unplaced"),
    ] {
        assert_eq!(
            changes(&kspt(&deep, &record)),
            [Change::No, Change::No],
            "{why}"
        );
    }
    assert_eq!(
        changes(&kspt(&near, &account_hint(0x48, 1, 1, 4))),
        [Change::No, Change::At(3)],
        "the bank's, placed wrongly"
    );
    // The coins gathered into one, the sweep's one output placed.
    let mut gathered = request(100_000 * KAS, &spk, &[(90_000 * KAS, &deep)]);
    gathered.extend_from_slice(&account_hint(0x48, 0, 1, 560));
    assert_eq!(changes(&gathered), [Change::At(560)], "gathered");

    // The input's key found by a search (receive 30, past the first
    // addresses): the review it ends in marks the change all the same.
    let far = p2pk(&w.signing_key(Path::receive(30)).unwrap().x_only());
    let mut searched = request(
        100_000 * KAS,
        &far,
        &[(60_000 * KAS, &theirs), (30_000 * KAS, &deep)],
    );
    searched.extend_from_slice(&account_hint(0x48, 1, 1, 560));
    let mut m = Memory::new();
    let mut f: Flow<'_, 1> = seeded(&mut m);
    f.step(scan(), &mut Live);
    deliver(&mut f, &searched);
    assert_eq!(swept(&mut f), 1, "one batch");
    assert_eq!(f.state(), State::Reviewing, "found, and reviewed");
    assert_eq!(walked(&mut f), [Change::No, Change::At(560)], "searched");

    // A bundle's key path on the output, the standard field.
    let bundle = bundle_request(
        100_000 * KAS,
        &spk,
        &[(60_000 * KAS, &theirs), (30_000 * KAS, &deep)],
    );
    let mut json = vec![0u8; bundle.len()];
    let n = decode_envelope(&bundle, &mut json).unwrap();
    let text = String::from_utf8(json[..n].to_vec()).unwrap();
    const EMPTY: &str = "\"bip32Derivations\":{}";
    let at = text.match_indices(EMPTY).nth(2).expect("output 1's").0;
    let placed = format!(
        "{}\"bip32Derivations\":{{\"{}\":{{\"keyFingerprint\":\"00000000\",\
         \"derivationPath\":\"m/44'/111111'/0'/1/560\"}}}}{}",
        &text[..at],
        hex(key.public_key()),
        &text[at + EMPTY.len()..]
    );
    let mut out = vec![0u8; 4 + 2 * placed.len()];
    let n = encode_envelope(placed.as_bytes(), &mut out).unwrap();
    out.truncate(n);
    assert_eq!(changes(&out), [Change::No, Change::At(560)]);
}

/// An output to the seed's own receive address is YOURS: one in the bank on
/// its own (the first input's address paid back, or receive 3); one past it
/// where a KSPT's `0x48` or a bundle's key path places it (receive 777),
/// its key derived and compared. Placed one key off, on the change chain,
/// or not placed, the deep one is an ordinary output; change stays CHANGE
/// beside it.
#[test]
fn an_output_to_the_seeds_own_receive_address_is_yours() {
    use kassigner_fw::ui::review::{Change, Shown};
    use kassigner_kaspa::pskb::{decode_envelope, encode_envelope};
    let w = wallet();
    let spk = p2pk(&x_only(&w));
    let at = |path| p2pk(&w.signing_key(path).unwrap().x_only());
    let key = w.signing_key(Path::receive(777)).unwrap();
    let deep = p2pk(&key.x_only());
    let theirs = p2pk(&[0x42; 32]);
    let changes = |req: &[u8]| {
        let mut m = Memory::new();
        let mut f = reviewing(&mut m, req);
        let pages = match f.step(Event::Tick { now_us: 1 }, &mut Live).screen {
            Screen::Page { pages, .. } => pages,
            other => panic!("{other:?}"),
        };
        let mut seen = Vec::new();
        for _ in 1..pages {
            arrow(&mut f, RIGHT);
            seen.extend(
                f.review(|s| match *s {
                    Shown::Output { change, .. } => Some(change),
                    _ => None,
                })
                .flatten(),
            );
        }
        seen
    };
    let kspt = |out: &[u8], record: &[u8]| {
        let mut req = request(
            100_000 * KAS,
            &spk,
            &[(60_000 * KAS, &theirs), (30_000 * KAS, out)],
        );
        req.extend_from_slice(record);
        req
    };

    assert_eq!(
        changes(&kspt(&spk, &[])),
        [Change::No, Change::Yours(0)],
        "paid back"
    );
    assert_eq!(
        changes(&kspt(&at(Path::receive(3)), &[])),
        [Change::No, Change::Yours(3)],
        "in the bank"
    );
    assert_eq!(
        changes(&kspt(&deep, &account_hint(0x48, 1, 0, 777))),
        [Change::No, Change::Yours(777)],
        "placed"
    );
    for (record, why) in [
        (account_hint(0x48, 1, 0, 778), "one key off"),
        (account_hint(0x48, 1, 1, 777), "the change chain"),
        (Vec::new(), "unplaced"),
    ] {
        assert_eq!(
            changes(&kspt(&deep, &record)),
            [Change::No, Change::No],
            "{why}"
        );
    }
    let mut both = request(
        100_000 * KAS,
        &spk,
        &[(40_000 * KAS, &deep), (30_000 * KAS, &at(Path::change(2)))],
    );
    both.extend_from_slice(&account_hint(0x48, 0, 0, 777));
    assert_eq!(
        changes(&both),
        [Change::Yours(777), Change::At(2)],
        "beside change"
    );

    // A bundle's key path on the output, the standard field.
    let bundle = bundle_request(
        100_000 * KAS,
        &spk,
        &[(60_000 * KAS, &theirs), (30_000 * KAS, &deep)],
    );
    let mut json = vec![0u8; bundle.len()];
    let n = decode_envelope(&bundle, &mut json).unwrap();
    let text = String::from_utf8(json[..n].to_vec()).unwrap();
    const EMPTY: &str = "\"bip32Derivations\":{}";
    let at = text.match_indices(EMPTY).nth(2).expect("output 1's").0;
    let placed = format!(
        "{}\"bip32Derivations\":{{\"{}\":{{\"keyFingerprint\":\"00000000\",\
         \"derivationPath\":\"m/44'/111111'/0'/0/777\"}}}}{}",
        &text[..at],
        hex(key.public_key()),
        &text[at + EMPTY.len()..]
    );
    let mut out = vec![0u8; 4 + 2 * placed.len()];
    let n = encode_envelope(placed.as_bytes(), &mut out).unwrap();
    out.truncate(n);
    assert_eq!(changes(&out), [Change::No, Change::Yours(777)]);
}
