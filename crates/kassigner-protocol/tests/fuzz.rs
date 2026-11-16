// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Every reader here that takes outside bytes, fuzzed (`testkit/mutate.rs`):
//! it must return on any input. What a camera reads (frames, KSPT, messages,
//! kpubs, descriptors, a card's backup line, covenant payloads, envelopes)
//! and what a card holds (containers, a photo's EXIF and picture); a KSPT
//! request also goes through signing's checks.

#[path = "../../../testkit/mutate.rs"]
mod mutate;
#[path = "../../../testkit/vectors.rs"]
mod vectors;

use kassigner_kaspa::bip32_public::{ChildNumber, ExtendedPublicKey};
use kassigner_kaspa::mass::{transaction_storage_mass, MassRates};
use kassigner_kaspa::subnets::SUBNETWORK_ID_NATIVE;
use kassigner_kaspa::tx::{
    CovenantBinding, Outpoint, ScriptPublicKey, Transaction, TransactionInput, TransactionOutput,
    UtxoEntry,
};
use kassigner_protocol::card::backup;
use kassigner_protocol::check::{self, MAX_MULTISIG_KEYS};
use kassigner_protocol::container;
use kassigner_protocol::descriptor;
use kassigner_protocol::ecies;
use kassigner_protocol::frame::{self, Format, Reassembler};
use kassigner_protocol::group::Group;
use kassigner_protocol::kpub;
use kassigner_protocol::kspt::{self, legacy, transaction};
use kassigner_protocol::kspt::{write_draft, CoinCovenant, Draft};
use kassigner_protocol::message;
use kassigner_protocol::payload;
use kassigner_protocol::profile::Profile;
use kassigner_protocol::stego::{blob, carrier, exif, picture, walk};

const P: Profile = Profile::ESP32S3;

/// The vectors' KSPT requests and replies, v1.0.7's and this version's.
fn kspts() -> Vec<Vec<u8>> {
    let mut out = vectors::files("v110/sdk", &[""]);
    out.extend(vectors::files("v107/site", &[".bin"]));
    out.extend(vectors::files("v107/device", &[".bin"]));
    out.extend(vectors::files("v107/cards", &[".KSP"]));
    out.retain(|b| b.starts_with(&kspt::MAGIC));
    out.extend(edges());
    assert!(out.len() >= 20, "the vectors' KSPT payloads");
    out
}

// ── KSPT at its limits ──────────────────────────────────────────────────────

const BLANK_IN: TransactionInput<'static> = TransactionInput {
    previous_outpoint: Outpoint {
        transaction_id: [0; 32],
        index: 0,
    },
    sequence: 0,
    sig_op_count: 1,
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

const BLANK_OUT: TransactionOutput<'static> = TransactionOutput {
    value: 0,
    script_public_key: ScriptPublicKey {
        version: 0,
        script: &[],
    },
    covenant: None,
};

/// A pay-to-key script.
const P2PK: [u8; 34] = {
    let mut s = [7u8; 34];
    s[0] = 0x20;
    s[33] = 0xAC;
    s
};

/// Placeholder amounts, byte patterns no other field holds, overwritten with
/// the edge values after writing: the writer refuses a total past the supply.
const INPUT_MARK: u64 = 123_456_789_012;
const OUTPUT_MARK: u64 = 987_654_321_098;

/// The covenant the bound coins and outputs of the edge requests name.
const COVENANT: [u8; 32] = [0xC0; 32];

/// Requests at the edges: the largest amounts on enough inputs to overflow a
/// `u64` sum, counts at the profile's limits, the largest payload and lock
/// time; and coins bound to a covenant, one, two apart and every input's,
/// ended or continued by an output.
fn edges() -> Vec<Vec<u8>> {
    let max = kassigner_kaspa::constants::MAX_SOMPI;
    let shapes: [(usize, u64, usize, u64); 6] = [
        (7, max, 1, max),
        (8, max, 2, u64::MAX),
        (1, 1, P.max_outputs, 1),
        (P.max_inputs, max, 1, 0),
        (P.max_inputs, u64::MAX, P.max_outputs, u64::MAX),
        (2, u64::MAX / 2 + 1, 1, 0),
    ];
    let mut out = Vec::new();
    for (k, &(ni, amount, no, value)) in shapes.iter().enumerate() {
        let mut ins = vec![BLANK_IN; ni];
        for (i, input) in ins.iter_mut().enumerate() {
            input.previous_outpoint.index = i as u32;
            input.utxo_entry.amount = INPUT_MARK;
            input.utxo_entry.script_public_key.script = &P2PK;
            input.sequence = if k == 5 { u64::MAX } else { 0 };
        }
        let mut outs = vec![BLANK_OUT; no];
        for output in outs.iter_mut() {
            output.value = OUTPUT_MARK;
            output.script_public_key.script = &P2PK;
        }
        // The inputs whose coins are bound: the covenant's records. The
        // second shape, version 1, continues it in its first output.
        let bound: Vec<u8> = match k {
            0 => vec![0, 6],
            1 => vec![0],
            4 => (0..ni as u8).collect(),
            _ => vec![],
        };
        if k == 1 {
            outs[0].covenant = Some(CovenantBinding {
                authorizing_input: 0,
                covenant_id: COVENANT,
            });
        }
        let coin_covenants: Vec<CoinCovenant> = bound
            .iter()
            .map(|&index| CoinCovenant {
                index,
                covenant_id: COVENANT,
            })
            .collect();
        let payload = vec![0xA5; if k == 4 { P.max_payload } else { 0 }];
        let tx = Transaction {
            version: (k % 2) as u16,
            inputs: &ins,
            outputs: &outs,
            lock_time: if k == 3 { u64::MAX } else { 0 },
            subnetwork_id: SUBNETWORK_ID_NATIVE,
            gas: 0,
            payload: &payload,
        };
        let redeems = vec![&[][..]; ni];
        let draft = Draft {
            redeems: &redeems,
            input_hints: &[],
            kcc3_hints: &[],
            account_hints: &[],
            output_hints: &[],
            account_output_hints: &[],
            coin_covenants: &coin_covenants,
        };
        let mut buf = vec![0u8; 256 * 1024];
        let n = write_draft(&draft, &tx, &P, &mut buf).unwrap();
        buf.truncate(n);
        let named = kspt::parse(&buf, &P)
            .unwrap()
            .records()
            .filter(|r| matches!(r, kspt::Record::CoinCovenant { .. }))
            .count();
        assert_eq!(named, bound.len(), "the seed names its bound coins");
        for (mark, edge) in [(INPUT_MARK, amount), (OUTPUT_MARK, value)] {
            let mark = mark.to_le_bytes();
            let mut at = 0;
            while let Some(i) = buf[at..].windows(8).position(|w| w == mark) {
                buf[at + i..at + i + 8].copy_from_slice(&edge.to_le_bytes());
                at += i + 8;
            }
        }
        out.push(buf);
    }
    out
}

/// A KSPT payload as a unit takes it to signing: read, its transaction
/// checked input by input, its signatures verified, a reply's signers
/// counted.
fn kspt_payloads(data: &[u8]) {
    let _ = kspt::parse(data, &P);
    let Ok(k) = legacy::parse_any(data, &P) else {
        return;
    };
    let _ = k.records().count();
    let mut ins = vec![BLANK_IN; P.max_inputs];
    let mut outs = vec![BLANK_OUT; P.max_outputs];
    let Ok((ni, no)) = transaction::fill(&k, &mut ins, &mut outs) else {
        return;
    };
    let tx = transaction::build(&k, &ins[..ni], &outs[..no]);
    let _ = check::transaction(&tx);
    // The spent coins' covenant ids: the bindings against them, and the
    // storage mass with the bound ones counted.
    let mut coins = vec![None; P.max_inputs];
    transaction::coins(&k, &mut coins);
    let _ = tx.check_covenant_ids(&coins[..ni]);
    let _ = transaction_storage_mass(&tx, &coins[..ni], MassRates::MAINNET.storage_mass_parameter);
    for (i, input) in k.inputs().enumerate().take(ni) {
        let _ = check::sequence(&tx, i);
        let _ = check::sig_ops(&tx, i, input.redeem);
        let _ = check::card(&tx, i, input.redeem);
        let _ = check::multisig(input.redeem);
        let _ = check::kspt_signatures(&tx, i, &input);
    }
    let _ = check::kspt_signers(data, &P);
    let _ = check::verify_kspt(data, &tx, &P);
}

#[test]
#[ignore = "fuzz: run with cargo +esp195 fuzz-all"]
fn a_kspt_payload_any_bytes() {
    mutate::run("kspt", 3000, kspts(), kspt_payloads);
}

// ── Frames ──────────────────────────────────────────────────────────────────

/// Codes as the camera hands them over: each a length byte and that many
/// bytes.
fn codes(data: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut rest = data;
    while let Some((&len, tail)) = rest.split_first() {
        let n = usize::from(len).min(tail.len());
        out.push(&tail[..n]);
        rest = &tail[n..];
    }
    out
}

fn framed(codes: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for c in codes {
        out.push(c.len() as u8);
        out.extend_from_slice(c);
    }
    out
}

/// Codes into the reassembler, and the payload out when it completes.
fn frame_codes(data: &[u8]) {
    let mut buf = vec![0u8; P.max_reassembled];
    let mut seen = vec![false; P.max_frames];
    let mut sizes = vec![0u8; P.max_frames];
    let mut r = Reassembler::new(&mut buf, &mut seen, &mut sizes, 255);
    for code in codes(data) {
        if let Ok(f) = frame::parse(code, P.max_frames) {
            let _ = r.push(&f);
            if r.is_complete() {
                let mut out = vec![0u8; P.max_reassembled];
                let _ = r.collect(&mut out);
            }
        }
    }
}

#[test]
#[ignore = "fuzz: run with cargo +esp195 fuzz-all"]
fn frames_any_bytes() {
    let mut seeds = Vec::new();
    for (format, payload) in [
        (Format::Kspt, kspts()[0].clone()),
        (Format::Kspt, kspts()[3].clone()),
        (Format::Opaque, b"kassigner.org login".to_vec()),
        (Format::Opaque, vec![0x5A; 2000]),
    ] {
        for per in [1, 40, 200] {
            let named = frame::digest(&payload);
            let codes: Vec<Vec<u8>> = payload
                .chunks(per)
                .enumerate()
                .map(|(i, chunk)| {
                    let total = payload.len().div_ceil(per).min(255) as u8;
                    let mut out = vec![0u8; frame::FIRST_HEADER_LEN + chunk.len()];
                    match frame::write(format, i as u8, total, named, chunk, &mut out) {
                        Ok(n) => out[..n].to_vec(),
                        Err(_) => Vec::new(),
                    }
                })
                .filter(|c| !c.is_empty() && c.len() < 256)
                .take(64)
                .collect();
            if !codes.is_empty() {
                seeds.push(framed(&codes));
            }
        }
    }
    mutate::run("frames", 3000, seeds, frame_codes);
}

// ── Text a camera reads ─────────────────────────────────────────────────────

fn messages(data: &[u8]) {
    let _ = message::is_text(data);
    let _ = message::is_signable(data);
    let mut hex = [0u8; 128];
    let _ = message::read_hex(data, &mut hex);
    if let Some(parts) = message::read(data) {
        let (text, address, signature) = (
            &data[parts.text.clone()],
            &data[parts.address.clone()],
            &data[parts.signature.clone()],
        );
        let _ = message::read_hex(signature, &mut hex);
        let mut out = vec![0u8; data.len() + 64];
        let _ = message::write(text, address, signature, &mut out);
    }
}

#[test]
#[ignore = "fuzz: run with cargo +esp195 fuzz-all"]
fn a_signed_message_any_bytes() {
    let mut seeds = vectors::files("v110/sdk", &["message.record"]);
    seeds.push(b"kassigner.org login".to_vec());
    seeds.push(b"0123456789abcdef".to_vec());
    mutate::run("message", 4000, seeds, messages);
}

fn kpubs(data: &[u8]) {
    let _ = kpub::starts_raw(data);
    let _ = kpub::read(data);
    let _ = kpub::read_cosigner(data);
}

#[test]
#[ignore = "fuzz: run with cargo +esp195 fuzz-all"]
fn a_kpub_any_bytes() {
    let mut seeds = vectors::files("v107/cards", &[".TXT"]);
    seeds.extend(vectors::files("v107/unit", &[".TXT"]));
    let first = seeds[0].clone();
    if let Some(key) = kpub::read(first.trim_ascii()) {
        let mut raw = [0u8; 128];
        let n = kpub::write_raw(&key, &mut raw).unwrap();
        seeds.push(raw[..n].to_vec());
        let mut cosigner = [0u8; 256];
        let n = kpub::write_cosigner([0x73, 0xC5, 0xDA, 0x0A], first.trim_ascii(), &mut cosigner)
            .unwrap();
        seeds.push(cosigner[..n].to_vec());
    }
    mutate::run("kpub", 3000, seeds, kpubs);
}

fn descriptors(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let mut keys = [""; MAX_MULTISIG_KEYS];
    let _ = descriptor::parse(descriptor::strip_header(text), &mut keys);
    if let Ok(group) = Group::<MAX_MULTISIG_KEYS>::from_descriptor(text) {
        let mut out = vec![0u8; 4096];
        let _ = group.write_descriptor(&mut out);
    }
}

#[test]
#[ignore = "fuzz: run with cargo +esp195 fuzz-all"]
fn a_descriptor_any_bytes() {
    // The vectors' kpub and its children, as cosigners.
    let first = vectors::files("v107/cards", &["KP000001.TXT"]).remove(0);
    let (prefix, key) = ExtendedPublicKey::from_text(first.trim_ascii()).unwrap();
    let kpubs: Vec<String> = (0..MAX_MULTISIG_KEYS as u32)
        .map(|i| {
            let mut out = [0u8; 128];
            let n = key
                .derive_child(ChildNumber(i))
                .unwrap()
                .to_text(prefix, &mut out)
                .unwrap();
            String::from_utf8(out[..n].to_vec()).unwrap()
        })
        .collect();
    let keys: Vec<&str> = kpubs.iter().map(String::as_str).collect();
    let mut seeds = Vec::new();
    for (m, n) in [
        (1, 1),
        (2, 3),
        (3, 5),
        (MAX_MULTISIG_KEYS, MAX_MULTISIG_KEYS),
    ] {
        let mut out = vec![0u8; 8192];
        let len = descriptor::write(m, &keys[..n], &mut out).unwrap();
        seeds.push(out[..len].to_vec());
    }
    mutate::run("descriptor", 2000, seeds, descriptors);
}

fn card_lines(data: &[u8]) {
    if let Ok(card) = backup::read(data) {
        let mut out = vec![0u8; 1024];
        let _ = backup::write(&card, &mut out);
    }
}

#[test]
#[ignore = "fuzz: run with cargo +esp195 fuzz-all"]
fn a_card_backup_line_any_bytes() {
    let seeds = vectors::files("v110/sdk", &["savings.backup"]);
    mutate::run("card backup", 4000, seeds, card_lines);
}

// ── Payloads, envelopes, containers ─────────────────────────────────────────

fn blobs(data: &[u8]) {
    let _ = payload::classify_blob(data);
    let _ = payload::parse_covenant(data);
    let mut out = vec![0u8; data.len() + 64];
    let _ = blob::shape(data);
    let _ = blob::strip(data, &mut out);
    let _ = blob::unpack(data, &mut out);
    let _ = blob::base64_decode(data, &mut out);
}

#[test]
#[ignore = "fuzz: run with cargo +esp195 fuzz-all"]
fn a_blob_any_bytes() {
    let mut seeds = Vec::new();
    let mut out = vec![0u8; 512];
    if let Ok(n) = payload::write_raw_blob(&[0x11; 100], &mut out) {
        seeds.push(out[..n].to_vec());
    }
    seeds.extend(vectors::files("v107/cards", &[".KAS"]));
    seeds.push(b"SGVsbG8sIGNhcmQh".to_vec());
    mutate::run("blob", 3000, seeds, blobs);
}

fn envelopes(data: &[u8]) {
    let _ = ecies::parse(data);
}

#[test]
#[ignore = "fuzz: run with cargo +esp195 fuzz-all"]
fn an_ecies_envelope_any_bytes() {
    let mut seeds = Vec::new();
    for len in [0usize, 1, 32, 300] {
        let mut wire = vec![0u8; 1 + 33 + 12 + len + 16 + 8];
        wire[1] = 0x02;
        seeds.push(wire);
    }
    mutate::run("ecies", 3000, seeds, envelopes);
}

fn containers(data: &[u8]) {
    let _ = container::parse(data);
}

#[test]
#[ignore = "fuzz: run with cargo +esp195 fuzz-all"]
fn a_container_any_bytes() {
    let mut seeds = vectors::files("v107/cards", &[".KAS"]);
    seeds.extend(vectors::files("v107/unit", &[".KAS"]));
    mutate::run("container", 4000, seeds, containers);
}

/// A photo as steganography reads it: its EXIF, and its payload by a key
/// from the picture and the metadata.
fn photos(data: &[u8]) {
    let _ = exif::read_payload(data);
    let _ = exif::read_descriptor(data);
    let mut coefficients = vec![0i16; picture::RANK_WINDOW];
    let mut filled = vec![0u8; picture::bitmap_len(picture::RANK_WINDOW)];
    let mut changed = filled.clone();
    let mut window = picture::Window {
        coefficients: &mut coefficients,
        filled: &mut filled,
        changed: &mut changed,
    };
    let mut tables = Box::new(picture::Tables::EMPTY);
    let mut picture = vec![0u8; kassigner_protocol::stego::PAYLOAD_MAX];
    let mut descriptor = picture.clone();
    let _ = carrier::extract(
        data,
        &[7; walk::KEY_SIZE],
        &mut window,
        &mut tables,
        &mut picture,
        &mut descriptor,
    );
}

#[test]
#[ignore = "fuzz: run with cargo +esp195 fuzz-all"]
fn a_photo_any_bytes() {
    let dir = "../../crates/kassigner-jpeg/tests/fixtures";
    let mut seeds = vectors::files(dir, &[".jpg"]);
    let host = seeds[0].clone();
    let mut app1 = vec![0u8; 64 * 1024];
    let n = exif::build(
        &host,
        b"a photo",
        &[0x42; 500],
        &[9; exif::RANDOM],
        &mut app1,
    )
    .unwrap();
    let mut file = host.clone();
    file.resize(host.len() + n + 64, 0);
    let len = exif::place(&mut file, host.len(), &app1[..n]).unwrap();
    file.truncate(len);
    seeds.push(file);
    mutate::run("exif", 1500, seeds, photos);
}
