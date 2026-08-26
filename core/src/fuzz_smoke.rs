// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

// fuzz_smoke.rs — the fuzz targets driven from `cargo test`.
//
// cargo-fuzz (core/fuzz/) is the real tool: coverage-guided, libFuzzer,
// nightly. This file is the part that runs everywhere: for each target in
// fuzz_api.rs it feeds a set of valid seeds minted from the crate's own
// serializers, then a fixed, reproducible mutation schedule over those
// seeds (bit flips, byte overwrites, truncations, insertions, doubling)
// and a set of structural edge cases. A few thousand executions per
// target, seconds on a host, and every one of them a `cargo test` failure
// with the offending input printed if a parser panics.
//
// The seeds double as the corpus for cargo-fuzz: `seed_corpus()` is what
// core/fuzz/ writes to disk before a run.

extern crate std;
use std::vec::Vec;
use std::string::String;
use std::println;

use crate::fuzz_api as t;
use crate::types::{PsktParsed, TxInputFormat};
use crate::wallet::transaction::{Transaction, MAX_SCRIPT_SIZE};
use crate::wallet::{address, bip32, bip39, pskt, std_pskt, transaction, xpub};

// ---- seeds ---------------------------------------------------------------

/// The transaction the KSPT round-trip KAT uses, one input, two outputs.
fn sample_tx() -> alloc::boxed::Box<Transaction> {
    let mut tx = Transaction::new_boxed().expect("alloc");
    tx.version = 0;
    tx.num_inputs = 1;
    tx.num_outputs = 2;
    tx.inputs[0].previous_outpoint.transaction_id = [0xDE; 32];
    tx.inputs[0].previous_outpoint.index = 3;
    tx.inputs[0].utxo_entry.amount = 500_000_000;
    tx.inputs[0].sequence = u64::MAX;
    tx.inputs[0].sig_op_count = 1;
    tx.inputs[0].sighash_type = 1; // SIGHASH_ALL, the only type the PSKT parser accepts
    let spk = &mut tx.inputs[0].utxo_entry.script_public_key;
    spk.version = 0;
    spk.script[0] = 0x20;
    spk.script[1..33].copy_from_slice(&[0xAA; 32]);
    spk.script[33] = 0xAC;
    spk.script_len = 34;
    for (o, (v, fill)) in [(450_000_000u64, 0xBBu8), (49_000_000, 0xCC)].into_iter().enumerate() {
        tx.outputs[o].value = v;
        let spk = &mut tx.outputs[o].script_public_key;
        spk.version = 0;
        spk.script[0] = 0x20;
        spk.script[1..33].copy_from_slice(&[fill; 32]);
        spk.script[33] = 0xAC;
        spk.script_len = 34;
    }
    tx
}

fn kspt_seeds() -> Vec<Vec<u8>> {
    let tx = sample_tx();
    let mut out = Vec::new();
    let mut buf = [0u8; 2048];
    // The device accepts KSPT v1 and v4 (v4 = v1 body plus the m/45'
    // hint trailer) as input; `serialize_pskt` emits v4 when any hint is
    // present. The signed layouts are device output only (KasSee parses
    // them), so they are not seeds here.
    let n = pskt::serialize_pskt(&tx, &mut buf).expect("kspt v1");
    out.push(buf[..n].to_vec());
    let mut hinted = tx;
    hinted.inputs[0].ms45_hint = transaction::Ms45Hint { present: true, cosigner: 1, chain: 0, index: 7 };
    hinted.outputs[1].ms45_hint = transaction::Ms45Hint { present: true, cosigner: 1, chain: 1, index: 3 };
    let n = pskt::serialize_pskt(&hinted, &mut buf).expect("kspt v4");
    out.push(buf[..n].to_vec());
    out
}

fn pskt_seeds() -> Vec<Vec<u8>> {
    let tx = sample_tx();
    let parsed = PsktParsed::empty();
    let scratch = [0u8; 0];
    let mut out = Vec::new();
    let mut buf = alloc::vec![0u8; 16384];
    let n = std_pskt::serialize_pskt(&tx, &parsed, &scratch, TxInputFormat::PsktPskb, &mut buf).expect("pskb");
    out.push(buf[..n].to_vec());
    // A second seed with the bare-object body under the same magic: not a
    // valid input (the parser requires the bundle array), kept as bytes
    // for the mutation loop so the array boundary itself gets exercised.
    let hex_body = &buf[4..n];
    let mut bare = b"PSKB".to_vec();
    bare.extend_from_slice(&hex_body[2..hex_body.len() - 2]); // drop hex("[") and hex("]")
    out.push(bare);
    out
}

fn account_key() -> bip32::ExtendedPrivKey {
    bip32::derive_account_key(&[0x42u8; 64]).expect("account key")
}

fn kpub_seeds() -> Vec<Vec<u8>> {
    let acct = account_key();
    let mut buf = [0u8; xpub::KPUB_MAX_LEN];
    let n = xpub::serialize_kpub_from_account(&acct, &mut buf).expect("kpub");
    alloc::vec![buf[..n].to_vec()]
}

fn xprv_seeds() -> Vec<Vec<u8>> {
    let acct = account_key();
    let mut buf = [0u8; xpub::XPRV_MAX_LEN];
    let n = xpub::serialize_xprv_from_account(&acct, &mut buf).expect("xprv");
    alloc::vec![buf[..n].to_vec()]
}

fn address_seeds() -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf = [0u8; address::MAX_ADDR_LEN];
    let pk = [0x11u8; 32];
    for ty in [address::AddressType::P2PK, address::AddressType::P2SH] {
        let n = address::encode_address(&pk, ty, &mut buf);
        out.push(buf[..n].to_vec());
    }
    out
}

fn script_seeds() -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    // P2PK
    let mut p2pk = alloc::vec![0x20u8];
    p2pk.extend_from_slice(&[0xAA; 32]);
    p2pk.push(0xAC);
    out.push(p2pk);
    // 2-of-3 multisig
    let mut ms = alloc::vec![transaction::OP_1 + 1];
    for k in 0..3u8 {
        ms.push(0x20);
        ms.extend_from_slice(&[0x10 + k; 32]);
    }
    ms.push(transaction::OP_1 + 2);
    ms.push(transaction::OP_CHECKMULTISIG);
    out.push(ms);
    out
}

fn payload_seeds() -> Vec<Vec<u8>> {
    let mut out = kspt_seeds();
    out.extend(pskt_seeds());
    out.extend(kpub_seeds());
    out
}

fn mnemonic_seeds() -> Vec<Vec<u8>> {
    let m12 = bip39::mnemonic_from_entropy_12(&[0u8; 16]);
    let m24 = bip39::mnemonic_from_entropy_24(&[0x7f; 32]);
    let mut a = Vec::new();
    for w in m12.indices { a.extend_from_slice(&w.to_le_bytes()); }
    let mut b = Vec::new();
    for w in m24.indices { b.extend_from_slice(&w.to_le_bytes()); }
    alloc::vec![a, b, b"abandon".to_vec()]
}

/// Every seed set, keyed by target name. Used by core/fuzz/ to populate
/// its corpus directories.
pub fn seed_corpus() -> Vec<(&'static str, Vec<Vec<u8>>)> {
    alloc::vec![
        ("kspt_parse", kspt_seeds()),
        ("pskt_parse", pskt_seeds()),
        ("hex_decode", pskt_seeds().into_iter().map(|w| w[4..].to_vec()).collect()),
        ("kpub_import", kpub_seeds()),
        ("xprv_import", xprv_seeds()),
        ("address_validate", address_seeds()),
        ("script_parse", script_seeds()),
        ("payload_classify", payload_seeds()),
        ("mnemonic_validate", mnemonic_seeds()),
    ]
}

// ---- mutation schedule ----------------------------------------------------

/// xorshift64*, fixed seed: the schedule is identical on every run, so a
/// failure reproduces without any corpus file.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize { (self.next() % (n.max(1) as u64)) as usize }
}

fn mutate(rng: &mut Rng, base: &[u8]) -> Vec<u8> {
    let mut v = base.to_vec();
    let rounds = 1 + rng.below(4);
    for _ in 0..rounds {
        match rng.below(8) {
            0 if !v.is_empty() => { let i = rng.below(v.len()); v[i] ^= 1 << rng.below(8); }
            1 if !v.is_empty() => { let i = rng.below(v.len()); v[i] = rng.next() as u8; }
            2 if !v.is_empty() => { let n = rng.below(v.len()); v.truncate(n); }
            3 => { let i = rng.below(v.len() + 1); v.insert(i, rng.next() as u8); }
            4 if !v.is_empty() => { let i = rng.below(v.len()); v.remove(i); }
            5 if !v.is_empty() => {
                // Interesting integers at a random offset.
                let i = rng.below(v.len());
                let pick = [0x00u8, 0xff, 0x7f, 0x80, 0x20, 0xac, 0xae, 0x51, 0x55];
                v[i] = pick[rng.below(pick.len())];
            }
            6 if v.len() < 8192 => { let c = v.clone(); v.extend_from_slice(&c); }
            _ => { let i = rng.below(v.len() + 1); let n = rng.below(64); for _ in 0..n { v.insert(i, rng.next() as u8); } }
        }
    }
    v
}

fn structural(seed: &[u8]) -> Vec<Vec<u8>> {
    let mut out = alloc::vec![Vec::new(), alloc::vec![0u8; 1], alloc::vec![0xffu8; 4096], alloc::vec![0u8; 65_536]];
    for n in [1usize, 2, 3, 4, 5, 8, 16, 33, 34, 35, 36, 37, 64, 255, 256] {
        if n < seed.len() { out.push(seed[..n].to_vec()); }
    }
    let mut hex = seed.to_vec();
    for b in hex.iter_mut() { *b = b"0123456789abcdefABCDEF"[(*b as usize) % 22]; }
    out.push(hex);
    out
}

fn drive(name: &str, target: fn(&[u8]), seeds: &[Vec<u8>], iterations: usize) {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15 ^ name.len() as u64);
    let mut runs = 0usize;
    for s in seeds {
        target(s);
        for e in structural(s) { target(&e); runs += 1; }
    }
    for _ in 0..iterations {
        let s = &seeds[rng.below(seeds.len())];
        let m = mutate(&mut rng, s);
        // Wrap so a panic reports the input that caused it.
        let r = std::panic::catch_unwind(|| target(&m));
        if r.is_err() {
            use core::fmt::Write;
            let mut hex = String::new();
            for b in &m { let _ = write!(hex, "{b:02x}"); }
            panic!("{name}: panic on input ({} bytes): {hex}", m.len());
        }
        runs += 1;
    }
    println!("{name}: {runs} executions, {} seeds", seeds.len());
}

const ITER: usize = 3000;

#[test] fn kspt_parse()        { drive("kspt_parse",        t::kspt_parse,        &kspt_seeds(),     ITER); }
#[test] fn pskt_parse()        { drive("pskt_parse",        t::pskt_parse,        &pskt_seeds(),     ITER); }
#[test] fn hex_decode()        { drive("hex_decode",        t::hex_decode,        &pskt_seeds(),     ITER); }
#[test] fn kpub_import()       { drive("kpub_import",       t::kpub_import,       &kpub_seeds(),     ITER); }
#[test] fn xprv_import()       { drive("xprv_import",       t::xprv_import,       &xprv_seeds(),     ITER); }
#[test] fn address_validate()  { drive("address_validate",  t::address_validate,  &address_seeds(),  ITER); }
#[test] fn script_parse()      { drive("script_parse",      t::script_parse,      &script_seeds(),   ITER); }
#[test] fn payload_classify()  { drive("payload_classify",  t::payload_classify,  &payload_seeds(),  ITER); }
#[test] fn mnemonic_validate() { drive("mnemonic_validate", t::mnemonic_validate, &mnemonic_seeds(), ITER); }

/// The seeds must be accepted by their own parsers, or the mutation loop
/// is exploring nothing.
#[test]
fn seeds_are_valid() {
    let mut tx = Transaction::new_boxed().unwrap();
    for (i, s) in kspt_seeds().iter().enumerate() { assert!(pskt::parse_pskt(s, &mut tx).is_ok(), "kspt seed {i} rejected"); }
    let mut scratch = alloc::vec![0u8; t::PSKT_SCRATCH];
    let mut parsed = PsktParsed::empty();
    // Only the first PSKB seed is valid input; the second is the bare
    // object under the same magic, kept for the mutation loop only.
    let pskb = &pskt_seeds()[0];
    let r = std_pskt::parse_pskt(pskb, &mut scratch, &mut tx, &mut parsed);
    assert!(r.is_ok(), "pskb seed rejected: {r:?}");
    for s in kpub_seeds() { assert!(xpub::import_kpub_any(&s).is_ok(), "kpub seed rejected"); }
    for s in xprv_seeds() { assert!(xpub::import_xprv(&s).is_ok(), "xprv seed rejected"); }
    for s in address_seeds() { assert!(address::validate_kaspa_address(&s), "address seed rejected"); }
    let ms = &script_seeds()[1];
    let mut script = [0u8; MAX_SCRIPT_SIZE];
    script[..ms.len()].copy_from_slice(ms);
    assert!(transaction::parse_multisig_script(&script, ms.len()).is_some(), "multisig seed rejected");
    let m12 = bip39::mnemonic_from_entropy_12(&[0u8; 16]);
    assert!(bip39::validate_mnemonic_12(&m12).is_ok());
}
