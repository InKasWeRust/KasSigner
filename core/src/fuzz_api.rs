// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

// fuzz_api.rs — one function per parser, each taking raw bytes and
// panicking only on an invariant violation.
//
// These are the bodies of the cargo-fuzz targets in core/fuzz/ and of the
// host smoke loop in fuzz_smoke.rs, kept in one place so both drive
// exactly the same code with exactly the same checks. Compiled only for
// tests and for the `fuzz-api` feature the fuzz crate enables; the firmware
// never sees this module.
//
// Every function must be total over arbitrary input: a parser that returns
// `Err` is doing its job, a parser that panics, loops or indexes out of
// bounds is the finding. On top of "no panic" each target asserts what a
// successful parse guarantees the rest of the firmware, since those are the
// bounds the signing and display code index with.

use crate::wallet::transaction::{Transaction, MAX_INPUTS, MAX_OUTPUTS, MAX_SCRIPT_SIZE};
use crate::wallet::{address, bip39, pskt, std_pskt, transaction, xpub};
use crate::types::PsktParsed;
use crate::qr::payload;

/// The scratch size the firmware gives the PSKT parser (`signed_qr_buf`).
pub const PSKT_SCRATCH: usize = 4096;

fn boxed_tx() -> alloc::boxed::Box<Transaction> {
    Transaction::new_boxed().expect("host allocation")
}

/// Bounds every consumer of a parsed `Transaction` relies on.
fn check_tx_bounds(tx: &Transaction) {
    assert!(tx.num_inputs <= MAX_INPUTS, "num_inputs {} > MAX_INPUTS", tx.num_inputs);
    assert!(tx.num_outputs <= MAX_OUTPUTS, "num_outputs {} > MAX_OUTPUTS", tx.num_outputs);
    for i in 0..tx.num_inputs {
        let l = tx.inputs[i].utxo_entry.script_public_key.script_len;
        assert!(l <= MAX_SCRIPT_SIZE, "input {i} script_len {l}");
    }
    for o in 0..tx.num_outputs {
        let l = tx.outputs[o].script_public_key.script_len;
        assert!(l <= MAX_SCRIPT_SIZE, "output {o} script_len {l}");
    }
}

/// KSPT v1/v2 (the compact binary envelope).
pub fn kspt_parse(data: &[u8]) {
    let mut tx = boxed_tx();
    if pskt::parse_pskt(data, &mut tx).is_ok() {
        check_tx_bounds(&tx);
        // A parsed transaction must survive the display paths that read it.
        let _ = tx.fee();
        for i in 0..tx.num_inputs {
            let _ = pskt::analyze_input_script(&tx, i);
        }
        let _ = pskt::signature_status(&tx);
    }
}

/// Kaspa-standard PSKB / single PSKT (hex-wrapped JSON).
pub fn pskt_parse(data: &[u8]) {
    let mut tx = boxed_tx();
    let mut scratch = alloc::vec![0u8; PSKT_SCRATCH];
    let mut parsed = PsktParsed::empty();
    if std_pskt::parse_pskt(data, &mut scratch, &mut tx, &mut parsed).is_ok() {
        check_tx_bounds(&tx);
        // The unknown-region offsets are sliced out of `scratch` by the
        // serializer; every one must lie inside the decoded JSON.
        assert!(parsed.unknowns_count as usize <= parsed.unknowns.len());
        let json_end = parsed.json_start as usize + parsed.json_len as usize;
        assert!(json_end <= PSKT_SCRATCH, "json range past scratch");
        for k in 0..parsed.unknowns_count as usize {
            let (s, e) = parsed.unknowns[k];
            assert!(s <= e && (e as usize) <= json_end, "unknown region {k} ({s},{e}) outside json");
        }
        let _ = std_pskt::detect_tx_format(data);
        let _ = std_pskt::pskt_signature_status(&tx);
        let _ = tx.fee();
    }
}

/// Strict hex decoder on its own: the front door of the PSKT path.
pub fn hex_decode(data: &[u8]) {
    let mut dst = alloc::vec![0u8; PSKT_SCRATCH];
    if let Ok(n) = std_pskt::hex_decode_strict(data, &mut dst) {
        assert_eq!(n * 2, data.len(), "decoded {n} bytes from {} hex chars", data.len());
    }
}

/// kpub in any of the accepted envelopes (base58 string, raw, wrapped).
pub fn kpub_import(data: &[u8]) {
    let _ = xpub::import_kpub_any(data);
    let _ = xpub::parse_kpub_parts_any(data);
    let _ = xpub::import_kpub(data);
    let _ = xpub::parse_kpub_parts(data);
}

/// xprv string import.
pub fn xprv_import(data: &[u8]) {
    let _ = xpub::import_xprv(data);
}

/// Address validation (bech32-style, `kaspa:` prefix).
pub fn address_validate(data: &[u8]) {
    let _ = address::validate_kaspa_address(data);
}

/// Script classification and multisig template parse, driven with the
/// same `(script, len)` contract the callers use: `len` never exceeds the
/// buffer, and the buffer is the fixed `MAX_SCRIPT_SIZE` array.
pub fn script_parse(data: &[u8]) {
    let mut script = [0u8; MAX_SCRIPT_SIZE];
    let len = data.len().min(MAX_SCRIPT_SIZE);
    script[..len].copy_from_slice(&data[..len]);
    let kind = transaction::detect_script_type(&script, len);
    if let Some(info) = transaction::parse_multisig_script(&script, len) {
        assert_eq!(kind, transaction::ScriptType::Multisig);
        assert!(info.m >= 1 && info.m <= info.n, "m={} n={}", info.m, info.n);
        assert!((info.n as usize) <= info.pubkeys.len(), "n={} > pubkey slots", info.n);
    }
}

/// QR payload envelope classifier.
pub fn payload_classify(data: &[u8]) {
    let _ = payload::classify(data);
}

/// Mnemonic checksum validation over arbitrary word indices, including
/// indices past the 2048-word list, which a scanned QR can carry.
pub fn mnemonic_validate(data: &[u8]) {
    if data.len() >= 24 {
        let mut m = bip39::Mnemonic12 { indices: [0u16; 12] };
        for (i, w) in m.indices.iter_mut().enumerate() {
            *w = u16::from_le_bytes([data[2 * i], data[2 * i + 1]]);
        }
        let _ = bip39::validate_mnemonic_12(&m);
        m.zeroize();
    }
    if data.len() >= 48 {
        let mut m = bip39::Mnemonic24 { indices: [0u16; 24] };
        for (i, w) in m.indices.iter_mut().enumerate() {
            *w = u16::from_le_bytes([data[2 * i], data[2 * i + 1]]);
        }
        let _ = bip39::validate_mnemonic_24(&m);
        m.zeroize();
    }
    if let Ok(s) = core::str::from_utf8(data) {
        let _ = bip39::word_to_index(s);
    }
}
