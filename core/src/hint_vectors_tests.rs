// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

// hint_vectors_tests.rs — the m/45' derivation-hint vectors, on the host.
//
// Source: `kspt_v4_vector.html` v10 (the audit QR vector page for the hint
// work, built on the BIP39 "abandon x11 + about" test seed), cases
// `V8_kspt_v4_to_device` and `V9_pskb_to_kassee`. Those pages had no home
// in the tree (STATE.md, "deferred to the v1.1 file reordering"); the
// payloads live here now, decoded from the QR frames.
//
// Multi-frame envelope, for anyone re-deriving these: each QR frame is
// three header bytes [frame index, frame count, payload length] followed by
// the payload; the payloads concatenate in index order. V8 is two frames
// (227 + 101 bytes), V9 fifteen. The assembler itself is firmware
// (camera_loop.rs, `process_multiframe`); only the assembled bytes are
// tested here.
//
// What the pair proves that neither alone does: the compact KSPT v4 hint
// trailer and the PSKB `bip32Derivations` map are two encodings of the same
// transaction, and both parsers must land on the same fields and the same
// hints. The device signs from the first; KasSee relays with the second.

extern crate std;
use crate::types::PsktParsed;
use crate::wallet::transaction::{Ms45Hint, Transaction};
use crate::wallet::{pskt, std_pskt};

/// V8: KSPT v4, version 0x04, flags 0x02 (redeem present), 1 input /
/// 2 outputs, trailer 0x44 input#0 = S1/C0/#0 and 0x45 output#1 = S1/C1/#3.
const V8_KSPT_V4_HEX: &str = "4b5350540402000001020000000000000000000000000000000000000000000000000000000000000000000000000000cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc0000000000a3e11100000000000000000000000002000023aa20e776ae0e80002529bb2f46aa37e4633dfa2e7ead0ee36bf87be9386b84b8101e87455220d1b13afab5c7f063447c2173dfa196ecd7d7f80515ffc1f507f7c2be55950f712093743a1020cc6afe2a9aaed750db7b4862c28c6c08986c6825269950dc99cdd352ae00e1f50500000000000022205fff3c4da18f45adcdd499e44611e9fff148ba69db3c4ea2b8b2a5b0b4b7c2a1ac409ae20b00000000000023aa20eaa397dd1842d6df2881215c350e4aa9195f6be0f895ac6b53bbda75eab9f6998744000100000000000000000000004501010000000100000003000000";

/// V9: the same transaction as a PSKB with bip32Derivations, keyFingerprint
/// and derivationPath `m/45'/111111'/0'/1/0/0` on the input and
/// `m/45'/111111'/0'/1/1/3` on output 1.
const V9_PSKB: &[u8] = b"PSKB5b7b22676c6f62616c223a7b2276657273696f6e223a302c22747856657273696f6e223a302c2266616c6c6261636b4c6f636b54696d65223a6e756c6c2c22696e707574734d6f6469666961626c65223a66616c73652c226f7574707574734d6f6469666961626c65223a66616c73652c22696e707574436f756e74223a312c226f7574707574436f756e74223a322c227870756273223a7b7d2c226964223a6e756c6c2c2270726f70726965746172696573223a7b7d7d2c22696e70757473223a5b7b227574786f456e747279223a7b22616d6f756e74223a3330303030303030302c227363726970745075626c69634b6579223a223030303061613230653737366165306538303030323532396262326634366161333765343633336466613265376561643065653336626638376265393338366238346238313031653837222c22626c6f636b44616153636f7265223a302c226973436f696e62617365223a66616c73657d2c2270726576696f75734f7574706f696e74223a7b227472616e73616374696f6e4964223a2263636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363222c22696e646578223a307d2c2273657175656e6365223a302c226d696e54696d65223a6e756c6c2c227061727469616c53696773223a7b7d2c227369676861736854797065223a312c2272656465656d536372697074223a22353232306431623133616661623563376630363334343763323137336466613139366563643764376638303531356666633166353037663763326265353539353066373132303933373433613130323063633661666532613961616564373530646237623438363263323863366330383938366336383235323639393530646339396364643335326165222c227369674f70436f756e74223a322c22626970333244657269766174696f6e73223a7b22303264316231336166616235633766303633343437633231373364666131393665636437643766383035313566666331663530376637633262653535393530663731223a7b226b657946696e6765727072696e74223a223531303063633731222c2264657269766174696f6e50617468223a226d2f3435272f313131313131272f30272f312f302f30227d2c22303339333734336131303230636336616665326139616165643735306462376234383632633238633663303839383663363832353236393935306463393963646433223a7b226b657946696e6765727072696e74223a223539343135306531222c2264657269766174696f6e50617468223a226d2f3435272f313131313131272f30272f312f302f30227d7d2c2266696e616c536372697074536967223a6e756c6c2c2270726f70726965746172696573223a7b7d7d5d2c226f757470757473223a5b7b22616d6f756e74223a3130303030303030302c227363726970745075626c69634b6579223a22303030303230356666663363346461313866343561646364643439396534343631316539666666313438626136396462336334656132623862326135623062346237633261316163222c2272656465656d536372697074223a6e756c6c2c22626970333244657269766174696f6e73223a7b7d2c2270726f70726965746172696573223a7b7d7d2c7b22616d6f756e74223a3139393430303030302c227363726970745075626c69634b6579223a223030303061613230656161333937646431383432643664663238383132313563333530653461613931393566366265306638393561633662353362626461373565616239663639393837222c2272656465656d536372697074223a6e756c6c2c22626970333244657269766174696f6e73223a7b22303366613064663935623335323066653663333237613563303430356163326438636434346432623439366235626432333663623332346235323134373361616433223a7b226b657946696e6765727072696e74223a223531303063633731222c2264657269766174696f6e50617468223a226d2f3435272f313131313131272f30272f312f312f33227d2c22303335376163646566393564623632363037316233326235393566653138623166356434653236616537623536393063356462303236383666303265616163396132223a7b226b657946696e6765727072696e74223a223539343135306531222c2264657269766174696f6e50617468223a226d2f3435272f313131313131272f30272f312f312f33227d7d2c2270726f70726965746172696573223a7b7d7d5d7d5d";

fn hex(s: &str) -> alloc::vec::Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex")).collect()
}

fn hint(h: &Ms45Hint) -> (bool, u32, u32, u32) {
    (h.present, h.cosigner, h.chain, h.index)
}

fn parse_kspt() -> alloc::boxed::Box<Transaction> {
    let mut tx = Transaction::new_boxed().expect("alloc");
    pskt::parse_pskt(&hex(V8_KSPT_V4_HEX), &mut tx).expect("V8 must parse");
    tx
}

fn parse_pskb() -> alloc::boxed::Box<Transaction> {
    let mut tx = Transaction::new_boxed().expect("alloc");
    let mut scratch = alloc::vec![0u8; 8192];
    let mut parsed = PsktParsed::empty();
    std_pskt::parse_pskt(V9_PSKB, &mut scratch, &mut tx, &mut parsed).expect("V9 must parse");
    tx
}

#[test]
fn v8_kspt_v4_hint_trailer() {
    let tx = parse_kspt();
    assert_eq!(tx.num_inputs, 1);
    assert_eq!(tx.num_outputs, 2);
    assert_eq!(hint(&tx.inputs[0].ms45_hint), (true, 1, 0, 0), "input 0: S1/C0/#0");
    assert_eq!(hint(&tx.outputs[0].ms45_hint), (false, 0, 0, 0), "output 0 carries no hint");
    assert_eq!(hint(&tx.outputs[1].ms45_hint), (true, 1, 1, 3), "output 1: S1/C1/#3");
}

#[test]
fn v9_pskb_bip32_derivations() {
    let tx = parse_pskb();
    assert_eq!(tx.num_inputs, 1);
    assert_eq!(tx.num_outputs, 2);
    assert_eq!(hint(&tx.inputs[0].ms45_hint), (true, 1, 0, 0));
    assert_eq!(hint(&tx.outputs[0].ms45_hint), (false, 0, 0, 0));
    assert_eq!(hint(&tx.outputs[1].ms45_hint), (true, 1, 1, 3));
    // Explicit fields in this vector: sequence 0 as written, no minTime.
    assert_eq!(tx.inputs[0].sequence, 0);
    assert_eq!(tx.locktime, 0);
}

/// The two encodings describe one transaction. Every field the signature
/// commits to and every hint must agree, or the device would sign one
/// thing while KasSee relays another.
#[test]
fn kspt_and_pskb_encodings_agree() {
    let a = parse_kspt();
    let b = parse_pskb();
    assert_eq!(a.version, b.version);
    assert_eq!(a.num_inputs, b.num_inputs);
    assert_eq!(a.num_outputs, b.num_outputs);
    assert_eq!(a.locktime, b.locktime);
    for i in 0..a.num_inputs {
        let (x, y) = (&a.inputs[i], &b.inputs[i]);
        assert_eq!(x.previous_outpoint.transaction_id, y.previous_outpoint.transaction_id, "input {i} outpoint");
        assert_eq!(x.previous_outpoint.index, y.previous_outpoint.index);
        assert_eq!(x.utxo_entry.amount, y.utxo_entry.amount, "input {i} amount");
        assert_eq!(x.sequence, y.sequence, "input {i} sequence");
        // `sighash_type` is deliberately NOT compared. KSPT carries no
        // per-input sighash byte (the type is implicit; the byte at
        // pskt.rs:87 belongs to the signed-response format), so the KSPT
        // parser leaves the field 0, while PSKB carries it explicitly and
        // the parser requires 1. Both mean SIGHASH_ALL, and every signing
        // call site passes `SigHashType::All` rather than reading the field
        // (app/signing.rs:1005,1024,1126,1277,1456). A format difference,
        // not a disagreement about the transaction.
        assert_eq!(y.sighash_type, 1, "PSKB states SIGHASH_ALL explicitly");
        assert_eq!(x.sig_op_count, y.sig_op_count);
        let (sx, sy) = (&x.utxo_entry.script_public_key, &y.utxo_entry.script_public_key);
        assert_eq!(sx.version, sy.version);
        assert_eq!(sx.script_len, sy.script_len);
        assert_eq!(sx.script[..sx.script_len], sy.script[..sy.script_len], "input {i} spk");
        assert_eq!(hint(&x.ms45_hint), hint(&y.ms45_hint), "input {i} hint");
    }
    for o in 0..a.num_outputs {
        let (x, y) = (&a.outputs[o], &b.outputs[o]);
        assert_eq!(x.value, y.value, "output {o} value");
        let (sx, sy) = (&x.script_public_key, &y.script_public_key);
        assert_eq!(sx.version, sy.version);
        assert_eq!(sx.script_len, sy.script_len);
        assert_eq!(sx.script[..sx.script_len], sy.script[..sy.script_len], "output {o} spk");
        assert_eq!(hint(&x.ms45_hint), hint(&y.ms45_hint), "output {o} hint");
    }
}
