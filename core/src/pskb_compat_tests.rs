// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

// pskb_compat_tests.rs — agreement with the reference implementation.
//
// The fixture below is rusty-kaspa 2.0.1's own committed PSKB, lifted
// verbatim from `wallet/pskt/src/wasm/bundle.rs:229` (`_test_deser`). It is
// their serializer's output, so it is the closest thing to a conformance
// vector this format has. Until 1.0.7 our parser rejected it, twice over:
// `"sequence": null` and `inputCount`/`outputCount` of 0 beside populated
// arrays. Both are normal output from their Creator and Constructor roles.
//
// A linked differential suite (generate with their crate, parse with ours)
// is the stronger form and is not possible here: rusty-kaspa 2.0.1 is
// edition 2024 and needs Rust 1.91, so it cannot be a dependency of this
// crate's tests on the toolchains we build with. Fixtures are the fallback:
// their bytes, our parser, no dependency, no network, runs in the Docker
// reproducible build like everything else.

extern crate std;
use std::vec::Vec;
use crate::types::PsktParsed;
use crate::wallet::std_pskt;
use crate::wallet::transaction::Transaction;

/// rusty-kaspa 2.0.1, `wallet/pskt/src/wasm/bundle.rs:229`.
const RK_FIXTURE: &[u8] = b"PSKB5b7b22676c6f62616c223a7b2276657273696f6e223a302c22747856657273696f6e223a302c2266616c6c6261636b4c6f636b54696d65223a6e756c6c2c22696e707574734d6f6469666961626c65223a66616c73652c226f7574707574734d6f6469666961626c65223a66616c73652c22696e707574436f756e74223a302c226f7574707574436f756e74223a302c227870756273223a7b7d2c226964223a6e756c6c2c2270726f70726965746172696573223a7b7d2c227061796c6f6164223a22227d2c22696e70757473223a5b7b227574786f456e747279223a7b22616d6f756e74223a3436383932383838372c227363726970745075626c69634b6579223a22303030303230326438613134313465363265303831666236626366363434653634386331383036316332383535353735636163373232663836333234636164393164643066616163222c22626c6f636b44616153636f7265223a38343938313138362c226973436f696e62617365223a66616c73657d2c2270726576696f75734f7574706f696e74223a7b227472616e73616374696f6e4964223a2236393135356430653333383065383831366466666532363731323934616431303466306233373736663335626365316132326630633231623166393038353030222c22696e646578223a307d2c2273657175656e6365223a6e756c6c2c226d696e54696d65223a6e756c6c2c227061727469616c53696773223a7b7d2c227369676861736854797065223a312c2272656465656d536372697074223a6e756c6c2c227369674f70436f756e74223a312c22626970333244657269766174696f6e73223a7b7d2c2266696e616c536372697074536967223a6e756c6c2c2270726f70726965746172696573223a7b7d7d5d2c226f757470757473223a5b7b22616d6f756e74223a313530303030303030302c227363726970745075626c69634b6579223a2230303030222c2272656465656d536372697074223a6e756c6c2c22626970333244657269766174696f6e73223a7b7d2c2270726f70726965746172696573223a7b7d7d5d7d5d";

fn parse(wire: &[u8]) -> Result<(alloc::boxed::Box<Transaction>, PsktParsed), std_pskt::PskError> {
    let mut tx = Transaction::new_boxed().expect("alloc");
    let mut scratch = alloc::vec![0u8; 8192];
    let mut parsed = PsktParsed::empty();
    std_pskt::parse_pskt(wire, &mut scratch, &mut tx, &mut parsed)?;
    Ok((tx, parsed))
}

/// Rebuild a bundle from parts so a single field can be varied.
fn wire_with(sequence: &str, min_time: &str, in_count: u32, out_count: u32) -> Vec<u8> {
    let json = alloc::format!(
        concat!(
            r#"[{{"global":{{"version":0,"txVersion":0,"fallbackLockTime":null,"#,
            r#""inputsModifiable":false,"outputsModifiable":false,"#,
            r#""inputCount":{},"outputCount":{},"xpubs":{{}},"id":null,"#,
            r#""proprietaries":{{}},"payload":""}},"inputs":[{{"#,
            r#""utxoEntry":{{"amount":468928887,"scriptPublicKey":"#,
            r#""0000202d8a1414e62e081fb6bcf644e648c18061c2855575cac722f86324cad91dd0faac","#,
            r#""blockDaaScore":84981186,"isCoinbase":false}},"previousOutpoint":{{"#,
            r#""transactionId":"69155d0e3380e8816dffe2671294ad104f0b3776f35bce1a22f0c21b1f908500","#,
            r#""index":0}},{}{}"partialSigs":{{}},"sighashType":1,"redeemScript":null,"#,
            r#""sigOpCount":1,"bip32Derivations":{{}},"finalScriptSig":null,"#,
            r#""proprietaries":{{}}}}],"outputs":[{{"amount":1500000000,"#,
            r#""scriptPublicKey":"0000202d8a1414e62e081fb6bcf644e648c18061c2855575cac722f86324cad91dd0faac","#,
            r#""redeemScript":null,"bip32Derivations":{{}},"proprietaries":{{}}}}]}}]"#,
        ),
        in_count, out_count, sequence, min_time
    );
    let mut wire = Vec::from(&b"PSKB"[..]);
    for b in json.as_bytes() {
        wire.extend_from_slice(alloc::format!("{b:02x}").as_bytes());
    }
    wire
}

#[test]
fn reference_fixture_parses() {
    let (tx, _) = parse(RK_FIXTURE).expect("rusty-kaspa's own bundle must parse");
    assert_eq!(tx.num_inputs, 1);
    assert_eq!(tx.num_outputs, 1);
    assert_eq!(tx.inputs[0].utxo_entry.amount, 468_928_887);
    assert_eq!(tx.outputs[0].value, 1_500_000_000);
    assert_eq!(tx.inputs[0].sighash_type, 1);
    // "sequence": null in the fixture.
    assert_eq!(tx.inputs[0].sequence, u64::MAX);
    // No minTime anywhere, so no lock time.
    assert_eq!(tx.locktime, 0);
}

/// Both spellings of "unset" mean the final sequence number, as the
/// reference signer hashes it (`pskt.rs:146`, `unwrap_or(u64::MAX)`).
#[test]
fn unset_sequence_is_max_in_both_spellings() {
    for spelling in ["", r#""sequence":null,"#] {
        let (tx, _) = parse(&wire_with(spelling, r#""minTime":null,"#, 1, 1)).expect("unset sequence");
        assert_eq!(tx.inputs[0].sequence, u64::MAX, "spelling {spelling:?}");
    }
}

/// An explicit sequence is signed exactly as given, including 0.
#[test]
fn explicit_sequence_is_preserved() {
    for v in [0u64, 1, 7, u64::MAX - 1, u64::MAX] {
        let field = alloc::format!(r#""sequence":{v},"#);
        let (tx, _) = parse(&wire_with(&field, r#""minTime":null,"#, 1, 1)).expect("explicit sequence");
        assert_eq!(tx.inputs[0].sequence, v);
    }
}

/// The lock time is the largest `minTime` over the inputs, 0 when none
/// states one (`pskt.rs:172`, `determine_lock_time`). Skipped entirely
/// until 1.0.7, which made the device sign 0 for a timelocked transaction.
#[test]
fn min_time_becomes_the_lock_time() {
    let (tx, _) = parse(&wire_with(r#""sequence":0,"#, r#""minTime":null,"#, 1, 1)).unwrap();
    assert_eq!(tx.locktime, 0, "null minTime is no lock time");

    let (tx, _) = parse(&wire_with(r#""sequence":0,"#, "", 1, 1)).unwrap();
    assert_eq!(tx.locktime, 0, "absent minTime is no lock time");

    for t in [1u64, 500_000_000, 1_615_462_089_000] {
        let field = alloc::format!(r#""minTime":{t},"#);
        let (tx, _) = parse(&wire_with(r#""sequence":0,"#, &field, 1, 1)).unwrap();
        assert_eq!(tx.locktime, t, "minTime {t} must reach tx.locktime");
    }
}

/// A zero count is "unset" (the reference Constructor does not maintain
/// them), but a stated non-zero count must still match the array.
#[test]
fn counts_zero_is_unset_but_wrong_counts_still_refused() {
    parse(&wire_with(r#""sequence":0,"#, r#""minTime":null,"#, 0, 0)).expect("zero counts accepted");
    parse(&wire_with(r#""sequence":0,"#, r#""minTime":null,"#, 1, 0)).expect("zero output count accepted");
    parse(&wire_with(r#""sequence":0,"#, r#""minTime":null,"#, 1, 1)).expect("correct counts accepted");
    assert!(parse(&wire_with(r#""sequence":0,"#, r#""minTime":null,"#, 2, 1)).is_err(), "wrong input count");
    assert!(parse(&wire_with(r#""sequence":0,"#, r#""minTime":null,"#, 1, 3)).is_err(), "wrong output count");
}

/// What the device emits must be re-readable by the device, with the
/// same values, including the defaults it filled in.
#[test]
fn reparse_of_our_own_output_agrees() {
    let (tx, parsed) = parse(RK_FIXTURE).unwrap();
    let mut scratch = alloc::vec![0u8; 8192];
    let mut out = alloc::vec![0u8; 16384];
    let n = std_pskt::serialize_pskt(
        &tx, &parsed, &mut scratch, crate::types::TxInputFormat::PsktPskb, &mut out,
    ).expect("serialize");
    let (tx2, _) = parse(&out[..n]).expect("our own output must parse");
    assert_eq!(tx2.num_inputs, tx.num_inputs);
    assert_eq!(tx2.num_outputs, tx.num_outputs);
    assert_eq!(tx2.inputs[0].sequence, u64::MAX);
    assert_eq!(tx2.inputs[0].utxo_entry.amount, tx.inputs[0].utxo_entry.amount);
    assert_eq!(tx2.outputs[0].value, tx.outputs[0].value);
    assert_eq!(tx2.locktime, tx.locktime);
}

/// The same roundtrip with a lock time set. `RK_FIXTURE` carries no
/// `minTime`, so the test above only ever proves locktime 0 survives; a
/// timelocked bundle is the case that matters, because the device signs
/// over the lock time and a value lost in serialization would produce a
/// signature the network rejects. Both spellings of the threshold are
/// covered: a DAA score below `LOCK_TIME_THRESHOLD` and a millisecond
/// timestamp above it.
#[test]
fn reparse_preserves_a_non_zero_lock_time() {
    for t in [500_000_000u64, 1_615_462_089_000u64] {
        let field = alloc::format!(r#""minTime":{t},"#);
        let wire = wire_with(r#""sequence":0,"#, &field, 1, 1);
        let (tx, parsed) = parse(&wire).expect("timelocked bundle must parse");
        assert_eq!(tx.locktime, t, "minTime {t} must reach tx.locktime");

        let mut scratch = alloc::vec![0u8; 8192];
        let mut out = alloc::vec![0u8; 16384];
        let n = std_pskt::serialize_pskt(
            &tx, &parsed, &mut scratch, crate::types::TxInputFormat::PsktPskb, &mut out,
        ).expect("serialize");
        let (tx2, _) = parse(&out[..n]).expect("our own timelocked output must parse");
        assert_eq!(tx2.locktime, t, "lock time {t} must survive the roundtrip");
        assert_eq!(tx2.num_inputs, tx.num_inputs);
        assert_eq!(tx2.num_outputs, tx.num_outputs);
        // The wire above states `"sequence":0` explicitly, and an explicit
        // zero is a value, not the unset spelling: it must survive the
        // roundtrip as 0 and never be promoted to MAX.
        assert_eq!(tx2.inputs[0].sequence, 0);
    }
}
