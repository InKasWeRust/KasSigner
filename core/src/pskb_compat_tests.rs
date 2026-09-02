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
    let (tx, parsed, _) = parse_keep_scratch(wire)?;
    Ok((tx, parsed))
}

/// Parse, and hand back the scratch buffer the JSON was decoded into.
///
/// `PsktParsed.unknowns` are byte offsets INTO THAT BUFFER, and
/// `find_captured_value` reads the captured bytes out of it at emit time. The
/// firmware passes one buffer to both halves (`signed_qr_buf`, see
/// `app/signing.rs`), so a test that gives the serializer a fresh zeroed vec is
/// not exercising the capture path at all: every lookup misses and every
/// emitter falls back to its default.
///
/// That is not hypothetical. The first cut of
/// `a_captured_region_is_emitted_in_its_own_object` did exactly that, and its
/// "the global object must not contain the input's map" assertion held because
/// NOTHING was found, not because the scope tag worked. Any test here that
/// asserts on captured content must use this.
#[allow(clippy::type_complexity)]
fn parse_keep_scratch(
    wire: &[u8],
) -> Result<(alloc::boxed::Box<Transaction>, PsktParsed, Vec<u8>), std_pskt::PskError> {
    let mut tx = Transaction::new_boxed().expect("alloc");
    let mut scratch = alloc::vec![0u8; 8192];
    let mut parsed = PsktParsed::empty();
    std_pskt::parse_pskt(wire, &mut scratch, &mut tx, &mut parsed)?;
    Ok((tx, parsed, scratch))
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

/// Does the captured region at `(a, b)` begin with `"name":`?
///
/// The ranges index the decoded JSON, which is the hex body of `wire` after
/// the four-byte magic, so the offsets are halved into the wire.
fn scratch_has_key(wire: &[u8], a: u16, b: u16, name: &[u8]) -> bool {
    let (a, b) = (a as usize, b as usize);
    if b <= a || name.len() + 3 > b - a {
        return false;
    }
    let mut bytes = Vec::new();
    for i in a..b {
        let off = 4 + i * 2;
        if off + 1 >= wire.len() {
            return false;
        }
        let hi = (wire[off] as char).to_digit(16).unwrap_or(16) as u8;
        let lo = (wire[off + 1] as char).to_digit(16).unwrap_or(16) as u8;
        if hi > 15 || lo > 15 {
            return false;
        }
        bytes.push((hi << 4) | lo);
    }
    bytes.starts_with(b"\"") && bytes[1..].starts_with(name)
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
    let scratch = alloc::vec![0u8; 8192];
    let mut out = alloc::vec![0u8; 16384];
    let n = std_pskt::serialize_pskt(
        &tx, &parsed, &scratch, crate::types::TxInputFormat::PsktPskb, &mut out,
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

        let scratch = alloc::vec![0u8; 8192];
        let mut out = alloc::vec![0u8; 16384];
        let n = std_pskt::serialize_pskt(
            &tx, &parsed, &scratch, crate::types::TxInputFormat::PsktPskb, &mut out,
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

/// A captured region must be emitted in the object it came from.
///
/// [S4]. The capture table is flat and `find_captured_value` matched on the
/// KEY NAME alone, taking the first hit. `proprietaries` is the only name that
/// occurs at all three levels, so an INPUT's map was handed to the GLOBAL
/// emitter whenever the global one was empty and therefore never captured.
/// The parser stored it correctly; the serializer put it in the wrong object.
///
/// Content relocation rather than loss, and the sighash never covers PSKT
/// metadata, so nothing signed was ever wrong. What it corrupts is the bundle
/// handed to the next signer.
///
/// This is written to fail on the flat lookup: the global map is empty and the
/// input's is not, which is precisely the shape that mis-resolved.
#[test]
fn a_captured_region_is_emitted_in_its_own_object() {
    // Input-level proprietaries non-empty, global-level empty.
    let json = concat!(
        r#"[{"global":{"version":0,"txVersion":0,"fallbackLockTime":null,"#,
        r#""inputsModifiable":false,"outputsModifiable":false,"#,
        r#""inputCount":1,"outputCount":1,"xpubs":{},"id":null,"#,
        r#""proprietaries":{},"payload":""},"inputs":[{"#,
        r#""utxoEntry":{"amount":468928887,"scriptPublicKey":"#,
        r#""0000202d8a1414e62e081fb6bcf644e648c18061c2855575cac722f86324cad91dd0faac","#,
        r#""blockDaaScore":84981186,"isCoinbase":false},"previousOutpoint":{"#,
        r#""transactionId":"69155d0e3380e8816dffe2671294ad104f0b3776f35bce1a22f0c21b1f908500","#,
        r#""index":0},"sequence":0,"minTime":null,"partialSigs":{},"sighashType":1,"#,
        r#""redeemScript":null,"sigOpCount":1,"bip32Derivations":{},"finalScriptSig":null,"#,
        r#""proprietaries":{"aa":"bb"}}],"outputs":[{"amount":1500000000,"#,
        r#""scriptPublicKey":"0000202d8a1414e62e081fb6bcf644e648c18061c2855575cac722f86324cad91dd0faac","#,
        r#""redeemScript":null,"bip32Derivations":{},"proprietaries":{}}]}]"#,
    );
    let mut wire = Vec::from(&b"PSKB"[..]);
    for b in json.as_bytes() {
        wire.extend_from_slice(alloc::format!("{b:02x}").as_bytes());
    }

    let (tx, parsed, scratch) = parse_keep_scratch(&wire).expect("bundle must parse");

    // Assert on the SCOPES, not on the count. The bundle also carries
    // `"payload":""` in the global object, which is not in the global parser's
    // known-field list and so is captured by its `_ =>` arm. That is correct
    // and is the reason this table exists; pinning the total here would be
    // testing the capture budget instead of the fix.
    let input_caps = (0..parsed.unknowns_count as usize)
        .filter(|&i| parsed.unknown_scopes[i] == crate::types::SCOPE_INPUT_BASE)
        .count();
    assert_eq!(input_caps, 1, "input 0's proprietaries must be captured, tagged to input 0");
    // The empty global proprietaries is not captured at all, which is what
    // made the flat lookup reach past it into the input's.
    let global_prop = (0..parsed.unknowns_count as usize).any(|i| {
        let (a, b) = parsed.unknowns[i];
        parsed.unknown_scopes[i] == crate::types::SCOPE_GLOBAL
            && scratch_has_key(&wire, a, b, b"proprietaries")
    });
    assert!(!global_prop, "an empty global proprietaries must not be captured");

    let mut out = alloc::vec![0u8; 16384];
    let n = std_pskt::serialize_pskt(
        &tx, &parsed, &scratch, crate::types::TxInputFormat::PsktPskb, &mut out,
    ).expect("serialize");

    // The emitted global object must carry an EMPTY proprietaries. Before the
    // scope tag it carried `{"aa":"bb"}`, lifted out of the input.
    let emitted = &out[4..n]; // past the PSKB magic
    let mut json_out = Vec::new();
    for pair in emitted.chunks_exact(2) {
        let hi = (pair[0] as char).to_digit(16).expect("lowercase hex") as u8;
        let lo = (pair[1] as char).to_digit(16).expect("lowercase hex") as u8;
        json_out.push((hi << 4) | lo);
    }
    let text = std::str::from_utf8(&json_out).expect("utf8");
    let global_end = text.find(r#","inputs":"#).expect("global object ends before inputs");
    let global = &text[..global_end];
    assert!(
        global.contains(r#""proprietaries":{}"#),
        "global proprietaries must be empty, got: {global}"
    );
    assert!(
        !global.contains("aa"),
        "the input's proprietaries leaked into the global object: {global}"
    );
}

/// A non-empty `proprietaries` must survive the round trip, in its own object.
///
/// [S3]. Both emitters wrote a hardcoded `{}`, so a map that the parser had
/// captured correctly was dropped on the way out: the first signer stripped it
/// and the next signer never saw it. Same defect as N-20 was for
/// `bip32Derivations`, and the same fix.
///
/// Input AND output are populated here, and differently, which is the case
/// that discriminates. With one map present a scoped lookup and a flat one can
/// agree by luck; with two, a flat lookup hands the same first hit to both
/// emitters and the output gets the input's map.
#[test]
fn proprietaries_survive_the_round_trip_in_their_own_object() {
    let json = concat!(
        r#"[{"global":{"version":0,"txVersion":0,"fallbackLockTime":null,"#,
        r#""inputsModifiable":false,"outputsModifiable":false,"#,
        r#""inputCount":1,"outputCount":1,"xpubs":{},"id":null,"#,
        r#""proprietaries":{},"payload":""},"inputs":[{"#,
        r#""utxoEntry":{"amount":468928887,"scriptPublicKey":"#,
        r#""0000202d8a1414e62e081fb6bcf644e648c18061c2855575cac722f86324cad91dd0faac","#,
        r#""blockDaaScore":84981186,"isCoinbase":false},"previousOutpoint":{"#,
        r#""transactionId":"69155d0e3380e8816dffe2671294ad104f0b3776f35bce1a22f0c21b1f908500","#,
        r#""index":0},"sequence":0,"minTime":null,"partialSigs":{},"sighashType":1,"#,
        r#""redeemScript":null,"sigOpCount":1,"bip32Derivations":{},"finalScriptSig":null,"#,
        r#""proprietaries":{"in":"AAA"}}],"outputs":[{"amount":1500000000,"#,
        r#""scriptPublicKey":"0000202d8a1414e62e081fb6bcf644e648c18061c2855575cac722f86324cad91dd0faac","#,
        r#""redeemScript":null,"bip32Derivations":{},"proprietaries":{"out":"BBB"}}]}]"#,
    );
    let mut wire = Vec::from(&b"PSKB"[..]);
    for b in json.as_bytes() {
        wire.extend_from_slice(alloc::format!("{b:02x}").as_bytes());
    }

    let (tx, parsed, scratch) = parse_keep_scratch(&wire).expect("bundle must parse");
    let mut out = alloc::vec![0u8; 16384];
    let n = std_pskt::serialize_pskt(
        &tx, &parsed, &scratch, crate::types::TxInputFormat::PsktPskb, &mut out,
    ).expect("serialize");

    let mut json_out = Vec::new();
    for pair in out[4..n].chunks_exact(2) {
        let hi = (pair[0] as char).to_digit(16).expect("lowercase hex") as u8;
        let lo = (pair[1] as char).to_digit(16).expect("lowercase hex") as u8;
        json_out.push((hi << 4) | lo);
    }
    let text = std::str::from_utf8(&json_out).expect("utf8");

    // Split the three objects so each assertion is about one of them and a map
    // landing in the wrong place cannot pass.
    let in_at = text.find(r#","inputs":"#).expect("inputs");
    let out_at = text.find(r#","outputs":"#).expect("outputs");
    let (global, inputs, outputs) = (&text[..in_at], &text[in_at..out_at], &text[out_at..]);

    assert!(inputs.contains(r#""proprietaries":{"in":"AAA"}"#),
        "the input's map was dropped or altered: {inputs}");
    assert!(outputs.contains(r#""proprietaries":{"out":"BBB"}"#),
        "the output's map was dropped or altered: {outputs}");
    // Neither may appear anywhere else.
    assert!(global.contains(r#""proprietaries":{}"#) && !global.contains("AAA")
        && !global.contains("BBB"), "global object is not clean: {global}");
    assert!(!inputs.contains("BBB"), "the output's map leaked into the input");
    assert!(!outputs.contains("AAA"), "the input's map leaked into the output");

    // And the result must still be readable by us.
    let (tx2, _) = parse(&out[..n]).expect("our own output must parse");
    assert_eq!(tx2.num_inputs, tx.num_inputs);
    assert_eq!(tx2.num_outputs, tx.num_outputs);
    assert_eq!(tx2.inputs[0].utxo_entry.amount, tx.inputs[0].utxo_entry.amount);
    assert_eq!(tx2.outputs[0].value, tx.outputs[0].value);
}

/// An output's `redeemScript` must survive the round trip.
///
/// [S5]. The output parser called `skip_value` and the emitter wrote a
/// hardcoded `null`, so a redeem script on an output was parsed, discarded and
/// replaced with nothing. The comment on the parser arm claimed the serializer
/// "passes through the parsed hex"; it did not.
///
/// The INPUT side is deliberately populated too, and by a different route: an
/// input's redeem script is a parsed VALUE (`inp.redeem_script_len` and
/// `tx.redeem_bytes`), not a captured region. So this also proves the new
/// capture path did not disturb the one that already worked.
#[test]
fn output_redeem_script_survives_the_round_trip() {
    let json = concat!(
        r#"[{"global":{"version":0,"txVersion":0,"fallbackLockTime":null,"#,
        r#""inputsModifiable":false,"outputsModifiable":false,"#,
        r#""inputCount":1,"outputCount":1,"xpubs":{},"id":null,"#,
        r#""proprietaries":{},"payload":""},"inputs":[{"#,
        r#""utxoEntry":{"amount":468928887,"scriptPublicKey":"#,
        r#""0000202d8a1414e62e081fb6bcf644e648c18061c2855575cac722f86324cad91dd0faac","#,
        r#""blockDaaScore":84981186,"isCoinbase":false},"previousOutpoint":{"#,
        r#""transactionId":"69155d0e3380e8816dffe2671294ad104f0b3776f35bce1a22f0c21b1f908500","#,
        r#""index":0},"sequence":0,"minTime":null,"partialSigs":{},"sighashType":1,"#,
        r#""redeemScript":"51ae","sigOpCount":1,"bip32Derivations":{},"finalScriptSig":null,"#,
        r#""proprietaries":{}}],"outputs":[{"amount":1500000000,"#,
        r#""scriptPublicKey":"0000202d8a1414e62e081fb6bcf644e648c18061c2855575cac722f86324cad91dd0faac","#,
        r#""redeemScript":"aabbccdd","bip32Derivations":{},"proprietaries":{}}]}]"#,
    );
    let mut wire = Vec::from(&b"PSKB"[..]);
    for b in json.as_bytes() {
        wire.extend_from_slice(alloc::format!("{b:02x}").as_bytes());
    }

    let (tx, parsed, scratch) = parse_keep_scratch(&wire).expect("bundle must parse");
    let mut out = alloc::vec![0u8; 16384];
    let n = std_pskt::serialize_pskt(
        &tx, &parsed, &scratch, crate::types::TxInputFormat::PsktPskb, &mut out,
    ).expect("serialize");

    let mut json_out = Vec::new();
    for pair in out[4..n].chunks_exact(2) {
        let hi = (pair[0] as char).to_digit(16).expect("lowercase hex") as u8;
        let lo = (pair[1] as char).to_digit(16).expect("lowercase hex") as u8;
        json_out.push((hi << 4) | lo);
    }
    let text = std::str::from_utf8(&json_out).expect("utf8");

    let in_at = text.find(r#","inputs":"#).expect("inputs");
    let out_at = text.find(r#","outputs":"#).expect("outputs");
    let (inputs, outputs) = (&text[in_at..out_at], &text[out_at..]);

    assert!(outputs.contains(r#""redeemScript":"aabbccdd""#),
        "the output's redeem script was dropped: {outputs}");
    // The input's, by the other mechanism, must be untouched.
    assert!(inputs.contains(r#""redeemScript":"51ae""#),
        "the input's redeem script changed: {inputs}");
    // Neither may appear in the other object.
    assert!(!inputs.contains("aabbccdd"), "the output's redeem script leaked into the input");
    assert!(!outputs.contains("51ae"), "the input's redeem script leaked into the output");

    let (tx2, _) = parse(&out[..n]).expect("our own output must parse");
    assert_eq!(tx2.num_outputs, tx.num_outputs);
    assert_eq!(tx2.outputs[0].value, tx.outputs[0].value);
}

/// An output with no redeem script must still emit `null`.
///
/// The fallback half of [S5]. A lookup-based emitter that forgot its default
/// would drop the field entirely and produce a bundle the reference
/// implementation cannot read.
#[test]
fn output_without_a_redeem_script_still_emits_null() {
    let (tx, parsed, scratch) = parse_keep_scratch(RK_FIXTURE).expect("fixture parses");
    let mut out = alloc::vec![0u8; 16384];
    let n = std_pskt::serialize_pskt(
        &tx, &parsed, &scratch, crate::types::TxInputFormat::PsktPskb, &mut out,
    ).expect("serialize");
    let mut json_out = Vec::new();
    for pair in out[4..n].chunks_exact(2) {
        let hi = (pair[0] as char).to_digit(16).expect("lowercase hex") as u8;
        let lo = (pair[1] as char).to_digit(16).expect("lowercase hex") as u8;
        json_out.push((hi << 4) | lo);
    }
    let text = std::str::from_utf8(&json_out).expect("utf8");
    let out_at = text.find(r#","outputs":"#).expect("outputs");
    assert!(text[out_at..].contains(r#""redeemScript":null"#),
        "an output without a redeem script must emit null: {}", &text[out_at..]);
}

/// A prettified bundle must round-trip its captured fields, not drop them.
///
/// The tokenizer skips whitespace by design, and says so: prettified inputs
/// tokenize. So such a bundle PARSES, and the regions are captured correctly.
/// `find_captured_value` then required `"key":value` with no space, missed
/// every one of them, and the emitters fell back to `{}` and `null`. The
/// bundle came out of the device with its metadata silently stripped.
///
/// Fails on the pre-fix lookup: with `"proprietaries" : {...}` the colon is
/// not where it expected it, so nothing matches.
#[test]
fn prettified_input_still_round_trips_its_captured_fields() {
    // Whitespace in three different places: after the key, around the colon,
    // and before the value. All legal JSON, all previously fatal to the lookup.
    let json = concat!(
        "[{\"global\": {\"version\": 0, \"txVersion\": 0,\n",
        "  \"fallbackLockTime\": null, \"inputsModifiable\": false,\n",
        "  \"outputsModifiable\": false, \"inputCount\": 1, \"outputCount\": 1,\n",
        "  \"xpubs\": {}, \"id\": null, \"proprietaries\": {}, \"payload\": \"\"},\n",
        " \"inputs\": [{\"utxoEntry\": {\"amount\": 468928887,\n",
        "  \"scriptPublicKey\":\n",
        "    \"0000202d8a1414e62e081fb6bcf644e648c18061c2855575cac722f86324cad91dd0faac\",\n",
        "  \"blockDaaScore\": 84981186, \"isCoinbase\": false},\n",
        "  \"previousOutpoint\": {\"transactionId\":\n",
        "    \"69155d0e3380e8816dffe2671294ad104f0b3776f35bce1a22f0c21b1f908500\",\n",
        "   \"index\": 0}, \"sequence\": 0, \"minTime\": null, \"partialSigs\": {},\n",
        "  \"sighashType\": 1, \"redeemScript\": null, \"sigOpCount\": 1,\n",
        "  \"bip32Derivations\": {}, \"finalScriptSig\": null,\n",
        "  \"proprietaries\" : {\"in\": \"AAA\"}}],\n",
        " \"outputs\": [{\"amount\": 1500000000, \"scriptPublicKey\":\n",
        "    \"0000202d8a1414e62e081fb6bcf644e648c18061c2855575cac722f86324cad91dd0faac\",\n",
        "  \"redeemScript\" : \"aabbccdd\", \"bip32Derivations\": {},\n",
        "  \"proprietaries\":  {\"out\": \"BBB\"}}]}]",
    );
    let mut wire = Vec::from(&b"PSKB"[..]);
    for b in json.as_bytes() {
        wire.extend_from_slice(alloc::format!("{b:02x}").as_bytes());
    }

    let (tx, parsed, scratch) = parse_keep_scratch(&wire).expect("prettified must parse");
    let mut out = alloc::vec![0u8; 16384];
    let n = std_pskt::serialize_pskt(
        &tx, &parsed, &scratch, crate::types::TxInputFormat::PsktPskb, &mut out,
    ).expect("serialize");

    let mut json_out = Vec::new();
    for pair in out[4..n].chunks_exact(2) {
        let hi = (pair[0] as char).to_digit(16).expect("lowercase hex") as u8;
        let lo = (pair[1] as char).to_digit(16).expect("lowercase hex") as u8;
        json_out.push((hi << 4) | lo);
    }
    let text = std::str::from_utf8(&json_out).expect("utf8");

    let in_at = text.find(r#","inputs":"#).expect("inputs");
    let out_at = text.find(r#","outputs":"#).expect("outputs");
    let (inputs, outputs) = (&text[in_at..out_at], &text[out_at..]);

    // Each field survives, in its own object. The emitted form is compact
    // regardless of how the input was spaced.
    assert!(inputs.contains(r#""proprietaries":{"in": "AAA"}"#),
        "input proprietaries lost on prettified input: {inputs}");
    assert!(outputs.contains(r#""proprietaries":{"out": "BBB"}"#),
        "output proprietaries lost on prettified input: {outputs}");
    assert!(outputs.contains(r#""redeemScript":"aabbccdd""#),
        "output redeemScript lost on prettified input: {outputs}");
}
