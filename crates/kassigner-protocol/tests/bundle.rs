// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The v1.0.7 companion's bundle dialect, turned back into upstream's.
//! Either name reads as the binding; both at once are refused.

use kassigner_kaspa::pskb::transaction::{fill, ReadError};
use kassigner_kaspa::pskb::{Field, Scope};
use kassigner_kaspa::tx::{
    CovenantBinding, Outpoint, ScriptPublicKey, TransactionInput, TransactionOutput, UtxoEntry,
};
use kassigner_protocol::bundle::{fill_payload, upstream_names, FillError};

const BLANK_IN: TransactionInput<'static> = TransactionInput {
    previous_outpoint: Outpoint {
        transaction_id: [0; 32],
        index: 0,
    },
    sequence: 0,
    sig_op_count: 0,
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

const BINDING: CovenantBinding = CovenantBinding {
    authorizing_input: 0,
    covenant_id: [0xcc; 32],
};

/// One transaction whose one output carries `members` after its script;
/// every field upstream requires is there.
fn doc(members: &str) -> Vec<u8> {
    let outpoint = format!("{{\"transactionId\":\"{}\",\"index\":0}}", "01".repeat(32));
    let entry =
        "{\"amount\":5,\"scriptPublicKey\":\"0000aa\",\"blockDaaScore\":0,\"isCoinbase\":false}";
    format!(
        "[{{\"global\":{{\"version\":0,\"txVersion\":1,\"inputsModifiable\":false,\
         \"outputsModifiable\":false,\"inputCount\":1,\"outputCount\":1,\"xpubs\":{{}},\
         \"proprietaries\":{{}},\"payload\":null}},\
         \"inputs\":[{{\"previousOutpoint\":{outpoint},\"utxoEntry\":{entry},\"partialSigs\":{{}},\
         \"sighashType\":1,\"redeemScript\":null,\"bip32Derivations\":{{}},\
         \"finalScriptSig\":null,\"proprietaries\":{{}}}}],\
         \"outputs\":[{{\"amount\":1,\"scriptPublicKey\":\"0000\",\"redeemScript\":null,\
         \"bip32Derivations\":{{}},\"proprietaries\":{{}},{members}}}]}}]"
    )
    .into_bytes()
}

fn binding() -> String {
    format!(
        "{{\"authorizingInput\":0,\"covenantId\":\"{}\"}}",
        "cc".repeat(32)
    )
}

/// Rename, then read the output's covenant as the level-0 reader reads it.
fn read(mut d: Vec<u8>) -> (usize, Result<Option<CovenantBinding>, ReadError>) {
    let len = d.len();
    let renamed = upstream_names(&mut d).expect("tokenizes");
    assert_eq!(d.len(), len, "renamed in place");
    let mut ins = [BLANK_IN; 2];
    let mut outs = [BLANK_OUT; 2];
    let mut buf = [0u8; 64];
    let got = fill(&d, 0, &mut ins, &mut outs, &mut buf).map(|_| outs[0].covenant);
    (renamed, got)
}

/// The old name reads as the binding.
#[test]
fn the_old_name_is_the_binding() {
    let (renamed, got) = read(doc(&format!("\"covenantBinding\":{}", binding())));
    assert_eq!(renamed, 1);
    assert_eq!(got, Ok(Some(BINDING)));
}

/// The old name with an escaped letter, at the start, in the middle or in
/// upper-case hex, is the old name: serde_json decodes a key before matching.
#[test]
fn the_old_name_with_escapes_is_the_binding() {
    for name in [
        r"\u0063ovenantBinding",
        r"covenant\u0042inding",
        r"covenantBi\u006Eding",
    ] {
        let (renamed, got) = read(doc(&format!("\"{name}\":{}", binding())));
        assert_eq!(renamed, 1, "{name}");
        assert_eq!(got, Ok(Some(BINDING)), "{name}");
    }
    // A value written so is still a value.
    let original = doc(r#""note":"covenant\u0042inding""#);
    let mut d = original.clone();
    assert_eq!(upstream_names(&mut d), Ok(0));
    assert_eq!(d, original);
}

/// Upstream's name is left alone and reads the same.
#[test]
fn upstreams_name_is_untouched() {
    let original = doc(&format!("\"covenant\":{}", binding()));
    let mut d = original.clone();
    assert_eq!(upstream_names(&mut d), Ok(0));
    assert_eq!(d, original, "nothing to rename, nothing changed");
    assert_eq!(read(original).1, Ok(Some(BINDING)));
}

/// An explicit `null` under the old name is no binding.
#[test]
fn a_null_under_the_old_name_is_no_binding() {
    let (renamed, got) = read(doc("\"covenantBinding\":null"));
    assert_eq!(renamed, 1);
    assert_eq!(got, Ok(None));
}

/// Both names at once is the key twice, and refused.
#[test]
fn both_names_are_refused() {
    let b = binding();
    let (renamed, got) = read(doc(&format!("\"covenant\":{b},\"covenantBinding\":{b}")));
    assert_eq!(renamed, 1);
    assert_eq!(
        got,
        Err(ReadError::Duplicate {
            scope: Scope::Output(0),
            field: Field::Covenant
        })
    );
}

/// Only keys are renamed; a value that reads the same is left alone.
#[test]
fn a_value_is_not_a_key() {
    let original = doc("\"note\":\"covenantBinding\"");
    let mut d = original.clone();
    assert_eq!(upstream_names(&mut d), Ok(0));
    assert_eq!(d, original);
}

// ── The payload kassigner.org 1.0.7 never writes ────────────────────────────

/// One transaction as kassigner.org 1.0.7's writer builds it
/// (`kassee/src/kspt/mod.rs`), with `global` as its global map.
fn v107(global: &str) -> String {
    let outpoint = format!("{{\"transactionId\":\"{}\",\"index\":0}}", "01".repeat(32));
    let entry =
        "{\"amount\":5,\"scriptPublicKey\":\"0000aa\",\"blockDaaScore\":0,\"isCoinbase\":false}";
    format!(
        "{{\"global\":{global},\
         \"inputs\":[{{\"utxoEntry\":{entry},\"previousOutpoint\":{outpoint},\"sequence\":0,\
         \"minTime\":null,\"partialSigs\":{{}},\"sighashType\":1,\"redeemScript\":null,\
         \"sigOpCount\":1,\"bip32Derivations\":{{}},\"finalScriptSig\":null,\"proprietaries\":{{}}}}],\
         \"outputs\":[{{\"amount\":1,\"scriptPublicKey\":\"0000\",\"redeemScript\":null,\
         \"bip32Derivations\":{{}},\"proprietaries\":{{}}}}]}}"
    )
}

/// kassigner.org 1.0.7's global map, which has no `payload`.
const V107_GLOBAL: &str = "{\"version\":0,\"txVersion\":0,\"fallbackLockTime\":null,\
                           \"inputsModifiable\":false,\"outputsModifiable\":false,\"inputCount\":1,\
                           \"outputCount\":1,\"xpubs\":{},\"id\":null,\"proprietaries\":{}}";

/// Fill `doc` in a buffer with `room` bytes to spare, and return the result.
fn filled(doc: &str, room: usize) -> Result<String, FillError> {
    let mut buf = doc.as_bytes().to_vec();
    buf.resize(doc.len() + room, 0);
    let n = fill_payload(&mut buf, doc.len())?;
    Ok(String::from_utf8(buf[..n].to_vec()).expect("text"))
}

fn read_doc(doc: &str) -> Result<(usize, usize), ReadError> {
    let mut ins = [BLANK_IN; 2];
    let mut outs = [BLANK_OUT; 2];
    let mut buf = [0u8; 64];
    fill(doc.as_bytes(), 0, &mut ins, &mut outs, &mut buf).map(|f| (f.inputs, f.outputs))
}

/// A kassigner.org 1.0.7 bundle, refused for its missing `payload`, reads
/// once the fill adds upstream's `null` there, and nothing else.
#[test]
fn a_bundle_without_payload_reads_once_it_is_filled() {
    let doc = format!("[{}]", v107(V107_GLOBAL));
    assert_eq!(
        read_doc(&doc),
        Err(ReadError::Missing {
            scope: Scope::Global,
            field: Field::Payload
        }),
        "refused as it comes"
    );
    let after = filled(&doc, 64).expect("fills");
    assert_eq!(after.len(), doc.len() + 15);
    assert_eq!(
        after,
        doc.replacen("{\"global\":{", "{\"global\":{\"payload\":null,", 1)
    );
    assert_eq!(read_doc(&after), Ok((1, 1)));
}

/// Every global map lacking `payload` is filled. One already there, escaped
/// or not, is kept; one nested in another value is not the map's own.
#[test]
fn every_global_without_payload_is_filled_and_no_other() {
    let two = format!("[{},{}]", v107(V107_GLOBAL), v107(V107_GLOBAL));
    let after = filled(&two, 64).expect("fills");
    assert_eq!(after.len(), two.len() + 30, "both maps");
    assert_eq!(after.matches("{\"payload\":null,\"version\"").count(), 2);

    let open = &V107_GLOBAL[..V107_GLOBAL.len() - 1];
    for global in [
        format!("{open},\"payload\":null}}"),
        format!("{open},\"p\\u0061yload\":null}}"),
    ] {
        let doc = format!("[{}]", v107(&global));
        assert_eq!(filled(&doc, 64), Ok(doc.clone()), "{global}");
    }

    let nested = V107_GLOBAL.replace("\"proprietaries\":{}", "\"proprietaries\":{\"payload\":1}");
    let doc = format!("[{}]", v107(&nested));
    assert_eq!(filled(&doc, 64).expect("fills").len(), doc.len() + 15);
}

/// An empty global map gets the member alone, with no comma.
#[test]
fn an_empty_global_gets_payload_alone() {
    let doc = "[{\"global\":{},\"inputs\":[],\"outputs\":[]}]";
    assert_eq!(
        filled(doc, 64).as_deref(),
        Ok("[{\"global\":{\"payload\":null},\"inputs\":[],\"outputs\":[]}]")
    );
}

/// A bundle with no room left for `payload` is refused, not cut.
#[test]
fn no_room_for_payload_is_refused() {
    let doc = format!("[{}]", v107(V107_GLOBAL));
    assert_eq!(
        filled(&doc, 14),
        Err(FillError::NoRoom {
            needed: doc.len() + 15
        })
    );
    assert!(filled(&doc, 15).is_ok(), "exactly enough is enough");
}

/// A covenant bundle from kassigner.org 1.0.7 reads with its binding:
/// `covenantBinding` renamed, then `payload` filled.
#[test]
fn a_v107_covenant_bundle_reads_with_its_binding() {
    let doc = format!("[{}]", v107(V107_GLOBAL)).replacen(
        "\"proprietaries\":{}}]}]",
        &format!(
            "\"proprietaries\":{{}},\"covenantBinding\":{}}}]}}]",
            binding()
        ),
        1,
    );
    assert!(doc.contains("covenantBinding"));
    let mut d = doc.into_bytes();
    assert_eq!(upstream_names(&mut d), Ok(1));
    let after = filled(core::str::from_utf8(&d).unwrap(), 64).expect("fills");
    let mut ins = [BLANK_IN; 2];
    let mut outs = [BLANK_OUT; 2];
    let mut buf = [0u8; 64];
    fill(after.as_bytes(), 0, &mut ins, &mut outs, &mut buf).expect("reads");
    assert_eq!(outs[0].covenant, Some(BINDING));
}
