use serde_json::{json, Map, Value};

use super::super::{
    build_if_else_covenant_script, build_p2sh_covenant_sig_script,
    build_p2sh_merkle_claim_sig_script, build_p2sh_oracle_mb_heartbeat_sig_script,
    build_p2sh_oracle_mb_publish_sig_script, build_p2sh_oracle_v1_claim_sig_script,
    build_p2sh_private_swap_claim_sig_script, build_p2sh_risc0_claim_sig_script,
    build_p2sh_rollup_refund_sig_script, build_p2sh_zk_claim_sig_script,
};

fn signatures() -> Map<String, Value> {
    let mut signatures = Map::new();
    signatures.insert(
        format!("02{}", "11".repeat(32)),
        json!({"schnorr": "55".repeat(64)}),
    );
    signatures
}

fn with_properties(values: &[(&str, Value)]) -> Map<String, Value> {
    let properties = values
        .iter()
        .map(|(key, value)| ((*key).to_string(), value.clone()))
        .collect();
    let mut input = Map::new();
    input.insert("proprietaries".to_string(), Value::Object(properties));
    input
}

fn route(input: &Map<String, Value>, signatures: &Map<String, Value>) -> Vec<u8> {
    let redeem = [0x63, 0x51, 0x67, 0x00, 0x68];
    build_if_else_covenant_script(input, &redeem, &redeem, signatures, false, false, &None)
        .expect("route")
}

#[test]
fn routing_dispatches_oracle_and_rollup_branches_byte_exactly() {
    let redeem = [0x63, 0x51, 0x67, 0x00, 0x68];
    let empty = Map::new();
    let oracle = with_properties(&[("oracleMbHeartbeat", Value::Bool(true))]);
    assert_eq!(
        route(&oracle, &empty),
        build_p2sh_oracle_mb_heartbeat_sig_script(&redeem).expect("oracle heartbeat"),
    );

    let sigs = signatures();
    let state_refund = with_properties(&[("rollupStateRefund", Value::Bool(true))]);
    let deposit_refund = with_properties(&[("depositHoldingRefund", Value::Bool(true))]);
    let expected = build_p2sh_rollup_refund_sig_script(&redeem, &sigs).expect("refund");
    assert_eq!(route(&state_refund, &sigs), expected);
    assert_eq!(route(&deposit_refund, &sigs), expected);
}

#[test]
fn routing_dispatches_each_proof_family_byte_exactly() {
    let redeem = [0x63, 0x51, 0x67, 0x00, 0x68];
    let sigs = signatures();

    let zk = with_properties(&[
        ("zkProof", Value::String("75".into())),
        (
            "zkPublicInputs",
            Value::Array(vec![Value::String("76".into())]),
        ),
        ("zkVk", Value::String("77".into())),
    ]);
    assert_eq!(
        route(&zk, &sigs),
        build_p2sh_zk_claim_sig_script(&redeem, &sigs, &[0x75], &[vec![0x76]], &[0x77],)
            .expect("zk claim"),
    );

    let fields = json!({
        "claim": "01",
        "controlIndex": "02",
        "controlDigests": "03",
        "journal": "04",
        "imageId": "05",
        "controlId": "06",
        "hashfn": "07"
    });
    let risc0 = with_properties(&[
        ("risc0Seal", Value::String("81".into())),
        ("risc0Fields", fields.clone()),
    ]);
    assert_eq!(
        route(&risc0, &sigs),
        build_p2sh_risc0_claim_sig_script(
            &redeem,
            &sigs,
            &[0x81],
            fields.as_object().expect("fields"),
        )
        .expect("risc0 claim"),
    );

    let private_swap = with_properties(&[("privateSwapClaim", Value::Bool(true))]);
    assert_eq!(
        route(&private_swap, &sigs),
        build_p2sh_private_swap_claim_sig_script(&redeem, &sigs).expect("private swap"),
    );

    let proof_json = json!([{"sibling": "b1".repeat(32), "direction": 0}]).to_string();
    let merkle = with_properties(&[
        ("merkleProof", Value::String(proof_json.clone())),
        ("merkleDestSpk", Value::String("b2".into())),
    ]);
    assert_eq!(
        route(&merkle, &sigs),
        build_p2sh_merkle_claim_sig_script(&redeem, &sigs, &proof_json, &[0xb2])
            .expect("merkle claim"),
    );
}

#[test]
fn fallback_signature_route_requires_either_owner_or_nonbeneficiary_signature() {
    let redeem = [0x51, 0xac];
    let sigs = signatures();
    let actual =
        build_if_else_covenant_script(&Map::new(), &redeem, &redeem, &sigs, false, false, &None)
            .expect("fallback signature route");
    let expected =
        build_p2sh_covenant_sig_script(&redeem, &sigs, false).expect("direct signature route");
    assert_eq!(actual, expected);
}

#[test]
fn oracle_v1_signature_filter_rejects_each_malformed_role_signature_shape() {
    let owner = [0x31u8; 32];
    let beneficiary = [0x32u8; 32];
    let oracle = [0x33u8; 32];
    let commitment = [0x34u8; 32];
    let salt = [0x35u8; 16];
    let redeem = crate::contracts::covenant::script::build_oracle_v1_covenant_script(
        &owner,
        &beneficiary,
        &oracle,
        &commitment,
        77,
        &salt,
    );
    let oracle_signature = [0x36u8; 64];
    let beneficiary_xonly = hex::encode(beneficiary);
    let beneficiary_key = format!("02{beneficiary_xonly}");

    let mut good = Map::new();
    good.insert(beneficiary_key.clone(), json!({"schnorr": "55".repeat(64)}));
    let witness = build_p2sh_oracle_v1_claim_sig_script(&redeem, &good, &oracle_signature)
        .expect("canonical oracle-v1 claim");
    assert!(witness.len() > redeem.len());

    for malformed_key in [
        "short-key".to_string(),
        format!("04{beneficiary_xonly}"),
        format!("02{}", "zz".repeat(32)),
        format!("02{}", hex::encode([0x99u8; 32])),
    ] {
        let mut signatures = Map::new();
        signatures.insert(malformed_key, json!({"schnorr": "55".repeat(64)}));
        assert!(
            build_p2sh_oracle_v1_claim_sig_script(&redeem, &signatures, &oracle_signature)
                .unwrap_err()
                .contains("transaction signature is missing")
        );
    }

    let mut ambiguous = Map::new();
    ambiguous.insert(
        format!("02{beneficiary_xonly}"),
        json!({"schnorr": "55".repeat(64)}),
    );
    ambiguous.insert(
        format!("03{beneficiary_xonly}"),
        json!({"schnorr": "66".repeat(64)}),
    );
    assert!(
        build_p2sh_oracle_v1_claim_sig_script(&redeem, &ambiguous, &oracle_signature)
            .unwrap_err()
            .contains("signature is ambiguous")
    );

    for bad_value in [
        json!({}),
        json!({"schnorr": 7}),
        json!({"schnorr": "55"}),
        json!({"schnorr": "zz".repeat(64)}),
    ] {
        let mut signatures = Map::new();
        signatures.insert(beneficiary_key.clone(), bad_value);
        assert!(
            build_p2sh_oracle_v1_claim_sig_script(&redeem, &signatures, &oracle_signature).is_err()
        );
    }

    assert!(
        build_p2sh_oracle_v1_claim_sig_script(&redeem, &good, &[0x36; 63])
            .unwrap_err()
            .contains("must be 64 bytes")
    );

    let mut noncanonical = redeem.clone();
    noncanonical.push(0x51);
    assert!(
        build_p2sh_oracle_v1_claim_sig_script(&noncanonical, &good, &oracle_signature)
            .unwrap_err()
            .contains("not canonical")
    );
}

#[test]
fn oracle_risc0_publish_fields_cover_missing_type_hex_journal_and_success_paths() {
    let redeem = [0x51, 0xac];
    let seal = [0x71, 0x72];
    let valid = || {
        json!({
            "claim": "01",
            "controlIndex": "02",
            "controlDigests": "03",
            "journal": "04".repeat(48),
        })
        .as_object()
        .expect("object")
        .clone()
    };

    let script = build_p2sh_oracle_mb_publish_sig_script(&redeem, &seal, &valid())
        .expect("valid RISC0 oracle publish witness");
    assert!(script.ends_with(&redeem));

    let mut missing = valid();
    missing.remove("claim");
    assert!(
        build_p2sh_oracle_mb_publish_sig_script(&redeem, &seal, &missing)
            .unwrap_err()
            .contains("missing risc0 field: claim")
    );

    let mut wrong_type = valid();
    wrong_type.insert("claim".into(), Value::Bool(true));
    assert!(
        build_p2sh_oracle_mb_publish_sig_script(&redeem, &seal, &wrong_type)
            .unwrap_err()
            .contains("missing risc0 field: claim")
    );

    let mut bad_hex = valid();
    bad_hex.insert("controlIndex".into(), Value::String("zz".into()));
    assert!(
        build_p2sh_oracle_mb_publish_sig_script(&redeem, &seal, &bad_hex)
            .unwrap_err()
            .contains("bad hex for controlIndex")
    );

    let mut short_journal = valid();
    short_journal.insert("journal".into(), Value::String("04".repeat(47)));
    assert!(
        build_p2sh_oracle_mb_publish_sig_script(&redeem, &seal, &short_journal)
            .unwrap_err()
            .contains("journal must be 48 bytes")
    );
}

#[test]
fn routing_incomplete_proof_and_oracle_claim_boundaries_raise_branch_margin() {
    let sigs = signatures();

    // Oracle-v1 dispatch must take the claim branch before requiring its
    // attestation payload. This directly covers the claim=true/missing-signature
    // edge without needing a synthetic covenant witness.
    let oracle_missing_signature = with_properties(&[("oracleV1Claim", Value::Bool(true))]);
    assert!(build_if_else_covenant_script(
        &oracle_missing_signature,
        &[0x51, 0xac],
        &[0x51, 0xac],
        &sigs,
        false,
        false,
        &None,
    )
    .unwrap_err()
    .contains("missing oracleV1Signature"));

    // The proof routers intentionally fall through when a multi-field proof is
    // incomplete. Cover each staged Option guard independently so malformed host
    // metadata cannot accidentally become an authorization branch.
    let zk_proof_only = with_properties(&[("zkProof", Value::String("71".into()))]);
    assert!(route(&zk_proof_only, &Map::new()).ends_with(&[0x63, 0x51, 0x67, 0x00, 0x68]));

    let zk_missing_key = with_properties(&[
        ("zkProof", Value::String("72".into())),
        (
            "zkPublicInputs",
            Value::Array(vec![Value::String("73".into())]),
        ),
    ]);
    assert!(route(&zk_missing_key, &Map::new()).ends_with(&[0x63, 0x51, 0x67, 0x00, 0x68]));

    let risc0_seal_only = with_properties(&[("risc0Seal", Value::String("81".into()))]);
    assert!(route(&risc0_seal_only, &Map::new()).ends_with(&[0x63, 0x51, 0x67, 0x00, 0x68]));

    // Merkle routing also requires both halves. Characterize both one-sided
    // inputs so the tuple-pattern fallthrough remains fail-closed.
    let merkle_proof_only = with_properties(&[(
        "merkleProof",
        Value::String(json!([{"sibling": "b1".repeat(32), "direction": 0}]).to_string()),
    )]);
    assert!(route(&merkle_proof_only, &Map::new()).ends_with(&[0x63, 0x51, 0x67, 0x00, 0x68]));

    let merkle_destination_only = with_properties(&[("merkleDestSpk", Value::String("b2".into()))]);
    assert!(route(&merkle_destination_only, &Map::new()).ends_with(&[0x63, 0x51, 0x67, 0x00, 0x68]));
}

#[test]
fn preimage_claim_covers_pushdata1_boundary() {
    let redeem = [0x51, 0xac];
    let sigs = signatures();
    let preimage = [0x42u8; 76];
    let witness = super::super::build_p2sh_preimage_claim_sig_script(&redeem, &sigs, &preimage)
        .expect("76-byte preimage claim");
    assert_eq!(&witness[..2], &[0x4c, 76]);
    assert_eq!(&witness[2..78], preimage.as_slice());
    assert!(witness.ends_with(&redeem));
}
