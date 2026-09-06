mod encoding_boundaries;
mod routing_boundaries;

use serde_json::{json, Map, Value};

use super::{
    build_p2sh_covenant_borrower_sig_script, build_p2sh_covenant_nosig_script,
    build_p2sh_covenant_sig_script, build_p2sh_private_swap_claim_sig_script,
    build_p2sh_token_conservation_sig_script, first_schnorr_signature, push_data_item,
    push_data_sigscript, push_int_sigscript, push_redeem_script,
};

fn signatures(public_key: &str) -> Map<String, Value> {
    let mut signatures = Map::new();
    signatures.insert(
        public_key.to_string(),
        json!({ "schnorr": "55".repeat(64) }),
    );
    signatures
}

#[test]
fn push_helpers_cover_all_size_and_integer_encodings() {
    for (length, prefix) in [
        (0usize, 0x00),
        (1, 0x01),
        (75, 75),
        (76, 0x4c),
        (255, 0x4c),
        (256, 0x4d),
    ] {
        let mut script = Vec::new();
        push_data_item(&mut script, &vec![0xaa; length]).expect("push");
        assert_eq!(script[0], prefix);
    }
    let mut too_large = Vec::new();
    assert!(push_data_item(&mut too_large, &vec![0; 65_536]).is_err());
    assert!(push_redeem_script(&mut Vec::new(), &vec![0; 65_536]).is_err());

    let mut integers = Vec::new();
    for value in [0, 1, 16, 17, 127, 128, 65_535] {
        push_int_sigscript(&mut integers, value);
    }
    assert_eq!(integers[0], 0x00);
    assert_eq!(integers[1], 0x51);
    assert_eq!(integers[2], 0x60);
    assert!(integers.len() > 7);
}

#[test]
fn signature_data_pushes_are_byte_exact_at_every_prefix_boundary() {
    for (length, prefix) in [
        (0usize, vec![0x00]),
        (1, vec![0x01]),
        (75, vec![0x4b]),
        (76, vec![0x4c, 0x4c]),
        (255, vec![0x4c, 0xff]),
        (256, vec![0x4d, 0x00, 0x01]),
        (65_535, vec![0x4d, 0xff, 0xff]),
        (65_536, vec![0x4e, 0x00, 0x00, 0x01, 0x00]),
    ] {
        let payload = vec![0xa5; length];
        let mut script = Vec::new();
        push_data_sigscript(&mut script, &payload);
        assert_eq!(
            &script[..prefix.len()],
            prefix.as_slice(),
            "length {length}"
        );
        assert_eq!(
            &script[prefix.len()..],
            payload.as_slice(),
            "length {length}"
        );
    }
}

#[test]
fn first_signature_validates_presence_variant_length_and_hex() {
    let map = signatures(&format!("02{}", "11".repeat(32)));
    let (_, signature) = first_schnorr_signature(
        &map,
        "missing".into(),
        "variant".into(),
        Some("length"),
        "hex",
    )
    .expect("signature");
    assert_eq!(signature.len(), 65);
    assert_eq!(signature[64], 1);

    assert!(
        first_schnorr_signature(&Map::new(), "missing".into(), "variant".into(), None, "hex")
            .is_err()
    );
    let missing = json!({"02": {}}).as_object().unwrap().clone();
    assert!(
        first_schnorr_signature(&missing, "missing".into(), "variant".into(), None, "hex").is_err()
    );
    let short = json!({"02": {"schnorr": "00"}})
        .as_object()
        .unwrap()
        .clone();
    assert!(first_schnorr_signature(
        &short,
        "missing".into(),
        "variant".into(),
        Some("length"),
        "hex"
    )
    .is_err());
    let bad_hex = json!({"02": {"schnorr": "zz".repeat(64)}})
        .as_object()
        .unwrap()
        .clone();
    assert!(
        first_schnorr_signature(&bad_hex, "missing".into(), "variant".into(), None, "hex").is_err()
    );
}

#[test]
fn covenant_signature_builder_covers_owner_counterparty_nested_salted_and_default_routes() {
    let alice = [0x11u8; 32];
    let alice_key = format!("02{}", hex::encode(alice));
    let bob_key = format!("03{}", "22".repeat(32));
    let mut redeem = vec![0x63, 0x20];
    redeem.extend_from_slice(&alice);
    redeem.extend_from_slice(&[0xad, 0x63, 0x51, 0x67, 0x00, 0x68, 0x67, 0x20]);
    redeem.extend_from_slice(&[0x22; 32]);
    redeem.extend_from_slice(&[0xac, 0x68]);

    let owner =
        build_p2sh_covenant_sig_script(&redeem, &signatures(&alice_key), false).expect("owner");
    assert_eq!(owner[0], 0x51);
    assert_eq!(owner[67], 0x51);

    let time =
        build_p2sh_covenant_sig_script(&redeem, &signatures(&alice_key), true).expect("time");
    assert_eq!(time[0], 0x00);

    let counterparty = build_p2sh_covenant_sig_script(&redeem, &signatures(&bob_key), false)
        .expect("counterparty");
    assert_eq!(counterparty[66], 0x00);

    let mut salted = vec![0x08];
    salted.extend_from_slice(&[0x99; 8]);
    salted.push(0x75);
    salted.extend_from_slice(&redeem);
    assert!(build_p2sh_covenant_sig_script(&salted, &signatures(&alice_key), false).is_ok());

    assert!(build_p2sh_covenant_sig_script(&redeem, &Map::new(), false).is_err());
}

#[test]
fn covenant_signature_builder_distinguishes_salt_and_nested_boundaries_exactly() {
    let alice = [0x11u8; 32];
    let bob = [0x22u8; 32];
    let alice_key = format!("02{}", hex::encode(alice));
    let bob_key = format!("03{}", hex::encode(bob));

    let mut nested = vec![0x63, 0x20];
    nested.extend_from_slice(&alice);
    nested.extend_from_slice(&[0xad, 0x63]);

    let amount = build_p2sh_covenant_sig_script(&nested, &signatures(&alice_key), false)
        .expect("nested amount path");
    assert_eq!(amount[0], 0x51);
    assert_eq!(amount[1], 65);
    assert_eq!(amount[66], 0x01);
    assert_eq!(amount[67], 0x51);

    let time = build_p2sh_covenant_sig_script(&nested, &signatures(&alice_key), true)
        .expect("nested time path");
    assert_eq!(time[0], 0x00);
    assert_eq!(time[1], 65);
    assert_eq!(time[67], 0x51);

    let mut not_nested = nested.clone();
    not_nested[34] = 0xac;
    let witness = build_p2sh_covenant_sig_script(&not_nested, &signatures(&alice_key), false)
        .expect("non-nested owner path");
    assert_eq!(witness[0], 65);
    assert_eq!(witness[66], 0x51);

    let mut salted = vec![0x08];
    salted.extend_from_slice(&[0x99; 8]);
    salted.push(0x75);
    salted.extend_from_slice(&nested);
    let bob_witness = build_p2sh_covenant_sig_script(&salted, &signatures(&bob_key), false)
        .expect("salted counterparty path");
    assert_eq!(bob_witness[0], 65);
    assert_eq!(bob_witness[66], 0x00);

    for corrupt_index in [0usize, 9] {
        let mut malformed = salted.clone();
        malformed[corrupt_index] ^= 0x01;
        let witness = build_p2sh_covenant_sig_script(&malformed, &signatures(&bob_key), false)
            .expect("malformed salt is not stripped");
        assert_eq!(witness[0], 65);
        assert_eq!(witness[66], 0x51);
    }

    for body_opcode in [0xb9u8, 0x20] {
        let mut body = nested.clone();
        body[0] = body_opcode;
        let mut redeem = vec![0x08];
        redeem.extend_from_slice(&[0x88; 8]);
        redeem.push(0x75);
        redeem.extend_from_slice(&body);
        let witness = build_p2sh_covenant_sig_script(&redeem, &signatures(&alice_key), false)
            .expect("recognized salted body opcode");
        assert_eq!(witness[0], 0x51);
        assert_eq!(witness[1], 65);
        assert_eq!(witness[67], 0x51);
    }

    let mut unknown_body = nested.clone();
    unknown_body[0] = 0x51;
    let mut unknown = vec![0x08];
    unknown.extend_from_slice(&[0x77; 8]);
    unknown.push(0x75);
    unknown.extend_from_slice(&unknown_body);
    let witness = build_p2sh_covenant_sig_script(&unknown, &signatures(&alice_key), false)
        .expect("unknown salted body is not stripped");
    assert_eq!(witness[0], 65);
    assert_eq!(witness[66], 0x51);
}

#[test]
fn borrower_and_keyless_builders_cover_nested_and_pushdata_redeems() {
    let map = signatures(&format!("02{}", "11".repeat(32)));
    let nested = [0x63, 0x51, 0x67, 0x63, 0x51, 0x68, 0x68];
    let witness = build_p2sh_covenant_borrower_sig_script(&nested, &map).expect("nested");
    assert_eq!(&witness[65..68], &[0x01, 0x51, 0x00]);

    let pushed_else_if = [0x02, 0x67, 0x63, 0x67, 0x51, 0x68];
    let witness =
        build_p2sh_covenant_borrower_sig_script(&pushed_else_if, &map).expect("opcode walk");
    assert_eq!(&witness[65..67], &[0x01, 0x00]);

    let large = vec![0x51; 300];
    let keyless = build_p2sh_covenant_nosig_script(&large).expect("keyless");
    assert_eq!(&keyless[..4], &[0x00, 0x4d, 0x2c, 0x01]);
    let conservation = build_p2sh_token_conservation_sig_script(&large).expect("conservation");
    assert_eq!(&conservation[..3], &[0x4d, 0x2c, 0x01]);
}

fn p2sh_script_public_key() -> Vec<u8> {
    let mut script = vec![0xaa, 0x20];
    script.extend_from_slice(&[0x77; 32]);
    script.push(0x87);
    script
}

fn valid_signature_map(bytes: u8) -> Map<String, Value> {
    signatures(&format!("02{}", format!("{bytes:02x}").repeat(32)))
}

#[test]
fn multisig_signature_builder_orders_valid_signers_and_rejects_invalid_sets() {
    let keys = [[0x11; 32], [0x22; 32], [0x33; 32]];
    let redeem = crate::multisig::build_redeem_script(2, &keys).expect("redeem");
    let mut map = Map::new();
    map.insert(
        format!("03{}", hex::encode(keys[2])),
        json!({"schnorr": "33".repeat(64)}),
    );
    map.insert(
        format!("02{}", hex::encode(keys[0])),
        json!({"schnorr": "11".repeat(64)}),
    );
    map.insert("short-key".into(), json!({"schnorr": "44".repeat(64)}));

    let witness = super::build_p2sh_multisig_sig_script(&redeem, &map).expect("2-of-3 witness");
    assert_eq!(witness[0], 65);
    assert_eq!(witness[1], 0x11);
    assert_eq!(witness[66], 65);
    assert_eq!(witness[67], 0x33);

    assert!(super::build_p2sh_multisig_sig_script(&redeem, &Map::new())
        .unwrap_err()
        .contains("need 2"));

    let unknown = signatures(&format!("02{}", "99".repeat(32)));
    assert!(super::build_p2sh_multisig_sig_script(&redeem, &unknown)
        .unwrap_err()
        .contains("not in redeem"));

    let mut short = Map::new();
    short.insert(
        format!("02{}", hex::encode(keys[0])),
        json!({"schnorr": "00"}),
    );
    assert!(super::build_p2sh_multisig_sig_script(&redeem, &short)
        .unwrap_err()
        .contains("bad sig length"));
    assert!(super::build_p2sh_multisig_sig_script(&[0x51, 0xae], &map).is_err());
}

#[test]
fn escrow_witnesses_cover_every_branch_and_validation_error() {
    let redeem = vec![0x51, 0xac];
    let map = valid_signature_map(0x11);
    for branch in [
        "buyer-release",
        "seller-refund",
        "arbiter-award-seller",
        "arbiter-refund-buyer",
        "buyer-dispute",
        "seller-dispute",
    ] {
        let witness =
            super::build_p2sh_escrow_sig_script(&redeem, &map, branch).expect("escrow branch");
        assert!(witness.ends_with(&redeem));
    }
    assert!(
        super::build_p2sh_escrow_sig_script(&redeem, &map, "unknown")
            .unwrap_err()
            .contains("Unknown escrow branch")
    );
    assert!(super::build_p2sh_escrow_sig_script(&redeem, &Map::new(), "buyer-release").is_err());
}

#[test]
fn shipping_escrow_witnesses_cover_signed_timeout_and_unknown_branches() {
    let redeem = vec![0xb9, 0x51, 0xac];
    let map = valid_signature_map(0x12);
    let empty = Map::new();
    for branch in [
        "pickup",
        "delivery",
        "state0-arb-refund",
        "state0-timeout",
        "state1-arb-award",
        "state1-timeout",
        "state1-arb-refund",
    ] {
        let signatures = if branch.ends_with("timeout") {
            &empty
        } else {
            &map
        };
        let witness = super::build_p2sh_ship_escrow_sig_script(&redeem, signatures, branch)
            .expect("shipping branch");
        assert!(witness.ends_with(&redeem));
    }
    assert!(
        super::build_p2sh_ship_escrow_sig_script(&redeem, &Map::new(), "pickup")
            .unwrap_err()
            .contains("requires a signature")
    );
    assert!(
        super::build_p2sh_ship_escrow_sig_script(&redeem, &map, "unknown")
            .unwrap_err()
            .contains("Unknown ship-escrow branch")
    );
}

#[test]
fn atomic_commit_merkle_and_risc0_witnesses_cover_data_and_error_paths() {
    let redeem = vec![0x63, 0x51, 0x67, 0x00, 0x68];
    let map = valid_signature_map(0x13);

    let atomic = super::build_p2sh_preimage_claim_sig_script(&redeem, &map, &[0x41; 32])
        .expect("atomic claim");
    assert_eq!(atomic[0], 32);
    assert!(
        super::build_p2sh_preimage_claim_sig_script(&redeem, &map, &[0; 256])
            .unwrap_err()
            .contains("preimage too large")
    );

    let split =
        super::build_p2sh_commit_reveal_split_sig_script(&redeem, &map, &[0x21; 4], &[0x22; 80])
            .expect("split reveal");
    assert_eq!(split[0], 4);
    assert!(split.ends_with(&redeem));

    let proof = json!([
        {"sibling": "11".repeat(32), "direction": 0},
        {"sibling": "22".repeat(32), "direction": 1}
    ])
    .to_string();
    let merkle = super::build_p2sh_merkle_claim_sig_script(&redeem, &map, &proof, &[0x20, 0x33])
        .expect("merkle claim");
    assert!(merkle.ends_with(&redeem));
    assert!(
        super::build_p2sh_merkle_claim_sig_script(&redeem, &map, "not-json", &[0x20],)
            .unwrap_err()
            .contains("Bad proof JSON")
    );
    assert!(super::build_p2sh_merkle_claim_sig_script(
        &redeem,
        &map,
        "[{\"direction\":0}]",
        &[0x20],
    )
    .unwrap_err()
    .contains("missing sibling"));
    assert!(super::build_p2sh_merkle_claim_sig_script(
        &redeem,
        &map,
        "[{\"sibling\":\"zz\",\"direction\":0}]",
        &[0x20],
    )
    .unwrap_err()
    .contains("bad sibling hex"));

    let fields = json!({
        "claim": "01",
        "controlIndex": "02",
        "controlDigests": "03",
        "journal": "04",
        "imageId": "05",
        "controlId": "06",
        "hashfn": "07"
    })
    .as_object()
    .unwrap()
    .clone();
    assert!(super::build_p2sh_risc0_claim_sig_script(&redeem, &map, &[0x31; 8], &fields,).is_ok());
    assert!(
        super::build_p2sh_risc0_bridge_claim_sig_script(&redeem, &map, &[0x31; 8], &fields,)
            .is_ok()
    );

    let missing = json!({"claim": "01"}).as_object().unwrap().clone();
    assert!(
        super::build_p2sh_risc0_claim_sig_script(&redeem, &map, &[0x31], &missing,)
            .unwrap_err()
            .contains("missing risc0 field")
    );
    let bad = json!({
        "claim": "zz",
        "controlIndex": "02",
        "controlDigests": "03",
        "journal": "04",
        "imageId": "05",
        "controlId": "06",
        "hashfn": "07"
    })
    .as_object()
    .unwrap()
    .clone();
    assert!(
        super::build_p2sh_risc0_claim_sig_script(&redeem, &map, &[0x31], &bad,)
            .unwrap_err()
            .contains("bad hex")
    );
}

#[test]
fn signature_router_covers_p2pk_keyless_covenant_treasury_state_and_multisig_routes() {
    use super::{build_signature_script, ScriptBuildOptions};

    let no_branch = None;
    let options = ScriptBuildOptions {
        force_beneficiary: false,
        force_time_path: false,
        escrow_branch: &no_branch,
        ship_branch: &no_branch,
    };
    let map = valid_signature_map(0x14);
    let input = Map::new();

    let p2pk =
        build_signature_script(&input, &[0x20, 0xac], &None, &map, options).expect("P2PK route");
    assert_eq!(p2pk[0], 65);

    assert!(
        build_signature_script(&input, &p2sh_script_public_key(), &None, &map, options,)
            .unwrap_err()
            .contains("without redeem script")
    );

    for property in [
        "oracleMbHeartbeat",
        "oracleMbPassthrough",
        "oracleMbConsumer",
    ] {
        let mut proprietary = Map::new();
        proprietary.insert(property.to_string(), Value::Bool(true));
        let mut input = Map::new();
        input.insert("proprietaries".to_string(), Value::Object(proprietary));
        assert!(build_signature_script(
            &input,
            &p2sh_script_public_key(),
            &Some(vec![0x51, 0xac]),
            &Map::new(),
            options,
        )
        .is_ok());
    }

    let covenant = Some(vec![0x63, 0x51, 0x67, 0x00, 0x68]);
    assert!(build_signature_script(
        &Map::new(),
        &p2sh_script_public_key(),
        &covenant,
        &Map::new(),
        options,
    )
    .is_ok());

    let mut treasury = vec![0x20];
    treasury.extend_from_slice(&[0x15; 32]);
    treasury.push(0xad);
    treasury.push(0x51);
    assert!(build_signature_script(
        &Map::new(),
        &p2sh_script_public_key(),
        &Some(treasury.clone()),
        &Map::new(),
        options,
    )
    .unwrap_err()
    .contains("Treasury"));
    assert!(build_signature_script(
        &Map::new(),
        &p2sh_script_public_key(),
        &Some(treasury),
        &map,
        options,
    )
    .is_ok());

    let state = Some(vec![0xb9, 0x51, 0xac]);
    assert!(build_signature_script(
        &Map::new(),
        &p2sh_script_public_key(),
        &state,
        &Map::new(),
        options,
    )
    .unwrap_err()
    .contains("State machine"));
    assert!(build_signature_script(
        &Map::new(),
        &p2sh_script_public_key(),
        &state,
        &map,
        options,
    )
    .is_ok());

    let ship_branch = Some("state0-timeout".to_string());
    let ship_options = ScriptBuildOptions {
        ship_branch: &ship_branch,
        ..options
    };
    assert!(build_signature_script(
        &Map::new(),
        &p2sh_script_public_key(),
        &state,
        &Map::new(),
        ship_options,
    )
    .is_ok());

    let single = Some({
        let mut redeem = vec![0x20];
        redeem.extend_from_slice(&[0x16; 32]);
        redeem.push(0xad);
        redeem.push(0x51);
        redeem
    });
    assert!(build_signature_script(
        &Map::new(),
        &p2sh_script_public_key(),
        &single,
        &map,
        options,
    )
    .is_ok());

    assert!(build_signature_script(
        &Map::new(),
        &p2sh_script_public_key(),
        &Some(vec![0x00, 0x51]),
        &Map::new(),
        options,
    )
    .is_ok());

    let multisig = crate::multisig::build_redeem_script(1, &[[0x14; 32]]).expect("multisig redeem");
    assert!(build_signature_script(
        &Map::new(),
        &p2sh_script_public_key(),
        &Some(multisig),
        &map,
        options,
    )
    .is_ok());
}

#[test]
fn signer_branch_detection_and_context_parsing_cover_owner_beneficiary_and_properties() {
    let owner = [0x21; 32];
    let beneficiary = [0x22; 32];
    let mut redeem = vec![0x63, 0x20];
    redeem.extend_from_slice(&owner);
    redeem.extend_from_slice(&[0xad, 0x67, 0x20]);
    redeem.extend_from_slice(&beneficiary);
    redeem.extend_from_slice(&[0xac, 0x68]);

    let owner_map = valid_signature_map(0x21);
    let owner_branch = super::SignerBranch::detect(&redeem, &owner_map, false);
    assert!(owner_branch.is_owner);
    assert!(!owner_branch.is_beneficiary);

    let beneficiary_map = valid_signature_map(0x22);
    let beneficiary_branch = super::SignerBranch::detect(&redeem, &beneficiary_map, false);
    assert!(!beneficiary_branch.is_owner);
    assert!(beneficiary_branch.is_beneficiary);

    let forced = super::SignerBranch::detect(&redeem, &owner_map, true);
    assert!(!forced.is_owner);
    assert!(forced.is_beneficiary);

    let mut nested = vec![0x63, 0x20];
    nested.extend_from_slice(&owner);
    nested.extend_from_slice(&[0x67, 0x63, 0x20]);
    nested.extend_from_slice(&beneficiary);
    nested.extend_from_slice(&[0xac, 0x68, 0x68]);
    let nested_branch = super::SignerBranch::detect(&nested, &beneficiary_map, false);
    assert!(!nested_branch.is_owner);
    assert!(nested_branch.is_beneficiary);

    let no_beneficiary = super::SignerBranch::detect(&[0x51], &Map::new(), false);
    assert!(!no_beneficiary.is_owner);
    assert!(!no_beneficiary.is_beneficiary);

    let input = json!({
        "minimumSignatures": 0,
        "proprietaries": {
            "risc0OracleMb": true,
            "oracleMbPassthrough": true,
            "oracleMbHeartbeat": true,
            "oracleMbConsumer": true,
            "oracleV1Signature": "11",
            "zkProof": "44",
            "zkPublicInputs": ["55", "bad"],
            "zkVk": "66",
            "risc0Seal": "77",
            "risc0Fields": {"claim": "88"},
            "risc0Bridge": true,
            "groth16Bridge": true,
            "commitPartA": "99",
            "commitPartB": "aa",
            "commitPreimage": "bb",
            "merkleProof": "[]",
            "merkleDestSpk": "cc",
            "withdrawalSpk": "dd",
            "rollupStateAdvance": true,
            "rollupStateRefund": true,
            "rollupProof": "ee",
            "rollupPrefix": "ff",
            "rollupSuffix": "00",
            "rollupDepositAdvance": true,
            "rollupUnifiedAdvance": true,
            "rollupForcedExit": true,
            "depositHoldingCredit": true,
            "depositHoldingRefund": true
        }
    });
    let context = super::CovenantContext::parse(input.as_object().unwrap());
    assert_eq!(context.signatures.minimum_signatures, 0);
    assert_eq!(context.oracle.v1.signature.as_deref(), Some(&[0x11][..]));
    assert!(context.oracle.model_b.risc0);
    assert_eq!(context.proofs.zk_public_inputs.as_ref().unwrap().len(), 1);
    assert!(context.rollup.state_advance);
    assert!(context.rollup.deposit_holding_refund);
}

#[test]
fn covenant_router_covers_operational_and_proof_branch_families() {
    fn input(properties: Map<String, Value>) -> Map<String, Value> {
        let mut input = Map::new();
        input.insert("proprietaries".to_string(), Value::Object(properties));
        input
    }

    fn properties(values: &[(&str, Value)]) -> Map<String, Value> {
        values
            .iter()
            .map(|(key, value)| ((*key).to_string(), value.clone()))
            .collect()
    }

    fn route(
        input: &Map<String, Value>,
        signatures: &Map<String, Value>,
        escrow: &Option<String>,
    ) -> Result<Vec<u8>, String> {
        let redeem = [0x63, 0x51, 0x67, 0x00, 0x68];
        super::build_if_else_covenant_script(
            input, &redeem, &redeem, signatures, false, false, escrow,
        )
    }

    let signatures = valid_signature_map(0x31);
    let no_escrow = None;

    let deposit_credit = input(properties(&[
        ("depositHoldingCredit", Value::Bool(true)),
        ("rollupPrefix", Value::String("11".to_string())),
        ("rollupSuffix", Value::String("22".to_string())),
    ]));
    assert!(route(&deposit_credit, &Map::new(), &no_escrow).is_ok());

    let mut no_signature = Map::new();
    no_signature.insert("minimumSignatures".to_string(), Value::from(0));
    assert!(route(&no_signature, &Map::new(), &no_escrow).is_ok());

    let escrow = Some("buyer-release".to_string());
    assert!(route(&Map::new(), &signatures, &escrow).is_ok());

    for flag in [
        "rollupStateAdvance",
        "rollupDepositAdvance",
        "rollupUnifiedAdvance",
        "rollupForcedExit",
    ] {
        let branch = input(properties(&[
            (flag, Value::Bool(true)),
            ("rollupProof", Value::String("33".to_string())),
            ("rollupPrefix", Value::String("44".to_string())),
            ("rollupSuffix", Value::String("55".to_string())),
        ]));
        assert!(route(&branch, &signatures, &no_escrow).is_ok());
    }

    for flag in ["rollupStateRefund", "depositHoldingRefund"] {
        let refund = input(properties(&[(flag, Value::Bool(true))]));
        assert!(route(&refund, &signatures, &no_escrow).is_ok());
    }

    let groth16 = input(properties(&[("groth16Bridge", Value::Bool(true))]));
    assert!(route(&groth16, &signatures, &no_escrow).is_ok());

    for flag in [
        "oracleMbHeartbeat",
        "oracleMbPassthrough",
        "oracleMbConsumer",
    ] {
        let branch = input(properties(&[(flag, Value::Bool(true))]));
        assert!(route(&branch, &Map::new(), &no_escrow).is_ok());
    }

    let missing_rollup_part = input(properties(&[
        ("rollupStateAdvance", Value::Bool(true)),
        ("rollupProof", Value::String("33".to_string())),
    ]));
    assert!(route(&missing_rollup_part, &signatures, &no_escrow,)
        .unwrap_err()
        .contains("rollupPrefix"));

    let zk_bridge = input(properties(&[
        ("zkProof", Value::String("71".to_string())),
        (
            "zkPublicInputs",
            Value::Array(vec![Value::String("72".to_string())]),
        ),
        ("zkVk", Value::String("73".to_string())),
        ("withdrawalSpk", Value::String("74".to_string())),
    ]));
    assert!(route(&zk_bridge, &signatures, &no_escrow).is_ok());

    let zk = input(properties(&[
        ("zkProof", Value::String("75".to_string())),
        (
            "zkPublicInputs",
            Value::Array(vec![Value::String("76".to_string())]),
        ),
        ("zkVk", Value::String("77".to_string())),
    ]));
    assert!(route(&zk, &signatures, &no_escrow).is_ok());

    let risc0_fields = json!({
        "claim": "01",
        "controlIndex": "02",
        "controlDigests": "03",
        "journal": "04",
        "imageId": "05",
        "controlId": "06",
        "hashfn": "07"
    });
    let risc0 = input(properties(&[
        ("risc0Seal", Value::String("81".to_string())),
        ("risc0Fields", risc0_fields.clone()),
    ]));
    assert!(route(&risc0, &signatures, &no_escrow).is_ok());

    let risc0_bridge = input(properties(&[
        ("risc0Seal", Value::String("82".to_string())),
        ("risc0Fields", risc0_fields.clone()),
        ("risc0Bridge", Value::Bool(true)),
    ]));
    assert!(route(&risc0_bridge, &signatures, &no_escrow).is_ok());

    let mut oracle_fields = risc0_fields;
    oracle_fields["journal"] = Value::String("83".repeat(48));
    let oracle_mb = input(properties(&[
        ("risc0Seal", Value::String("84".to_string())),
        ("risc0Fields", oracle_fields),
        ("risc0OracleMb", Value::Bool(true)),
    ]));
    assert!(route(&oracle_mb, &Map::new(), &no_escrow).is_ok());

    let split = input(properties(&[
        ("commitPartA", Value::String("a1".to_string())),
        ("commitPartB", Value::String("a2".to_string())),
    ]));
    assert!(route(&split, &signatures, &no_escrow).is_ok());

    let commit = input(properties(&[(
        "commitPreimage",
        Value::String("a3".repeat(32)),
    )]));
    assert!(route(&commit, &signatures, &no_escrow).is_ok());

    let merkle = input(properties(&[
        (
            "merkleProof",
            Value::String(json!([{"sibling": "b1".repeat(32), "direction": 0}]).to_string()),
        ),
        ("merkleDestSpk", Value::String("b2".to_string())),
    ]));
    assert!(route(&merkle, &signatures, &no_escrow).is_ok());
}

#[test]
fn single_path_script_and_proprietary_hex_reader_are_directly_covered() {
    let redeem = vec![0x51, 0xac];
    let map = valid_signature_map(0x42);
    let script = super::build_p2sh_single_path_sig_script(&redeem, &map)
        .expect("single-path signature script");
    assert_eq!(script[0], 65);
    assert!(script.ends_with(&redeem));

    let values = serde_json::json!({"proof": "0102"})
        .as_object()
        .unwrap()
        .clone();
    assert_eq!(
        super::router::hex_field(Some(&values), "proof"),
        Some(vec![1, 2])
    );
    assert_eq!(super::router::hex_field(Some(&values), "missing"), None);
}

#[test]
fn contract_witness_builders_are_byte_observable_not_merely_successful() {
    let redeem = vec![0x51, 0xac];
    let map = signatures(&format!("02{}", "11".repeat(32)));

    let oracle_fields = json!({
        "claim": "01",
        "controlIndex": "0203",
        "controlDigests": "040506",
        "journal": "07".repeat(48)
    })
    .as_object()
    .unwrap()
    .clone();
    let oracle_publish =
        super::build_p2sh_oracle_mb_publish_sig_script(&redeem, &[0x08; 9], &oracle_fields)
            .expect("oracle publish");
    let expected_publish = crate::contracts::oracle::script::build_oracle_mb_publish_sig_script(
        &redeem,
        &[0x01],
        &[0x02, 0x03],
        &[0x04, 0x05, 0x06],
        &[0x08; 9],
        &[0x07; 48],
    );
    assert_eq!(oracle_publish, expected_publish);

    assert_eq!(
        super::build_p2sh_oracle_mb_passthrough_sig_script(&redeem).expect("passthrough"),
        crate::contracts::oracle::script::build_oracle_mb_passthrough_sig_script(&redeem),
    );
    assert_eq!(
        super::build_p2sh_oracle_mb_heartbeat_sig_script(&redeem).expect("heartbeat"),
        crate::contracts::oracle::script::build_oracle_mb_heartbeat_sig_script(&redeem),
    );
    assert_eq!(
        super::build_p2sh_oracle_mb_consumer_sig_script(&redeem).expect("consumer"),
        crate::contracts::oracle::script::build_oracle_mb_consumer_sig_script(&redeem),
    );

    let proof = [0x31, 0x32, 0x33];
    let prefix = [0x41, 0x42];
    let suffix = [0x51, 0x52, 0x53];
    for witness in [
        super::build_p2sh_rollup_advance_sig_script(&redeem, &map, &proof, &prefix, &suffix)
            .expect("rollup advance"),
        super::build_p2sh_rollup_unified_advance_sig_script(
            &redeem, &map, &proof, &prefix, &suffix,
        )
        .expect("unified advance"),
        super::build_p2sh_rollup_forced_exit_sig_script(&redeem, &map, &proof, &prefix, &suffix)
            .expect("forced exit"),
        super::build_p2sh_rollup_refund_sig_script(&redeem, &map).expect("rollup refund"),
        super::build_p2sh_deposit_holding_credit_sig_script(&redeem, &prefix, &suffix)
            .expect("deposit credit"),
    ] {
        assert!(witness.len() > redeem.len() + 2);
        assert!(witness.ends_with(&redeem));
    }

    let public_inputs = vec![vec![0x61], vec![0x62, 0x63]];
    let vk = [0x71, 0x72];
    let withdrawal_spk = [0x20, 0x73, 0xac];
    for witness in [
        super::build_p2sh_zk_claim_sig_script(&redeem, &map, &proof, &public_inputs, &vk)
            .expect("zk claim"),
        super::build_p2sh_bridge_claim_sig_script(
            &redeem,
            &map,
            &proof,
            &public_inputs,
            &vk,
            &withdrawal_spk,
        )
        .expect("bridge claim"),
        super::build_p2sh_groth16_bridge_claim_sig_script(&redeem, &map).expect("groth16 bridge"),
    ] {
        assert!(witness.len() > redeem.len() + 2);
        assert!(witness.ends_with(&redeem));
    }

    let risc0_fields = json!({
        "claim": "81",
        "controlIndex": "82",
        "controlDigests": "83"
    })
    .as_object()
    .unwrap()
    .clone();
    let risc0_bridge = super::build_p2sh_risc0_bridge_claim_sig_script(
        &redeem,
        &map,
        &[0x84, 0x85],
        &risc0_fields,
    )
    .expect("risc0 bridge");
    assert!(risc0_bridge.len() > redeem.len() + 70);
    assert!(risc0_bridge.ends_with(&redeem));

    let treasury = super::build_p2sh_treasury_sig_script(&redeem, &map).expect("treasury");
    assert_eq!(treasury[0], 65);
    assert!(treasury.ends_with(&redeem));
}

#[test]
fn merkle_direction_and_genesis_covenant_id_are_exact() {
    let redeem = vec![0x51, 0xac];
    let map = signatures(&format!("02{}", "11".repeat(32)));
    let destination = [0x20, 0x33];
    let proof = json!([
        {"sibling": "11".repeat(32), "direction": 0},
        {"sibling": "22".repeat(32), "direction": 1}
    ])
    .to_string();
    let actual = super::build_p2sh_merkle_claim_sig_script(&redeem, &map, &proof, &destination)
        .expect("merkle witness");

    let mut expected = Vec::new();
    push_data_sigscript(&mut expected, &destination);
    push_data_sigscript(&mut expected, &[0x22; 32]);
    expected.push(0x51);
    push_data_sigscript(&mut expected, &[0x11; 32]);
    expected.push(0x00);
    push_data_sigscript(&mut expected, &destination);
    let mut signature = vec![0x55; 64];
    signature.push(1);
    push_data_sigscript(&mut expected, &signature);
    expected.push(0x00);
    push_redeem_script(&mut expected, &redeem).expect("redeem push");
    assert_eq!(actual, expected);

    assert_eq!(
        hex::encode(super::compute_genesis_covenant_id(
            &[0x11; 32],
            7,
            2,
            123_456_789,
            3,
            &[0x51, 0xac, 0x00],
        )),
        "6385a4192310af4731f87c781e195a568dd4ae17e675ccfad6b606547008f5cf"
    );
}

#[test]
fn signature_router_requires_exact_p2sh_salt_and_single_path_shapes() {
    use super::{build_signature_script, ScriptBuildOptions};

    let no_branch = None;
    let options = ScriptBuildOptions {
        force_beneficiary: false,
        force_time_path: false,
        escrow_branch: &no_branch,
        ship_branch: &no_branch,
    };
    let map = valid_signature_map(0x41);
    let input = Map::new();
    let p2sh = p2sh_script_public_key();

    for index in [0usize, 1, 34] {
        let mut malformed = p2sh.clone();
        malformed[index] ^= 1;
        let witness = build_signature_script(&input, &malformed, &None, &map, options)
            .expect("near-P2SH must use P2PK route");
        assert_eq!(witness.len(), 66, "P2SH byte {index}");
    }
    assert_eq!(
        build_signature_script(&input, &p2sh[..34], &None, &map, options)
            .expect("short P2SH must use P2PK route")
            .len(),
        66,
    );

    let mut salted_single = vec![0x08];
    salted_single.extend_from_slice(&[0x99; 8]);
    salted_single.push(0x75);
    salted_single.push(0x20);
    salted_single.extend_from_slice(&[0x43; 32]);
    salted_single.push(0xad);
    salted_single.push(0x51);
    assert!(
        build_signature_script(&input, &p2sh, &Some(salted_single.clone()), &map, options,).is_ok()
    );
    for index in [0usize, 9] {
        let mut malformed = salted_single.clone();
        malformed[index] ^= 1;
        assert!(build_signature_script(&input, &p2sh, &Some(malformed), &map, options).is_err());
    }

    let mut single = vec![0x20];
    single.extend_from_slice(&[0x42; 32]);
    single.push(0xad);
    single.push(0x51);
    assert!(build_signature_script(&input, &p2sh, &Some(single.clone()), &map, options).is_ok());
    let mut bad_opcode = single.clone();
    bad_opcode[33] = 0xac;
    assert!(build_signature_script(&input, &p2sh, &Some(bad_opcode), &map, options).is_err());
    let mut bad_prefix = single.clone();
    bad_prefix[0] = 0x21;
    assert!(build_signature_script(&input, &p2sh, &Some(bad_prefix), &map, options).is_err());
    assert!(
        build_signature_script(&input, &p2sh, &Some(single[..34].to_vec()), &map, options).is_err()
    );
}

#[test]
fn covenant_context_preserves_exact_optional_property_values_and_absence() {
    let input = json!({
        "minimumSignatures": 3,
        "proprietaries": {
            "zkPublicInputs": ["0055", "aabb"],
            "merkleProof": "[{\"left\":\"11\"}]",
            "risc0Fields": {"claim": "88", "height": 7}
        }
    });
    let context = super::CovenantContext::parse(input.as_object().unwrap());
    assert_eq!(context.signatures.minimum_signatures, 3);
    assert_eq!(
        context.proofs.zk_public_inputs.as_deref(),
        Some(&[vec![0x00, 0x55], vec![0xaa, 0xbb]][..]),
    );
    assert_eq!(context.merkle.proof.as_deref(), Some("[{\"left\":\"11\"}]"));
    let fields = context.proofs.risc0_fields.as_ref().expect("risc0 fields");
    assert_eq!(fields.get("claim").and_then(Value::as_str), Some("88"));
    assert_eq!(fields.get("height").and_then(Value::as_u64), Some(7));

    let absent_input = Map::new();
    let absent = super::CovenantContext::parse(&absent_input);
    assert!(absent.proofs.zk_public_inputs.is_none());
    assert!(absent.merkle.proof.is_none());
    assert!(absent.proofs.risc0_fields.is_none());

    let wrong_types = json!({
        "proprietaries": {
            "zkPublicInputs": "0055",
            "merkleProof": 7,
            "risc0Fields": []
        }
    });
    let wrong = super::CovenantContext::parse(wrong_types.as_object().unwrap());
    assert!(wrong.proofs.zk_public_inputs.is_none());
    assert!(wrong.merkle.proof.is_none());
    assert!(wrong.proofs.risc0_fields.is_none());
}

#[test]
fn beneficiary_key_detection_observes_first_legal_marker_and_exact_tail_lengths() {
    let beneficiary = [0x7bu8; 32];
    let signatures = valid_signature_map(0x7b);

    let mut direct = vec![0x51; 34];
    direct.push(0x67);
    direct.push(0x20);
    direct.extend_from_slice(&beneficiary);
    let branch = super::SignerBranch::detect(&direct, &signatures, false);
    assert!(branch.is_beneficiary);

    let mut nested = vec![0x51; 34];
    nested.extend_from_slice(&[0x67, 0x63, 0x20]);
    nested.extend_from_slice(&beneficiary);
    let nested_branch = super::SignerBranch::detect(&nested, &signatures, false);
    assert!(nested_branch.is_beneficiary);

    let mut truncated_direct = vec![0x51; 34];
    truncated_direct.extend_from_slice(&[0x67, 0x20]);
    truncated_direct.extend_from_slice(&beneficiary[..31]);
    let branch = super::SignerBranch::detect(&truncated_direct, &signatures, false);
    assert!(!branch.is_beneficiary);

    let mut truncated_nested = vec![0x51; 34];
    truncated_nested.extend_from_slice(&[0x67, 0x63, 0x20]);
    truncated_nested.extend_from_slice(&beneficiary[..31]);
    let branch = super::SignerBranch::detect(&truncated_nested, &signatures, false);
    assert!(!branch.is_beneficiary);
}

#[test]
fn signer_branch_short_circuit_boundaries_are_explicit() {
    let beneficiary = [0x7bu8; 32];
    let valid = valid_signature_map(0x7b);

    // Atomic-swap prefix reaches the second structural check but deliberately
    // fails it, covering the non-atomic branch without relying on truncation.
    let mut wrong_atomic_prefix = vec![0x63, 0x21];
    wrong_atomic_prefix.resize(37, 0x51);
    let branch = super::SignerBranch::detect(&wrong_atomic_prefix, &valid, false);
    assert!(!branch.is_owner);

    // A candidate OP_ELSE at the last scannable offset cannot contain the
    // nested 35-byte form and must simply produce no beneficiary.
    let mut exact_tail = vec![0x51; 68];
    exact_tail[34] = 0x67;
    exact_tail[35] = 0x63;
    let branch = super::SignerBranch::detect(&exact_tail, &valid, false);
    assert!(!branch.is_beneficiary);

    // Enough bytes for the nested shape, but with a non-OP_IF byte after ELSE.
    let mut wrong_nested_opcode = vec![0x51; 69];
    wrong_nested_opcode[34] = 0x67;
    wrong_nested_opcode[35] = 0x64;
    wrong_nested_opcode[36] = 0x20;
    let branch = super::SignerBranch::detect(&wrong_nested_opcode, &valid, false);
    assert!(!branch.is_beneficiary);

    // Signer maps may contain unrelated metadata keys; only compressed-key
    // strings of exactly 66 hex characters are considered signer identities.
    let mut short_key = Map::new();
    short_key.insert("11".repeat(32), json!({"schnorr": "55".repeat(64)}));
    let mut direct = vec![0x51; 34];
    direct.extend_from_slice(&[0x67, 0x20]);
    direct.extend_from_slice(&beneficiary);
    let branch = super::SignerBranch::detect(&direct, &short_key, false);
    assert!(!branch.is_beneficiary);
}

#[test]
fn standard_covenant_builder_covers_short_shape_key_and_nested_short_circuits() {
    let map = valid_signature_map(0x11);

    // Short redeems cannot be salted, standard-owner, or nested shapes.
    let short = [0x51, 0xac];
    let witness =
        super::build_p2sh_covenant_sig_script(&short, &map, false).expect("short covenant witness");
    assert!(witness.ends_with(&short));

    // Long enough for an owner-shape check, but with the wrong push opcode.
    let mut wrong_push = vec![0x63, 0x21];
    wrong_push.resize(36, 0x51);
    assert!(super::build_p2sh_covenant_sig_script(&wrong_push, &map, false).is_ok());

    // A 64-character x-only key is accepted by the signature extractor but
    // follows the no-compressed-prefix normalization branch.
    let mut xonly_map = Map::new();
    xonly_map.insert("11".repeat(32), json!({"schnorr": "55".repeat(64)}));
    let mut owner = vec![0x63, 0x20];
    owner.extend_from_slice(&[0x11; 32]);
    owner.extend_from_slice(&[0xac, 0x51]);
    let witness =
        super::build_p2sh_covenant_sig_script(&owner, &xonly_map, false).expect("x-only map key");
    assert_eq!(witness.last().copied(), Some(0x51));

    // Exactly 35 bytes reaches owner detection but cannot contain a nested IF.
    let mut exact_non_nested = vec![0x63, 0x20];
    exact_non_nested.extend_from_slice(&[0x11; 32]);
    exact_non_nested.push(0xad);
    let witness = super::build_p2sh_covenant_sig_script(&exact_non_nested, &map, false)
        .expect("exact non-nested covenant");
    assert!(witness.ends_with(&exact_non_nested));
}

#[test]
fn fallback_covenant_router_covers_owner_beneficiary_signature_and_nosig_paths() {
    let none = None;
    let empty_input = Map::new();

    let mut owner_redeem = vec![0x63, 0x20];
    owner_redeem.extend_from_slice(&[0x11; 32]);
    owner_redeem.extend_from_slice(&[0xac, 0x51]);
    let owner_map = valid_signature_map(0x11);
    let owner = super::build_if_else_covenant_script(
        &empty_input,
        &owner_redeem,
        &owner_redeem,
        &owner_map,
        false,
        false,
        &none,
    )
    .expect("owner fallback");
    assert!(owner.ends_with(&owner_redeem));

    let generic_redeem = [0x51, 0xac];
    let generic = super::build_if_else_covenant_script(
        &empty_input,
        &generic_redeem,
        &generic_redeem,
        &owner_map,
        false,
        false,
        &none,
    )
    .expect("generic signed fallback");
    assert!(generic.ends_with(&generic_redeem));

    let mut beneficiary_redeem = vec![0x63, 0x20];
    beneficiary_redeem.extend_from_slice(&[0x11; 32]);
    beneficiary_redeem.extend_from_slice(&[0x67, 0x20]);
    beneficiary_redeem.extend_from_slice(&[0x22; 32]);
    let beneficiary_map = valid_signature_map(0x22);
    let beneficiary = super::build_if_else_covenant_script(
        &empty_input,
        &beneficiary_redeem,
        &beneficiary_redeem,
        &beneficiary_map,
        false,
        false,
        &none,
    )
    .expect("beneficiary fallback");
    assert!(beneficiary.ends_with(&beneficiary_redeem));

    let nosig = super::build_if_else_covenant_script(
        &empty_input,
        &generic_redeem,
        &generic_redeem,
        &Map::new(),
        false,
        false,
        &none,
    )
    .expect("no-signature fallback");
    assert!(nosig.ends_with(&generic_redeem));
}

#[test]
fn oracle_mb_publish_rejects_exact_journal_length_boundary() {
    let redeem = [0x51, 0xac];
    let fields = json!({
        "claim": "01",
        "controlIndex": "02",
        "controlDigests": "03",
        "journal": "04".repeat(47)
    })
    .as_object()
    .unwrap()
    .clone();
    assert!(
        super::build_p2sh_oracle_mb_publish_sig_script(&redeem, &[0x05], &fields)
            .unwrap_err()
            .contains("48 bytes")
    );
}

#[test]
fn private_swap_claim_sigscript_requires_one_canonical_schnorr_signature() {
    let redeem = [0x51, 0xac];
    let partial = signatures(&format!("02{}", "11".repeat(32)));
    let script = build_p2sh_private_swap_claim_sig_script(&redeem, &partial)
        .expect("private swap claim sigscript");
    assert!(script.ends_with(&redeem));
    assert_eq!(script[0], 65); // 64-byte Schnorr signature + SIGHASH_ALL byte.
    assert_eq!(script[65], 0x01); // SIGHASH_ALL is the final pushed signature byte.
    assert_eq!(script[66], 0x51); // OP_TRUE selects the adaptor-claim branch.
    assert!(build_p2sh_private_swap_claim_sig_script(&redeem, &Map::new()).is_err());
    let malformed = json!({format!("02{}", "11".repeat(32)): {"schnorr": "zz"}})
        .as_object()
        .unwrap()
        .clone();
    assert!(build_p2sh_private_swap_claim_sig_script(&redeem, &malformed).is_err());
}

#[test]
fn oracle_v1_claim_script_requires_one_matching_beneficiary_signature_and_canonical_redeem() {
    let owner = [0x11; 32];
    let beneficiary = [0x22; 32];
    let oracle = [0x33; 32];
    let commitment = [0x44; 32];
    let redeem = crate::contracts::covenant::script::build_oracle_v1_covenant_script(
        &owner,
        &beneficiary,
        &oracle,
        &commitment,
        77,
        &[0x55; 16],
    );
    let beneficiary_key = format!("02{}", hex::encode(beneficiary));
    let partial = signatures(&beneficiary_key);
    let script = super::build_p2sh_oracle_v1_claim_sig_script(&redeem, &partial, &[0x66; 64])
        .expect("oracle-v1 claim sigscript");
    assert!(script.ends_with(&redeem));
    assert!(script.windows(64).any(|window| window == [0x66; 64]));

    assert!(super::build_p2sh_oracle_v1_claim_sig_script(&redeem, &partial, &[0x66; 63]).is_err());
    assert!(super::build_p2sh_oracle_v1_claim_sig_script(&[0x51], &partial, &[0x66; 64]).is_err());
    assert!(
        super::build_p2sh_oracle_v1_claim_sig_script(&redeem, &Map::new(), &[0x66; 64]).is_err()
    );

    let mut ambiguous = partial.clone();
    ambiguous.insert(
        format!("03{}", hex::encode(beneficiary)),
        json!({"schnorr": "77".repeat(64)}),
    );
    assert!(
        super::build_p2sh_oracle_v1_claim_sig_script(&redeem, &ambiguous, &[0x66; 64]).is_err()
    );

    let invalid_prefix =
        json!({format!("04{}", hex::encode(beneficiary)): {"schnorr": "88".repeat(64)}})
            .as_object()
            .unwrap()
            .clone();
    assert!(
        super::build_p2sh_oracle_v1_claim_sig_script(&redeem, &invalid_prefix, &[0x66; 64])
            .is_err()
    );
    let non_hex_key = json!({format!("02{}", "gg".repeat(32)): {"schnorr": "99".repeat(64)}})
        .as_object()
        .unwrap()
        .clone();
    assert!(
        super::build_p2sh_oracle_v1_claim_sig_script(&redeem, &non_hex_key, &[0x66; 64]).is_err()
    );

    let short = json!({beneficiary_key.clone(): {"schnorr": "00"}})
        .as_object()
        .unwrap()
        .clone();
    assert!(super::build_p2sh_oracle_v1_claim_sig_script(&redeem, &short, &[0x66; 64]).is_err());
    let malformed = json!({beneficiary_key: {"schnorr": "zz".repeat(64)}})
        .as_object()
        .unwrap()
        .clone();
    assert!(
        super::build_p2sh_oracle_v1_claim_sig_script(&redeem, &malformed, &[0x66; 64]).is_err()
    );
}
