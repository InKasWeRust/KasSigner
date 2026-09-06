use serde_json::json;

fn signature_map() -> serde_json::Value {
    let mut signatures = serde_json::Map::new();
    signatures.insert(
        format!("02{}", "11".repeat(32)),
        json!({ "schnorr": "22".repeat(64) }),
    );
    serde_json::Value::Object(signatures)
}

fn p2pk_input() -> serde_json::Value {
    json!({
        "utxoEntry": {
            "amount": 100_000_000u64,
            "scriptPublicKey": format!("000020{}ac", "33".repeat(32))
        },
        "previousOutpoint": {
            "transactionId": "44".repeat(32),
            "index": 7
        },
        "sequence": 9,
        "sigOpCount": 2,
        "redeemScript": null,
        "partialSigs": signature_map()
    })
}

fn encoded_pskb(document: serde_json::Value) -> String {
    crate::transaction_builder::pskb::encode_pskt_value(document).expect("PSKB wire")
}

fn encoded_pskb_unchecked(document: serde_json::Value) -> String {
    let json = serde_json::to_string(&vec![document]).expect("test JSON");
    let mut wire = b"PSKB".to_vec();
    wire.extend_from_slice(hex::encode(json.as_bytes()).as_bytes());
    hex::encode(wire)
}

#[test]
fn consensus_finalizer_covers_settings_payload_and_persistent_vault_binding() {
    use super::super::consensus::finalize_to_consensus;

    let mut input = p2pk_input();
    input["proprietaries"] = json!({"persistentVault": true});
    let wire = encoded_pskb(json!({
        "global": {
            "txVersion": 1,
            "fallbackLockTime": 42,
            "covenantBranch": "beneficiary",
            "gas": 7,
            "txPayload": "aabb",
            "proprietaries": {
                "escrowBranch": "buyer-release",
                "shipBranch": "pickup"
            }
        },
        "inputs": [input],
        "outputs": [{
            "amount": 41,
            "scriptPublicKey": "000051",
            "covenantBinding": null
        }]
    }));

    let finalized = finalize_to_consensus(&wire).expect("finalized transaction");
    assert_eq!(finalized.tx_version, 1);
    assert_eq!(finalized.locktime, 42);
    assert_eq!(finalized.gas, 7);
    assert_eq!(finalized.payload, vec![0xaa, 0xbb]);
    assert_eq!(finalized.inputs.len(), 1);
    assert_eq!(finalized.outputs.len(), 1);
    assert!(finalized.outputs[0].covenant.is_some());

    let consensus = finalized.into_consensus_transaction();
    assert_eq!(consensus.tx_version, 1);
    assert_eq!(consensus.locktime, 42);
}

#[test]
fn consensus_finalizer_preserves_explicit_bindings_and_reports_shape_errors() {
    use super::super::consensus::finalize_to_consensus;

    let explicit_id = "ab".repeat(32);
    let wire = encoded_pskb(json!({
        "global": {"txVersion": 0},
        "inputs": [p2pk_input()],
        "outputs": [{
            "amount": 5,
            "scriptPublicKey": "000051",
            "covenantBinding": {
                "authorizingInput": 0,
                "covenantId": explicit_id
            }
        }]
    }));
    let finalized = finalize_to_consensus(&wire).expect("explicit covenant binding");
    assert_eq!(finalized.outputs[0].covenant, Some((0, [0xab; 32])));

    let subnetwork_id = "00".repeat(20);
    for (document, expected) in [
        (json!(null), "PSKT not object"),
        (json!({"inputs": [], "outputs": []}), "missing global"),
        (
            json!({"global": {"subnetworkId": subnetwork_id.clone()}, "inputs": [], "outputs": []}),
            "missing txVersion",
        ),
        (
            json!({"global": {"txVersion": "1", "subnetworkId": subnetwork_id.clone()}, "inputs": [], "outputs": []}),
            "txVersion must be an unsigned integer",
        ),
        (
            json!({"global": {"txVersion": 65_536, "subnetworkId": subnetwork_id.clone()}, "inputs": [], "outputs": []}),
            "txVersion exceeds u16 range",
        ),
        (
            json!({"global": {"txVersion": 0, "subnetworkId": subnetwork_id.clone(), "fallbackLockTime": "01"}, "inputs": [], "outputs": []}),
            "fallbackLockTime must be a canonical unsigned decimal string",
        ),
        (
            json!({"global": {"txVersion": 0, "subnetworkId": subnetwork_id.clone(), "covenantBranch": 7}, "inputs": [], "outputs": []}),
            "covenantBranch must be a string",
        ),
        (
            json!({"global": {"txVersion": 0, "subnetworkId": subnetwork_id.clone(), "proprietaries": []}, "inputs": [], "outputs": []}),
            "proprietaries must be an object",
        ),
        (
            json!({"global": {"txVersion": 0, "subnetworkId": subnetwork_id.clone(), "proprietaries": {"escrowBranch": 7}}, "inputs": [], "outputs": []}),
            "escrowBranch must be a string",
        ),
        (
            json!({"global": {"txVersion": 0, "subnetworkId": subnetwork_id.clone(), "proprietaries": {"shipBranch": 7}}, "inputs": [], "outputs": []}),
            "shipBranch must be a string",
        ),
        (
            json!({"global": {"txVersion": 0}, "inputs": [], "outputs": []}),
            "missing subnetworkId",
        ),
        (
            json!({"global": {"txVersion": 0, "subnetworkId": "00"}, "inputs": [], "outputs": []}),
            "subnetworkId must be 20 bytes, got 1",
        ),
        (
            json!({"global": {"txVersion": 0, "subnetworkId": subnetwork_id.clone(), "gas": true}, "inputs": [], "outputs": []}),
            "gas must be a decimal string",
        ),
        (
            json!({"global": {"txVersion": 0, "subnetworkId": subnetwork_id.clone(), "txPayload": true}, "inputs": [], "outputs": []}),
            "txPayload must be a string",
        ),
        (
            json!({"global": {"txVersion": 0, "subnetworkId": subnetwork_id.clone(), "txPayload": "0"}, "inputs": [], "outputs": []}),
            "invalid txPayload hex",
        ),
        (
            json!({"global": {"txVersion": 0, "subnetworkId": subnetwork_id.clone()}, "outputs": []}),
            "missing inputs",
        ),
        (
            json!({"global": {"txVersion": 0, "subnetworkId": subnetwork_id.clone()}, "inputs": []}),
            "missing outputs",
        ),
        (
            json!({"global": {"txVersion": 0, "subnetworkId": subnetwork_id.clone()}, "inputs": [null], "outputs": []}),
            "input[0]: not object",
        ),
        (
            json!({"global": {"txVersion": 0, "subnetworkId": subnetwork_id.clone()}, "inputs": [], "outputs": [null]}),
            "output[0]: not object",
        ),
    ] {
        let wire = encoded_pskb_unchecked(document);
        let error = match finalize_to_consensus(&wire) {
            Ok(_) => panic!("expected finalizer error: {expected}"),
            Err(error) => error,
        };
        assert_eq!(error, expected);
    }
}

fn plain_output(amount: u64) -> serde_json::Value {
    json!({
        "amount": amount,
        "scriptPublicKey": "000051",
        "covenantBinding": null
    })
}

fn p2sh_covenant_input(redeem: &[u8], signer_byte: u8) -> serde_json::Value {
    let mut signatures = serde_json::Map::new();
    signatures.insert(
        format!("02{}", hex::encode([signer_byte; 32])),
        json!({ "schnorr": "22".repeat(64) }),
    );
    json!({
        "utxoEntry": {
            "amount": 100_000_000u64,
            "scriptPublicKey": format!("0000aa20{}87", "99".repeat(32))
        },
        "previousOutpoint": {
            "transactionId": "44".repeat(32),
            "index": 7
        },
        "sequence": 9,
        "sigOpCount": 2,
        "redeemScript": hex::encode(redeem),
        "partialSigs": serde_json::Value::Object(signatures)
    })
}

fn simple_branch_redeem() -> Vec<u8> {
    let mut redeem = vec![0x63, 0x20];
    redeem.extend_from_slice(&[0x11; 32]);
    redeem.extend_from_slice(&[0xad, 0x67, 0x20]);
    redeem.extend_from_slice(&[0x22; 32]);
    redeem.extend_from_slice(&[0xac, 0x68]);
    redeem
}

fn nested_owner_redeem() -> Vec<u8> {
    let mut redeem = vec![0x63, 0x20];
    redeem.extend_from_slice(&[0x11; 32]);
    redeem.extend_from_slice(&[0xad, 0x63, 0x51, 0x67, 0x00, 0x68, 0x67, 0x20]);
    redeem.extend_from_slice(&[0x22; 32]);
    redeem.extend_from_slice(&[0xac, 0x68]);
    redeem
}

fn expected_witness(prefix: &[u8], redeem: &[u8]) -> Vec<u8> {
    let mut result = prefix.to_vec();
    match redeem.len() {
        0..=75 => result.push(redeem.len() as u8),
        76..=255 => {
            result.push(0x4c);
            result.push(redeem.len() as u8);
        }
        _ => panic!("test redeem unexpectedly large"),
    }
    result.extend_from_slice(redeem);
    result
}

fn signature_push_with_selectors(before: &[u8], after: &[u8]) -> Vec<u8> {
    let mut result = before.to_vec();
    result.push(65);
    result.extend_from_slice(&[0x22; 64]);
    result.push(0x01);
    result.extend_from_slice(after);
    result
}

fn finalize_branch_input(
    covenant_branch: Option<&str>,
    locktime: u64,
    proprietaries: Option<serde_json::Value>,
    redeem: &[u8],
) -> Vec<u8> {
    use super::super::consensus::finalize_to_consensus;

    let mut global = serde_json::Map::new();
    global.insert("txVersion".into(), json!(0));
    global.insert("subnetworkId".into(), json!("00".repeat(20)));
    global.insert("fallbackLockTime".into(), json!(locktime));
    if let Some(branch) = covenant_branch {
        global.insert("covenantBranch".into(), json!(branch));
    }
    if let Some(proprietaries) = proprietaries {
        global.insert("proprietaries".into(), proprietaries);
    }
    let wire = encoded_pskb(json!({
        "global": serde_json::Value::Object(global),
        "inputs": [p2sh_covenant_input(redeem, 0x11)],
        "outputs": [plain_output(1)]
    }));
    finalize_to_consensus(&wire)
        .expect("branch-specific finalization")
        .inputs[0]
        .sig_script
        .clone()
}

#[test]
fn consensus_finalizer_emits_byte_exact_submission_wire() {
    use super::super::consensus::finalize_to_consensus;

    let mut input = p2pk_input();
    input["utxoEntry"]["amount"] = json!(41u64);
    input["proprietaries"] = json!({"persistentVault": true});
    let wire = encoded_pskb(json!({
        "global": {
            "txVersion": 1,
            "fallbackLockTime": 42,
            "gas": 7,
            "txPayload": "aabb"
        },
        "inputs": [input],
        "outputs": [plain_output(41)]
    }));

    let transaction = finalize_to_consensus(&wire)
        .expect("exact finalizer vector")
        .into_consensus_transaction();
    let encoded = crate::network::submission::encoder::encode_submit_request(&transaction, false)
        .expect("exact submit wire");

    assert_eq!(
        hex::encode(encoded),
        concat!(
            "01001401000001000100880000000100000080000000022500000001444444444444444444444444",
            "44444444444444444444444444444444444444440700000042000000412222222222222222222222",
            "22222222222222222222222222222222222222222222222222222222222222222222222222222222",
            "22222222222222222222222222010900000000000000000100000000140049000000010000004100",
            "00000229000000000000000000010000005101000000002800000001230000000100006caadbe5f2",
            "937e1d8f3578d6cd2f08f98cdfbbda03acc2e968d2d15c39e8fb432a000000000000000000000000",
            "000000000000000000000000000000070000000000000002000000aabb0000000000000000010000",
            "000000",
        )
    );
}

#[test]
fn consensus_finalizer_branch_settings_have_exact_witness_bytes() {
    let simple = simple_branch_redeem();
    let nested = nested_owner_redeem();

    let owner = finalize_branch_input(Some("owner"), 0, None, &simple);
    assert_eq!(
        owner,
        expected_witness(&signature_push_with_selectors(&[], &[0x51]), &simple)
    );

    let beneficiary = finalize_branch_input(Some("beneficiary"), 0, None, &simple);
    assert_eq!(
        beneficiary,
        expected_witness(&signature_push_with_selectors(&[], &[0x00]), &simple)
    );

    let amount_path = finalize_branch_input(Some("owner"), 0, None, &nested);
    assert_eq!(
        amount_path,
        expected_witness(&signature_push_with_selectors(&[0x51], &[0x51]), &nested)
    );

    let named_time_path = finalize_branch_input(Some("owner-time"), 0, None, &nested);
    assert_eq!(
        named_time_path,
        expected_witness(&signature_push_with_selectors(&[0x00], &[0x51]), &nested)
    );

    let locktime_path = finalize_branch_input(Some("owner"), 7, None, &nested);
    assert_eq!(
        locktime_path,
        expected_witness(&signature_push_with_selectors(&[0x00], &[0x51]), &nested)
    );

    let escrow = finalize_branch_input(
        Some("owner"),
        0,
        Some(json!({"escrowBranch": "seller-refund"})),
        &simple,
    );
    assert_eq!(
        escrow,
        expected_witness(&signature_push_with_selectors(&[], &[0x51, 0x00]), &simple)
    );
}

#[test]
fn persistent_vault_binding_is_applied_only_when_required_and_never_overwrites() {
    use super::super::consensus::finalize_to_consensus;

    let finalize = |input: serde_json::Value, output: serde_json::Value| {
        let wire = encoded_pskb(json!({
            "global": {"txVersion": 1},
            "inputs": [input],
            "outputs": [output]
        }));
        finalize_to_consensus(&wire).expect("persistent-vault finalization")
    };

    let plain = finalize(p2pk_input(), plain_output(41));
    assert_eq!(plain.outputs[0].covenant, None);

    let mut persistent_input = p2pk_input();
    persistent_input["proprietaries"] = json!({"persistentVault": true});
    let persistent = finalize(persistent_input.clone(), plain_output(41));
    let mut expected_persistent_id = [0u8; 32];
    expected_persistent_id.copy_from_slice(
        &hex::decode("6caadbe5f2937e1d8f3578d6cd2f08f98cdfbbda03acc2e968d2d15c39e8fb43").unwrap(),
    );
    assert_eq!(
        persistent.outputs[0].covenant,
        Some((0, expected_persistent_id))
    );

    let explicit = json!({
        "amount": 41,
        "scriptPublicKey": "000051",
        "covenantBinding": {
            "authorizingInput": 0,
            "covenantId": "ab".repeat(32)
        }
    });
    let persistent_with_explicit = finalize(persistent_input, explicit);
    assert_eq!(
        persistent_with_explicit.outputs[0].covenant,
        Some((0, [0xab; 32]))
    );
}

#[test]
fn persistent_vault_binding_handles_each_missing_first_input_or_output_shape() {
    use super::super::consensus::finalize_to_consensus;

    for document in [
        json!({
            "global": {"txVersion": 0, "subnetworkId": "00".repeat(20)},
            "inputs": [],
            "outputs": []
        }),
        json!({
            "global": {"txVersion": 0, "subnetworkId": "00".repeat(20)},
            "inputs": [p2pk_input()],
            "outputs": []
        }),
        json!({
            "global": {"txVersion": 0, "subnetworkId": "00".repeat(20)},
            "inputs": [],
            "outputs": [plain_output(5)]
        }),
    ] {
        let wire = encoded_pskb_unchecked(document);
        assert!(finalize_to_consensus(&wire).is_ok());
    }
}

#[test]
fn input_covenant_id_increases_kip9_storage_plurality() {
    use super::super::consensus::finalize_to_consensus;

    let output = json!({
        "amount": 100_000_000u64,
        "scriptPublicKey": format!("000020{}ac", "55".repeat(32))
    });

    let mut plain_input = p2pk_input();
    plain_input["utxoEntry"]["amount"] = json!(1_000_000_000u64);
    let plain_wire = encoded_pskb(json!({
        "global": {"txVersion": 0},
        "inputs": [plain_input],
        "outputs": [output.clone()]
    }));
    let plain = finalize_to_consensus(&plain_wire).expect("plain storage mass");
    assert_eq!(plain.storage_mass, 9_000);

    let mut covenant_input = p2pk_input();
    covenant_input["utxoEntry"]["amount"] = json!(1_000_000_000u64);
    covenant_input["utxoEntry"]["covenantId"] = json!("ab".repeat(32));
    let covenant_wire = encoded_pskb(json!({
        "global": {"txVersion": 0},
        "inputs": [covenant_input],
        "outputs": [output]
    }));
    let covenant = finalize_to_consensus(&covenant_wire).expect("covenant storage mass");
    assert_eq!(covenant.storage_mass, 6_000);
}

#[test]
fn finalized_transaction_commits_kip9_storage_mass_from_pskt_utxos() {
    use super::super::consensus::finalize_to_consensus;

    let mut input = p2pk_input();
    input["utxoEntry"]["amount"] = json!(1_000_000_000u64);
    let wire = encoded_pskb(json!({
        "global": {"txVersion": 0},
        "inputs": [input],
        "outputs": [
            {
                "amount": 100_000_000u64,
                "scriptPublicKey": format!("000020{}ac", "55".repeat(32))
            },
            {
                "amount": 899_600_000u64,
                "scriptPublicKey": format!("0000aa20{}87", "66".repeat(32))
            }
        ]
    }));

    let finalized = finalize_to_consensus(&wire).expect("storage-mass finalization");
    assert_eq!(finalized.storage_mass, 10_111);
    assert_eq!(finalized.into_consensus_transaction().storage_mass, 10_111);
}
