mod boundaries;
mod function_coverage;

use crate::account::utxo::UtxoEntry;

use super::pskb::{
    global_thread::{
        plan_global_thread_topup, plan_global_thread_withdrawal, GlobalThreadPlanError,
        GlobalThreadTopupRequest, GlobalThreadWithdrawalRequest,
    },
    GlobalThreadPolicy,
};

fn utxo(transaction_byte: u8, index: u32, amount: u64) -> UtxoEntry {
    UtxoEntry {
        tx_id: format!("{transaction_byte:02x}").repeat(32),
        index,
        amount,
        script_public_key: vec![0x20; 34],
        block_daa_score: 0,
        covenant_id: None,
    }
}

#[test]
fn explicit_selection_rejects_duplicate_indices() {
    let result =
        super::selection::select_explicit(vec![utxo(0x11, 0, 10), utxo(0x22, 1, 20)], &[0, 0]);
    assert!(result.is_err());
}

#[test]
fn automatic_selection_is_largest_first() {
    let selected = super::selection::select_automatic_with_limit(
        vec![utxo(0x11, 0, 10), utxo(0x22, 1, 30), utxo(0x33, 2, 20)],
        40,
        usize::MAX,
    )
    .expect("selection");
    assert_eq!(
        selected
            .iter()
            .map(|entry| entry.amount)
            .collect::<Vec<_>>(),
        vec![30, 20]
    );
}

#[test]
fn automatic_selection_limit_requires_an_explicit_power_user_override() {
    let utxos = vec![utxo(0x11, 0, 30), utxo(0x22, 1, 20), utxo(0x33, 2, 10)];
    let limited = super::selection::select_automatic_with_limit(utxos.clone(), 55, 2);
    assert!(limited
        .unwrap_err()
        .contains("Raise the Advanced UTXO limit"));

    let selected = super::selection::select_automatic_with_limit(utxos, 55, 3)
        .expect("power-user limit permits the required input count");
    assert_eq!(selected.len(), 3);
}

#[test]
fn change_calculation_absorbs_dust() {
    assert_eq!(
        super::planning::calculate_change(100_000_000, 98_999_999, 1),
        Ok(0),
    );
}

#[test]
fn change_calculation_preserves_non_dust_change() {
    assert_eq!(
        super::planning::calculate_change(100_000_000, 80_000_000, 1),
        Ok(19_999_999),
    );
}

#[test]
fn change_calculation_rejects_monetary_overflow_and_insufficient_selection() {
    assert_eq!(
        super::planning::calculate_change(u64::MAX, u64::MAX, 1).unwrap_err(),
        "Spend plus fee exceeds supported monetary range",
    );
    assert_eq!(
        super::planning::calculate_change(10, 11, 0).unwrap_err(),
        "Selected UTXOs: 10 sompi, need 11 sompi",
    );
}

fn decode_pskb_wire(wire: &str) -> serde_json::Value {
    let envelope = hex::decode(wire).expect("outer hex");
    assert_eq!(&envelope[..4], b"PSKB");
    let json_hex = core::str::from_utf8(&envelope[4..]).expect("JSON hex text");
    let json_bytes = hex::decode(json_hex).expect("JSON hex");
    serde_json::from_slice(&json_bytes).expect("PSKB JSON")
}

#[test]
fn typed_pskb_sweep_preserves_contract_metadata() {
    let inputs = vec![utxo(0x44, 7, 50_000)];
    let mut global = super::pskb::PskbGlobalPlan::standard()
        .with_lock_time(123)
        .with_branch("beneficiary");
    global.transaction_payload = Some(b"payload".to_vec());
    let policy = super::pskb::SweepInputPolicy::covenant(
        &[0x51, 0x75],
        9,
        serde_json::json!({"proof": "abcd"}),
    );
    let plan = super::pskb::plan_sweep(
        &inputs,
        &[0xaa, 0xbb],
        &[0xcc, 0xdd],
        49_000,
        global,
        &policy,
    );
    let document = decode_pskb_wire(&super::pskb::encode_wire(&plan).expect("encode"));
    let pskt = &document[0];

    assert_eq!(pskt["global"]["txVersion"], 0);
    assert_eq!(pskt["global"]["subnetworkId"], "00".repeat(20));
    assert_eq!(pskt["global"]["fallbackLockTime"], "123");
    assert_eq!(pskt["global"]["covenantBranch"], "beneficiary");
    assert_eq!(pskt["global"]["txPayload"], hex::encode(b"payload"));
    assert_eq!(pskt["inputs"][0]["sequence"], "9");
    assert_eq!(pskt["inputs"][0]["redeemScript"], "5175");
    assert_eq!(pskt["inputs"][0]["proprietaries"]["proof"], "abcd");
    assert_eq!(pskt["outputs"][0]["amount"], "49000");
    assert_eq!(pskt["outputs"][0]["scriptPublicKey"], "0000ccdd");
}

#[test]
fn pskb_output_binding_field_is_explicitly_configurable() {
    let plan = super::pskb::PskbPlan {
        global: super::pskb::PskbGlobalPlan::standard(),
        inputs: vec![super::pskb::PskbInputPlan::p2pk(
            utxo(0x55, 1, 10),
            &[0x20],
            serde_json::json!({}),
        )],
        outputs: vec![super::pskb::PskbOutputPlan::plain(9, &[0x21])
            .with_binding_field(serde_json::Value::Null)],
    };
    let document = decode_pskb_wire(&super::pskb::encode_wire(&plan).expect("encode"));
    assert!(document[0]["outputs"][0]
        .as_object()
        .expect("output object")
        .contains_key("covenantBinding"));
    assert!(document[0]["outputs"][0]["covenantBinding"].is_null());
}

#[test]
fn typed_sweep_matches_the_browser_pskb_shape() {
    let inputs = vec![utxo(0x66, 3, 42_000)];
    let global = super::pskb::PskbGlobalPlan::standard()
        .with_lock_time(77)
        .with_branch("savings");
    let policy = super::pskb::SweepInputPolicy::covenant(&[0x51, 0xac], 0, serde_json::json!([]));
    let typed = super::pskb::plan_sweep(
        &inputs,
        &[0xaa, 0xbb],
        &[0xcc, 0xdd],
        41_000,
        global,
        &policy,
    );

    let source = serde_json::json!({
        "global": {
            "txVersion": 0,
            "fallbackLockTime": 77,
            "covenantBranch": "savings",
            "inputsModifiableFlag": false,
            "outputsModifiableFlag": false,
            "inputCount": 1,
            "outputCount": 1,
            "bip32Derivations": [],
            "proprietaries": []
        },
        "inputs": [{
            "previousOutpoint": {
                "transactionId": inputs[0].tx_id,
                "index": inputs[0].index
            },
            "sequence": 0,
            "sigOpCount": 1,
            "utxoEntry": {
                "amount": inputs[0].amount,
                "scriptPublicKey": "0000aabb",
                "blockDaaScore": 0,
                "isCoinbase": false
            },
            "redeemScript": "51ac",
            "partialSigs": {},
            "minimumSignatures": 1,
            "bip32Derivations": [],
            "proprietaries": [],
            "finalScriptSig": serde_json::Value::Null,
            "minTime": 0
        }],
        "outputs": [{
            "amount": 41_000,
            "scriptPublicKey": "0000ccdd",
            "bip32Derivations": [],
            "proprietaries": []
        }]
    });

    assert_eq!(
        super::pskb::encode_wire(&typed).expect("typed wire"),
        super::pskb::encode_pskt_value(source).expect("source wire")
    );
}

#[test]
fn typed_p2pk_sweep_matches_the_stealth_pskb_shape() {
    let inputs = vec![utxo(0x77, 4, 60_000)];
    let policy =
        super::pskb::SweepInputPolicy::p2pk(serde_json::json!({ "stealthTweak": "aa".repeat(32) }));
    let typed = super::pskb::plan_sweep(
        &inputs,
        &[0x11, 0x22],
        &[0x33, 0x44],
        59_000,
        super::pskb::PskbGlobalPlan::standard(),
        &policy,
    );

    let source = serde_json::json!({
        "global": {
            "txVersion": 0,
            "fallbackLockTime": serde_json::Value::Null,
            "inputsModifiableFlag": false,
            "outputsModifiableFlag": false,
            "inputCount": 1,
            "outputCount": 1,
            "bip32Derivations": [],
            "proprietaries": []
        },
        "inputs": [{
            "previousOutpoint": {
                "transactionId": inputs[0].tx_id,
                "index": inputs[0].index
            },
            "sequence": 0,
            "sigOpCount": 1,
            "utxoEntry": {
                "amount": inputs[0].amount,
                "scriptPublicKey": "00001122",
                "blockDaaScore": 0,
                "isCoinbase": false
            },
            "redeemScript": serde_json::Value::Null,
            "partialSigs": {},
            "minimumSignatures": 1,
            "bip32Derivations": [],
            "proprietaries": { "stealthTweak": "aa".repeat(32) },
            "finalScriptSig": serde_json::Value::Null,
            "minTime": 0
        }],
        "outputs": [{
            "amount": 59_000,
            "scriptPublicKey": "00003344",
            "bip32Derivations": [],
            "proprietaries": []
        }]
    });

    assert_eq!(
        super::pskb::encode_wire(&typed).expect("typed wire"),
        super::pskb::encode_pskt_value(source).expect("source wire")
    );
}

#[test]
fn typed_keyless_covenant_preserves_zero_signature_requirement() {
    let mut policy = super::pskb::SweepInputPolicy::covenant(&[0x51], 0, serde_json::json!([]));
    policy.minimum_signatures = 0;
    let plan = super::pskb::plan_sweep(
        &[utxo(0x88, 0, 20_000)],
        &[0x55],
        &[0x66],
        19_000,
        super::pskb::PskbGlobalPlan::standard().with_lock_time(500),
        &policy,
    );
    let document = decode_pskb_wire(&super::pskb::encode_wire(&plan).expect("encode"));
    assert_eq!(document[0]["inputs"][0]["minimumSignatures"], 0);
    assert_eq!(document[0]["global"]["fallbackLockTime"], "500");
    assert!(document[0]["global"].get("covenantBranch").is_none());
}

#[test]
fn global_thread_allowance_withdrawal_matches_browser_wire_shape() {
    let thread = utxo(0x91, 2, 100_000_000);
    let covenant_id = [0x42; 32];
    let planned = plan_global_thread_withdrawal(GlobalThreadWithdrawalRequest {
        thread_utxos: std::slice::from_ref(&thread),
        covenant_script_public_key: &[0xaa, 0xbb],
        destination_script_public_key: &[0xcc, 0xdd],
        redeem_script: &[0x51, 0xac],
        covenant_id: &covenant_id,
        withdrawal: 20_000_000,
        fee: 1_000_000,
        csv_sequence: 9,
        policy: &GlobalThreadPolicy::allowance(123),
    })
    .expect("allowance plan");

    let source = serde_json::json!({
        "global": {
            "txVersion": 1,
            "fallbackLockTime": 123,
            "covenantBranch": "beneficiary",
            "inputsModifiableFlag": false,
            "outputsModifiableFlag": false,
            "inputCount": 1,
            "outputCount": 2,
            "bip32Derivations": [],
            "proprietaries": []
        },
        "inputs": [{
            "previousOutpoint": {
                "transactionId": thread.tx_id,
                "index": thread.index
            },
            "sequence": 9,
            "sigOpCount": 1,
            "utxoEntry": {
                "amount": thread.amount,
                "scriptPublicKey": "0000aabb",
                "blockDaaScore": 0,
                "isCoinbase": false
            },
            "redeemScript": "51ac",
            "partialSigs": {},
            "minimumSignatures": 1,
            "bip32Derivations": [],
            "proprietaries": [],
            "finalScriptSig": serde_json::Value::Null,
            "minTime": 0
        }],
        "outputs": [{
            "amount": 80_000_000,
            "scriptPublicKey": "0000aabb",
            "covenantBinding": {
                "authorizingInput": 0,
                "covenantId": hex::encode(covenant_id)
            },
            "bip32Derivations": [],
            "proprietaries": []
        }, {
            "amount": 19_000_000,
            "scriptPublicKey": "0000ccdd",
            "covenantBinding": serde_json::Value::Null,
            "bip32Derivations": [],
            "proprietaries": []
        }]
    });

    assert_eq!(
        super::pskb::encode_wire(&planned.plan).expect("typed wire"),
        super::pskb::encode_pskt_value(source).expect("source wire")
    );
}

#[test]
fn global_thread_spending_limit_close_keeps_explicit_null_policy_fields() {
    let planned = plan_global_thread_withdrawal(GlobalThreadWithdrawalRequest {
        thread_utxos: &[utxo(0x92, 0, 10_000_000)],
        covenant_script_public_key: &[0xaa],
        destination_script_public_key: &[0xbb],
        redeem_script: &[0x51],
        covenant_id: &[0x24; 32],
        withdrawal: 10_000_000,
        fee: 1_000_000,
        csv_sequence: 7,
        policy: &GlobalThreadPolicy::spending_limit(),
    })
    .expect("spending-limit close plan");
    let document = decode_pskb_wire(&super::pskb::encode_wire(&planned.plan).expect("wire"));

    assert_eq!(document[0]["global"]["fallbackLockTime"], "0");
    assert!(document[0]["global"]["covenantBranch"].is_null());
    assert_eq!(document[0]["outputs"].as_array().expect("outputs").len(), 1);
    assert!(document[0]["outputs"][0]["covenantBinding"].is_null());
}

#[test]
fn global_thread_topup_matches_mixed_input_shape() {
    let thread = utxo(0x93, 1, 50_000_000);
    let mut wallet_one = utxo(0x94, 2, 20_000_000);
    wallet_one.script_public_key = vec![0x11, 0x22];
    wallet_one.block_daa_score = 456;
    let mut wallet_two = utxo(0x95, 3, 30_000_000);
    wallet_two.script_public_key = vec![0x33, 0x44];
    wallet_two.block_daa_score = 789;
    let covenant_id = [0x66; 32];

    let planned = plan_global_thread_topup(GlobalThreadTopupRequest {
        thread_utxo: thread.clone(),
        wallet_utxos: &[wallet_one.clone(), wallet_two.clone()],
        covenant_script_public_key: &[0xaa, 0xbb],
        redeem_script: &[0x51, 0xac],
        covenant_id: &covenant_id,
        fee: 1_000_000,
        policy: &GlobalThreadPolicy::spending_limit_topup(11),
    })
    .expect("topup plan");

    let source = serde_json::json!({
        "global": {
            "txVersion": 1,
            "fallbackLockTime": 0,
            "covenantBranch": serde_json::Value::Null,
            "inputsModifiableFlag": false,
            "outputsModifiableFlag": false,
            "inputCount": 3,
            "outputCount": 1,
            "bip32Derivations": [],
            "proprietaries": []
        },
        "inputs": [{
            "previousOutpoint": { "transactionId": thread.tx_id, "index": thread.index },
            "sequence": 11,
            "sigOpCount": 1,
            "utxoEntry": {
                "amount": thread.amount,
                "scriptPublicKey": "0000aabb",
                "blockDaaScore": 0,
                "isCoinbase": false
            },
            "redeemScript": "51ac",
            "partialSigs": {},
            "minimumSignatures": 1,
            "bip32Derivations": [],
            "proprietaries": [],
            "finalScriptSig": serde_json::Value::Null,
            "minTime": 0
        }, {
            "previousOutpoint": { "transactionId": wallet_one.tx_id, "index": wallet_one.index },
            "sequence": 0,
            "sigOpCount": 1,
            "utxoEntry": {
                "amount": wallet_one.amount,
                "scriptPublicKey": "00001122",
                "blockDaaScore": wallet_one.block_daa_score,
                "isCoinbase": false
            },
            "redeemScript": serde_json::Value::Null,
            "partialSigs": {},
            "minimumSignatures": 1,
            "bip32Derivations": [],
            "proprietaries": [],
            "finalScriptSig": serde_json::Value::Null,
            "minTime": 0
        }, {
            "previousOutpoint": { "transactionId": wallet_two.tx_id, "index": wallet_two.index },
            "sequence": 0,
            "sigOpCount": 1,
            "utxoEntry": {
                "amount": wallet_two.amount,
                "scriptPublicKey": "00003344",
                "blockDaaScore": wallet_two.block_daa_score,
                "isCoinbase": false
            },
            "redeemScript": serde_json::Value::Null,
            "partialSigs": {},
            "minimumSignatures": 1,
            "bip32Derivations": [],
            "proprietaries": [],
            "finalScriptSig": serde_json::Value::Null,
            "minTime": 0
        }],
        "outputs": [{
            "amount": 99_000_000,
            "scriptPublicKey": "0000aabb",
            "covenantBinding": {
                "authorizingInput": 0,
                "covenantId": hex::encode(covenant_id)
            },
            "bip32Derivations": [],
            "proprietaries": []
        }]
    });

    assert_eq!(
        super::pskb::encode_wire(&planned.plan).expect("typed wire"),
        super::pskb::encode_pskt_value(source).expect("source wire")
    );
}

#[test]
fn multisig_planning_covers_automatic_explicit_empty_and_dust_change_paths() {
    use super::multisig::{
        encode_from_utxos, MultisigSelection, MultisigTransactionRequest, PreparedMultisig,
    };

    let prepared = PreparedMultisig {
        redeem_script: vec![0x51, 0xae],
        sig_op_count: 1,
        minimum_signatures: 1,
        destination_script: vec![0x20, 0x01, 0xac],
        change_script: vec![0x20, 0x02, 0xac],
        source_derivations: serde_json::json!({}),
        change_derivations: serde_json::json!({}),
        source_path: crate::multisig::ResolvedMultisigPath {
            index: 0,
            cosigner: 0,
            chain: 0,
        },
    };
    let request = |selection| MultisigTransactionRequest {
        descriptor_text: "",
        source_address: "",
        destination_address: "",
        amount: 100_000,
        fee: 1_000,
        change_address: "",
        websocket_url: "",
        requested_index: 0,
        change_index_hint: u32::MAX,
        selection,
    };

    // The Toccata fee floor grows with the fully signed input count. Keep the
    // automatic fixture large enough that one input is insufficient while two
    // inputs cover amount + the two-input standard fee.
    let automatic = encode_from_utxos(
        &request(MultisigSelection::Automatic),
        &prepared,
        vec![utxo(1, 0, 200_000), utxo(2, 1, 200_000)],
    )
    .expect("automatic multisig selection");
    assert_eq!(
        decode_pskb_wire(&automatic)[0]["inputs"]
            .as_array()
            .expect("automatic inputs")
            .len(),
        2,
    );

    // Explicit indexes are resolved after descending display-order sorting.
    // A single 250k-sompi input covers the 100k spend plus the one-input
    // Toccata standard fee for this synthetic 1-of-1 fixture.
    let explicit_indices = [0usize];
    let explicit = encode_from_utxos(
        &request(MultisigSelection::Explicit(&explicit_indices)),
        &prepared,
        vec![utxo(1, 0, 50_000), utxo(2, 1, 250_000)],
    )
    .expect("explicit multisig selection");
    assert_eq!(
        decode_pskb_wire(&explicit)[0]["inputs"]
            .as_array()
            .expect("explicit inputs")
            .len(),
        1,
    );

    assert!(encode_from_utxos(
        &request(MultisigSelection::Automatic),
        &prepared,
        Vec::new(),
    )
    .unwrap_err()
    .contains("No UTXOs"));

    let duplicate = [0usize, 0usize];
    assert!(encode_from_utxos(
        &request(MultisigSelection::Explicit(&duplicate)),
        &prepared,
        vec![utxo(1, 0, 200_000)],
    )
    .is_err());
}

#[test]
fn multisig_request_preparation_covers_validation_and_source_ownership() {
    use super::multisig::{
        prepare_request, validate_amounts, verify_source_address, MultisigSelection,
        MultisigTransactionRequest,
    };
    use crate::multisig::{build_redeem_script, MultisigDescriptor};

    let descriptor_text = format!("multi(1,{}, {})", "11".repeat(32), "22".repeat(32),);
    let descriptor = MultisigDescriptor::parse(&descriptor_text).expect("descriptor");
    let public_keys = descriptor.public_keys_at(0, 0, 0).expect("public keys");
    let redeem_script =
        build_redeem_script(descriptor.threshold(), &public_keys).expect("redeem script");
    let source_address = crate::protocol::script::p2sh::script_to_address(&redeem_script, "kaspa")
        .expect("source address");
    let destination_address = crate::account::address::encode_p2pk_address(&[0x33; 32], "kaspa");

    fn request<'a>(
        descriptor_text: &'a str,
        source_address: &'a str,
        destination_address: &'a str,
        amount: u64,
        change_address: &'a str,
    ) -> MultisigTransactionRequest<'a> {
        MultisigTransactionRequest {
            descriptor_text,
            source_address,
            destination_address,
            amount,
            fee: 1_000,
            change_address,
            websocket_url: "ws://unused.invalid",
            requested_index: 0,
            change_index_hint: u32::MAX,
            selection: MultisigSelection::Automatic,
        }
    }

    let valid = request(
        &descriptor_text,
        &source_address,
        &destination_address,
        20_000_000,
        &source_address,
    );
    assert!(validate_amounts(&valid).is_ok());
    let prepared = prepare_request(&valid).expect("prepared multisig request");
    assert_eq!(prepared.redeem_script, redeem_script);
    assert_eq!(prepared.sig_op_count, 2);
    assert_eq!(
        prepared.destination_script,
        crate::account::address::address_to_script_pubkey(&destination_address)
            .expect("destination script"),
    );

    assert!(matches!(
        prepare_request(&request(
            &descriptor_text,
            &source_address,
            &destination_address,
            20_000_000,
            &destination_address,
        )),
        Err(error) if error.contains("change address")
    ));
    assert!(matches!(
        validate_amounts(&request(
            &descriptor_text,
            &source_address,
            &destination_address,
            0,
            &source_address,
        )),
        Err(error) if error.contains("recipient amount")
    ));
    assert!(matches!(
        validate_amounts(&request(
            &descriptor_text,
            &source_address,
            &destination_address,
            1,
            &source_address,
        )),
        Err(error) if error.contains("recipient amount")
    ));

    assert!(verify_source_address(&source_address, &redeem_script).is_ok());
    let unrelated_script =
        build_redeem_script(1, &[[0x44; 32], [0x55; 32]]).expect("unrelated script");
    assert!(matches!(
        verify_source_address(&source_address, &unrelated_script),
        Err(error) if error.contains("does not control")
    ));
}

fn watch_wallet() -> crate::account::bip32::WalletData {
    let receive = crate::account::address::encode_p2pk_address(&[0x81; 32], "kaspa");
    let change = crate::account::address::encode_p2pk_address(&[0x82; 32], "kaspa");
    crate::account::bip32::WalletData {
        kpub: "test-only".to_string(),
        receive_addresses: vec![receive],
        change_addresses: vec![change],
        next_receive_index: 0,
        next_change_index: 0,
    }
}

#[test]
fn storage_mass_estimation_covers_relaxed_arithmetic_and_zero_amounts() {
    use super::planning::amounts::storage_mass_estimate;

    assert_eq!(
        storage_mass_estimate(&[(10_000_000, 1)], &[(10_000_000, 1)]).unwrap(),
        0
    );
    assert!(
        storage_mass_estimate(
            &[(50_000_000, 1), (25_000_000, 1), (25_000_000, 1)],
            &[(20_000_000, 1), (30_000_000, 1), (50_000_000, 1)],
        )
        .unwrap()
            > 0
    );
    assert_eq!(storage_mass_estimate(&[(0, 1)], &[(0, 1)]).unwrap(), 0);
    assert_eq!(storage_mass_estimate(&[], &[]).unwrap(), 0);
    assert!(storage_mass_estimate(&[], &[(1, u64::MAX)]).is_err());
    assert!(storage_mass_estimate(&[(u64::MAX, 3), (1, 3), (1, 3)], &[(1, 3)]).is_err());
}

#[test]
fn standard_payment_planning_covers_change_exact_spend_and_address_exhaustion() {
    use super::{model::PlannedOutput, planning::plan_payment};

    let wallet = watch_wallet();
    let destination_script = vec![0x20; 34];
    let with_change = plan_payment(
        &wallet,
        vec![utxo(0x91, 0, 50_000_000)],
        vec![PlannedOutput::new(20_000_000, destination_script.clone())],
        1_000_000,
    )
    .expect("payment with change");
    assert_eq!(with_change.outputs.len(), 2);
    assert_eq!(with_change.outputs[0].amount, 20_000_000);
    assert_eq!(with_change.outputs[1].amount, 29_000_000);
    assert_eq!(with_change.outputs[1].derivation_hint, Some((1, 0)));

    let exact = plan_payment(
        &wallet,
        vec![utxo(0x92, 0, 21_000_000)],
        vec![PlannedOutput::new(20_000_000, destination_script.clone())],
        1_000_000,
    )
    .expect("exact payment");
    assert_eq!(exact.outputs.len(), 1);

    let mut exhausted = wallet.clone();
    exhausted.change_addresses.clear();
    assert!(plan_payment(
        &exhausted,
        vec![utxo(0x93, 0, 50_000_000)],
        vec![PlannedOutput::new(20_000_000, destination_script)],
        1_000_000,
    )
    .unwrap_err()
    .contains("No more change addresses"));
}

#[test]
fn explicit_change_planning_preserves_privacy_input_derivation_hints() {
    use super::{model::PlannedOutput, planning::plan_payment_with_change_and_derivations};

    let wallet = watch_wallet();
    let plan = plan_payment_with_change_and_derivations(
        vec![(utxo(0x95, 0, 50_000_000), Some((0, 500)))],
        vec![PlannedOutput::new(20_000_000, vec![0x20; 34])],
        1_000_000,
        &wallet.change_addresses[0],
        700,
    )
    .expect("privacy-hinted payment");
    assert_eq!(plan.inputs[0].derivation_hint, Some((0, 500)));
    assert_eq!(plan.outputs[1].derivation_hint, Some((1, 700)));
}

#[test]
fn consolidation_planning_covers_success_and_balance_failures() {
    use super::planning::plan_consolidation;

    let wallet = watch_wallet();
    let plan = plan_consolidation(
        &wallet,
        vec![utxo(0xa1, 0, 30_000_000), utxo(0xa2, 1, 20_000_000)],
        1_000_000,
    )
    .expect("consolidation plan");
    assert_eq!(plan.outputs.len(), 1);
    assert_eq!(plan.outputs[0].amount, 49_000_000);
    assert_eq!(plan.outputs[0].derivation_hint, Some((0, 0)));

    assert!(
        plan_consolidation(&wallet, vec![utxo(0xa3, 0, 1_000_000)], 1_000_000,)
            .unwrap_err()
            .contains("Balance too low")
    );

    let mut no_receive = wallet;
    no_receive.receive_addresses.clear();
    assert!(
        plan_consolidation(&no_receive, vec![utxo(0xa4, 0, 2_000_000)], 1_000_000,)
            .unwrap_err()
            .contains("Wallet has no receive address")
    );
}

#[test]
fn standard_send_preparation_and_utxo_paths_are_host_testable() {
    use super::standard::{
        create_consolidation_from_utxos, create_send_from_utxos, create_send_selected_from_utxos,
        prepare_send, storage_mass_fee, validate_recipient_amount,
    };

    let wallet = watch_wallet();
    let destination = crate::account::address::encode_p2pk_address(&[0x83; 32], "kaspa");

    assert!(validate_recipient_amount(0)
        .unwrap_err()
        .contains("must be > 0"));
    assert!(validate_recipient_amount(1)
        .unwrap_err()
        .contains("too small"));
    assert!(prepare_send("not-an-address", 20_000_000, 1_000_000).is_err());

    let prepared = prepare_send(&destination, 20_000_000, 1_000_000).expect("prepared send");
    let automatic = create_send_from_utxos(
        &wallet,
        &prepared,
        vec![utxo(0xb1, 0, 10_000_000), utxo(0xb2, 1, 40_000_000)],
    )
    .expect("automatic send");
    let automatic_doc = decode_pskb_wire(&automatic);
    assert_eq!(automatic_doc[0]["inputs"].as_array().unwrap().len(), 1);
    assert_eq!(automatic_doc[0]["outputs"].as_array().unwrap().len(), 2);

    let selected = create_send_selected_from_utxos(
        &wallet,
        &prepared,
        &[0, 1],
        vec![utxo(0xb3, 0, 12_000_000), utxo(0xb4, 1, 12_000_000)],
    )
    .expect("selected send");
    assert_eq!(
        decode_pskb_wire(&selected)[0]["inputs"]
            .as_array()
            .unwrap()
            .len(),
        2,
    );
    assert!(create_send_selected_from_utxos(
        &wallet,
        &prepared,
        &[0, 0],
        vec![utxo(0xb5, 0, 25_000_000)],
    )
    .is_err());

    let consolidation = create_consolidation_from_utxos(
        &wallet,
        1_000_000,
        vec![utxo(0xb6, 0, 30_000_000), utxo(0xb7, 1, 20_000_000)],
    )
    .expect("consolidation wire");
    assert_eq!(
        decode_pskb_wire(&consolidation)[0]["inputs"]
            .as_array()
            .unwrap()
            .len(),
        2,
    );
    assert!(
        create_consolidation_from_utxos(&wallet, 1_000_000, vec![utxo(0xb8, 0, 30_000_000)],)
            .is_err()
    );

    let fee = storage_mass_fee(
        &[utxo(0xb9, 0, 50_000_000)],
        50_000_000,
        20_000_000,
        500_000,
    )
    .expect("storage fee");
    assert!(fee >= 500_000);
    assert!(storage_mass_fee(&[utxo(0xba, 0, u64::MAX)], u64::MAX, u64::MAX, 0,).is_err());
}

#[test]
fn limited_send_api_is_host_covered_before_network_io() {
    use super::standard::{create_limited_send_from_utxos, prepare_send};
    use crate::wasm_api::test_support::ready;

    let wallet = watch_wallet();
    let result = ready(super::standard::create_send_limited(
        &wallet,
        "not-an-address",
        20_000_000,
        300_000,
        8,
        "ws://unused",
    ));
    assert!(result.is_err());

    let destination = crate::account::address::encode_p2pk_address(&[0x84; 32], "kaspa");
    let prepared = prepare_send(&destination, 20_000_000, 300_000).expect("prepared limited send");
    let wire = create_limited_send_from_utxos(
        &wallet,
        &prepared,
        vec![utxo(0xbd, 0, 30_000_000), utxo(0xbe, 1, 10_000_000)],
        2,
    )
    .expect("limited send from supplied utxos");
    assert!(!wire.is_empty());
    assert!(create_limited_send_from_utxos(
        &wallet,
        &prepared,
        vec![utxo(0xbf, 0, 10_000_000), utxo(0xc0, 1, 11_000_000)],
        1,
    )
    .is_err());

    #[cfg(not(target_arch = "wasm32"))]
    assert!(ready(super::standard::create_consolidation(
        &wallet,
        300_000,
        "ws://unused"
    ))
    .expect_err("native consolidation transport")
    .contains("unavailable on native hosts"));

    assert!(super::selection::select_automatic_with_limit(
        vec![utxo(0xbc, 0, 50_000_000)],
        20_000_000,
        0,
    )
    .unwrap_err()
    .contains("at least 1"));
}

#[test]
fn explicit_pskb_creation_covers_empty_inputs_and_success() {
    let wallet = watch_wallet();
    let destination = crate::account::address::encode_p2pk_address(&[0x84; 32], "kaspa");

    assert!(super::standard::create_pskb_with_utxos(
        &wallet,
        &destination,
        20_000_000,
        300_000,
        Vec::new(),
    )
    .unwrap_err()
    .contains("No UTXOs"));

    let wire = super::standard::create_pskb_with_utxos(
        &wallet,
        &destination,
        20_000_000,
        300_000,
        vec![utxo(0xbb, 0, 50_000_000)],
    )
    .expect("explicit PSKB");
    assert_eq!(
        decode_pskb_wire(&wire)[0]["inputs"]
            .as_array()
            .unwrap()
            .len(),
        1
    );

    let explicit_change = super::standard::create_pskb_with_utxos_and_change(
        &destination,
        20_000_000,
        300_000,
        vec![utxo(0xbc, 1, 50_000_000)],
        &wallet.change_addresses[0],
        7,
    )
    .expect("explicit-change PSKB");
    let decoded = decode_pskb_wire(&explicit_change);
    let outputs = decoded[0]["outputs"].as_array().expect("outputs");
    assert_eq!(outputs.len(), 2);
    assert_eq!(
        outputs[1]["proprietaries"]["kassignerDerivation"]["branch"],
        1
    );
    assert_eq!(
        outputs[1]["proprietaries"]["kassignerDerivation"]["index"],
        "7"
    );
}

#[test]
fn global_thread_plan_errors_have_specific_actionable_messages() {
    let cases = [
        GlobalThreadPlanError::BalanceTooLow { total: 1, fee: 2 },
        GlobalThreadPlanError::WithdrawalNotAboveFee {
            withdrawal: 2,
            fee: 2,
        },
        GlobalThreadPlanError::ContinuationTooSmall { continuation: 3 },
        GlobalThreadPlanError::SelectedFundsTooLow {
            selected_total: 4,
            fee: 5,
        },
    ];
    for error in cases {
        let message = error.to_string();
        assert!(!message.is_empty());
        assert!(message.contains(|character: char| character.is_ascii_digit()));
    }
}

#[test]
fn storage_mass_estimation_distinguishes_each_relaxed_plurality_gate() {
    use super::planning::amounts::storage_mass_estimate;

    // outputs plurality == 1 is independently sufficient for the relaxed formula.
    assert_eq!(
        storage_mass_estimate(&[(100_000_000, 3)], &[(10_000_000, 1)]).unwrap(),
        10_000,
    );
    // inputs plurality == 1 is independently sufficient.
    assert_eq!(
        storage_mass_estimate(&[(100_000_000, 1)], &[(10_000_000, 3)]).unwrap(),
        890_000,
    );
    // The 2-in/2-out special case is relaxed even though neither side is singular.
    assert_eq!(
        storage_mass_estimate(&[(100_000_000, 2)], &[(10_000_000, 2)]).unwrap(),
        360_000,
    );
    // 3-in/3-out uses the arithmetic-input branch.
    assert_eq!(
        storage_mass_estimate(&[(100_000_000, 3)], &[(10_000_000, 3)]).unwrap(),
        810_000,
    );
}

#[test]
fn global_thread_withdrawal_enforces_fee_close_and_continuation_boundaries_exactly() {
    use super::pskb::global_thread::MIN_THREAD_CONTINUATION_SOMPI;

    let covenant_script = [0xaa, 0xbb];
    let destination_script = [0xcc, 0xdd];
    let redeem_script = [0x51, 0xac];
    let covenant_id = [0x42; 32];
    let policy = GlobalThreadPolicy::allowance(0);

    let plan = |total: u64, withdrawal: u64, fee: u64| {
        let thread = [utxo(0xa1, 0, total)];
        plan_global_thread_withdrawal(GlobalThreadWithdrawalRequest {
            thread_utxos: &thread,
            covenant_script_public_key: &covenant_script,
            destination_script_public_key: &destination_script,
            redeem_script: &redeem_script,
            covenant_id: &covenant_id,
            withdrawal,
            fee,
            csv_sequence: 5,
            policy: &policy,
        })
    };

    assert!(matches!(
        plan(1_000_000, 2_000_000, 1_000_000),
        Err(GlobalThreadPlanError::BalanceTooLow {
            total: 1_000_000,
            fee: 1_000_000
        })
    ));
    assert!(matches!(
        plan(2_000_000, 1_000_000, 1_000_000),
        Err(GlobalThreadPlanError::WithdrawalNotAboveFee {
            withdrawal: 1_000_000,
            fee: 1_000_000
        })
    ));

    let exact_floor_total = 50_000_000;
    let exact_floor_withdrawal = exact_floor_total - MIN_THREAD_CONTINUATION_SOMPI;
    let exact_floor = plan(exact_floor_total, exact_floor_withdrawal, 1_000_000)
        .expect("exact continuation floor is valid");
    assert!(!exact_floor.is_close);
    assert_eq!(exact_floor.continuation, MIN_THREAD_CONTINUATION_SOMPI);
    assert_eq!(
        exact_floor.user_receives,
        exact_floor_withdrawal - 1_000_000
    );
    assert_eq!(
        exact_floor.plan.global.fallback_lock_time,
        serde_json::Value::Null
    );

    assert!(matches!(
        plan(exact_floor_total, exact_floor_withdrawal + 1, 1_000_000),
        Err(GlobalThreadPlanError::ContinuationTooSmall { continuation })
            if continuation == MIN_THREAD_CONTINUATION_SOMPI - 1
    ));

    let close = plan(25_000_000, 25_000_000, 1_000_000).expect("exact close");
    assert!(close.is_close);
    assert_eq!(close.continuation, 0);
    assert_eq!(close.user_receives, 24_000_000);
    assert_eq!(close.plan.outputs.len(), 1);
}

#[test]
fn global_thread_planning_reports_monetary_overflow_instead_of_panicking() {
    let covenant_script = [0xaa, 0xbb];
    let destination_script = [0xcc, 0xdd];
    let redeem_script = [0x51, 0xac];
    let covenant_id = [0x42; 32];
    let policy = GlobalThreadPolicy::allowance(0);
    let overflowing = [utxo(0xe1, 0, u64::MAX), utxo(0xe2, 1, 1)];

    assert!(matches!(
        plan_global_thread_withdrawal(GlobalThreadWithdrawalRequest {
            thread_utxos: &overflowing,
            covenant_script_public_key: &covenant_script,
            destination_script_public_key: &destination_script,
            redeem_script: &redeem_script,
            covenant_id: &covenant_id,
            withdrawal: 1,
            fee: 1,
            csv_sequence: 0,
            policy: &policy,
        }),
        Err(GlobalThreadPlanError::ArithmeticOverflow {
            operation: "summing thread UTXOs"
        })
    ));

    assert!(matches!(
        plan_global_thread_topup(GlobalThreadTopupRequest {
            thread_utxo: utxo(0xe3, 0, 1),
            wallet_utxos: &overflowing,
            covenant_script_public_key: &covenant_script,
            redeem_script: &redeem_script,
            covenant_id: &covenant_id,
            fee: 1,
            policy: &policy,
        }),
        Err(GlobalThreadPlanError::ArithmeticOverflow {
            operation: "summing wallet top-up UTXOs"
        })
    ));

    let max_wallet = [utxo(0xe4, 0, u64::MAX)];
    assert!(matches!(
        plan_global_thread_topup(GlobalThreadTopupRequest {
            thread_utxo: utxo(0xe5, 0, 1),
            wallet_utxos: &max_wallet,
            covenant_script_public_key: &covenant_script,
            redeem_script: &redeem_script,
            covenant_id: &covenant_id,
            fee: 1,
            policy: &policy,
        }),
        Err(GlobalThreadPlanError::ArithmeticOverflow {
            operation: "adding thread and wallet balances"
        })
    ));
}

#[test]
fn amount_planning_boundaries_are_exact() {
    use super::planning::amounts::{is_dust, storage_mass_estimate};

    assert!(is_dust(0));
    assert!(is_dust(9_999_900));
    assert!(!is_dust(9_999_901));
    assert!(!is_dust(10_000_000));
    assert!(!is_dust(19_999_999));
    assert!(!is_dust(20_000_000));

    assert_eq!(
        storage_mass_estimate(&[(100_000_000, 2)], &[(10_000_000, 1)]).unwrap(),
        60_000
    );
    assert_eq!(
        storage_mass_estimate(&[(100_000_000, 1)], &[(10_000_000, 2)]).unwrap(),
        390_000
    );
    assert_eq!(
        storage_mass_estimate(&[(100_000_000, 2)], &[(10_000_000, 2)]).unwrap(),
        360_000
    );
    assert_eq!(
        storage_mass_estimate(&[(100_000_000, 2)], &[(10_000_000, 3)]).unwrap(),
        860_000
    );
    assert_eq!(
        storage_mass_estimate(&[(100_000_000, 3)], &[(10_000_000, 2)]).unwrap(),
        310_000
    );
}
