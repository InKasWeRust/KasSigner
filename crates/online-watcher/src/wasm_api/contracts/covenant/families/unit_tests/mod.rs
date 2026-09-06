use serde_json::{json, Value};

use super::{
    dms::build_dms_json,
    escrow::{build_escrow_json, build_shipping_escrow_json, build_timelocked_escrow_json},
    oracle_v1::build_oracle_v1_json,
    private_swap::{covenant_private_swap, private_swap_key_request},
    savings::build_timelocked_savings_json,
};

fn address(byte: u8, prefix: &str) -> String {
    crate::account::address::encode_p2pk_address(&[byte; 32], prefix)
}

fn key(byte: u8) -> String {
    format!("{byte:02x}").repeat(32)
}

fn parse(document: String) -> Value {
    serde_json::from_str(&document).expect("valid builder JSON")
}

#[test]
fn dms_savings_and_timelocked_escrow_builders_validate_keys_and_addresses() {
    let dms = parse(build_dms_json(&key(4), &key(5), 100, "simnet").unwrap());
    assert_eq!(dms["inactivity_daa"], "100");
    assert!(dms["address"].as_str().unwrap().starts_with("kaspasim:"));
    assert!(build_dms_json("00", &key(5), 1, "mainnet").is_err());

    let savings = parse(build_timelocked_savings_json(&key(6), &key(7), 200, "devnet").unwrap());
    assert_eq!(savings["locktime_daa"], "200");
    assert!(savings["address"]
        .as_str()
        .unwrap()
        .starts_with("kaspadev:"));
    assert!(build_timelocked_savings_json(&key(6), "zz", 0, "mainnet").is_err());

    let escrow = parse(
        build_timelocked_escrow_json(
            &key(8),
            &key(9),
            &address(8, "kaspa"),
            &address(9, "kaspa"),
            300,
            "mainnet",
        )
        .unwrap(),
    );
    assert_eq!(escrow["locktime_daa"], "300");
    assert!(build_timelocked_escrow_json(
        &key(8),
        &key(9),
        "not-an-address",
        &address(9, "kaspa"),
        0,
        "mainnet",
    )
    .is_err());
}

#[test]
fn escrow_builder_binds_deterministic_salt() {
    let escrow = parse(
        build_escrow_json(
            &key(10),
            &key(11),
            &key(12),
            &address(10, "kaspa"),
            &address(11, "kaspa"),
            "mainnet",
            [0x44; 8],
        )
        .unwrap(),
    );
    assert_eq!(escrow["salt"], "44".repeat(8));
    assert!(build_escrow_json(
        &key(10),
        &key(11),
        &key(12),
        "bad",
        &address(11, "kaspa"),
        "mainnet",
        [0; 8],
    )
    .is_err());
}

fn shipping_request(product: &str, fee: &str) -> String {
    json!({
        "seller_pubkey_hex": key(20),
        "deliverer_pubkey_hex": key(21),
        "buyer_pubkey_hex": key(22),
        "arbiter_pubkey_hex": key(23),
        "product_sompi": product,
        "fee_sompi": fee,
        "cltv1_deadline": "100",
        "cltv2_deadline": "200",
        "network": "testnet-12"
    })
    .to_string()
}

#[test]
fn shipping_escrow_builder_covers_amount_partitioning_and_invalid_requests() {
    let document =
        parse(build_shipping_escrow_json(&shipping_request("101", "9"), [0x66; 8]).unwrap());
    assert_eq!(document["t1_sompi"], "50");
    assert_eq!(document["t2_sompi"], "51");
    assert_eq!(document["total_sompi"], "110");
    assert_eq!(document["rem_sompi"], "60");
    assert_eq!(document["salt"], "66".repeat(8));

    assert!(build_shipping_escrow_json("{}", [0; 8]).is_err());
    assert!(build_shipping_escrow_json(&shipping_request("bad", "1"), [0; 8]).is_err());
    assert!(
        build_shipping_escrow_json(&shipping_request(&u64::MAX.to_string(), "1"), [0; 8],).is_err()
    );

    let key = [0x44; 32];
    assert!(
        crate::contracts::shipping_escrow::script::build_ship_escrow_script(
            crate::contracts::shipping_escrow::script::ShippingEscrowScriptRequest {
                seller_pubkey: &key,
                deliverer_pubkey: &key,
                buyer_pubkey: &key,
                arbiter_pubkey: &key,
                product_sompi: u64::MAX,
                fee_sompi: 1,
                cltv1_deadline: 100,
                cltv2_deadline: 200,
                salt: &[0; 8],
            },
        )
        .is_err()
    );

    let mut bad_key: Value = serde_json::from_str(&shipping_request("1", "1")).unwrap();
    bad_key["seller_pubkey_hex"] = json!("00");
    assert!(build_shipping_escrow_json(&bad_key.to_string(), [0; 8]).is_err());
}

fn utxo(byte: u8, amount: u64) -> crate::account::utxo::UtxoEntry {
    crate::account::utxo::UtxoEntry {
        tx_id: format!("{byte:02x}").repeat(32),
        index: u32::from(byte),
        amount,
        script_public_key: vec![0x51],
        block_daa_score: 0,
        covenant_id: None,
    }
}

#[test]
fn allowance_withdrawal_builder_covers_success_balance_and_storage_errors() {
    use super::allowance::build_allowance_withdrawal;

    let owner = [0x31; 32];
    let beneficiary = [0x32; 32];
    let redeem = crate::contracts::covenant::script::build_allowance_script(
        &owner,
        &beneficiary,
        50_000_000,
        12,
        0,
    );
    let covenant = crate::protocol::script::p2sh::script_to_address(&redeem, "kaspa").unwrap();
    let destination = address(0x33, "kaspa");
    let utxos = [utxo(1, 60_000_000), utxo(2, 60_000_000)];

    let withdrawal = build_allowance_withdrawal(
        &covenant,
        &destination,
        &hex::encode(&redeem),
        40_000_000,
        1_000_000,
        &utxos,
    )
    .unwrap();
    assert_eq!(withdrawal.input_count, 2);
    assert_eq!(withdrawal.total_balance, 120_000_000);
    assert_eq!(withdrawal.return_amount, 79_000_000);
    assert_eq!(withdrawal.sequence, 12);
    assert!(!withdrawal.wire.is_empty());
    super::allowance::log_withdrawal(&withdrawal, 40_000_000, 1_000_000);
    let finalized =
        super::allowance::finalize_withdrawal_result(Ok(withdrawal), 40_000_000, 1_000_000)
            .expect("finalize allowance withdrawal");
    assert!(!finalized.is_empty());
    assert!(super::allowance::finalize_withdrawal_result(
        Err("transport failed".to_string()),
        40_000_000,
        1_000_000,
    )
    .is_err());

    assert!(
        build_allowance_withdrawal(&covenant, &destination, &hex::encode(&redeem), 1, 1, &[],)
            .is_err()
    );
    assert!(build_allowance_withdrawal(
        &covenant,
        &destination,
        &hex::encode(&redeem),
        121_000_000,
        0,
        &utxos,
    )
    .is_err());
    assert!(build_allowance_withdrawal(
        &covenant,
        &destination,
        &hex::encode(&redeem),
        110_000_001,
        0,
        &utxos,
    )
    .is_err());
    assert!(build_allowance_withdrawal(&covenant, &destination, "zz", 1, 0, &utxos,).is_err());
    assert!(build_allowance_withdrawal(
        "bad-address",
        &destination,
        &hex::encode(&redeem),
        1,
        0,
        &utxos,
    )
    .is_err());
    assert!(build_allowance_withdrawal(
        &covenant,
        &destination,
        &hex::encode(&redeem),
        u64::MAX,
        1,
        &utxos,
    )
    .is_err());
    let overflow = [utxo(1, u64::MAX), utxo(2, 1)];
    assert!(build_allowance_withdrawal(
        &covenant,
        &destination,
        &hex::encode(&redeem),
        1,
        0,
        &overflow,
    )
    .is_err());
}

#[test]
fn covenant_wasm_address_boundaries_are_host_testable() {
    use super::{
        covenant_additive_address, covenant_allowance, covenant_dms, covenant_escrow,
        covenant_global_allowance, covenant_global_spending_limit, covenant_payjoin,
        covenant_ship_escrow, covenant_timelocked_escrow, covenant_timelocked_savings,
    };

    let owner = key(0x21);
    let beneficiary = key(0x22);
    let arbiter = key(0x23);
    let alice_address = address(0x31, "kaspa");
    let bob_address = address(0x32, "kaspa");

    assert!(
        covenant_additive_address(&owner, 10_000_000, 900, "mainnet")
            .unwrap()
            .contains("address")
    );
    assert!(covenant_dms(&owner, &beneficiary, 144, "mainnet")
        .unwrap()
        .contains("redeem_script_hex"));
    assert!(
        covenant_timelocked_savings(&owner, &beneficiary, 600, "mainnet")
            .unwrap()
            .contains("locktime_daa")
    );
    assert!(covenant_timelocked_escrow(
        &owner,
        &beneficiary,
        &alice_address,
        &bob_address,
        700,
        "mainnet",
    )
    .unwrap()
    .contains("redeem_script_hex"));
    assert!(covenant_escrow(
        &owner,
        &beneficiary,
        &arbiter,
        &alice_address,
        &bob_address,
        "mainnet",
    )
    .unwrap()
    .contains("salt"));
    assert!(covenant_payjoin(&owner, &beneficiary, 900, 2, 2, "mainnet")
        .unwrap()
        .contains("redeem_script_hex"));
    assert!(
        covenant_allowance(&owner, &beneficiary, 50_000_000, 10, 0, "mainnet")
            .unwrap()
            .contains("max_withdraw_sompi")
    );
    assert!(
        covenant_global_allowance(&owner, &beneficiary, 50_000_000, 10, 0, "mainnet",)
            .unwrap()
            .contains("global_allowance")
    );
    assert!(
        covenant_global_spending_limit(&owner, 50_000_000, 10, "mainnet")
            .unwrap()
            .contains("redeem_script_hex")
    );
    assert!(
        covenant_ship_escrow(&shipping_request("100000000", "1000000"))
            .unwrap()
            .contains("total_sompi")
    );
}

#[test]
fn shared_covenant_sweep_boundaries_cover_selection_encoding_and_logging() {
    use super::sweep::{
        encode_covenant_sweep, finalize_covenant_sweep, CovenantSweepConfig, SweepSourceKind,
    };

    assert_eq!(
        SweepSourceKind::Automatic.choose("auto", "selected"),
        "auto"
    );
    assert_eq!(
        SweepSourceKind::Selected.choose("auto", "selected"),
        "selected"
    );

    let source = address(0x51, "kaspa");
    let destination = address(0x52, "kaspa");
    let prepared = crate::wasm_api::protocol::pskb_planning::prepare_sweep_from_utxos_string(
        vec![utxo(9, 100_000_000)],
        &source,
        &destination,
        1_000_000,
        "empty",
        "low",
    )
    .unwrap();
    let config = CovenantSweepConfig {
        redeem_script: &[0x51],
        input_sequence: 0,
        lock_time: 0,
        branch: Some("owner"),
        minimum_signatures: Some(1),
    };
    let wire = encode_covenant_sweep(&prepared, config).unwrap();
    assert!(!wire.is_empty());
    let wire = finalize_covenant_sweep(&prepared, config, "test", 1_000_000, None).unwrap();
    assert!(!wire.is_empty());
}

#[test]
fn selected_covenant_spend_boundaries_and_sweep_helpers_are_directly_covered() {
    use super::{
        create_covenant_beneficiary_spend_selected, create_covenant_owner_spend_selected,
        create_covenant_timelocked_savings_claim_selected,
    };
    use crate::wasm_api::contracts::covenant::sweep::{
        decode_redeem_script, prepare_and_finalize_selected, CovenantSweepConfig, CovenantSweepSpec,
    };

    let covenant = crate::protocol::script::p2sh::script_to_address(&[0x51], "kaspa").unwrap();
    let destination = address(0x61, "kaspa");
    let selected = serde_json::json!([{
        "tx_id": "66".repeat(32),
        "index": 0,
        "amount": 20_000_000u64
    }])
    .to_string();

    assert!(create_covenant_owner_spend_selected(
        &covenant,
        &destination,
        "51",
        &selected,
        100_000,
        "",
    )
    .unwrap()
    .starts_with("50534b42"));
    assert!(create_covenant_beneficiary_spend_selected(
        &covenant,
        &destination,
        "51",
        0,
        &selected,
        100_000,
    )
    .unwrap()
    .starts_with("50534b42"));
    assert!(create_covenant_timelocked_savings_claim_selected(
        &covenant,
        &destination,
        "51",
        0,
        &selected,
        100_000,
    )
    .unwrap()
    .starts_with("50534b42"));

    let redeem = decode_redeem_script("51").expect("redeem");
    let wire = prepare_and_finalize_selected(
        &selected,
        CovenantSweepSpec {
            covenant_address: &covenant,
            destination_address: &destination,
            fee: 100_000,
            empty_error: "missing",
            low_balance_error: "low",
            config: CovenantSweepConfig {
                redeem_script: &redeem,
                input_sequence: 0,
                lock_time: 0,
                branch: None,
                minimum_signatures: None,
            },
            label: "test selected sweep",
            detail: None,
        },
    )
    .expect("selected finalization");
    assert!(wire.starts_with("50534b42"));
}

mod feature_contracts;

mod coverage;
