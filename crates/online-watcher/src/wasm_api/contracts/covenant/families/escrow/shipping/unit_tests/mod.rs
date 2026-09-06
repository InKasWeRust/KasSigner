use super::{
    deposit::build_deposit,
    plan::{build_plan_from_sources, parse_plan_request},
    withdraw::build_withdrawal,
};

fn address(byte: u8, prefix: &str) -> String {
    crate::account::address::encode_p2pk_address(&[byte; 32], prefix)
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

fn wallet(receive: Vec<String>, change: Vec<String>) -> crate::account::bip32::WalletData {
    crate::account::bip32::WalletData {
        kpub: "test".to_string(),
        receive_addresses: receive,
        change_addresses: change,
        next_receive_index: 99,
        next_change_index: 99,
    }
}

#[test]
fn borrower_plan_deposit_and_withdrawal_are_host_testable() {
    let redeem =
        crate::contracts::covenant::script::build_dms_csv_script(&[0x41; 32], &[0x42; 32], 15);
    let covenant_address =
        crate::protocol::script::p2sh::script_to_address(&redeem, "kaspa").unwrap();
    let borrower_wallet = wallet(vec![address(0x43, "kaspa")], vec![address(0x44, "kaspa")]);
    let plan = build_plan_from_sources(
        borrower_wallet,
        &covenant_address,
        redeem.clone(),
        vec![utxo(1, 200_000_000)],
        vec![
            utxo(2, 30_000_000),
            utxo(3, 40_000_000),
            utxo(4, 50_000_000),
        ],
        60_000_000,
    )
    .unwrap();
    assert_eq!(plan.covenant.amount, 200_000_000);
    assert_eq!(plan.funding.len(), 2);
    assert_eq!(plan.funding_total, 70_000_000);
    assert_eq!(plan.csv_sequence, 15);
    assert_eq!(plan.inputs().len(), 3);

    let deposit = build_deposit(&plan, 50_000_000, 10_000_000).unwrap();
    assert_eq!(deposit.covenant_output, 250_000_000);
    assert_eq!(deposit.change, 10_000_000);
    assert_eq!(deposit.funding_count, 2);
    assert!(!deposit.wire.is_empty());
    super::deposit::log_summary(&deposit, 10_000_000);

    let withdrawal = build_withdrawal(&plan, 80_000_000, 10_000_000).unwrap();
    assert_eq!(withdrawal.covenant_return, 120_000_000);
    assert_eq!(withdrawal.borrower_receive, 140_000_000);
    assert_eq!(withdrawal.funding_count, 2);
    assert!(!withdrawal.wire.is_empty());
    super::withdraw::log_summary(&withdrawal, 10_000_000);

    assert!(build_deposit(&plan, u64::MAX, 1).is_err());
    assert!(build_withdrawal(&plan, 200_000_001, 10_000_000).is_err());

    let no_change = build_plan_from_sources(
        wallet(vec![address(0x45, "kaspa")], vec![address(0x46, "kaspa")]),
        &covenant_address,
        redeem.clone(),
        vec![utxo(1, 200_000_000)],
        vec![utxo(2, 60_000_000)],
        60_000_000,
    )
    .unwrap();
    assert_eq!(
        build_deposit(&no_change, 50_000_000, 10_000_000)
            .unwrap()
            .change,
        0,
    );

    assert!(build_plan_from_sources(
        wallet(vec![address(0x45, "kaspa")], vec![address(0x46, "kaspa")]),
        &covenant_address,
        redeem.clone(),
        vec![],
        vec![utxo(2, 60_000_000)],
        60_000_000,
    )
    .is_err());
    assert!(build_plan_from_sources(
        wallet(vec![address(0x45, "kaspa")], vec![address(0x46, "kaspa")]),
        &covenant_address,
        redeem.clone(),
        vec![utxo(1, 200_000_000)],
        vec![utxo(2, 10_000_000)],
        60_000_000,
    )
    .is_err());

    let no_change_address = build_plan_from_sources(
        wallet(vec![address(0x45, "kaspa")], vec![]),
        &covenant_address,
        redeem.clone(),
        vec![utxo(1, 200_000_000)],
        vec![utxo(2, 70_000_000)],
        60_000_000,
    )
    .unwrap();
    assert!(build_deposit(&no_change_address, 50_000_000, 10_000_000).is_err());

    let no_receive_address = build_plan_from_sources(
        wallet(vec![], vec![address(0x46, "kaspa")]),
        &covenant_address,
        redeem,
        vec![utxo(1, 200_000_000)],
        vec![utxo(2, 70_000_000)],
        60_000_000,
    )
    .unwrap();
    assert!(build_withdrawal(&no_receive_address, 50_000_000, 10_000_000).is_err());
}

#[test]
fn borrower_plan_request_parser_is_native_testable() {
    let wallet_json = serde_json::json!({
        "kpub": "test",
        "receive_addresses": [address(0x51, "kaspa")],
        "change_addresses": [address(0x52, "kaspa")],
        "next_receive_index": 0,
        "next_change_index": 0
    })
    .to_string();
    assert!(parse_plan_request(&wallet_json, &address(0x53, "kaspa"), "51").is_ok());
    assert!(parse_plan_request("not-json", &address(0x53, "kaspa"), "51").is_err());
    assert!(parse_plan_request(&wallet_json, &address(0x53, "kaspa"), "zz").is_err());
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn shipping_wasm_facades_and_plan_fetchers_fail_closed_on_host() {
    use crate::wasm_api::test_support::ready;

    assert!(ready(super::deposit::create_covenant_borrower_spend(
        "not-json",
        "bad",
        "zz",
        1,
        1,
        "ws://unused",
    ))
    .is_err());
    assert!(ready(super::withdraw::create_covenant_borrower_withdraw(
        "not-json",
        "bad",
        "zz",
        1,
        1,
        "ws://unused",
    ))
    .is_err());
    assert!(ready(super::plan::prepare(
        "not-json",
        "bad",
        "zz",
        1,
        "ws://unused",
    ))
    .is_err());
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn shipping_valid_plan_reaches_native_transport_helpers() {
    use crate::wasm_api::test_support::ready;

    let borrower = wallet(vec![address(0x55, "kaspa")], vec![address(0x56, "kaspa")]);
    let wallet_json = serde_json::to_string(&borrower).expect("wallet json");
    let redeem =
        crate::contracts::covenant::script::build_dms_csv_script(&[0x41; 32], &[0x42; 32], 15);
    let covenant_address =
        crate::protocol::script::p2sh::script_to_address(&redeem, "kaspa").unwrap();

    assert!(ready(super::plan::prepare(
        &wallet_json,
        &covenant_address,
        &hex::encode(&redeem),
        1,
        "ws://unused",
    ))
    .is_err());
    assert!(ready(super::plan::fetch_covenant_utxos(
        "ws://unused",
        &covenant_address
    ))
    .is_err());
    assert!(ready(super::plan::fetch_wallet_utxos("ws://unused", &borrower)).is_err());
}

#[test]
fn borrower_plan_wrapper_delegates_to_source_builder() {
    let borrower = wallet(vec![address(0x65, "kaspa")], vec![address(0x66, "kaspa")]);
    let wallet_json = serde_json::to_string(&borrower).expect("wallet json");
    let redeem =
        crate::contracts::covenant::script::build_dms_csv_script(&[0x41; 32], &[0x42; 32], 15);
    let covenant_address =
        crate::protocol::script::p2sh::script_to_address(&redeem, "kaspa").unwrap();
    let request =
        super::plan::parse_plan_request(&wallet_json, &covenant_address, &hex::encode(&redeem))
            .expect("plan request");
    let plan = super::plan::build_borrower_plan(
        request,
        super::plan::PlanSources {
            covenant: vec![utxo(9, 200_000_000)],
            funding: vec![utxo(10, 70_000_000)],
        },
        60_000_000,
    )
    .expect("borrower plan wrapper");
    assert_eq!(plan.covenant.amount, 200_000_000);
    assert_eq!(plan.funding_total, 70_000_000);
}
