use serde_json::json;

use super::planning::{GlobalThreadFamily, TopupRequest, WithdrawalRequest};
use crate::transaction_builder::pskb::{
    build_global_thread_topup as build_topup_core,
    build_global_thread_withdrawal as build_withdrawal_core, prepare_global_thread_topup_material,
    select_wallet_utxos,
};

#[cfg(not(target_arch = "wasm32"))]
mod native_boundary;

fn address(byte: u8) -> String {
    crate::account::address::encode_p2pk_address(&[byte; 32], "kaspa")
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

fn wallet_json() -> String {
    json!({
        "kpub": "test",
        "receive_addresses": [address(1)],
        "change_addresses": [address(2)],
        "next_receive_index": 0,
        "next_change_index": 0
    })
    .to_string()
}

fn thread_json(amount: u64) -> String {
    json!({"tx_id": "11".repeat(32), "index": 0, "amount": amount}).to_string()
}

fn topup_request<'a>(
    wallet_json: &'a str,
    covenant_address: &'a str,
    redeem_script_hex: &'a str,
    covenant_id_hex: &'a str,
    thread_utxo_json: &'a str,
) -> TopupRequest<'a> {
    TopupRequest {
        family: GlobalThreadFamily::Allowance,
        wallet_json,
        covenant_address,
        redeem_script_hex,
        covenant_id_hex,
        thread_utxo_json,
        fee: 1,
        #[cfg(target_arch = "wasm32")]
        utxo_indices_csv: "0",
        #[cfg(target_arch = "wasm32")]
        websocket_url: "ws://unused",
    }
}

#[test]
fn global_thread_withdrawal_covers_allowance_spending_limit_and_invalid_inputs() {
    let allowance = crate::contracts::covenant::script::build_global_allowance_script(
        &[0x11; 32],
        &[0x22; 32],
        50_000_000,
        4,
        0,
        &[0x33; 8],
    );
    let covenant = crate::protocol::script::p2sh::script_to_address(&allowance, "kaspa").unwrap();
    let selected = json!([
        {"tx_id": "11".repeat(32), "index": 0, "amount": 100_000_000, "block_daa_score": 1}
    ])
    .to_string();
    let prepared = build_withdrawal_core(WithdrawalRequest {
        family: GlobalThreadFamily::Allowance,
        covenant_address: &covenant,
        destination_address: &address(3),
        redeem_script_hex: &hex::encode(&allowance),
        covenant_id_hex: &"44".repeat(32),
        withdrawal: 40_000_000,
        fee: 1_000_000,
        selected_utxos_json: &selected,
    })
    .unwrap();
    assert_eq!(prepared.input_count, 1);
    assert_eq!(prepared.total, 100_000_000);
    assert!(!prepared.wire.is_empty());

    let spending = crate::contracts::covenant::script::build_global_spending_limit_script(
        &[0x11; 32],
        50_000_000,
        5,
        &[0x44; 8],
    );
    let spending_address =
        crate::protocol::script::p2sh::script_to_address(&spending, "kaspa").unwrap();
    assert!(build_withdrawal_core(WithdrawalRequest {
        family: GlobalThreadFamily::SpendingLimit,
        covenant_address: &spending_address,
        destination_address: &address(4),
        redeem_script_hex: &hex::encode(&spending),
        covenant_id_hex: &"55".repeat(32),
        withdrawal: 40_000_000,
        fee: 1_000_000,
        selected_utxos_json: &selected,
    })
    .is_ok());

    for bad in ["not-json", "[]"] {
        assert!(build_withdrawal_core(WithdrawalRequest {
            family: GlobalThreadFamily::Allowance,
            covenant_address: &covenant,
            destination_address: &address(3),
            redeem_script_hex: &hex::encode(&allowance),
            covenant_id_hex: &"44".repeat(32),
            withdrawal: 1_000_000,
            fee: 0,
            selected_utxos_json: bad,
        })
        .is_err());
    }
}

#[test]
fn global_thread_topup_and_manual_selection_are_host_testable() {
    let available = vec![
        utxo(1, 10_000_000),
        utxo(2, 20_000_000),
        utxo(3, 30_000_000),
    ];
    let selected = select_wallet_utxos(&available, "2, 0").unwrap();
    assert_eq!(selected[0].amount, 30_000_000);
    assert_eq!(selected[1].amount, 10_000_000);
    assert!(select_wallet_utxos(&available, "").is_err());
    assert!(select_wallet_utxos(&available, "bad").is_err());
    assert!(select_wallet_utxos(&available, "9").is_err());

    let redeem = crate::contracts::covenant::script::build_global_spending_limit_script(
        &[0x31; 32],
        50_000_000,
        6,
        &[0x45; 8],
    );
    let covenant = crate::protocol::script::p2sh::script_to_address(&redeem, "kaspa").unwrap();
    let wallet = wallet_json();
    let redeem_hex = hex::encode(&redeem);
    let covenant_id = "66".repeat(32);
    let thread = thread_json(100_000_000);
    let request = TopupRequest {
        family: GlobalThreadFamily::SpendingLimit,
        wallet_json: &wallet,
        covenant_address: &covenant,
        redeem_script_hex: &redeem_hex,
        covenant_id_hex: &covenant_id,
        thread_utxo_json: &thread,
        fee: 1_000_000,
        #[cfg(target_arch = "wasm32")]
        utxo_indices_csv: "0",
        #[cfg(target_arch = "wasm32")]
        websocket_url: "ws://unused",
    };
    let fee = request.fee;
    let material = prepare_global_thread_topup_material(
        request.family,
        request.covenant_address,
        request.redeem_script_hex,
        request.covenant_id_hex,
        request.thread_utxo_json,
    )
    .unwrap();
    let prepared = build_topup_core(material, vec![utxo(7, 20_000_000)], fee).unwrap();
    assert_eq!(prepared.selected_count, 1);
    assert_eq!(prepared.thread_amount, 100_000_000);
    assert!(!prepared.wire.is_empty());
}

#[test]
fn topup_material_parser_covers_both_families_and_validation_errors() {
    let allowance_redeem = crate::contracts::covenant::script::build_global_allowance_script(
        &[0x61; 32],
        &[0x62; 32],
        50_000_000,
        4,
        0,
        &[0x63; 8],
    );
    let allowance_address =
        crate::protocol::script::p2sh::script_to_address(&allowance_redeem, "kaspa").unwrap();
    let allowance_hex = hex::encode(&allowance_redeem);
    let covenant_id = "64".repeat(32);
    let thread = thread_json(100_000_000);
    assert!(prepare_global_thread_topup_material(
        GlobalThreadFamily::Allowance,
        &allowance_address,
        &allowance_hex,
        &covenant_id,
        &thread,
    )
    .is_ok());
    assert!(prepare_global_thread_topup_material(
        GlobalThreadFamily::Allowance,
        &allowance_address,
        "zz",
        &covenant_id,
        &thread,
    )
    .is_err());
    assert!(prepare_global_thread_topup_material(
        GlobalThreadFamily::Allowance,
        &allowance_address,
        &allowance_hex,
        "00",
        &thread,
    )
    .is_err());
    assert!(prepare_global_thread_topup_material(
        GlobalThreadFamily::Allowance,
        &allowance_address,
        &allowance_hex,
        &covenant_id,
        "not-json",
    )
    .is_err());
    assert!(prepare_global_thread_topup_material(
        GlobalThreadFamily::Allowance,
        "bad-address",
        &allowance_hex,
        &covenant_id,
        &thread,
    )
    .is_err());

    let spending = crate::contracts::covenant::script::build_global_spending_limit_script(
        &[0x31; 32],
        50_000_000,
        6,
        &[0x45; 8],
    );
    let spending_address =
        crate::protocol::script::p2sh::script_to_address(&spending, "kaspa").unwrap();
    assert!(prepare_global_thread_topup_material(
        GlobalThreadFamily::SpendingLimit,
        &spending_address,
        &hex::encode(spending),
        &covenant_id,
        &thread,
    )
    .is_ok());
}

#[test]
fn global_thread_wasm_boundaries_cover_withdraw_topup_and_api_conversion() {
    use crate::wasm_api::test_support::ready;

    let api = super::TopupApiRequest {
        wallet_json: "not-json".to_string(),
        covenant_address: "bad".to_string(),
        redeem_script_hex: "00".to_string(),
        covenant_id_hex: "00".to_string(),
        thread_utxo_json: "{}".to_string(),
        fee: "1".to_string(),
        #[cfg(target_arch = "wasm32")]
        utxo_indices_csv: "0".to_string(),
        #[cfg(target_arch = "wasm32")]
        ws_url: "ws://unused".to_string(),
    };
    let request = api
        .request(GlobalThreadFamily::Allowance)
        .expect("API conversion");
    assert!(ready(super::create_topup(request, "test")).is_err());

    let bad_withdrawal = WithdrawalRequest {
        family: GlobalThreadFamily::SpendingLimit,
        covenant_address: "bad",
        destination_address: "bad",
        redeem_script_hex: "00",
        covenant_id_hex: "00",
        withdrawal: 1,
        fee: 0,
        selected_utxos_json: "not-json",
    };
    assert!(ready(super::create_withdrawal(bad_withdrawal, "test")).is_err());

    assert!(ready(crate::wasm_api::create_global_allowance_topup("not-json")).is_err());
    assert!(ready(crate::wasm_api::create_global_spending_limit_topup(
        "not-json"
    ))
    .is_err());
    assert!(ready(crate::wasm_api::create_global_allowance_withdraw(
        "bad", "bad", "00", "00", 1, 0, "not-json",
    ))
    .is_err());
    assert!(
        ready(crate::wasm_api::create_global_spending_limit_withdraw(
            "bad", "bad", "00", "00", 1, 0, "not-json",
        ))
        .is_err()
    );
}
