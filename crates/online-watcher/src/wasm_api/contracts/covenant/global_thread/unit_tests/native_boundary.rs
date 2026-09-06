use super::{thread_json, topup_request, wallet_json};
use crate::wasm_api::{
    contracts::covenant::global_thread::planning::{build_topup, GlobalThreadFamily, TopupRequest},
    test_support::ready,
};

fn expect_error<T>(result: Result<T, String>) -> String {
    match result {
        Ok(_) => panic!("expected top-up validation to fail"),
        Err(error) => error,
    }
}

#[test]
fn covers_every_validation_stage_and_both_families() {
    const BROWSER_ONLY: &str = "Wallet UTXO lookup requires a wasm32 browser target";

    let wallet = wallet_json();
    let covenant_id = "66".repeat(32);
    let thread = thread_json(100_000_000);

    let allowance_redeem = crate::contracts::covenant::script::build_global_allowance_script(
        &[0x31; 32],
        &[0x32; 32],
        50_000_000,
        4,
        0,
        &[0x33; 8],
    );
    let allowance_address =
        crate::protocol::script::p2sh::script_to_address(&allowance_redeem, "kaspa").unwrap();
    let allowance_hex = hex::encode(&allowance_redeem);

    let allowance_error = expect_error(ready(build_topup(topup_request(
        &wallet,
        &allowance_address,
        &allowance_hex,
        &covenant_id,
        &thread,
    ))));
    assert_eq!(allowance_error, BROWSER_ONLY);

    let spending_redeem = crate::contracts::covenant::script::build_global_spending_limit_script(
        &[0x41; 32],
        50_000_000,
        6,
        &[0x42; 8],
    );
    let spending_address =
        crate::protocol::script::p2sh::script_to_address(&spending_redeem, "kaspa").unwrap();
    let spending_hex = hex::encode(&spending_redeem);
    let spending_error = expect_error(ready(build_topup(TopupRequest {
        family: GlobalThreadFamily::SpendingLimit,
        wallet_json: &wallet,
        covenant_address: &spending_address,
        redeem_script_hex: &spending_hex,
        covenant_id_hex: &covenant_id,
        thread_utxo_json: &thread,
        fee: 1,
    })));
    assert_eq!(spending_error, BROWSER_ONLY);

    let invalid_wallet = expect_error(ready(build_topup(topup_request(
        "not-json",
        &allowance_address,
        &allowance_hex,
        &covenant_id,
        &thread,
    ))));
    assert!(invalid_wallet.starts_with("Bad wallet JSON:"));

    let invalid_redeem = expect_error(ready(build_topup(topup_request(
        &wallet,
        &allowance_address,
        "zz",
        &covenant_id,
        &thread,
    ))));
    assert!(invalid_redeem.starts_with("Bad redeem hex:"));

    let malformed_csv = hex::encode([0x4d, 3, 0, 9, 0xb1]);
    let invalid_csv = expect_error(ready(build_topup(TopupRequest {
        family: GlobalThreadFamily::SpendingLimit,
        wallet_json: &wallet,
        covenant_address: &spending_address,
        redeem_script_hex: &malformed_csv,
        covenant_id_hex: &covenant_id,
        thread_utxo_json: &thread,
        fee: 1,
    })));
    assert_eq!(invalid_csv, "Truncated OP_PUSHDATA2 data");

    let invalid_covenant_id = expect_error(ready(build_topup(topup_request(
        &wallet,
        &allowance_address,
        &allowance_hex,
        "00",
        &thread,
    ))));
    assert_eq!(invalid_covenant_id, "covenant_id not 32 bytes");

    let invalid_thread = expect_error(ready(build_topup(topup_request(
        &wallet,
        &allowance_address,
        &allowance_hex,
        &covenant_id,
        "not-json",
    ))));
    assert!(invalid_thread.starts_with("Bad thread UTXO JSON:"));

    let invalid_address = expect_error(ready(build_topup(topup_request(
        &wallet,
        "bad-address",
        &allowance_hex,
        &covenant_id,
        &thread,
    ))));
    assert_eq!(invalid_address, "Unknown address prefix");
}
