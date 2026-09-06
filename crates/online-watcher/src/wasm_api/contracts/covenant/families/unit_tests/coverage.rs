use crate::wasm_api::test_support::ready;

fn address(byte: u8, prefix: &str) -> String {
    crate::account::address::encode_p2pk_address(&[byte; 32], prefix)
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn automatic_covenant_sweep_network_boundaries_are_host_covered() {
    use crate::wasm_api::contracts::covenant::sweep::{
        prepare_and_finalize_automatic, CovenantSweepConfig, CovenantSweepSpec,
    };
    use crate::wasm_api::protocol::pskb_planning::{build_covenant_sweep, CovenantSweepRequest};

    let source = address(0x71, "kaspa");
    let destination = address(0x72, "kaspa");
    let config = CovenantSweepConfig {
        redeem_script: &[0x51],
        input_sequence: 0,
        lock_time: 0,
        branch: Some("owner"),
        minimum_signatures: Some(1),
    };
    let spec = CovenantSweepSpec {
        covenant_address: &source,
        destination_address: &destination,
        fee: 1,
        empty_error: "empty",
        low_balance_error: "low",
        config,
        label: "automatic-test",
        detail: None,
    };
    assert!(ready(prepare_and_finalize_automatic("ws://unused", spec)).is_err());

    let request = CovenantSweepRequest {
        websocket_url: "ws://unused",
        covenant_address: &source,
        destination_address: &destination,
        fee: 1,
        redeem_script: &[0x51],
        branch: "owner",
        proprietaries: serde_json::json!([]),
        signature_op_count: 1,
        transaction_payload: None,
        empty_error: "empty",
        low_balance_error: "low",
    };
    assert!(ready(build_covenant_sweep(request)).is_err());
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn allowance_automatic_wasm_facade_reaches_native_transport() {
    let owner = "11".repeat(32);
    let beneficiary = "22".repeat(32);
    let covenant_json = super::super::allowance::covenant_allowance(
        &owner,
        &beneficiary,
        20_000_000,
        1,
        0,
        "mainnet",
    )
    .expect("allowance covenant");
    let covenant: serde_json::Value = serde_json::from_str(&covenant_json).unwrap();
    let covenant_address = covenant["address"].as_str().unwrap();
    let redeem = covenant["redeem_script_hex"].as_str().unwrap();
    let destination = address(0x73, "kaspa");
    assert!(
        ready(super::super::allowance::create_covenant_allowance_withdraw(
            covenant_address,
            &destination,
            redeem,
            10_000_000,
            1,
            "ws://unused",
        ))
        .is_err()
    );
}
