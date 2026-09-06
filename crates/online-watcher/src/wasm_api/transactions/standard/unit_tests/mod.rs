use super::*;
use crate::wasm_api::test_support::ready;

fn wallet_json() -> String {
    serde_json::json!({
        "kpub": "test",
        "receive_addresses": [crate::account::address::encode_p2pk_address(&[0x61; 32], "kaspa")],
        "change_addresses": [crate::account::address::encode_p2pk_address(&[0x62; 32], "kaspa")],
        "next_receive_index": 0,
        "next_change_index": 0
    })
    .to_string()
}

#[test]
fn standard_transaction_boundaries_complete_on_host_validation_paths() {
    let wallet = wallet_json();
    let destination = crate::account::address::encode_p2pk_address(&[0x63; 32], "kaspa");

    assert!(ready(create_send(
        "not-json",
        &destination,
        20_000_000,
        300_000,
        "ws://unused",
        "wallet"
    ))
    .is_err());
    assert!(ready(create_consolidation(
        "not-json",
        300_000,
        "ws://unused",
        "wallet"
    ))
    .is_err());
    assert!(ready(create_selected_send(SelectedSendRequest {
        wallet_json: "not-json",
        destination: &destination,
        amount_sompi: 20_000_000,
        fee_sompi: 300_000,
        utxo_indices_csv: "0",
        ws_url: "ws://unused",
        wallet_error_prefix: "wallet",
    }))
    .is_err());

    assert!(ready(create_send_pskb(
        "not-json",
        &destination,
        20_000_000,
        300_000,
        "ws://unused"
    ))
    .is_err());
    assert!(ready(create_consolidate_pskb("not-json", 300_000, "ws://unused")).is_err());
    assert!(ready(create_send_pskb_selected(
        "not-json",
        &destination,
        20_000_000,
        300_000,
        "0",
        "ws://unused"
    ))
    .is_err());
    assert!(ready(create_send_pskb_limited(
        &wallet,
        &destination,
        20_000_000,
        300_000,
        0,
        "ws://unused"
    ))
    .is_err());
    assert!(ready(create_send_pskb_limited(
        "not-json",
        &destination,
        20_000_000,
        300_000,
        8,
        "ws://unused"
    ))
    .is_err());

    let (_, max_inputs) =
        parse_limited_send_request(&wallet, 12).expect("valid Advanced UTXO limit");
    assert_eq!(max_inputs, 12);
    let (_, max_inputs) =
        parse_limited_send_request(&wallet, 32).expect("signer capability ceiling");
    assert_eq!(max_inputs, 32);
    assert!(parse_limited_send_request(&wallet, 33).is_err());

    let utxos = serde_json::json!([{
        "tx_id": "11".repeat(32),
        "index": 0,
        "amount": 50_000_000u64,
        "script_public_key": [0u64, 0, 0x20, 0x61],
        "block_daa_score": 0
    }])
    .to_string();
    let wire = ready(create_send_pskb_with_utxos(
        &wallet,
        &destination,
        20_000_000,
        300_000,
        &utxos,
    ))
    .expect("explicit UTXO PSKB");
    assert!(wire.starts_with("50534b42"));

    let parsed = super::parse_explicit_utxos(&utxos).expect("boundary parser");
    assert_eq!(parsed.len(), 1);
}
#[cfg(not(target_arch = "wasm32"))]
#[test]
fn valid_standard_requests_reach_native_transport_fail_closed() {
    use std::panic::{catch_unwind, AssertUnwindSafe};

    macro_rules! assert_transport_boundary {
        ($future:expr) => {{
            let outcome = catch_unwind(AssertUnwindSafe(|| ready($future)));
            assert!(
                matches!(outcome, Ok(Err(_)) | Err(_)),
                "native host transaction boundary unexpectedly succeeded"
            );
        }};
    }

    let wallet = wallet_json();
    let destination = crate::account::address::encode_p2pk_address(&[0x64; 32], "kaspa");

    assert_transport_boundary!(create_send(
        &wallet,
        &destination,
        20_000_000,
        300_000,
        "ws://unused",
        "wallet",
    ));
    assert_transport_boundary!(create_consolidation(
        &wallet,
        300_000,
        "ws://unused",
        "wallet",
    ));
    assert_transport_boundary!(create_selected_send(SelectedSendRequest {
        wallet_json: &wallet,
        destination: &destination,
        amount_sompi: 20_000_000,
        fee_sompi: 300_000,
        utxo_indices_csv: "0",
        ws_url: "ws://unused",
        wallet_error_prefix: "wallet",
    }));

    assert_transport_boundary!(create_send_pskb(
        &wallet,
        &destination,
        20_000_000,
        300_000,
        "ws://unused",
    ));
    assert_transport_boundary!(create_consolidate_pskb(&wallet, 300_000, "ws://unused"));
    assert_transport_boundary!(create_send_pskb_selected(
        &wallet,
        &destination,
        20_000_000,
        300_000,
        "0",
        "ws://unused",
    ));
    assert_transport_boundary!(create_send_pskb_limited(
        &wallet,
        &destination,
        20_000_000,
        300_000,
        8,
        "ws://unused",
    ));
}
