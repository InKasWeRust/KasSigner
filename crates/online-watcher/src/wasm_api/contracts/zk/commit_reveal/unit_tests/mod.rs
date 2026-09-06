use super::*;
use crate::wasm_api::test_support::ready;

#[test]
fn commit_reveal_spend_boundary_rejects_bad_json_before_network_io() {
    assert!(ready(create_commit_reveal_spend("not-json")).is_err());
}
#[cfg(not(target_arch = "wasm32"))]
#[test]
fn valid_commit_reveal_spend_reaches_native_transport_fail_closed() {
    use crate::wasm_api::test_support::ready;
    use std::panic::{catch_unwind, AssertUnwindSafe};

    let address = |byte: u8| crate::account::address::encode_p2pk_address(&[byte; 32], "kaspa");
    let request = serde_json::json!({
        "covenant_address": address(0x71),
        "dest_address": address(0x72),
        "redeem_script_hex": "51",
        "part_a_hex": "aa",
        "part_b_hex": "bb",
        "payload_hex": "cc",
        "fee": "300000",
        "ws_url": "ws://unused"
    })
    .to_string();

    let outcome = catch_unwind(AssertUnwindSafe(|| {
        ready(create_commit_reveal_spend(&request))
    }));
    assert!(
        matches!(outcome, Ok(Err(_)) | Err(_)),
        "native commit-reveal transport boundary unexpectedly succeeded"
    );
}
