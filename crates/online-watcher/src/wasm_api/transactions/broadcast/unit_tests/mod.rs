use super::*;
use crate::wasm_api::test_support::ready;

#[test]
fn broadcast_boundary_rejects_malformed_signed_transactions_before_network_io() {
    assert!(ready(broadcast_signed("00", "ws://unused")).is_err());
}
