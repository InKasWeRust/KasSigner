use super::*;
use crate::wasm_api::test_support::ready;

#[test]
fn native_wallet_fetch_boundary_is_not_a_successful_empty_selection() {
    let wallet = crate::account::bip32::WalletData {
        kpub: String::new(),
        receive_addresses: Vec::new(),
        change_addresses: Vec::new(),
        next_receive_index: 0,
        next_change_index: 0,
    };
    assert!(ready(fetch_selected_wallet_utxos("ws://unused", &wallet, "")).is_err());
}
