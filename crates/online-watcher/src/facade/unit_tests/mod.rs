use super::WatchWallet;
use crate::{
    transaction_builder::{MultisigSelection, MultisigTransactionRequest},
    wasm_api::test_support::ready,
};

fn account_payload() -> [u8; shared_signer::account_key::ACCOUNT_KEY_PAYLOAD_LEN] {
    use shared_signer::account_key::{
        ACCOUNT_KEY_CHILD_INDEX, ACCOUNT_KEY_DEPTH, ACCOUNT_KEY_PAYLOAD_LEN, ACCOUNT_KEY_VERSION,
    };
    let mut payload = [0u8; ACCOUNT_KEY_PAYLOAD_LEN];
    payload[..4].copy_from_slice(&ACCOUNT_KEY_VERSION);
    payload[4] = ACCOUNT_KEY_DEPTH;
    payload[9..13].copy_from_slice(&ACCOUNT_KEY_CHILD_INDEX.to_be_bytes());
    payload[13..45].fill(0x11);
    payload[45..78].copy_from_slice(&[
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
        0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
        0xf8, 0x17, 0x98,
    ]);
    payload
}

#[test]
fn facade_import_signing_and_transaction_boundaries_are_host_testable() {
    let facade = WatchWallet::new();
    let wallet = facade
        .import_raw_account(&account_payload(), "kaspa")
        .unwrap();
    assert!(facade.import_account(&wallet.kpub, "kaspa").is_ok());
    assert!(facade.import_account("bad", "kaspa").is_err());

    assert!(ready(
        facade.build_transaction(&wallet, "bad-address", 100_000_000, 1, "ws://unused",)
    )
    .is_err());
    assert!(ready(facade.build_selected_transaction(
        &wallet,
        "bad-address",
        100_000_000,
        1,
        &[0],
        "ws://unused",
    ))
    .is_err());
    assert!(facade
        .build_pskb_with_utxos(&wallet, "bad-address", 100_000_000, 1, Vec::new())
        .is_err());

    let request = MultisigTransactionRequest {
        descriptor_text: "bad",
        source_address: "bad",
        destination_address: "bad",
        amount: 0,
        fee: 0,
        change_address: "bad",
        websocket_url: "ws://unused",
        requested_index: 0,
        change_index_hint: u32::MAX,
        selection: MultisigSelection::Automatic,
    };
    assert!(ready(facade.build_multisig_transaction(request)).is_err());

    assert_ne!(
        facade.verify_message(&[2; 32], &[3; 32], &[4; 64]),
        Ok(true),
    );
    assert!(ready(facade.finalize_and_broadcast("00", "ws://unused")).is_err());
    assert!(ready(facade.broadcast("00", "ws://unused")).is_err());

    #[cfg(not(target_arch = "wasm32"))]
    {
        use crate::protocol::transaction::consensus::{ConsensusTransaction, InputEncoding};

        assert!(ready(facade.synchronize_utxos(&wallet, "ws://unused")).is_err());
        assert!(ready(facade.synchronize_balance(&wallet, "ws://unused")).is_err());
        assert!(ready(facade.build_consolidation(&wallet, 1, "ws://unused")).is_err());

        let transaction = ConsensusTransaction {
            tx_version: 0,
            input_encoding: InputEncoding::Budgeted,
            inputs: Vec::new(),
            outputs: Vec::new(),
            locktime: 0,
            subnetwork_id: [0; 20],
            gas: 0,
            payload: Vec::new(),
            storage_mass: 0,
        };
        assert!(ready(facade.submit_transaction(&transaction, "ws://unused")).is_err());
    }
}
