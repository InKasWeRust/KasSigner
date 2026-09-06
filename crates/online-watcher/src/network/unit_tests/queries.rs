use crate::{
    account::bip32::WalletData,
    network::queries::utxos::{
        fetch_all, fetch_all_complete, fetch_for_address, fetch_for_addresses,
    },
    wasm_api::test_support::ready,
};

#[test]
fn utxo_query_boundaries_reject_invalid_addresses_before_transport() {
    let wallet = WalletData {
        kpub: String::new(),
        receive_addresses: vec!["not-an-address".to_string()],
        change_addresses: Vec::new(),
        next_receive_index: 0,
        next_change_index: 0,
    };
    assert!(ready(fetch_all("ws://unused", &wallet)).is_err());
    assert!(ready(fetch_all_complete("ws://unused", &wallet)).is_err());
    assert!(ready(fetch_for_address("ws://unused", "not-an-address")).is_err());
    assert!(ready(fetch_for_addresses(
        "ws://unused",
        &["not-an-address".to_string()],
    ))
    .is_err());
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn native_network_query_and_submission_surfaces_reach_transport_fail_closed() {
    use crate::{
        network::{
            queries::{blocks, chain, fees},
            submission,
        },
        protocol::transaction::consensus::{ConsensusTransaction, InputEncoding},
    };

    const ADDRESS: &str = "kaspa:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkx9awp4e";
    let transport_error = "unavailable on native hosts";

    assert!(ready(fetch_for_address("ws://unused", ADDRESS))
        .expect_err("utxo native transport")
        .contains(transport_error));
    let wallet = WalletData {
        kpub: String::new(),
        receive_addresses: vec![ADDRESS.to_string()],
        change_addresses: vec![],
        next_receive_index: 0,
        next_change_index: 0,
    };
    assert!(ready(fetch_all_complete("ws://unused", &wallet))
        .expect_err("complete utxo native transport")
        .contains(transport_error));
    assert!(ready(blocks::get_raw("ws://unused", &[0x11; 32]))
        .expect_err("block native transport")
        .contains(transport_error));
    assert!(ready(chain::virtual_daa_score("ws://unused"))
        .expect_err("dag native transport")
        .contains(transport_error));
    assert!(ready(fees::get("ws://unused"))
        .expect_err("fees native transport")
        .contains(transport_error));

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
    assert!(ready(submission::submit("ws://unused", &transaction))
        .expect_err("submission native transport")
        .contains(transport_error));
}

#[test]
fn complete_utxo_union_keeps_distinct_outpoints_and_deduplicates_exact_keys() {
    use crate::{account::utxo::UtxoEntry, network::queries::utxos::append_unique_outpoints};
    use std::collections::HashSet;

    fn entry(tx_byte: u8, index: u32, amount: u64) -> UtxoEntry {
        UtxoEntry {
            tx_id: hex::encode([tx_byte; 32]),
            index,
            amount,
            script_public_key: vec![0x20, tx_byte, 0xac],
            block_daa_score: 7,
            covenant_id: None,
        }
    }

    let mut destination = Vec::new();
    let mut seen = HashSet::new();
    append_unique_outpoints(
        &mut destination,
        &mut seen,
        vec![entry(0x11, 0, 10), entry(0x22, 1, 20)],
    );
    append_unique_outpoints(
        &mut destination,
        &mut seen,
        vec![entry(0x11, 0, 10), entry(0x11, 2, 30)],
    );
    assert_eq!(destination.len(), 3);
    assert_eq!(
        destination
            .iter()
            .map(|entry| entry.amount)
            .collect::<Vec<_>>(),
        vec![10, 20, 30]
    );
}
