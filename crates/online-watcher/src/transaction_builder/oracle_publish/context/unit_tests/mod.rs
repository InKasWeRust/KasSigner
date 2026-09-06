use super::*;
use crate::wasm_api::test_support::ready;

fn request() -> PublishRequest {
    PublishRequest {
        wallet: crate::account::bip32::WalletData {
            kpub: "coverage".to_string(),
            receive_addresses: Vec::new(),
            change_addresses: Vec::new(),
            next_receive_index: 0,
            next_change_index: 0,
        },
        oracle_address: String::new(),
        redeem_script_hex: String::new(),
        covenant_id_hex: "11".repeat(32),
        heartbeat_cov_id_hex: "22".repeat(32),
        image_id: [0x33; 32],
        control_id: [0x44; 32],
        set_root: [0x55; 32],
        hashfn: 1,
        seal_hex: String::new(),
        claim_hex: String::new(),
        control_index_hex: String::new(),
        control_digests_hex: String::new(),
        journal_hex: String::new(),
        new_price: 1,
        new_t: 2,
        fee: 10,
        change_spk: Vec::new(),
        network: "mainnet".to_string(),
        ws_url: "ws://unused".to_string(),
        omit_heartbeat: true,
    }
}

fn template() -> PublishTemplate {
    PublishTemplate {
        next_address: String::new(),
        next_script_public_key: Vec::new(),
        oracle_script_public_key: Vec::new(),
        oracle_redeem_script: Vec::new(),
        heartbeat: None,
    }
}

#[test]
fn staged_publish_preparation_helpers_have_direct_host_entry_coverage() {
    assert!(prepare_template(&request()).is_err());

    assert!(ready(prepare_oracle_source(request(), template())).is_err());
    assert!(ready(prepare_wallet_source(request(), template(), Vec::new())).is_err());

    let heartbeat_result = ready(prepare_heartbeat_source(
        request(),
        template(),
        Vec::new(),
        Vec::new(),
    ));
    assert!(heartbeat_result.is_err());

    assert!(finish_prepare(request(), template(), Vec::new(), Vec::new(), Vec::new(),).is_err());

    assert!(derive_heartbeat_template(&request(), "kaspa")
        .expect("omitted heartbeat has no template")
        .is_none());
}

#[test]
fn heartbeat_fetch_and_singleton_boundaries_fail_closed() {
    let heartbeat_utxos =
        ready(fetch_heartbeat_utxos("ws://unused", None)).expect("omitted heartbeat fetch");
    assert!(heartbeat_utxos.is_empty());
    let heartbeat = HeartbeatTemplate {
        address: "kaspa:invalid".into(),
        redeem_script: vec![],
        script_public_key: vec![],
    };
    #[cfg(not(target_arch = "wasm32"))]
    assert!(ready(fetch_heartbeat_utxos("ws://unused", Some(&heartbeat))).is_err());

    assert!(select_singleton("11", Vec::new(), "missing", "multiple")
        .unwrap_err()
        .contains("missing"));
    let one = UtxoEntry {
        tx_id: "11".repeat(32),
        index: 0,
        amount: 1,
        script_public_key: vec![],
        block_daa_score: 0,
        covenant_id: Some("aa".into()),
    };
    assert_eq!(
        select_singleton("aa", vec![one.clone()], "missing", "multiple")
            .unwrap()
            .tx_id,
        one.tx_id
    );
    assert!(
        select_singleton("aa", vec![one.clone(), one], "missing", "multiple")
            .unwrap_err()
            .contains("multiple")
    );
}
