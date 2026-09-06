use super::claim::build_claim;

fn address(byte: u8, prefix: &str) -> String {
    crate::account::address::encode_p2pk_address(&[byte; 32], prefix)
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

#[test]
fn claim_builder_covers_mixed_inputs_change_and_balance_errors() {
    let redeem = crate::contracts::covenant::script::build_payjoin_covenant_script(
        &[0x51; 32],
        &[0x52; 32],
        100,
        2,
        1,
    );
    let covenant = crate::protocol::script::p2sh::script_to_address(&redeem, "kaspa").unwrap();
    let destination = address(0x53, "kaspa");
    let mixing = address(0x54, "kaspa");
    let claim = build_claim(
        &covenant,
        &destination,
        &hex::encode(&redeem),
        &mixing,
        1,
        vec![utxo(1, 10_000_000), utxo(2, 5_000_000)],
        utxo(3, 2_000_000),
    )
    .unwrap();
    assert_eq!(claim.input_count, 3);
    assert_eq!(claim.covenant_input_count, 2);
    assert!(claim.send > 0);
    assert!(claim.change > 0);
    assert!(!claim.wire.is_empty());

    assert!(build_claim(
        &covenant,
        &destination,
        &hex::encode(&redeem),
        &mixing,
        0,
        vec![],
        utxo(3, 1),
    )
    .is_err());
    assert!(build_claim(
        &covenant,
        &destination,
        "zz",
        &mixing,
        0,
        vec![utxo(1, 1)],
        utxo(3, 1),
    )
    .is_err());
    assert!(build_claim(
        &covenant,
        &destination,
        &hex::encode(&redeem),
        &mixing,
        u64::MAX,
        vec![utxo(1, 1)],
        utxo(3, 1),
    )
    .is_err());
    assert!(build_claim(
        "bad-address",
        &destination,
        &hex::encode(&redeem),
        &mixing,
        0,
        vec![utxo(1, 10_000_000)],
        utxo(3, 2_000_000),
    )
    .is_err());
    assert!(build_claim(
        &covenant,
        &destination,
        &hex::encode(&redeem),
        &mixing,
        0,
        vec![utxo(1, u64::MAX), utxo(2, 1)],
        utxo(3, 1),
    )
    .is_err());
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn payjoin_claim_wasm_facade_rejects_bad_request_before_network() {
    let result = crate::wasm_api::test_support::ready(super::create_covenant_payjoin_claim(
        "bad",
        "bad",
        "zz",
        "bad",
        1,
        "ws://unused",
    ));
    assert!(result.is_err());
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn payjoin_network_helpers_and_logging_are_host_covered() {
    use crate::wasm_api::test_support::ready;

    let covenant = address(0x61, "kaspa");
    let mixing = address(0x62, "kaspa");
    assert!(ready(super::claim::fetch_covenant_utxos("ws://unused", &covenant)).is_err());
    assert!(ready(super::claim::fetch_smallest_mixing_utxo(
        "ws://unused",
        &mixing
    ))
    .is_err());

    let redeem = crate::contracts::covenant::script::build_payjoin_covenant_script(
        &[0x51; 32],
        &[0x52; 32],
        100,
        2,
        1,
    );
    let covenant_address =
        crate::protocol::script::p2sh::script_to_address(&redeem, "kaspa").unwrap();
    let destination = address(0x63, "kaspa");
    let mixing_address = address(0x64, "kaspa");
    let claim = build_claim(
        &covenant_address,
        &destination,
        &hex::encode(redeem),
        &mixing_address,
        1,
        vec![utxo(7, 10_000_000)],
        utxo(8, 2_000_000),
    )
    .expect("payjoin claim");
    super::claim::log_claim(&claim);
}
