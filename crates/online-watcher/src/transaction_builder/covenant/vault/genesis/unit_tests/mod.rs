use super::*;

#[test]
fn vault_genesis_wire_uses_real_builder_boundary() {
    let owner = [0x31; 32];
    let material =
        prepare_vault_genesis(VaultGenesisKind::Tagged, &owner, "kaspa").expect("material");
    let change_address = crate::account::address::encode_p2pk_address(&[0x32; 32], "kaspa");
    let prepared = PreparedVaultGenesisRequest {
        material,
        wallet: WalletData {
            kpub: String::new(),
            receive_addresses: vec![change_address.clone()],
            change_addresses: vec![change_address.clone()],
            next_receive_index: 0,
            next_change_index: 0,
        },
        change_address,
    };

    let result = crate::wasm_api::test_support::ready(build_vault_genesis_wire(
        &prepared,
        1_000_000,
        100_000,
        "ws://unused",
    ));
    assert!(result.is_err());
}
