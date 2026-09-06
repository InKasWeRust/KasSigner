use crate::common::workspace_root;

#[test]
fn rpc_subsystem_is_grouped_by_responsibility() {
    let root = workspace_root();
    let online = root.join("crates/online-watcher/src");
    let network = online.join("network");

    assert!(!network.join("rpc.rs").exists());
    for required in [
        "codec/primitives/reader.rs",
        "codec/primitives/writer.rs",
        "queries/utxos.rs",
        "submission/encoder.rs",
        "wrpc/request.rs",
        "wrpc/response.rs",
    ] {
        assert!(network.join(required).exists(), "missing network/{required}");
    }

    assert!(
        online.join("infrastructure/browser_websocket.rs").exists(),
        "missing browser WebSocket infrastructure adapter"
    );

    for required in [
        "protocol/transaction/signed_kspt.rs",
        "protocol/transaction/sighash.rs",
        "privacy/stealth/scanner.rs",
        "contracts/vault/script.rs",
        "wasm_api/contracts/vault/genesis.rs",
        "wasm_api/contracts/vault/spend.rs",
        "wasm_api/contracts/vault/split.rs",
        "wasm_api/contracts/vault/tagged.rs",
        "contracts/seq_commit/proof.rs",
    ] {
        assert!(online.join(required).exists(), "missing {required}");
    }
    assert!(
        !online.join("contracts/vault/transactions.rs").exists(),
        "retired browser-signing vault transaction layer must not return",
    );
}
