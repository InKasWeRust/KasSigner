use super::*;
use crate::wasm_api::test_support::ready;

const KPUB_A: &str = "kpub2J937qL9n85s7HrhYyYYdMkzq1kaMiAf9PAcJzRW3jV7NgntNfGGrNgut7ZxcVrJqH42BCT2WyjfnxJh3SBDjLhXHe3UC2RJUu5tcjsViuK";
const KPUB_B: &str = "kpub2Jtuqt6WJWZv3fQUnKhuEaCxbAyzLsFn3UEEaM4g7CXa2LZjQZH4o6tpj83tFaewMEyX56qrAF4Q64uqunVyBayuuRNwjru5DWchDEcq5vz";

fn hd45_descriptor() -> String {
    format!("multi_hd45(1,{KPUB_A},{KPUB_B})")
}

fn hd45_source(descriptor_text: &str) -> String {
    let descriptor =
        crate::multisig::MultisigDescriptor::parse(descriptor_text).expect("45' descriptor");
    let keys = descriptor
        .public_keys_at(0, 0, 0)
        .expect("45' receive keys");
    let redeem = crate::multisig::build_redeem_script(descriptor.threshold(), &keys)
        .expect("45' redeem script");
    crate::protocol::script::p2sh::script_to_address(&redeem, "kaspa").expect("45' source address")
}

fn request() -> MultisigApiRequest {
    MultisigApiRequest {
        descriptor: format!("multi(1,{})", "11".repeat(32)),
        source_address: crate::account::address::encode_p2sh_address(&[0x21; 32], "kaspa"),
        dest_address: crate::account::address::encode_p2pk_address(&[0x22; 32], "kaspa"),
        amount_sompi: "0".to_string(),
        fee_sompi: "300000".to_string(),
        change_address: crate::account::address::encode_p2sh_address(&[0x21; 32], "kaspa"),
        ws_url: "ws://unused".to_string(),
        addr_index: 0,
        change_index_hint: 0,
        utxo_csv: "0".to_string(),
    }
}

#[test]
fn multisig_transaction_boundaries_are_host_testable() {
    let request = request();
    let automatic = request.automatic().expect("automatic request conversion");
    assert!(ready(create_multisig(automatic)).is_err());

    assert!(ready(create_multisig_pskb("not-json")).is_err());
    assert!(ready(create_multisig_pskb_selected("not-json")).is_err());

    let valid = serde_json::json!({
        "descriptor": request.descriptor,
        "source_address": request.source_address,
        "dest_address": request.dest_address,
        "amount_sompi": "10000000",
        "fee_sompi": "300000",
        "change_address": request.change_address,
        "ws_url": "ws://unused",
        "addr_index": 0,
        "utxo_csv": "0"
    })
    .to_string();
    assert!(ready(create_multisig_pskb_selected(&valid)).is_err());
}

#[test]
fn restored_hd45_wasm_exports_are_host_testable() {
    assert!(ready(scan_multisig_branch_js("not-json")).is_err());
    assert!(ready(create_multisig_pskb_multi_js("not-json")).is_err());

    let static_scan = serde_json::json!({
        "descriptor": format!("multi(1,{},{})", "11".repeat(32), "22".repeat(32)),
        "cosigner_index": 0,
        "depth": 1,
        "ws_url": "ws://unused",
        "address_prefix": "kaspa"
    })
    .to_string();
    assert!(ready(scan_multisig_branch_js(&static_scan)).is_err());

    let descriptor = hd45_descriptor();
    let source = hd45_source(&descriptor);
    let scan = serde_json::json!({
        "descriptor": descriptor,
        "cosigner_index": 0,
        "depth": 2,
        "ws_url": "ws://unused",
        "address_prefix": "kaspa"
    })
    .to_string();
    #[cfg(not(target_arch = "wasm32"))]
    assert!(ready(scan_multisig_branch_js(&scan)).is_err());

    let sources_json = serde_json::json!([{
        "address": source.clone(),
        "tx_id": "11".repeat(32),
        "index": 0
    }])
    .to_string();
    let multi = serde_json::json!({
        "descriptor": hd45_descriptor(),
        "sources_json": sources_json,
        "dest_address": source,
        "amount_sompi": "1000000",
        "fee_sompi": "1000",
        "cosigner_index": 0,
        "change_index_hint": 0,
        "ws_url": "ws://unused"
    })
    .to_string();
    #[cfg(not(target_arch = "wasm32"))]
    assert!(ready(create_multisig_pskb_multi_js(&multi)).is_err());

    let bad_amount = multi.replace("\"1000000\"", "\"not-a-number\"");
    assert!(ready(create_multisig_pskb_multi_js(&bad_amount)).is_err());
}
