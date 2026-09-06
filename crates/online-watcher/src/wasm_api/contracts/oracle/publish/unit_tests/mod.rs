use serde_json::json;

use super::{context, parse_publish_request_string, plan, request};
use crate::account::utxo::UtxoEntry;

fn p2pk_address(byte: u8) -> String {
    crate::account::address::encode_p2pk_address(&[byte; 32], "kaspa")
}

fn wallet_json() -> String {
    json!({
        "kpub": "test",
        "receive_addresses": [p2pk_address(1)],
        "change_addresses": [p2pk_address(2)],
        "next_receive_index": 0,
        "next_change_index": 0
    })
    .to_string()
}

fn journal_hex(price: u64, time: u64, set_root: &[u8; 32]) -> String {
    let mut journal = Vec::with_capacity(48);
    journal.extend_from_slice(&price.to_le_bytes());
    journal.extend_from_slice(&time.to_le_bytes());
    journal.extend_from_slice(set_root);
    hex::encode(journal)
}

fn oracle_redeem() -> Vec<u8> {
    crate::contracts::oracle::script::build_oracle_mb_redeem(
        10,
        20,
        &[0x11; 32],
        &[0x22; 32],
        &[0x33; 32],
        1,
        &[0x44; 32],
    )
}

struct RequestInputFixture<'a> {
    wallet: &'a str,
    oracle_address: &'a str,
    redeem_script_hex: &'a str,
    covenant_id_hex: &'a str,
    heartbeat_cov_id_hex: &'a str,
    image_id_hex: &'a str,
    control_id_hex: &'a str,
    set_root_hex: &'a str,
    hashfn_hex: &'a str,
    journal_hex: &'a str,
    change_address: &'a str,
    omit_heartbeat: bool,
}

fn request_input(input: RequestInputFixture<'_>) -> request::PublishRequestInput<'_> {
    request::PublishRequestInput {
        wallet_json: input.wallet,
        oracle_address: input.oracle_address,
        redeem_script_hex: input.redeem_script_hex,
        covenant_id_hex: input.covenant_id_hex,
        heartbeat_cov_id_hex: input.heartbeat_cov_id_hex,
        image_id_hex: input.image_id_hex,
        control_id_hex: input.control_id_hex,
        set_root_hex: input.set_root_hex,
        hashfn_hex: input.hashfn_hex,
        seal_hex: "aa",
        claim_hex: "bb",
        control_index_hex: "cc",
        control_digests_hex: "dd",
        journal_hex: input.journal_hex,
        fee: 10,
        change_address: input.change_address,
        network: "mainnet",
        ws_url: "ws://unused",
        omit_heartbeat: input.omit_heartbeat,
    }
}

fn valid_request(omit_heartbeat: bool) -> request::PublishRequest {
    let wallet = wallet_json();
    let redeem = oracle_redeem();
    let oracle_address =
        crate::protocol::script::p2sh::script_to_address(&redeem, "kaspa").unwrap();
    let redeem_hex = hex::encode(redeem);
    let covenant_id = "55".repeat(32);
    let heartbeat_id = "44".repeat(32);
    let image_id = "11".repeat(32);
    let control_id = "22".repeat(32);
    let set_root = [0x33; 32];
    let set_root_hex = hex::encode(set_root);
    let journal = journal_hex(50, 60, &set_root);
    let change_address = p2pk_address(3);
    request::PublishRequest::parse_string(request_input(RequestInputFixture {
        wallet: &wallet,
        oracle_address: &oracle_address,
        redeem_script_hex: &redeem_hex,
        covenant_id_hex: &covenant_id,
        heartbeat_cov_id_hex: &heartbeat_id,
        image_id_hex: &image_id,
        control_id_hex: &control_id,
        set_root_hex: &set_root_hex,
        hashfn_hex: "01",
        journal_hex: &journal,
        change_address: &change_address,
        omit_heartbeat,
    }))
    .unwrap()
}

fn valid_api_request_json(omit_heartbeat: bool) -> String {
    let wallet = wallet_json();
    let redeem = oracle_redeem();
    let oracle_address =
        crate::protocol::script::p2sh::script_to_address(&redeem, "kaspa").unwrap();
    let set_root = [0x33; 32];
    serde_json::json!({
        "wallet_json": wallet,
        "oracle_address": oracle_address,
        "redeem_script_hex": hex::encode(redeem),
        "covenant_id_hex": "55".repeat(32),
        "heartbeat_cov_id_hex": "44".repeat(32),
        "image_id_hex": "11".repeat(32),
        "control_id_hex": "22".repeat(32),
        "set_root_hex": hex::encode(set_root),
        "hashfn_hex": "01",
        "seal_hex": "aa",
        "claim_hex": "bb",
        "control_index_hex": "cc",
        "control_digests_hex": "dd",
        "journal_hex": journal_hex(50, 60, &set_root),
        "fee": "10",
        "change_address": p2pk_address(3),
        "network": "mainnet",
        "ws_url": "ws://unused",
        "omit_heartbeat": omit_heartbeat
    })
    .to_string()
}

fn utxo(byte: u8, amount: u64, covenant_id: Option<&str>) -> UtxoEntry {
    UtxoEntry {
        tx_id: format!("{byte:02x}").repeat(32),
        index: u32::from(byte),
        amount,
        script_public_key: vec![0x51],
        block_daa_score: 7,
        covenant_id: covenant_id.map(str::to_string),
    }
}

fn prepare_context(
    omit_heartbeat: bool,
    oracle_utxos: Vec<UtxoEntry>,
    wallet_utxos: Vec<UtxoEntry>,
    heartbeat_utxos: Vec<UtxoEntry>,
) -> Result<context::PublishContext, String> {
    let request = valid_request(omit_heartbeat);
    let template = context::derive_template(&request)?;
    context::prepare_from_sources(
        request,
        template,
        context::PublishSources {
            oracle_utxos,
            wallet_utxos,
            heartbeat_utxos,
        },
    )
}

#[test]
fn publish_request_parsing_validates_fixed_width_fields_and_journal_commitment() {
    let parsed = valid_request(false);
    assert_eq!(parsed.new_price, 50);
    assert_eq!(parsed.new_t, 60);
    assert_eq!(parsed.hashfn, 1);

    let wallet = wallet_json();
    let redeem = oracle_redeem();
    let oracle_address =
        crate::protocol::script::p2sh::script_to_address(&redeem, "kaspa").unwrap();
    let redeem_hex = hex::encode(redeem);
    let covenant_id = "55".repeat(32);
    let heartbeat_id = "44".repeat(32);
    let image_id = "11".repeat(32);
    let control_id = "22".repeat(32);
    let set_root = [0x33; 32];
    let set_root_hex = hex::encode(set_root);
    let journal = journal_hex(1, 2, &set_root);
    let change_address = p2pk_address(3);

    for bad_hashfn in ["", "0102", "zz"] {
        let result = request::PublishRequest::parse_string(request_input(RequestInputFixture {
            wallet: &wallet,
            oracle_address: &oracle_address,
            redeem_script_hex: &redeem_hex,
            covenant_id_hex: &covenant_id,
            heartbeat_cov_id_hex: &heartbeat_id,
            image_id_hex: &image_id,
            control_id_hex: &control_id,
            set_root_hex: &set_root_hex,
            hashfn_hex: bad_hashfn,
            journal_hex: &journal,
            change_address: &change_address,
            omit_heartbeat: false,
        }));
        assert!(result.is_err());
    }

    let bad_journal = "00".repeat(48);
    assert!(
        request::PublishRequest::parse_string(request_input(RequestInputFixture {
            wallet: &wallet,
            oracle_address: &oracle_address,
            redeem_script_hex: &redeem_hex,
            covenant_id_hex: &covenant_id,
            heartbeat_cov_id_hex: &heartbeat_id,
            image_id_hex: &image_id,
            control_id_hex: &control_id,
            set_root_hex: &set_root_hex,
            hashfn_hex: "01",
            journal_hex: &bad_journal,
            change_address: &change_address,
            omit_heartbeat: false,
        }))
        .is_err()
    );

    let short_id = "00".repeat(31);
    assert!(
        request::PublishRequest::parse_string(request_input(RequestInputFixture {
            wallet: &wallet,
            oracle_address: &oracle_address,
            redeem_script_hex: &redeem_hex,
            covenant_id_hex: &short_id,
            heartbeat_cov_id_hex: &heartbeat_id,
            image_id_hex: &image_id,
            control_id_hex: &control_id,
            set_root_hex: &set_root_hex,
            hashfn_hex: "01",
            journal_hex: &journal,
            change_address: &change_address,
            omit_heartbeat: false,
        }))
        .is_err()
    );
}

#[test]
fn publish_context_selection_covers_singletons_fee_change_and_heartbeat() {
    let covenant_id = "55".repeat(32);
    let heartbeat_id = "44".repeat(32);
    let context = prepare_context(
        false,
        vec![utxo(1, 100, Some(&covenant_id))],
        vec![utxo(2, 9, None), utxo(3, 30_010, None)],
        vec![utxo(4, 50, Some(&heartbeat_id))],
    )
    .unwrap();
    assert_eq!(context.oracle_utxo.amount, 100);
    assert_eq!(context.fee_utxo.amount, 30_010);
    assert_eq!(context.change, 30_000);
    assert!(context.emit_change);
    assert!(context.heartbeat.is_some());

    let result = plan::build(&context).unwrap();
    assert_eq!(result.input_count, 3);
    assert_eq!(result.output_count, 3);
    assert!(!result.wire.is_empty());

    let no_heartbeat = prepare_context(
        true,
        vec![utxo(5, 100, Some(&covenant_id))],
        vec![utxo(6, 10, None)],
        Vec::new(),
    )
    .unwrap();
    assert!(!no_heartbeat.emit_change);
    assert!(no_heartbeat.heartbeat.is_none());
    let result = plan::build(&no_heartbeat).unwrap();
    assert_eq!(result.input_count, 2);
    assert_eq!(result.output_count, 1);
}

#[test]
fn publish_context_rejects_missing_or_ambiguous_sources() {
    let covenant_id = "55".repeat(32);
    let heartbeat_id = "44".repeat(32);
    assert!(prepare_context(false, Vec::new(), vec![utxo(1, 20, None)], Vec::new()).is_err());
    assert!(prepare_context(
        false,
        vec![
            utxo(1, 100, Some(&covenant_id)),
            utxo(2, 100, Some(&covenant_id)),
        ],
        vec![utxo(3, 20, None)],
        vec![utxo(4, 20, Some(&heartbeat_id))],
    )
    .is_err());
    assert!(prepare_context(
        false,
        vec![utxo(1, 100, Some(&covenant_id))],
        vec![utxo(2, 9, None), utxo(3, 100, Some("foreign"))],
        vec![utxo(4, 20, Some(&heartbeat_id))],
    )
    .is_err());
    assert!(prepare_context(
        false,
        vec![utxo(1, 100, Some(&covenant_id))],
        vec![utxo(2, 20, None)],
        Vec::new(),
    )
    .is_err());
    assert!(prepare_context(
        false,
        vec![utxo(1, 100, Some(&covenant_id))],
        vec![utxo(2, 20, None)],
        vec![
            utxo(3, 20, Some(&heartbeat_id)),
            utxo(4, 20, Some(&heartbeat_id)),
        ],
    )
    .is_err());
}

#[test]
fn publish_api_json_parser_is_native_testable() {
    let set_root = [0x33; 32];
    let redeem = oracle_redeem();
    let oracle_address =
        crate::protocol::script::p2sh::script_to_address(&redeem, "kaspa").unwrap();
    let document = json!({
        "wallet_json": wallet_json(),
        "oracle_address": oracle_address,
        "redeem_script_hex": hex::encode(redeem),
        "covenant_id_hex": "55".repeat(32),
        "heartbeat_cov_id_hex": "44".repeat(32),
        "image_id_hex": "11".repeat(32),
        "control_id_hex": "22".repeat(32),
        "set_root_hex": hex::encode(set_root),
        "hashfn_hex": "01",
        "seal_hex": "aa",
        "claim_hex": "bb",
        "control_index_hex": "cc",
        "control_digests_hex": "dd",
        "journal_hex": journal_hex(50, 60, &set_root),
        "fee": "10",
        "change_address": p2pk_address(3),
        "network": "mainnet",
        "ws_url": "ws://unused",
        "omit_heartbeat": true,
    });
    let parsed = parse_publish_request_string(&document.to_string()).unwrap();
    assert_eq!(parsed.fee, 10);
    assert_eq!(parsed.new_price, 50);
    assert!(parsed.omit_heartbeat);

    let mut bad_fee = document.clone();
    bad_fee["fee"] = json!("bad");
    assert!(parse_publish_request_string(&bad_fee.to_string()).is_err());
    assert!(parse_publish_request_string("not-json").is_err());
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn oracle_publish_async_boundaries_are_native_host_covered() {
    use crate::wasm_api::test_support::ready;

    let request_json = valid_api_request_json(true);
    assert!(ready(super::create_oracle_mb_publish(&request_json)).is_err());

    let request = parse_publish_request_string(&request_json).expect("publish request");
    assert!(ready(context::prepare(request)).is_err());

    let address = p2pk_address(0x71);
    assert!(ready(context::fetch_address_utxos("ws://unused", &address)).is_err());

    let wallet: crate::account::bip32::WalletData =
        serde_json::from_str(&wallet_json()).expect("wallet");
    assert!(ready(context::fetch_wallet_utxos("ws://unused", &wallet)).is_err());
    assert!(ready(context::fetch_heartbeat_utxos("ws://unused", None))
        .unwrap()
        .is_empty());
}
