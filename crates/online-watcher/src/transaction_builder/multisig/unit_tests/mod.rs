use super::{branch::*, consolidation::*, *};
use crate::{account::utxo::UtxoEntry, wasm_api::test_support::ready};

const KPUB_A: &str = "kpub2J937qL9n85s7HrhYyYYdMkzq1kaMiAf9PAcJzRW3jV7NgntNfGGrNgut7ZxcVrJqH42BCT2WyjfnxJh3SBDjLhXHe3UC2RJUu5tcjsViuK";
const KPUB_B: &str = "kpub2Jtuqt6WJWZv3fQUnKhuEaCxbAyzLsFn3UEEaM4g7CXa2LZjQZH4o6tpj83tFaewMEyX56qrAF4Q64uqunVyBayuuRNwjru5DWchDEcq5vz";
const KPUB_C: &str = "kpub2JZg9pofE54nqvkhFRRx18pAMhYDPL2CpYqBx2AkzvsEknCh8V4rtez9ZYeab3HCW1Xsm9f4d6J5dfJVg9NADWN7rtqNft21batcii1SjXy";

fn descriptor_text() -> String {
    format!("multi_hd45(1,{KPUB_A},{KPUB_B})")
}

fn descriptor() -> MultisigDescriptor {
    MultisigDescriptor::parse(&descriptor_text()).expect("45' descriptor")
}

fn source_address(descriptor: &MultisigDescriptor, cosigner: u32, index: u32) -> String {
    branch_address(descriptor, cosigner, 0, index, "kaspa")
        .expect("source address")
        .2
}

fn utxo(address: &str, tx_byte: u8, index: u32, amount: u64) -> UtxoEntry {
    UtxoEntry {
        tx_id: format!("{tx_byte:02x}").repeat(32),
        index,
        amount,
        script_public_key: crate::account::address::address_to_script_pubkey(address)
            .expect("source script"),
        block_daa_score: 0,
        covenant_id: None,
    }
}

fn finish_request<'a>(
    destination_address: &'a str,
    amount: u64,
    fee: u64,
    cosigner: u32,
    change_index_hint: u32,
    websocket_url: &'a str,
) -> FinishConsolidationRequest<'a> {
    FinishConsolidationRequest {
        destination_address,
        amount,
        fee,
        cosigner,
        change_index_hint,
        websocket_url,
    }
}

fn change_request<'a>(
    source_address: &'a str,
    prefix: &'a str,
    cosigner: u32,
    change_index_hint: u32,
    websocket_url: &'a str,
    change: u64,
) -> ConsolidationChangeRequest<'a> {
    ConsolidationChangeRequest {
        source_address,
        prefix,
        cosigner,
        change_index_hint,
        websocket_url,
        change,
    }
}

fn request<'a>(
    text: &'a str,
    source: &'a str,
    selection: MultisigSelection<'a>,
) -> MultisigTransactionRequest<'a> {
    MultisigTransactionRequest {
        descriptor_text: text,
        source_address: source,
        destination_address: source,
        amount: 20_000_000,
        fee: 1_000,
        change_address: source,
        websocket_url: "ws://unused",
        requested_index: 0,
        change_index_hint: 0,
        selection,
    }
}

#[test]
fn hd45_preparation_selection_and_derivation_maps_are_covered() {
    let text = descriptor_text();
    let descriptor = descriptor();
    let source = source_address(&descriptor, 0, 0);
    let automatic = request(&text, &source, MultisigSelection::Automatic);
    let prepared = prepare_request(&automatic).expect("prepared multisig");
    assert_eq!(prepared.source_path.cosigner, 0);
    assert_eq!(prepared.source_path.chain, 0);
    assert!(verify_source_address(&source, &prepared.redeem_script).is_ok());
    assert!(verify_source_address(
        "kaspa:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkx9awp4e",
        &prepared.redeem_script
    )
    .is_err());

    assert!(encode_from_utxos(&automatic, &prepared, Vec::new())
        .unwrap_err()
        .contains("No UTXOs"));
    let wire = encode_from_utxos(
        &automatic,
        &prepared,
        vec![utxo(&source, 0x11, 0, 40_000_000)],
    )
    .expect("automatic multisig PSKB");
    assert!(!wire.is_empty());

    let selected = [0usize];
    let explicit = request(&text, &source, MultisigSelection::Explicit(&selected));
    let wire = encode_from_utxos(
        &explicit,
        &prepared,
        vec![utxo(&source, 0x22, 1, 21_000_000)],
    )
    .expect("explicit multisig PSKB");
    assert!(!wire.is_empty());

    let mut invalid = request(&text, &source, MultisigSelection::Automatic);
    invalid.amount = 0;
    assert!(validate_amounts(&invalid).is_err());
    invalid.amount = 1;
    assert!(validate_amounts(&invalid).is_err());
}

#[test]
fn multisig_exact_standard_fee_boundary_is_spendable() {
    let text = descriptor_text();
    let descriptor = descriptor();
    let source = source_address(&descriptor, 0, 0);
    let req = request(&text, &source, MultisigSelection::Automatic);
    let prepared = prepare_request(&req).expect("prepared multisig");
    let fee = multisig_standard_fee(&prepared, 1, req.fee).expect("standard fee");
    let exact_total =
        crate::transaction_builder::planning::amounts::checked_required(req.amount, fee)
            .expect("exact required total");

    let wire = encode_from_utxos(&req, &prepared, vec![utxo(&source, 0x23, 0, exact_total)])
        .expect("exact amount plus standard fee must be spendable");
    assert!(!wire.is_empty());
}

#[test]
fn branch_helpers_cover_both_chains_usage_and_first_free_indexes() {
    let descriptor = descriptor();
    let addresses = branch_addresses(&descriptor, 0, 3, "kaspa").expect("branches");
    assert_eq!(addresses.len(), 6);
    assert_eq!(branch_query(&addresses).len(), 6);
    let by_script = branch_address_map(&addresses).expect("script map");

    let receive0 = addresses
        .iter()
        .find(|(chain, index, _)| *chain == 0 && *index == 0)
        .unwrap();
    let change1 = addresses
        .iter()
        .find(|(chain, index, _)| *chain == 1 && *index == 1)
        .unwrap();
    let summary = summarize_branch_utxos(
        vec![
            utxo(&receive0.2, 0x31, 0, 10),
            utxo(&change1.2, 0x32, 1, 20),
            UtxoEntry {
                script_public_key: vec![0xaa],
                ..utxo(&receive0.2, 0x33, 2, 30)
            },
        ],
        &by_script,
        3,
    )
    .expect("summary");
    assert_eq!(summary.balance, 30);
    assert_eq!(summary.labelled.len(), 2);
    assert_eq!(first_free(&summary.receive_used), 1);
    assert_eq!(first_free(&summary.change_used), 0);
    assert_eq!(first_free(&[true, true]), 2);
    let json = encode_branch_summary(summary, 0, 3, "kaspa:next-receive", "kaspa:next-change")
        .expect("summary json");
    assert!(json.contains("\"balance_sompi\":\"30\""));
    assert!(json.contains("\"next_receive_address\":\"kaspa:next-receive\""));
    assert!(json.contains("\"next_change_address\":\"kaspa:next-change\""));

    let empty_scan = finalize_branch_scan(&descriptor, 0, 3, "kaspa", &addresses, Vec::new())
        .expect("empty branch scan");
    let empty_scan: serde_json::Value = serde_json::from_str(&empty_scan).expect("scan json");
    assert_eq!(empty_scan["balance_sompi"], "0");
    assert_eq!(empty_scan["utxo_count"], 0);
    assert!(empty_scan["next_receive_address"]
        .as_str()
        .unwrap()
        .starts_with("kaspa:"));
    assert!(empty_scan["next_change_address"]
        .as_str()
        .unwrap()
        .starts_with("kaspa:"));

    let change = change_branch_addresses(&descriptor, 0, 3, "kaspa").expect("change branch");
    assert_eq!(first_unused_change_index(&change, &[], 3), Ok(0));
    let used0 = utxo(&change[0].2, 0x34, 0, 10);
    assert_eq!(first_unused_change_index(&change, &[used0], 3), Ok(1));
    let all_used = change
        .iter()
        .enumerate()
        .map(|(slot, (_, _, address))| utxo(address, 0x40 + slot as u8, slot as u32, 10))
        .collect::<Vec<_>>();
    assert_eq!(first_unused_change_index(&change, &all_used, 3), Ok(3));
}

#[test]
fn branch_scan_and_change_index_reach_native_transport_after_validation() {
    let text = descriptor_text();
    let descriptor = descriptor();
    let source = source_address(&descriptor, 0, 0);

    let static_descriptor = format!("multi(1,{},{})", "11".repeat(32), "22".repeat(32));
    assert!(ready(scan_branch_json(
        &static_descriptor,
        0,
        1,
        "ws://unused",
        "kaspa"
    ))
    .unwrap_err()
    .contains("Branch scan requires"));
    #[cfg(not(target_arch = "wasm32"))]
    assert!(ready(scan_branch_json(&text, 0, 2, "ws://unused", "kaspa"))
        .unwrap_err()
        .contains("unavailable on native hosts"));

    assert_eq!(
        ready(resolve_change_index(
            &descriptor,
            &source,
            0,
            7,
            "ws://unused"
        )),
        Ok(7)
    );
    #[cfg(not(target_arch = "wasm32"))]
    assert!(ready(resolve_change_index(
        &descriptor,
        &source,
        0,
        u32::MAX,
        "ws://unused"
    ))
    .unwrap_err()
    .contains("unavailable on native hosts"));
}

#[test]
fn consolidation_helpers_cover_limits_resolution_inputs_and_change() {
    let descriptor = descriptor();
    let source0 = source_address(&descriptor, 0, 0);
    let source1 = source_address(&descriptor, 0, 1);
    let first = MultisigConsolidationSource {
        address: source0.clone(),
        tx_id: "11".repeat(32),
        index: 0,
    };
    let second = MultisigConsolidationSource {
        address: source1.clone(),
        tx_id: "22".repeat(32),
        index: 1,
    };
    let sources = vec![first.clone(), second.clone()];

    assert!(parse_consolidation_sources("not-json").is_err());
    assert!(parse_consolidation_sources("[]").is_err());
    assert!(parse_consolidation_sources("[{\"address\":\"a\",\"tx_id\":\"b\",\"index\":0},{\"address\":\"a\",\"tx_id\":\"b\",\"index\":1},{\"address\":\"a\",\"tx_id\":\"b\",\"index\":2},{\"address\":\"a\",\"tx_id\":\"b\",\"index\":3}]").is_err());
    assert_eq!(
        unique_source_addresses(&[first.clone(), first.clone(), second.clone()]).len(),
        2
    );

    let resolved =
        resolve_consolidation_sources(&descriptor, &sources, 0).expect("resolved sources");
    assert_eq!(resolved.len(), 2);
    let duplicate_resolved =
        resolve_consolidation_sources(&descriptor, &[first.clone(), first.clone()], 0)
            .expect("deduplicated resolved source");
    assert_eq!(duplicate_resolved.len(), 1);
    assert!(resolve_consolidation_sources(&descriptor, &sources, 1).is_err());

    let available = vec![
        utxo(&source0, 0x11, 0, 20_000_000),
        utxo(&source1, 0x22, 1, 30_000_000),
    ];
    let (inputs, total) =
        build_consolidation_inputs(&sources, &available, &resolved).expect("inputs");
    assert_eq!(inputs.len(), 2);
    assert_eq!(total, 50_000_000);
    assert!(build_consolidation_inputs(&sources, &available[..1], &resolved).is_err());
    assert_eq!(required_total(4_000_000, 1_000), Ok(4_001_000));
    assert!(required_total(u64::MAX, 1).is_err());
    assert!(require_selected_total(4_001_000, 4_001_000).is_ok());
    assert!(require_selected_total(4_000_999, 4_001_000).is_err());

    let mut outputs = vec![PlannedOutput::new(1_000_000, vec![0x51])];
    assert!(ready(append_consolidation_change(
        &descriptor,
        change_request(&source0, "kaspa", 0, 2, "ws://unused", 20_000_000),
        &mut outputs,
    ))
    .is_ok());
    assert_eq!(outputs.len(), 2);
    assert!(ready(append_consolidation_change(
        &descriptor,
        change_request(&source0, "kaspa", 0, 2, "ws://unused", 0),
        &mut outputs,
    ))
    .is_ok());
    assert_eq!(outputs.len(), 2);
    assert!(ready(append_consolidation_change(
        &descriptor,
        change_request(&source0, "kaspa", 0, 2, "ws://unused", 1),
        &mut outputs,
    ))
    .is_ok());
    assert_eq!(outputs.len(), 2);

    let sources_json = format!(
        "[{{\"address\":\"{}\",\"tx_id\":\"{}\",\"index\":0}},{{\"address\":\"{}\",\"tx_id\":\"{}\",\"index\":1}}]",
        source0, "11".repeat(32), source1, "22".repeat(32),
    );
    let static_descriptor = format!("multi(1,{},{})", "11".repeat(32), "22".repeat(32));
    assert!(prepare_consolidation(&static_descriptor, &sources_json, 0).is_err());
    let prepared = prepare_consolidation(&descriptor_text(), &sources_json, 0)
        .expect("prepared consolidation");
    let encoded = ready(finish_consolidation(
        prepared,
        &available,
        finish_request(&source0, 20_000_000, 1_000, 0, 2, "ws://unused"),
    ))
    .expect("finished consolidation");
    assert!(!encoded.is_empty());
}

#[test]
fn public_async_multisig_boundaries_fail_closed_before_or_at_native_transport() {
    let text = descriptor_text();
    let descriptor = descriptor();
    let source = source_address(&descriptor, 0, 0);
    let mut tx_request = request(&text, &source, MultisigSelection::Automatic);
    #[cfg(not(target_arch = "wasm32"))]
    assert!(ready(create(tx_request))
        .unwrap_err()
        .contains("unavailable on native hosts"));

    tx_request = request(&text, &source, MultisigSelection::Automatic);
    tx_request.change_index_hint = u32::MAX;
    #[cfg(not(target_arch = "wasm32"))]
    assert!(ready(create(tx_request))
        .unwrap_err()
        .contains("unavailable on native hosts"));

    let sources_json = format!(
        "[{{\"address\":\"{}\",\"tx_id\":\"{}\",\"index\":0}}]",
        source,
        "11".repeat(32),
    );
    #[cfg(not(target_arch = "wasm32"))]
    assert!(ready(create_multi_address(MultiAddressRequest {
        descriptor_text: &text,
        sources_json: &sources_json,
        destination_address: &source,
        amount: 20_000_000,
        fee: 1_000,
        cosigner: 0,
        change_index_hint: 0,
        websocket_url: "ws://unused",
    }))
    .unwrap_err()
    .contains("unavailable on native hosts"));
}

#[test]
fn legacy_change_policy_and_prefix_fallback_are_covered() {
    let static_text = format!("multi(1,{},{})", "11".repeat(32), "22".repeat(32));
    let descriptor = MultisigDescriptor::parse(&static_text).expect("static descriptor");
    let keys = descriptor.public_keys_at(0, 0, 0).expect("static keys");
    let redeem = build_redeem_script(1, &keys).expect("redeem");
    let source =
        crate::protocol::script::p2sh::script_to_address(&redeem, "kaspa").expect("source");
    let mut legacy = request(&static_text, &source, MultisigSelection::Automatic);
    let source_path =
        crate::multisig::resolve_address_path(&descriptor, &source, 0).expect("static path");
    legacy.change_index_hint = u32::MAX;
    assert_eq!(
        ready(transaction_change_index(&descriptor, &source_path, &legacy)),
        Ok(0)
    );
    assert!(prepare_request(&legacy).is_ok());
    legacy.change_address = "kaspa:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkx9awp4e";
    let error = match prepare_request(&legacy) {
        Ok(_) => panic!("legacy multisig change mismatch must fail"),
        Err(error) => error,
    };
    assert!(error.contains("Legacy multisig change"));
    assert_eq!(address_prefix("without-prefix"), "kaspa");
    assert_eq!(address_prefix("kaspatest:value"), "kaspatest");
}

#[test]
fn new_hd45_branch_error_paths_cover_overflow_invalid_address_and_zero_depth() {
    let descriptor = descriptor();
    let source0 = source_address(&descriptor, 0, 0);
    let source1 = source_address(&descriptor, 0, 1);
    let first = MultisigConsolidationSource {
        address: source0.clone(),
        tx_id: "11".repeat(32),
        index: 0,
    };
    let second = MultisigConsolidationSource {
        address: source1.clone(),
        tx_id: "22".repeat(32),
        index: 1,
    };
    let sources = vec![first.clone(), second.clone()];
    let resolved = resolve_consolidation_sources(&descriptor, &sources, 0).expect("resolved");

    assert!(
        build_consolidation_inputs(&sources, &[], &ResolvedConsolidationSources::new()).is_err()
    );
    let overflow_available = vec![
        utxo(&source0, 0x11, 0, u64::MAX),
        utxo(&source1, 0x22, 1, 1),
    ];
    let overflow_error = build_consolidation_inputs(&sources, &overflow_available, &resolved)
        .expect_err("selected total overflow");
    assert!(overflow_error.contains("overflow"));

    assert!(branch_address_map(&[(0, 0, "not-an-address".to_string())]).is_err());
    assert!(first_unused_change_index(&[(1, 0, "not-an-address".to_string())], &[], 1).is_err());
    assert!(branch_addresses(&descriptor, 0, 0, "kaspa")
        .expect("zero depth")
        .is_empty());
    assert!(change_branch_addresses(&descriptor, 0, 0, "kaspa")
        .expect("zero change depth")
        .is_empty());

    let addresses = branch_addresses(&descriptor, 0, 1, "kaspa").expect("one branch");
    let by_script = branch_address_map(&addresses).expect("map");
    let receive = addresses
        .iter()
        .find(|(chain, _, _)| *chain == 0)
        .expect("receive");
    let overflow_utxos = vec![
        utxo(&receive.2, 0x31, 0, u64::MAX),
        utxo(&receive.2, 0x32, 1, 1),
    ];
    let overflow_error = summarize_branch_utxos(overflow_utxos, &by_script, 1)
        .err()
        .expect("branch balance overflow");
    assert!(overflow_error.contains("overflow"));

    // A known script with a summary depth of zero reaches the out-of-range
    // mark_branch_used path without affecting the balance/labelled result.
    let single = vec![utxo(&receive.2, 0x33, 2, 7)];
    let summary = summarize_branch_utxos(single, &by_script, 0).expect("depth-zero summary");
    assert_eq!(summary.balance, 7);
    assert!(summary.receive_used.is_empty());
}

#[test]
fn consolidation_finish_rejects_bad_destination_and_unresolved_material() {
    let descriptor = descriptor();
    let source = source_address(&descriptor, 0, 0);
    let item = MultisigConsolidationSource {
        address: source.clone(),
        tx_id: "44".repeat(32),
        index: 0,
    };
    let sources_json = format!(
        "[{{\"address\":\"{}\",\"tx_id\":\"{}\",\"index\":0}}]",
        source,
        "44".repeat(32),
    );
    let prepared = prepare_consolidation(&descriptor_text(), &sources_json, 0).expect("prepared");
    let available = vec![utxo(&source, 0x44, 0, 30_000_000)];
    assert!(ready(finish_consolidation(
        prepared,
        &available,
        finish_request("not-an-address", 20_000_000, 1_000, 0, 2, "ws://unused"),
    ))
    .is_err());

    let resolved = ResolvedConsolidationSources::new();
    assert!(build_consolidation_inputs(&[item], &available, &resolved).is_err());
}

#[test]
fn branch_and_consolidation_helpers_cover_short_circuit_and_change_marking_edges() {
    assert_eq!(first_free(&[]), 0);
    assert_eq!(first_free(&[true, true]), 2);
    assert_eq!(first_free(&[true, false, true]), 1);
    assert!(branch_query(&[]).is_empty());
    assert!(require_source_count(1).is_ok());
    assert!(require_source_count(3).is_ok());
    assert!(require_source_count(0).is_err());
    assert!(require_source_count(4).is_err());

    let descriptor = descriptor();
    let receive = branch_address(&descriptor, 0, 0, 0, "kaspa").expect("receive branch");
    let change = branch_address(&descriptor, 0, 1, 0, "kaspa").expect("change branch");
    let addresses = vec![receive.clone(), change.clone()];
    let by_script = branch_address_map(&addresses).expect("branch map");
    let summary = summarize_branch_utxos(vec![utxo(&change.2, 0x71, 4, 9)], &by_script, 1)
        .expect("change summary");
    assert_eq!(summary.balance, 9);
    assert_eq!(summary.change_used, vec![true]);
    assert_eq!(summary.receive_used, vec![false]);

    let source = MultisigConsolidationSource {
        address: receive.2.clone(),
        tx_id: "72".repeat(32),
        index: 7,
    };
    let resolved = resolve_consolidation_sources(&descriptor, core::slice::from_ref(&source), 0)
        .expect("resolved source");
    let available = vec![
        // Same output index but wrong txid: exercises the left side of && false.
        utxo(&receive.2, 0x73, 7, 1),
        // Correct txid but wrong output index: left side true, right side false.
        UtxoEntry {
            tx_id: source.tx_id.clone(),
            index: 8,
            amount: 2,
            script_public_key: crate::account::address::address_to_script_pubkey(&receive.2)
                .expect("receive script"),
            block_daa_score: 0,
            covenant_id: None,
        },
        UtxoEntry {
            tx_id: source.tx_id.clone(),
            index: source.index,
            amount: 3,
            script_public_key: crate::account::address::address_to_script_pubkey(&receive.2)
                .expect("receive script"),
            block_daa_score: 0,
            covenant_id: None,
        },
    ];
    let (_, total) =
        build_consolidation_inputs(core::slice::from_ref(&source), &available, &resolved)
            .expect("selected source after decoys");
    assert_eq!(total, 3);
}

#[test]
fn hd45_branch_scan_covers_descriptor_parse_depth_cap_and_derivation_failures() {
    assert!(ready(scan_branch_json(
        "not-a-descriptor",
        0,
        1,
        "ws://unused",
        "kaspa"
    ))
    .is_err());

    let text = descriptor_text();
    #[cfg(not(target_arch = "wasm32"))]
    {
        // Depth > 100 must take the cap branch before native transport rejects
        // the request. This exercises the safety cap without requiring a node.
        let error = ready(scan_branch_json(&text, 0, 101, "ws://unused", "kaspa")).unwrap_err();
        assert!(error.contains("unavailable on native hosts"));
    }

    let descriptor = descriptor();
    assert!(branch_address(&descriptor, 0, 2, 0, "kaspa").is_err());
    assert!(branch_address(&descriptor, u32::MAX, 0, 0, "kaspa").is_err());
}

#[test]
fn consolidation_covers_parse_source_and_change_derivation_failures() {
    let descriptor = descriptor();
    let source = source_address(&descriptor, 0, 0);
    let sources_json = format!(
        "[{{\"address\":\"{}\",\"tx_id\":\"{}\",\"index\":0}}]",
        source,
        "91".repeat(32),
    );
    assert!(prepare_consolidation("not-a-descriptor", &sources_json, 0).is_err());

    let bad_source_json = format!(
        "[{{\"address\":\"not-an-address\",\"tx_id\":\"{}\",\"index\":0}}]",
        "92".repeat(32),
    );
    assert!(prepare_consolidation(&descriptor_text(), &bad_source_json, 0).is_err());

    let mut outputs = Vec::new();
    let error = ready(append_consolidation_change(
        &descriptor,
        change_request(&source, "kaspa", u32::MAX, 0, "ws://unused", 20_000_000),
        &mut outputs,
    ))
    .unwrap_err();
    assert!(!error.is_empty());
    assert!(outputs.is_empty());
}

#[test]
fn mutation_boundaries_cover_change_index_material_maps_and_change_output() {
    let text = descriptor_text();
    let descriptor = descriptor();
    let source = source_address(&descriptor, 0, 0);
    let mut req = request(&text, &source, MultisigSelection::Automatic);
    req.change_index_hint = 3;
    let source_path = resolve_address_path(&descriptor, &source, 0).expect("source path");

    assert_eq!(
        ready(transaction_change_index(&descriptor, &source_path, &req)),
        Ok(3)
    );
    let (change_script, derivations) =
        prepare_hd45_change(&descriptor, &source_path, &source, 3).expect("hd45 change");
    assert!(change_script.len() > 1);
    assert!(derivations.is_object() || derivations.is_array());
    assert_ne!(derivations, serde_json::Value::Null);

    let prepared = prepare_request(&req).expect("prepared");
    let mut plan = UnsignedTransactionPlan {
        tx_version: 0,
        inputs: vec![crate::transaction_builder::model::PlannedInput::p2pk(utxo(
            &source, 0x77, 0, 30_000_000,
        ))],
        outputs: vec![
            PlannedOutput::new(20_000_000, vec![0x51]),
            PlannedOutput::new(9_999_000, vec![0x52]),
        ],
        payload: Vec::new(),
    };
    attach_derivation_maps(&mut plan, &prepared);
    assert_eq!(
        plan.inputs[0].bip32_derivations,
        Some(prepared.source_derivations.clone())
    );
    assert_eq!(
        plan.outputs[1].bip32_derivations,
        Some(prepared.change_derivations.clone())
    );
    assert!(multisig_change_output(&mut plan.outputs[..1]).is_none());
    assert!(multisig_change_output(&mut plan.outputs).is_some());

    assert_eq!(consolidation_change(50_000_000, 20_001_000), Ok(29_999_000));
    assert!(consolidation_change(1, 2).is_err());
}

#[test]
fn consolidation_fee_rejects_each_signing_shape_mismatch_independently() {
    let descriptor = descriptor();
    let source0 = source_address(&descriptor, 0, 0);
    let source1 = source_address(&descriptor, 0, 1);
    let sources = vec![
        MultisigConsolidationSource {
            address: source0.clone(),
            tx_id: "81".repeat(32),
            index: 0,
        },
        MultisigConsolidationSource {
            address: source1.clone(),
            tx_id: "82".repeat(32),
            index: 1,
        },
    ];
    let resolved =
        resolve_consolidation_sources(&descriptor, &sources, 0).expect("resolved sources");
    let available = vec![
        utxo(&source0, 0x81, 0, 30_000_000),
        utxo(&source1, 0x82, 1, 30_000_000),
    ];
    let (inputs, _) = build_consolidation_inputs(&sources, &available, &resolved).expect("inputs");
    let destination = crate::account::address::encode_p2pk_address(&[0x83; 32], "kaspa");

    let mut sigop_mismatch = inputs.clone();
    sigop_mismatch[1].sig_op_count = sigop_mismatch[1].sig_op_count.saturating_add(1);
    assert_eq!(
        consolidation_standard_fee(&descriptor, &sigop_mismatch, &destination, 0).unwrap_err(),
        "Multisig consolidation inputs have inconsistent signing shape",
    );

    let mut redeem_len_mismatch = inputs;
    redeem_len_mismatch[1]
        .redeem_script
        .as_mut()
        .expect("redeem script")
        .push(0x00);
    assert_eq!(
        consolidation_standard_fee(&descriptor, &redeem_len_mismatch, &destination, 0).unwrap_err(),
        "Multisig consolidation inputs have inconsistent signing shape",
    );
}

#[test]
fn consolidation_finish_always_encodes_destination_and_change_outputs() {
    let descriptor = descriptor();
    let source = source_address(&descriptor, 0, 0);
    let destination = crate::account::address::encode_p2pk_address(&[0x84; 32], "kaspa");
    let sources_json = format!(
        "[{{\"address\":\"{}\",\"tx_id\":\"{}\",\"index\":0}}]",
        source,
        "84".repeat(32),
    );
    let prepared = prepare_consolidation(&descriptor_text(), &sources_json, 0)
        .expect("prepared consolidation");
    let available = vec![utxo(&source, 0x84, 0, 50_000_000)];
    let wire = ready(finish_consolidation(
        prepared,
        &available,
        finish_request(&destination, 20_000_000, 0, 0, 0, "ws://unused"),
    ))
    .expect("consolidation wire");

    let envelope = hex::decode(wire).expect("outer PSKB hex");
    assert_eq!(&envelope[..4], b"PSKB");
    let json_hex = core::str::from_utf8(&envelope[4..]).expect("PSKB JSON hex");
    let document: serde_json::Value =
        serde_json::from_slice(&hex::decode(json_hex).expect("PSKB JSON bytes"))
            .expect("PSKB JSON");
    let outputs = document[0]["outputs"].as_array().expect("outputs");
    assert_eq!(outputs.len(), 2);
    assert_eq!(outputs[0]["amount"], serde_json::json!("20000000"));
}

#[test]
fn toccata_multisig_fee_uses_final_signed_shape() {
    let text = format!("multi_hd45(2,{KPUB_A},{KPUB_B})");
    let descriptor = MultisigDescriptor::parse(&text).expect("2-of-2 descriptor");
    let source = source_address(&descriptor, 0, 0);
    let req = request(&text, &source, MultisigSelection::Automatic);
    let prepared = prepare_request(&req).expect("prepared 2-of-2");

    assert_eq!(prepared.minimum_signatures, 2);
    assert_eq!(prepared.sig_op_count, 2);
    assert_eq!(prepared.redeem_script.len(), 69);
    assert_eq!(multisig_signature_script_len(2, 69), Ok(202));
    assert_eq!(multisig_standard_fee(&prepared, 1, 0), Ok(319_400));
    assert_eq!(multisig_standard_fee(&prepared, 1, 400_000), Ok(400_000));

    // Regression: the 2-of-3 HD45 consolidation shape observed on testnet-10
    // has compute mass 4217. A requested 400_000-sompi fee must therefore be
    // raised to the node-standard minimum of 421_700 rather than broadcast.
    let text = format!("multi_hd45(2,{KPUB_A},{KPUB_B},{KPUB_C})");
    let descriptor = MultisigDescriptor::parse(&text).expect("2-of-3 descriptor");
    let source = source_address(&descriptor, 0, 0);
    let destination = crate::account::address::encode_p2pk_address(&[0x57; 32], "kaspa");
    let mut req = request(&text, &source, MultisigSelection::Automatic);
    req.destination_address = &destination;
    let prepared = prepare_request(&req).expect("prepared 2-of-3 P2PK destination");
    assert_eq!(prepared.minimum_signatures, 2);
    assert_eq!(prepared.sig_op_count, 3);
    assert_eq!(prepared.redeem_script.len(), 102);
    assert_eq!(prepared.destination_script.len(), 34);
    assert_eq!(prepared.change_script.len(), 35);
    assert_eq!(multisig_signature_script_len(2, 102), Ok(236));
    assert_eq!(multisig_standard_fee(&prepared, 1, 400_000), Ok(421_700));

    // A P2SH destination is one byte larger and adds one script byte worth of
    // compute mass, so the otherwise-identical shape is 4228 rather than 4217.
    let p2sh_req = request(&text, &source, MultisigSelection::Automatic);
    let p2sh_prepared = prepare_request(&p2sh_req).expect("prepared 2-of-3 P2SH destination");
    assert_eq!(p2sh_prepared.destination_script.len(), 35);
    assert_eq!(
        multisig_standard_fee(&p2sh_prepared, 1, 400_000),
        Ok(422_800)
    );

    let sources_json = format!(
        "[{{\"address\":\"{}\",\"tx_id\":\"{}\",\"index\":0}}]",
        source,
        "93".repeat(32),
    );
    let sources = parse_consolidation_sources(&sources_json).expect("2-of-3 sources");
    let resolved =
        resolve_consolidation_sources(&descriptor, &sources, 0).expect("resolved 2-of-3 sources");
    let available = vec![utxo(&source, 0x93, 0, 1_000_000_000)];
    let (inputs, _) = build_consolidation_inputs(&sources, &available, &resolved)
        .expect("2-of-3 consolidation inputs");
    assert_eq!(
        consolidation_standard_fee(&descriptor, &inputs, &destination, 400_000),
        Ok(421_700),
    );
    assert_eq!(
        consolidation_standard_fee(&descriptor, &inputs, &source, 400_000),
        Ok(422_800),
    );
}
