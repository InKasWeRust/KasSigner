use serde_json::json;

use crate::{
    account::utxo::UtxoEntry,
    transaction_builder::{
        model::{PlannedInput, PlannedOutput, UnsignedTransactionPlan},
        planning::{
            amounts::{checked_required, checked_sum},
            plan_payment_with_change,
        },
        selection::{sort_for_display, sort_largest_first, sort_smallest_first},
    },
};

fn utxo(byte: u8, index: u32, amount: u64) -> UtxoEntry {
    UtxoEntry {
        tx_id: format!("{byte:02x}").repeat(32),
        index,
        amount,
        script_public_key: vec![0x20; 34],
        block_daa_score: 0,
        covenant_id: None,
    }
}

#[test]
fn amount_and_sort_helpers_have_direct_function_coverage() {
    assert_eq!(checked_required(40, 2), Ok(42));
    assert!(checked_required(u64::MAX, 1).is_err());
    assert_eq!(checked_sum([1, 2, 3]), Ok(6));
    assert!(checked_sum([u64::MAX, 1]).is_err());

    let mut entries = vec![utxo(0x22, 2, 20), utxo(0x11, 1, 30), utxo(0x33, 0, 10)];
    sort_largest_first(&mut entries);
    assert_eq!(
        entries.iter().map(|entry| entry.amount).collect::<Vec<_>>(),
        vec![30, 20, 10]
    );

    sort_smallest_first(&mut entries);
    assert_eq!(
        entries.iter().map(|entry| entry.amount).collect::<Vec<_>>(),
        vec![10, 20, 30]
    );

    entries = vec![utxo(0x22, 1, 20), utxo(0x11, 2, 20), utxo(0x11, 1, 20)];
    sort_for_display(&mut entries);
    assert_eq!(entries[0].tx_id, "11".repeat(32));
    assert_eq!(entries[0].index, 1);
    assert_eq!(entries[1].index, 2);
}

#[test]
fn transaction_plan_model_helpers_have_direct_function_coverage() {
    let derivations = json!([{"branch": 0, "index": 7}]);
    let input = PlannedInput::p2pk(utxo(0x41, 0, 50))
        .with_bip32_derivations(derivations.clone())
        .with_derivation(0, 7);
    assert_eq!(input.bip32_derivations, Some(derivations.clone()));
    assert_eq!(input.derivation_hint, Some((0, 7)));

    let output = PlannedOutput::new(40, vec![0x51])
        .with_derivation(1, 9)
        .with_bip32_derivations(derivations.clone());
    assert_eq!(output.derivation_hint, Some((1, 9)));
    assert_eq!(output.bip32_derivations, Some(derivations));

    let derived = UnsignedTransactionPlan::standard_with_derivations(
        vec![(utxo(0x42, 1, 50), Some((0, 8))), (utxo(0x43, 2, 60), None)],
        vec![output.clone()],
    );
    assert_eq!(derived.inputs[0].derivation_hint, Some((0, 8)));
    assert_eq!(derived.inputs[1].derivation_hint, None);

    let multisig_input = PlannedInput::p2sh_multisig(utxo(0x44, 3, 70), &[0x51, 0xae], 2);
    assert_eq!(multisig_input.sig_op_count, 2);
    assert_eq!(
        multisig_input.redeem_script.as_deref(),
        Some(&[0x51, 0xae][..])
    );

    let standard = UnsignedTransactionPlan::standard(vec![utxo(0x45, 4, 80)], vec![output.clone()]);
    assert_eq!(standard.inputs.len(), 1);
    assert_eq!(standard.outputs.len(), 1);

    let multisig =
        UnsignedTransactionPlan::multisig(vec![utxo(0x46, 5, 70)], vec![output], &[0x51, 0xae], 2);
    assert_eq!(multisig.inputs[0].sig_op_count, 2);
    assert_eq!(
        multisig.inputs[0].redeem_script.as_deref(),
        Some(&[0x51, 0xae][..])
    );
}

#[test]
fn explicit_change_and_thread_policy_helpers_have_direct_function_coverage() {
    let change_address = crate::account::address::encode_p2pk_address(&[0x55; 32], "kaspa");
    let plan = plan_payment_with_change(
        vec![utxo(0x51, 0, 50_000_000)],
        vec![PlannedOutput::new(20_000_000, vec![0x20; 34])],
        1_000_000,
        &change_address,
        12,
    )
    .expect("explicit change plan");
    assert_eq!(plan.outputs.len(), 2);
    assert_eq!(plan.outputs[1].derivation_hint, Some((1, 12)));

    use crate::transaction_builder::pskb::{
        topup_policy_for, withdrawal_policy_for, GlobalThreadFamily, GlobalThreadPolicy,
    };
    let allowance = GlobalThreadPolicy::allowance(123);
    let spending = GlobalThreadPolicy::spending_limit();
    let topup = GlobalThreadPolicy::spending_limit_topup(9);
    assert_ne!(format!("{allowance:?}"), format!("{spending:?}"));
    assert!(format!("{topup:?}").contains("GlobalThreadPolicy"));

    let (locktime, _) = withdrawal_policy_for(GlobalThreadFamily::SpendingLimit, &[])
        .expect("spending-limit withdrawal policy");
    assert_eq!(locktime, 0);
    let (sequence, _) =
        topup_policy_for(GlobalThreadFamily::Allowance, &[]).expect("allowance top-up policy");
    assert_eq!(sequence, 0);
}

#[test]
fn oracle_publish_parser_entrypoint_has_direct_fail_closed_coverage() {
    let error = crate::transaction_builder::oracle_publish::parse_request_json("not-json")
        .err()
        .expect("malformed oracle publish request must fail closed");
    assert!(error.contains("oracle publish request"));
}

fn selected_utxos_json(entries: &[(u8, u32, u64)]) -> String {
    serde_json::to_string(
        &entries
            .iter()
            .map(|(byte, index, amount)| {
                serde_json::json!({
                    "tx_id": format!("{byte:02x}").repeat(32),
                    "index": index,
                    "amount": amount.to_string(),
                })
            })
            .collect::<Vec<_>>(),
    )
    .expect("selected UTXO JSON")
}

#[test]
fn selected_covenant_sweep_wrappers_have_direct_function_entry_coverage() {
    use crate::transaction_builder::covenant::{
        sweep::SweepSourceKind,
        sweeps::{owner, savings, timelocked},
    };

    let covenant_address = crate::account::address::encode_p2pk_address(&[0x61; 32], "kaspa");
    let destination_address = crate::account::address::encode_p2pk_address(&[0x62; 32], "kaspa");
    let selected = selected_utxos_json(&[(0x63, 0, 30_000_000)]);

    assert_eq!(
        SweepSourceKind::Automatic.choose("automatic", "selected"),
        "automatic"
    );
    assert_eq!(
        SweepSourceKind::Selected.choose("automatic", "selected"),
        "selected"
    );

    let (owner_prepared, owner_wire, owner_locktime) = owner::build_selected(
        &covenant_address,
        &destination_address,
        "51",
        &selected,
        1_000_000,
        "owner",
    )
    .expect("selected owner sweep");
    assert_eq!(owner_prepared.total, 30_000_000);
    assert_eq!(owner_prepared.send_amount, 29_000_000);
    assert_eq!(owner_locktime, 0);
    assert!(!owner_wire.is_empty());

    let (savings_prepared, savings_wire) = savings::build_selected(
        &covenant_address,
        &destination_address,
        "51",
        123,
        &selected,
        1_000_000,
    )
    .expect("selected savings sweep");
    assert_eq!(savings_prepared.send_amount, 29_000_000);
    assert!(!savings_wire.is_empty());

    let (beneficiary_prepared, beneficiary_wire, displayed_locktime) =
        timelocked::build_beneficiary_selected(
            &covenant_address,
            &destination_address,
            "51",
            456,
            &selected,
            1_000_000,
        )
        .expect("selected beneficiary sweep");
    assert_eq!(beneficiary_prepared.send_amount, 29_000_000);
    assert_eq!(displayed_locktime, 456);
    assert!(!beneficiary_wire.is_empty());

    let timeout_spec = timelocked::timeout_refund_spec(
        &covenant_address,
        &destination_address,
        1_000_000,
        &[0x51],
        789,
    );
    assert_eq!(timeout_spec.config.lock_time, 789);
    assert_eq!(timeout_spec.config.minimum_signatures, Some(0));
}

#[test]
fn global_thread_request_material_and_wire_wrappers_have_direct_coverage() {
    use crate::transaction_builder::pskb::{
        build_global_thread_topup, build_global_thread_withdrawal,
        prepare_global_thread_topup_material, GlobalThreadFamily, WithdrawalBuildRequest,
    };

    let covenant_address = crate::account::address::encode_p2pk_address(&[0x71; 32], "kaspa");
    let destination_address = crate::account::address::encode_p2pk_address(&[0x72; 32], "kaspa");
    let selected = selected_utxos_json(&[(0x73, 2, 25_000_000)]);
    let covenant_id_hex = "74".repeat(32);

    let withdrawal = build_global_thread_withdrawal(WithdrawalBuildRequest {
        family: GlobalThreadFamily::SpendingLimit,
        covenant_address: &covenant_address,
        destination_address: &destination_address,
        redeem_script_hex: "51",
        covenant_id_hex: &covenant_id_hex,
        withdrawal: 25_000_000,
        fee: 1_000_000,
        selected_utxos_json: &selected,
    })
    .expect("typed global-thread withdrawal");
    assert_eq!(withdrawal.input_count, 1);
    assert_eq!(withdrawal.total, 25_000_000);
    assert!(withdrawal.is_close);
    assert!(!withdrawal.wire.is_empty());

    let thread_json = serde_json::json!({
        "tx_id": "75".repeat(32),
        "index": 3,
        "amount": "50_000_000".replace('_', ""),
        "block_daa_score": "123",
    })
    .to_string();
    let topup_material = prepare_global_thread_topup_material(
        GlobalThreadFamily::SpendingLimit,
        &covenant_address,
        "51",
        &covenant_id_hex,
        &thread_json,
    )
    .expect("typed global-thread top-up material");
    let topup =
        build_global_thread_topup(topup_material, vec![utxo(0x76, 4, 20_000_000)], 1_000_000)
            .expect("typed global-thread top-up");
    assert_eq!(topup.selected_count, 1);
    assert_eq!(topup.thread_amount, 50_000_000);
    assert!(topup.continuation > topup.thread_amount);
    assert!(!topup.wire.is_empty());
}

#[test]
fn selected_send_network_boundary_enters_before_transport() {
    use crate::wasm_api::test_support::ready;

    let wallet = crate::account::bip32::WalletData {
        kpub: "coverage".to_string(),
        receive_addresses: vec![],
        change_addresses: vec![],
        next_receive_index: 0,
        next_change_index: 0,
    };
    let result = ready(crate::transaction_builder::standard::create_send_selected(
        &wallet,
        "not-an-address",
        20_000_000,
        300_000,
        &[0],
        "ws://unused",
    ));
    assert!(result.is_err());
}

#[test]
fn measured_domain_uncovered_entries_have_direct_native_coverage() {
    use crate::{
        contracts::{
            oracle::script::{build_oracle_mb_genesis_redeem, build_oracle_mb_heartbeat_script},
            zk::crowdfund,
        },
        transaction_builder::covenant::CovenantEncoding,
    };

    let heartbeat = build_oracle_mb_heartbeat_script();
    assert!(!heartbeat.is_empty());
    let genesis = build_oracle_mb_genesis_redeem(
        123,
        456,
        &[0x11; 32],
        &[0x22; 32],
        &[0x33; 32],
        1,
        &[0x44; 32],
    );
    assert!(!genesis.is_empty());

    assert_eq!(
        crowdfund::decode_hex("00ff", "fixture"),
        Ok(vec![0x00, 0xff])
    );
    assert!(crowdfund::decode_hex("0z", "fixture").is_err());

    assert!(CovenantEncoding::Payload {
        payload_hex: "00",
        tag_genesis: true
    }
    .uses_tagged_genesis_policy());
    assert!(!CovenantEncoding::BoundGenesis.uses_tagged_genesis_policy());

    let encoded = crate::transaction_builder::covenant::shipping::plan::encode_pskb(
        serde_json::json!({"txVersion": 0}),
        Vec::new(),
        serde_json::json!([]),
    )
    .expect("shipping PSKB encoding");
    assert!(!encoded.is_empty());
}
