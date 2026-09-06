use crate::transaction_builder::planning::amounts::storage_mass_estimate;
use crate::transaction_builder::{model::PlannedOutput, planning::amounts::utxo_plurality};

#[test]
fn consolidation_rejects_empty_and_singleton_sets_before_sorting() {
    assert_eq!(
        super::super::selection::select_for_consolidation(Vec::new(), 5).unwrap_err(),
        "No UTXOs to consolidate"
    );
    assert_eq!(
        super::super::selection::select_for_consolidation(vec![super::utxo(0x11, 0, 10)], 5)
            .unwrap_err(),
        "Only 1 UTXO — nothing to consolidate"
    );
}

#[test]
fn consolidation_keeps_largest_utxos_when_limited() {
    let selected = super::super::selection::select_for_consolidation(
        vec![
            super::utxo(0x11, 0, 10),
            super::utxo(0x22, 1, 40),
            super::utxo(0x33, 2, 20),
            super::utxo(0x44, 3, 30),
        ],
        3,
    )
    .expect("consolidation selection");
    assert_eq!(
        selected
            .iter()
            .map(|entry| entry.amount)
            .collect::<Vec<_>>(),
        vec![40, 30, 20]
    );
}

#[test]
fn smallest_first_sort_is_not_a_noop() {
    let mut utxos = vec![
        super::utxo(0x11, 0, 30),
        super::utxo(0x22, 1, 10),
        super::utxo(0x33, 2, 20),
    ];
    super::super::selection::sort_smallest_first(&mut utxos);
    assert_eq!(
        utxos.iter().map(|entry| entry.amount).collect::<Vec<_>>(),
        vec![10, 20, 30]
    );
}

#[test]
fn multisig_accepts_exactly_three_inputs_and_rejects_four() {
    let destination = PlannedOutput::new(25, vec![0x51]);
    let three = vec![
        super::utxo(0x11, 0, 10),
        super::utxo(0x22, 1, 10),
        super::utxo(0x33, 2, 10),
    ];
    let (plan, change) = super::super::planning::plan_multisig(
        three.clone(),
        destination.clone(),
        5,
        vec![0x52],
        &[0x51],
        1,
    )
    .expect("three inputs are the protocol maximum");
    assert_eq!(change, 0);
    assert_eq!(plan.inputs.len(), 3);
    assert_eq!(plan.outputs.len(), 1);

    let mut four = three;
    four.push(super::utxo(0x44, 3, 10));
    let error = super::super::planning::plan_multisig(four, destination, 5, vec![0x52], &[0x51], 1)
        .unwrap_err();
    assert!(error.contains("limited to 3 inputs"));
}

#[test]
fn multisig_adds_only_positive_non_dust_change() {
    let destination = PlannedOutput::new(20_000_000, vec![0x51]);
    let (plan, change) = super::super::planning::plan_multisig(
        vec![super::utxo(0x11, 0, 40_000_001)],
        destination,
        1,
        vec![0x52],
        &[0x51],
        1,
    )
    .expect("multisig plan");
    assert_eq!(change, 20_000_000);
    assert_eq!(plan.outputs.len(), 2);
    assert_eq!(plan.outputs[1].amount, 20_000_000);
}

#[test]
fn storage_mass_uses_relaxed_harmonic_rule_for_two_by_two_plurality() {
    let mass = storage_mass_estimate(
        &[(90_000_000, 1), (10_000_000, 1)],
        &[(10_000_000, 1), (10_000_000, 1)],
    )
    .expect("storage mass");
    assert_eq!(mass, 88_889);
}

#[test]
fn utxo_plurality_counts_covenant_bytes_across_the_storage_unit_boundary() {
    // 63 fixed bytes + 6 script bytes fit in one 100-byte storage unit.
    assert_eq!(utxo_plurality(6, false), 1);
    // A 32-byte covenant id pushes the same UTXO to 101 bytes => two units.
    assert_eq!(utxo_plurality(6, true), 2);
}

#[test]
fn storage_mass_fee_distinguishes_dust_and_non_dust_change() {
    let dust_selected = vec![super::utxo(0x51, 0, 15_000_000)];
    assert_eq!(
        super::super::standard::storage_mass_fee(&dust_selected, 15_000_000, 10_000_000, 0,)
            .expect("dust-change fee"),
        3_666_740
    );

    let non_dust_selected = vec![super::utxo(0x52, 0, 30_000_000)];
    assert_eq!(
        super::super::standard::storage_mass_fee(&non_dust_selected, 30_000_000, 10_000_000, 0,)
            .expect("non-dust-change fee"),
        16_017_540
    );
}

#[test]
fn standard_input_count_follows_public_signer_capability() {
    let limit = usize::from(kassigner_protocol::SIGNER_CAPABILITIES.max_inputs);
    assert_eq!(limit, 32);
    assert!(super::super::standard::validate_signer_input_count(1).is_ok());
    assert!(super::super::standard::validate_signer_input_count(limit).is_ok());
    assert!(super::super::standard::validate_signer_input_count(limit + 1).is_err());
}
