use super::*;

#[test]
fn exact_balance_does_not_append_zero_change_output() {
    let change = crate::account::address::encode_p2pk_address(&[0x44; 32], "kaspa");
    let selected = vec![UtxoEntry {
        tx_id: "11".repeat(32),
        index: 0,
        amount: 10_000,
        script_public_key: vec![0x51],
        block_daa_score: 0,
        covenant_id: None,
    }];
    let recipients = vec![PlannedOutput::new(9_000, vec![0x52])];
    let plan =
        plan_payment_with_change(selected, recipients, 1_000, &change, 7).expect("exact balance");
    assert_eq!(plan.outputs.len(), 1);
    assert_eq!(plan.outputs[0].amount, 9_000);
}
