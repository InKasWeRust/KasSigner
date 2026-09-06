use super::*;

fn transaction() -> CompactKsptTransaction {
    CompactKsptTransaction {
        generation: 4,
        flags: 0,
        version: 0,
        locktime: 0,
        subnetwork_id: [0; 20],
        gas: 0,
        payload: Vec::new(),
        network: 1,
        inputs: vec![CompactKsptInput {
            previous_tx_id: [1; 32],
            previous_index: 0,
            amount: 100,
            sequence: 0,
            sig_op_count: 2,
            script_version: 0,
            script: vec![0x51],
            signatures: Vec::new(),
            redeem_script: vec![0x51, 0xae],
            derivation: None,
            ms45_derivation: Some((2, 0, 17)),
        }],
        outputs: vec![super::super::model::CompactKsptOutput {
            value: 90,
            script_version: 0,
            script: vec![0x51],
            covenant: None,
            derivation: None,
            ms45_derivation: Some((2, 1, 9)),
        }],
        stealth_tweak: None,
    }
}

#[test]
fn transaction_body_binds_hd45_input_and_output_hints() {
    let original = transaction();
    let same = transaction();
    assert!(same_transaction_body(&original, &same));

    let mut changed_input = same.clone();
    changed_input.inputs[0].ms45_derivation = Some((3, 0, 17));
    assert!(!same_transaction_body(&original, &changed_input));

    let mut changed_output = same;
    changed_output.outputs[0].ms45_derivation = Some((2, 1, 10));
    assert!(!same_transaction_body(&original, &changed_output));
}
