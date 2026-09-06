use crate::transaction::{
    model::{Transaction, MAX_SIGS_PER_INPUT},
    std_pskt::{move_ksp_sigs_to_pskt, pskt_signature_status},
};

fn p2pk_transaction() -> Transaction {
    let mut transaction = Transaction::try_new().expect("transaction test allocation");
    transaction.num_inputs = 1;
    let script = &mut transaction.inputs[0].utxo_entry.script_public_key;
    script.script[0] = 0x20;
    script.script[1..33].fill(0x11);
    script.script[33] = 0xac;
    script.script_len = 34;
    transaction
}

#[test]
fn pskt_signature_merge_preserves_existing_entries_deduplicates_and_sorts() {
    let mut transaction = p2pk_transaction();
    let input = &mut transaction.inputs[0];

    input.incoming_partial_sigs[0].present = true;
    input.incoming_partial_sigs[0].pubkey = [0x03; 33];
    input.incoming_partial_sigs[0].signature = [0x33; 64];
    input.incoming_partial_sigs_count = 1;

    input.sig_count = 5;
    input.sigs[0].present = false;
    input.sigs[1].present = true;
    input.sigs[1].pubkey_compressed = [0u8; 33];
    input.sigs[2].present = true;
    input.sigs[2].pubkey_compressed = [0x03; 33];
    input.sigs[3].present = true;
    input.sigs[3].pubkey_compressed = [0x02; 33];
    input.sigs[3].signature = [0x22; 64];
    input.sigs[4].present = true;
    input.sigs[4].pubkey_compressed = [0x04; 33];
    input.sigs[4].signature = [0x44; 64];

    move_ksp_sigs_to_pskt(&mut transaction);

    let input = &transaction.inputs[0];
    assert_eq!(input.incoming_partial_sigs_count, 3);
    assert_eq!(input.incoming_partial_sigs[0].pubkey, [0x02; 33]);
    assert_eq!(input.incoming_partial_sigs[1].pubkey, [0x03; 33]);
    assert_eq!(input.incoming_partial_sigs[2].pubkey, [0x04; 33]);
    assert_eq!(input.incoming_partial_sigs[1].signature, [0x33; 64]);

    move_ksp_sigs_to_pskt(&mut transaction);
    assert_eq!(transaction.inputs[0].incoming_partial_sigs_count, 3);
}

#[test]
fn pskt_signature_merge_stops_at_fixed_capacity() {
    let mut transaction = p2pk_transaction();
    let input = &mut transaction.inputs[0];
    input.incoming_partial_sigs_count = MAX_SIGS_PER_INPUT as u8;
    for index in 0..MAX_SIGS_PER_INPUT {
        input.incoming_partial_sigs[index].present = true;
        input.incoming_partial_sigs[index].pubkey = [index as u8 + 1; 33];
    }
    input.sig_count = 1;
    input.sigs[0].present = true;
    input.sigs[0].pubkey_compressed = [0xff; 33];

    move_ksp_sigs_to_pskt(&mut transaction);
    assert_eq!(
        transaction.inputs[0].incoming_partial_sigs_count,
        MAX_SIGS_PER_INPUT as u8
    );
}

#[test]
fn pskt_signature_status_handles_p2pk_unknown_and_multisig_inputs() {
    let mut p2pk = p2pk_transaction();
    assert_eq!(pskt_signature_status(&p2pk), (0, 1));
    p2pk.inputs[0].incoming_partial_sigs_count = 2;
    assert_eq!(pskt_signature_status(&p2pk), (1, 1));

    let mut unknown = Transaction::try_new().expect("transaction test allocation");
    unknown.num_inputs = 1;
    assert_eq!(pskt_signature_status(&unknown), (0, 1));

    let mut multisig = Transaction::try_new().expect("transaction test allocation");
    multisig.num_inputs = 1;
    let mut redeem = [0u8; 69];
    redeem[0] = 0x52;
    redeem[1] = 0x20;
    redeem[2..34].fill(0x11);
    redeem[34] = 0x20;
    redeem[35..67].fill(0x22);
    redeem[67] = 0x52;
    redeem[68] = 0xae;
    multisig.store_redeem(0, &redeem).expect("redeem script");
    let script = &mut multisig.inputs[0].utxo_entry.script_public_key;
    script.script[0] = 0xaa;
    script.script[1] = 0x20;
    script.script[2..34].fill(0x44);
    script.script[34] = 0x87;
    script.script_len = 35;
    multisig.inputs[0].incoming_partial_sigs_count = 3;
    assert_eq!(pskt_signature_status(&multisig), (2, 2));
}

#[test]
fn pskt_signature_status_handles_p2sh_without_multisig_metadata() {
    let mut transaction = Transaction::try_new().expect("transaction test allocation");
    transaction.num_inputs = 1;
    let script = &mut transaction.inputs[0].utxo_entry.script_public_key;
    script.script[0] = 0xaa;
    script.script[1] = 0x20;
    script.script[2..34].fill(0x44);
    script.script[34] = 0x87;
    script.script_len = 35;

    // A P2SH input without a stored/parseable multisig redeem script must not
    // fabricate a signature requirement from absent multisig metadata.
    assert_eq!(pskt_signature_status(&transaction), (0, 0));
}
