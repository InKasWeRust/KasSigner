use crate::transaction::model::Transaction;

use super::super::{is_fully_signed, signature_status};
use super::common::{add_single_signature, transaction};

#[test]
fn empty_transaction_is_not_fully_signed() {
    let tx = Transaction::try_new().expect("transaction test allocation");
    assert!(!is_fully_signed(&tx));
    assert_eq!(signature_status(&tx), (0, 0));
}

#[test]
fn status_and_completion_share_the_same_policy() {
    let mut tx = transaction();
    assert_eq!(signature_status(&tx), (0, 1));
    assert!(!is_fully_signed(&tx));

    add_single_signature(&mut tx, 0, [0x55; 64]);
    assert_eq!(signature_status(&tx), (1, 1));
    assert!(is_fully_signed(&tx));
}

#[test]
fn status_handles_multisig_p2sh_and_dynamic_input_capacity() {
    const MANY_INPUTS: usize = 16;
    use super::common::{add_single_signature, set_p2sh_script};

    fn two_of_two() -> [u8; 69] {
        let mut script = [0u8; 69];
        script[0] = 0x52;
        script[1] = 0x20;
        script[2..34].fill(0x11);
        script[34] = 0x20;
        script[35..67].fill(0x22);
        script[67] = 0x52;
        script[68] = 0xae;
        script
    }

    let multisig_script = two_of_two();
    let mut direct = transaction();
    direct.inputs[0].utxo_entry.script_public_key.script[..multisig_script.len()]
        .copy_from_slice(&multisig_script);
    direct.inputs[0].utxo_entry.script_public_key.script_len = multisig_script.len();
    assert_eq!(signature_status(&direct), (0, 2));
    assert!(!is_fully_signed(&direct));
    add_single_signature(&mut direct, 0, [0x31; 64]);
    assert_eq!(signature_status(&direct), (1, 2));
    assert!(!is_fully_signed(&direct));
    direct.inputs[0].sigs[1] = direct.inputs[0].sigs[0].clone();
    direct.inputs[0].sigs[1].pubkey_pos = 1;
    direct.inputs[0].sig_count = 2;
    assert_eq!(signature_status(&direct), (2, 2));
    assert!(is_fully_signed(&direct));

    let mut p2sh_multisig = transaction();
    set_p2sh_script(&mut p2sh_multisig, &multisig_script);
    assert_eq!(signature_status(&p2sh_multisig), (0, 2));
    add_single_signature(&mut p2sh_multisig, 0, [0x41; 64]);
    assert_eq!(signature_status(&p2sh_multisig), (1, 2));

    let mut p2sh_single = transaction();
    set_p2sh_script(&mut p2sh_single, &[0x51]);
    assert_eq!(signature_status(&p2sh_single), (0, 1));
    add_single_signature(&mut p2sh_single, 0, [0x51; 64]);
    assert_eq!(signature_status(&p2sh_single), (1, 1));
    assert!(is_fully_signed(&p2sh_single));

    let mut signed = transaction();
    add_single_signature(&mut signed, 0, [0x61; 64]);
    let mut exact = Transaction::try_new().expect("transaction test allocation");
    exact.ensure_input_slots(MANY_INPUTS).expect("grow inputs");
    exact.num_inputs = MANY_INPUTS;
    for index in 0..MANY_INPUTS {
        exact.inputs[index] = signed.inputs[0].clone();
    }
    assert_eq!(
        signature_status(&exact),
        (MANY_INPUTS as u32, MANY_INPUTS as u32)
    );
    assert!(is_fully_signed(&exact));

    let mut excessive = exact;
    excessive.num_inputs = excessive.inputs.len() + 1;
    assert_eq!(signature_status(&excessive), (0, 0));
    assert!(!is_fully_signed(&excessive));
}
