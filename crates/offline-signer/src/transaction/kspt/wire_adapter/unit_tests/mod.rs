use super::*;
use crate::transaction::model::MAX_REDEEM_SIZE;
use alloc::vec;

#[test]
fn hardware_sink_signature_rejects_input_and_slot_boundaries_independently() {
    let mut tx = Transaction::try_new().expect("transaction");
    tx.ensure_input_slots(1).expect("slot");
    tx.num_inputs = 1;
    let signature = kspt::Signature {
        position: 0,
        sighash: 1,
        bytes: [7; 64],
    };
    let mut sink = HardwareSink { tx: &mut tx };
    assert_eq!(
        sink.signature(1, 0, signature),
        Err(PsktError::TooManySignatures)
    );
    assert_eq!(
        sink.signature(0, MAX_SIGS_PER_INPUT as u8, signature),
        Err(PsktError::TooManySignatures)
    );
}

#[test]
fn hardware_sink_redeem_accepts_exact_capacity_and_rejects_oversize() {
    let mut tx = Transaction::try_new().expect("transaction");
    tx.ensure_input_slots(1).expect("slot");
    tx.num_inputs = 1;
    let mut sink = HardwareSink { tx: &mut tx };
    assert_eq!(sink.redeem(0, &vec![0x51; MAX_REDEEM_SIZE]), Ok(()));
    assert_eq!(
        sink.redeem(0, &vec![0x51; MAX_REDEEM_SIZE + 1]),
        Err(PsktError::ScriptTooLong)
    );
}

#[test]
fn hardware_sink_output_rejects_index_and_script_boundaries_independently() {
    let mut tx = Transaction::try_new().expect("transaction");
    tx.num_outputs = 1;
    let normal = [0x51];
    let oversized = vec![0x51; MAX_SCRIPT_SIZE + 1];
    let mut sink = HardwareSink { tx: &mut tx };
    assert_eq!(
        sink.output(
            1,
            kspt::Output {
                amount: 1,
                script_version: 0,
                script: &normal
            }
        ),
        Err(PsktError::ScriptTooLong)
    );
    assert_eq!(
        sink.output(
            0,
            kspt::Output {
                amount: 1,
                script_version: 0,
                script: &oversized
            }
        ),
        Err(PsktError::ScriptTooLong)
    );
}
