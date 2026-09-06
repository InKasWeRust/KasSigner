use super::*;

#[test]
fn serialization_shape_accepts_exact_input_limit_and_rejects_beyond_it() {
    let mut tx = Transaction::try_new().expect("transaction");
    tx.ensure_input_slots(MAX_INPUTS).expect("max slots");
    tx.num_inputs = MAX_INPUTS;
    tx.num_outputs = 1;
    let parsed = PsktParsed::empty();
    assert_eq!(validate_serialization_shape(&tx, &parsed, b""), Ok(()));

    tx.num_inputs = MAX_INPUTS + 1;
    assert_eq!(
        validate_serialization_shape(&tx, &parsed, b""),
        Err(PskError::TooManyInputs)
    );
}
