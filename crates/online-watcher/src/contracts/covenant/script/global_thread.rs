//! Shared covenant-ID single-thread enforcement script fragment.
use super::push_int;
/// Append the common continuation-or-close enforcement used by global-thread
/// spending-limit and allowance covenants.
pub(super) fn append_global_thread_enforcement(script: &mut Vec<u8>, max_withdraw_sompi: u64) {
    use super::covenant_ops::*;

    script.push(OP_TX_INPUT_INDEX);
    script.push(OP_INPUT_COVENANT_ID);
    script.push(OP_DUP);
    script.push(OP_COV_OUTPUT_COUNT);
    script.push(OP_DUP);
    push_int(script, 1);
    script.push(OP_EQUAL);

    script.push(OP_IF);
    script.push(OP_DROP);
    push_int(script, 0);
    script.push(OP_COV_OUTPUT_IDX);
    script.push(OP_DUP);
    script.push(OP_TX_OUTPUT_SPK);
    script.push(OP_TX_INPUT_INDEX);
    script.push(OP_TX_INPUT_SPK);
    script.push(OP_EQUALVERIFY);
    script.push(OP_TX_OUTPUT_AMOUNT);
    script.push(OP_TX_INPUT_INDEX);
    script.push(OP_TX_INPUT_AMOUNT);
    push_int(script, max_withdraw_sompi);
    script.push(OP_SUB);
    script.push(OP_GREATERTHANOREQUAL);
    script.push(OP_VERIFY);

    script.push(OP_ELSE);
    push_int(script, 0);
    script.push(OP_EQUALVERIFY);
    script.push(OP_DROP);
    script.push(OP_TX_INPUT_INDEX);
    script.push(OP_TX_INPUT_AMOUNT);
    push_int(script, max_withdraw_sompi);
    script.push(OP_LESSTHANOREQUAL);
    script.push(OP_VERIFY);
    script.push(OP_ENDIF);
    script.push(OP_1);
}
