use super::{number::find_preceding_script_integer, opcode};

pub fn extract_cltv_locktime(script: &[u8]) -> Result<Option<u64>, String> {
    find_preceding_script_integer(script, opcode::OP_CHECKLOCKTIMEVERIFY)
}

pub fn extract_csv_sequence(script: &[u8]) -> Result<Option<u64>, String> {
    find_preceding_script_integer(script, opcode::OP_CHECKSEQUENCEVERIFY)
}
