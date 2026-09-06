/// Groth16 precompile script units for a verifier with `public_inputs` field inputs.
/// Mirrors the Kaspa Toccata cost model used by OP_ZK_PRECOMPILE tag 0x20.
pub const fn groth16_script_units(public_inputs: u64) -> u64 {
    const TAG: u64 = 14_000_000;
    const VK_ELEMENT: u64 = 250_000;
    const BLAKE2B_VK: u64 = 640;
    const PUSH_BYTES: u64 = 2_000;
    const SAFETY: u64 = 50_000;
    TAG + (public_inputs + 1) * VK_ELEMENT + BLAKE2B_VK + PUSH_BYTES + SAFETY
}

pub const fn groth16_sig_op_count(public_inputs: u64) -> u8 {
    const FREE: u64 = 9_999;
    let needed = groth16_script_units(public_inputs);
    let sigops = (needed - FREE).div_ceil(100_000);
    if sigops > u8::MAX as u64 {
        u8::MAX
    } else {
        sigops as u8
    }
}

pub const fn groth16_min_fee_sompi(public_inputs: u64) -> u64 {
    const SCRIPT_UNITS_PER_GRAM: u64 = 100;
    const MIN_FEERATE_SOMPI_PER_GRAM: u64 = 100;
    const SIZE_MARGIN_GRAMS: u64 = 20_000;
    let script_grams = groth16_script_units(public_inputs) / SCRIPT_UNITS_PER_GRAM;
    (script_grams + SIZE_MARGIN_GRAMS) * MIN_FEERATE_SOMPI_PER_GRAM
}

pub const GROTH16_TAG: u8 = 0x20;
pub const GROTH16_SIG_OP_COUNT: u8 = groth16_sig_op_count(1);
pub const RISC0_TAG: u8 = 0x21;
pub const RISC0_SIG_OP_COUNT: u8 = u8::MAX;
