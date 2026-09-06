const STORAGE_MASS_C: u64 = 1_000_000_000_000;
const MAX_STANDARD_MASS: u64 = 100_000;
const DUST_THRESHOLD: u64 = 20_000_000;

#[must_use]
pub fn is_dust(amount: u64) -> bool {
    if amount == 0 {
        return true;
    }
    if amount >= DUST_THRESHOLD {
        return false;
    }
    STORAGE_MASS_C / amount > MAX_STANDARD_MASS
}

pub fn checked_required(amount: u64, fee: u64) -> Result<u64, String> {
    amount
        .checked_add(fee)
        .ok_or("Amount plus fee exceeds supported monetary range".to_string())
}

pub fn checked_sum(values: impl IntoIterator<Item = u64>) -> Result<u64, String> {
    values.into_iter().try_fold(0u64, |total, value| {
        total
            .checked_add(value)
            .ok_or("Amount total exceeds supported monetary range".to_string())
    })
}

/// Consensus-mirroring storage mass (KIP-9 with v2.0.1 plurality).
///
/// Arithmetic overflow is a planner error. Negative mass contributions are
/// explicitly floored at zero, matching the non-negative storage-mass rule.
///
/// Return the KIP-9 storage plurality for a UTXO with the supplied script shape.
/// The fixed UTXO fields consume 63 bytes and each storage unit is 100 bytes.
#[must_use]
pub fn utxo_plurality(script_len: usize, has_covenant_id: bool) -> u64 {
    const FIXED_UTXO_BYTES: usize = 63;
    const UTXO_UNIT_BYTES: usize = 100;
    let covenant_bytes = if has_covenant_id { 32 } else { 0 };
    let bytes = FIXED_UTXO_BYTES + script_len + covenant_bytes;
    bytes.div_ceil(UTXO_UNIT_BYTES) as u64
}

pub fn storage_mass_estimate(ins: &[(u64, u64)], outs: &[(u64, u64)]) -> Result<u64, String> {
    let outputs_plurality = plurality_total(outs, "Output")?;
    let inputs_plurality = plurality_total(ins, "Input")?;
    let harmonic_outputs = harmonic_mass(outs, "Output")?;
    let input_mass = if uses_relaxed_storage_mass(inputs_plurality, outputs_plurality) {
        harmonic_mass(ins, "Input")?
    } else {
        arithmetic_input_mass(ins, inputs_plurality)?
    };
    Ok(harmonic_outputs.saturating_sub(input_mass))
}

fn plurality_total(entries: &[(u64, u64)], kind: &str) -> Result<u64, String> {
    entries.iter().try_fold(0u64, |total, &(_, plurality)| {
        total
            .checked_add(plurality)
            .ok_or(format!("{kind} plurality exceeds supported range"))
    })
}

fn harmonic_mass(entries: &[(u64, u64)], kind: &str) -> Result<u64, String> {
    entries
        .iter()
        .try_fold(0u64, |total, &(amount, plurality)| {
            let term = storage_mass_term(amount, plurality, kind)?;
            total
                .checked_add(term)
                .ok_or(format!("{kind} storage mass exceeds supported range"))
        })
}

fn storage_mass_term(amount: u64, plurality: u64, kind: &str) -> Result<u64, String> {
    STORAGE_MASS_C
        .checked_mul(plurality)
        .and_then(|value| value.checked_mul(plurality))
        .map(|weighted| weighted / amount.max(1))
        .ok_or(format!("{kind} storage-mass term exceeds supported range"))
}

#[must_use]
fn uses_relaxed_storage_mass(inputs_plurality: u64, outputs_plurality: u64) -> bool {
    matches!(
        (inputs_plurality, outputs_plurality),
        (1, _) | (_, 1) | (2, 2)
    )
}

fn arithmetic_input_mass(ins: &[(u64, u64)], inputs_plurality: u64) -> Result<u64, String> {
    let input_sum = checked_sum(ins.iter().map(|(amount, _)| *amount))
        .map_err(|_| "Input amount total exceeds supported monetary range".to_string())?;
    let mean_input = (input_sum / inputs_plurality.max(1)).max(1);
    inputs_plurality
        .checked_mul(STORAGE_MASS_C / mean_input)
        .ok_or("Arithmetic input storage mass exceeds supported range".to_string())
}
