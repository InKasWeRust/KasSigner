//! Host-testable register-table sequencing shared by camera adapters.

pub fn write_pairs<Register, Write>(
    entries: &[(Register, u8)],
    error: &'static str,
    mut write: Write,
) -> Result<(), &'static str>
where
    Register: Copy,
    Write: FnMut(Register, u8) -> bool,
{
    for &(register, value) in entries {
        if !write(register, value) {
            return Err(error);
        }
    }
    Ok(())
}

pub fn write_pairs_with_hook<Register, Write, After>(
    entries: &[(Register, u8)],
    error: &'static str,
    mut write: Write,
    mut after: After,
) -> Result<(), &'static str>
where
    Register: Copy,
    Write: FnMut(Register, u8) -> bool,
    After: FnMut(Register, u8),
{
    for &(register, value) in entries {
        if !write(register, value) {
            return Err(error);
        }
        after(register, value);
    }
    Ok(())
}

pub fn write_banked<Write>(
    entries: &[(u8, u8, u8)],
    error: &'static str,
    mut write: Write,
) -> Result<(), &'static str>
where
    Write: FnMut(u8, u8, u8) -> bool,
{
    for &(register, value, bank) in entries {
        if !write(register, value, bank) {
            return Err(error);
        }
    }
    Ok(())
}

pub fn id_pair_matches(high: u8, low: u8, expected_high: u8, allowed_low: &[u8]) -> bool {
    high == expected_high && allowed_low.contains(&low)
}
