//! Host-testable register-write sequencing for board power devices.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegisterWriteStep {
    pub register: u8,
    pub value: u8,
    pub delay_after_ms: u32,
    pub error: &'static str,
}

impl RegisterWriteStep {
    pub const fn new(register: u8, value: u8, delay_after_ms: u32, error: &'static str) -> Self {
        Self {
            register,
            value,
            delay_after_ms,
            error,
        }
    }
}

pub fn run_register_writes<Write, Delay>(
    address: u8,
    steps: &[RegisterWriteStep],
    mut write: Write,
    mut delay: Delay,
) -> Result<(), &'static str>
where
    Write: FnMut(u8, u8, u8) -> bool,
    Delay: FnMut(u32),
{
    for step in steps {
        if !write(address, step.register, step.value) {
            return Err(step.error);
        }
        if step.delay_after_ms != 0 {
            delay(step.delay_after_ms);
        }
    }
    Ok(())
}
