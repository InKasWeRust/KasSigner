#[derive(Debug, Clone, Copy)]
pub(crate) struct CovenantFeeShape {
    pub(crate) p2pk_inputs: u64,
    pub(crate) redeem_bytes: u64,
    pub(crate) payload_bytes: u64,
    pub(crate) binding_bytes: u64,
}

impl CovenantFeeShape {
    pub(crate) fn calculate(self) -> Result<u64, String> {
        const FEE_RATE: u64 = 100;
        const FEE_MARKUP_PERCENT: u64 = 115;

        let has_p2sh_input = self.redeem_bytes > 0;
        let input_count = self
            .p2pk_inputs
            .checked_add(u64::from(has_p2sh_input))
            .ok_or("Covenant fee input-count overflow".to_string())?;
        let p2pk_bytes = self
            .p2pk_inputs
            .checked_mul(45 + 66 + 4)
            .ok_or("Covenant fee input-byte estimate overflow".to_string())?;
        let p2sh_bytes = 118u64
            .checked_add(self.redeem_bytes)
            .ok_or("Covenant P2SH input-byte estimate overflow".to_string())?
            * u64::from(has_p2sh_input);
        let covenant_output_bytes = 35u64
            .checked_add(self.binding_bytes)
            .ok_or("Covenant fee output-byte estimate overflow".to_string())?;
        let estimated_transaction_bytes = 46u64
            .checked_add(p2pk_bytes)
            .and_then(|value| value.checked_add(p2sh_bytes))
            .and_then(|value| value.checked_add(covenant_output_bytes))
            .and_then(|value| value.checked_add(43))
            .and_then(|value| value.checked_add(self.payload_bytes))
            .and_then(|value| value.checked_add(10))
            .ok_or("Covenant transaction-byte estimate overflow".to_string())?;
        let signature_operation_mass = input_count
            .checked_mul(1000)
            .ok_or("Covenant signature-operation mass overflow".to_string())?;
        let script_public_key_mass = (35u64 + 34u64) * 10u64;
        let compute_mass = estimated_transaction_bytes
            .checked_add(signature_operation_mass)
            .and_then(|value| value.checked_add(script_public_key_mass))
            .ok_or("Covenant compute-mass estimate overflow".to_string())?;

        let fee = compute_mass
            .checked_mul(FEE_RATE)
            .and_then(|value| value.checked_mul(FEE_MARKUP_PERCENT))
            .ok_or("Covenant fee estimate overflow".to_string())?
            / 100;
        Ok(fee.max(100_000))
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) struct DepositFeePolicy {
    payload_len: u64,
    tag_genesis: bool,
}

impl DepositFeePolicy {
    pub(super) fn new(payload_len: u64, tag_genesis: bool) -> Self {
        Self {
            payload_len,
            tag_genesis,
        }
    }

    pub(super) fn calculate(self, input_count: u64) -> Result<u64, String> {
        CovenantFeeShape {
            p2pk_inputs: input_count,
            redeem_bytes: 0,
            payload_bytes: self.payload_len,
            binding_bytes: if self.tag_genesis { 32 } else { 0 },
        }
        .calculate()
    }
}
