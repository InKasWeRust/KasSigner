use crate::transaction_builder::model::PlannedOutput;
use serde_json::Value;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PskbOutput {
    pub amount: u64,
    pub script: Vec<u8>,
    pub covenant: Option<(u16, [u8; 32])>,
    pub derivation_hint: Option<(u8, u32)>,
    pub bip32_derivations: Option<Value>,
}

impl PskbOutput {
    #[must_use]
    pub fn plain(amount: u64, script: Vec<u8>) -> Self {
        Self {
            amount,
            script,
            covenant: None,
            derivation_hint: None,
            bip32_derivations: None,
        }
    }
}

impl From<&PlannedOutput> for PskbOutput {
    fn from(output: &PlannedOutput) -> Self {
        let mut result = Self::plain(output.amount, output.script_public_key.clone());
        result.derivation_hint = output.derivation_hint;
        result.bip32_derivations = output.bip32_derivations.clone();
        result
    }
}
