use serde_json::Value;
/// A transaction output after address/script resolution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlannedOutput {
    pub amount: u64,
    pub script_public_key: Vec<u8>,
    /// Public BIP44 derivation hint `(branch, index)` for a wallet-owned output.
    pub derivation_hint: Option<(u8, u32)>,
    pub bip32_derivations: Option<Value>,
}

impl PlannedOutput {
    #[must_use]
    pub fn new(amount: u64, script_public_key: Vec<u8>) -> Self {
        Self {
            amount,
            script_public_key,
            derivation_hint: None,
            bip32_derivations: None,
        }
    }

    #[must_use]
    pub fn with_derivation(mut self, branch: u8, index: u32) -> Self {
        self.derivation_hint = Some((branch, index));
        self
    }

    #[must_use]
    pub fn with_bip32_derivations(mut self, derivations: Value) -> Self {
        self.bip32_derivations = Some(derivations);
        self
    }
}
