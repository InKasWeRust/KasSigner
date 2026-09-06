use serde_json::Value;

use crate::account::utxo::UtxoEntry;

/// Typed input description for browser-compatible PSKB planning.
#[derive(Clone, Debug)]
pub struct PskbInputPlan {
    pub utxo: UtxoEntry,
    pub source_script_public_key: Vec<u8>,
    pub sequence: u64,
    pub block_daa_score: u64,
    pub sig_op_count: u8,
    pub minimum_signatures: u8,
    pub redeem_script: Option<Vec<u8>>,
    pub proprietaries: Value,
    pub min_time: Value,
}

#[derive(Clone, Debug)]
pub struct CovenantInputSettings {
    pub sequence: u64,
    pub sig_op_count: u8,
    pub minimum_signatures: u8,
    pub proprietaries: Value,
    pub min_time: Value,
}

impl PskbInputPlan {
    #[must_use]
    pub fn covenant(
        utxo: UtxoEntry,
        source_script_public_key: &[u8],
        redeem_script: &[u8],
        settings: CovenantInputSettings,
    ) -> Self {
        Self {
            utxo,
            source_script_public_key: source_script_public_key.to_vec(),
            sequence: settings.sequence,
            block_daa_score: 0,
            sig_op_count: settings.sig_op_count,
            minimum_signatures: settings.minimum_signatures,
            redeem_script: Some(redeem_script.to_vec()),
            proprietaries: settings.proprietaries,
            min_time: settings.min_time,
        }
    }

    #[cfg(any(test, target_arch = "wasm32"))]
    #[must_use]
    pub fn p2pk(utxo: UtxoEntry, source_script_public_key: &[u8], proprietaries: Value) -> Self {
        Self {
            utxo,
            source_script_public_key: source_script_public_key.to_vec(),
            sequence: 0,
            block_daa_score: 0,
            sig_op_count: 1,
            minimum_signatures: 1,
            redeem_script: None,
            proprietaries,
            min_time: Value::from(0),
        }
    }
}

/// Typed output description. `covenant_binding_field == None` omits the field;
/// `Some(Value::Null)` emits an explicit null binding.
#[derive(Clone, Debug)]
pub struct PskbOutputPlan {
    pub amount: u64,
    pub script_public_key: Vec<u8>,
    pub covenant_binding_field: Option<Value>,
    pub proprietaries: Value,
}

impl PskbOutputPlan {
    #[must_use]
    pub fn plain(amount: u64, script_public_key: &[u8]) -> Self {
        Self {
            amount,
            script_public_key: script_public_key.to_vec(),
            covenant_binding_field: None,
            proprietaries: Value::Array(Vec::new()),
        }
    }

    #[must_use]
    pub fn with_binding_field(mut self, covenant_binding: Value) -> Self {
        self.covenant_binding_field = Some(covenant_binding);
        self
    }
}

/// Global PSKB metadata used by contract, oracle, ZK and privacy planners.
#[derive(Clone, Debug)]
pub struct PskbGlobalPlan {
    pub tx_version: u16,
    pub fallback_lock_time: Value,
    pub covenant_branch: Option<Value>,
    pub proprietaries: Value,
    pub transaction_payload: Option<Vec<u8>>,
}

impl PskbGlobalPlan {
    #[must_use]
    pub fn standard() -> Self {
        Self {
            tx_version: 0,
            fallback_lock_time: Value::Null,
            covenant_branch: None,
            proprietaries: Value::Array(Vec::new()),
            transaction_payload: None,
        }
    }

    #[must_use]
    pub fn with_branch(mut self, branch: impl Into<Value>) -> Self {
        self.covenant_branch = Some(branch.into());
        self
    }

    #[must_use]
    pub fn with_lock_time(mut self, lock_time: u64) -> Self {
        self.fallback_lock_time = Value::from(lock_time);
        self
    }
}

/// Complete typed plan for the browser PSKB wire envelope.
#[derive(Clone, Debug)]
pub struct PskbPlan {
    pub global: PskbGlobalPlan,
    pub inputs: Vec<PskbInputPlan>,
    pub outputs: Vec<PskbOutputPlan>,
}
