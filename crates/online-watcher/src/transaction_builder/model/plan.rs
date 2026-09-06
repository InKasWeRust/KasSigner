use crate::account::utxo::UtxoEntry;

use super::{PlannedInput, PlannedOutput};

/// Canonical unsigned transaction plan shared by KSPT and PSKB encoders.
#[derive(Clone, Debug)]
pub struct UnsignedTransactionPlan {
    pub tx_version: u16,
    pub inputs: Vec<PlannedInput>,
    pub outputs: Vec<PlannedOutput>,
    pub payload: Vec<u8>,
}

impl UnsignedTransactionPlan {
    #[must_use]
    pub fn standard(inputs: Vec<UtxoEntry>, outputs: Vec<PlannedOutput>) -> Self {
        Self {
            tx_version: 0,
            inputs: inputs.into_iter().map(PlannedInput::p2pk).collect(),
            outputs,
            payload: Vec::new(),
        }
    }

    #[cfg(test)]
    #[must_use]
    pub fn standard_with_derivations(
        inputs: Vec<(UtxoEntry, Option<(u8, u32)>)>,
        outputs: Vec<PlannedOutput>,
    ) -> Self {
        let inputs = inputs
            .into_iter()
            .map(|(utxo, hint)| match hint {
                Some((branch, index)) => PlannedInput::p2pk(utxo).with_derivation(branch, index),
                None => PlannedInput::p2pk(utxo),
            })
            .collect();
        Self {
            tx_version: 0,
            inputs,
            outputs,
            payload: Vec::new(),
        }
    }

    #[must_use]
    pub fn multisig(
        inputs: Vec<UtxoEntry>,
        outputs: Vec<PlannedOutput>,
        redeem_script: &[u8],
        sig_op_count: u8,
    ) -> Self {
        Self {
            tx_version: 0,
            inputs: inputs
                .into_iter()
                .map(|utxo| PlannedInput::p2sh_multisig(utxo, redeem_script, sig_op_count))
                .collect(),
            outputs,
            payload: Vec::new(),
        }
    }
}
