use super::{Input, Output, Signature, Transaction};
use crate::wire::kspt::{self, DecodeError, DecodeSink};

pub(super) fn parse(data: &[u8]) -> Result<Transaction, String> {
    let mut sink = HostSink::default();
    let envelope = kspt::decode(data, &mut sink).map_err(decode_error)?;
    let mut transaction = sink.finish()?;
    transaction.flags = envelope.flags;
    Ok(transaction)
}

fn decode_error(error: DecodeError<String>) -> String {
    match error {
        DecodeError::Wire(error) => error.to_string(),
        DecodeError::Sink(error) => error,
    }
}

#[derive(Default)]
struct HostSink {
    transaction: Option<Transaction>,
}

impl HostSink {
    fn transaction_mut(&mut self) -> Result<&mut Transaction, String> {
        self.transaction
            .as_mut()
            .ok_or_else(|| "KSPT global record was not decoded".to_string())
    }

    fn finish(self) -> Result<Transaction, String> {
        self.transaction
            .ok_or_else(|| "KSPT global record was not decoded".to_string())
    }
}

impl DecodeSink for HostSink {
    type Error = String;

    fn global(&mut self, value: kspt::Global<'_>) -> Result<(), Self::Error> {
        let input_capacity = usize::try_from(value.input_count)
            .map_err(|_| "KSPT input count exceeds usize".to_string())?;
        let mut inputs = Vec::new();
        inputs
            .try_reserve(input_capacity)
            .map_err(|_| "KSPT input allocation failed".to_string())?;
        let mut outputs = Vec::new();
        outputs
            .try_reserve(usize::from(value.output_count))
            .map_err(|_| "KSPT output allocation failed".to_string())?;
        self.transaction = Some(Transaction {
            flags: value.flags,
            version: value.version,
            locktime: value.locktime,
            subnetwork: value.subnetwork_id,
            gas: value.gas,
            payload: value.payload.to_vec(),
            network: 0,
            inputs,
            outputs,
            stealth: None,
        });
        Ok(())
    }

    fn input(
        &mut self,
        index: u32,
        value: kspt::Input<'_>,
        signature_count: u8,
    ) -> Result<(), Self::Error> {
        let transaction = self.transaction_mut()?;
        if usize::try_from(index).ok() != Some(transaction.inputs.len()) {
            return Err("KSPT input order is invalid".to_string());
        }
        let mut signatures = Vec::new();
        signatures
            .try_reserve(usize::from(signature_count))
            .map_err(|_| "KSPT signature allocation failed".to_string())?;
        transaction.inputs.push(Input {
            tx_id: value.previous_tx_id,
            index: value.previous_index,
            amount: value.amount,
            sequence: value.sequence,
            sig_op_count: value.sig_op_count,
            script_version: value.script_version,
            script: value.script.to_vec(),
            signatures,
            redeem: Vec::new(),
            derivation: None,
            ms45: None,
        });
        Ok(())
    }

    fn signature(
        &mut self,
        input: u32,
        slot: u8,
        value: kspt::Signature,
    ) -> Result<(), Self::Error> {
        let index =
            usize::try_from(input).map_err(|_| "KSPT input index exceeds usize".to_string())?;
        let target = self
            .transaction_mut()?
            .inputs
            .get_mut(index)
            .ok_or_else(|| "KSPT signature input is invalid".to_string())?;
        if usize::from(slot) != target.signatures.len() {
            return Err("KSPT signature slot order is invalid".to_string());
        }
        target.signatures.push(Signature {
            position: value.position,
            sighash: value.sighash,
            bytes: value.bytes,
        });
        Ok(())
    }

    fn redeem(&mut self, input: u32, value: &[u8]) -> Result<(), Self::Error> {
        let index =
            usize::try_from(input).map_err(|_| "KSPT input index exceeds usize".to_string())?;
        let target = self
            .transaction_mut()?
            .inputs
            .get_mut(index)
            .ok_or_else(|| "KSPT redeem input is invalid".to_string())?;
        target.redeem = value.to_vec();
        Ok(())
    }

    fn output(&mut self, index: u8, value: kspt::Output<'_>) -> Result<(), Self::Error> {
        let transaction = self.transaction_mut()?;
        if usize::from(index) != transaction.outputs.len() {
            return Err("KSPT output order is invalid".to_string());
        }
        transaction.outputs.push(Output {
            amount: value.amount,
            script_version: value.script_version,
            script: value.script.to_vec(),
            derivation: None,
            ms45: None,
            covenant: None,
        });
        Ok(())
    }

    fn network(&mut self, code: u8) -> Result<(), Self::Error> {
        self.transaction_mut()?.network = code;
        Ok(())
    }
    fn stealth(&mut self, tweak: [u8; 32]) -> Result<(), Self::Error> {
        self.transaction_mut()?.stealth = Some(tweak);
        Ok(())
    }
    fn input_derivation(&mut self, input: u8, value: kspt::Derivation) -> Result<(), Self::Error> {
        let target = self
            .transaction_mut()?
            .inputs
            .get_mut(usize::from(input))
            .ok_or_else(|| "KSPT input derivation position is invalid".to_string())?;
        target.derivation = Some((value.branch, value.index));
        Ok(())
    }
    fn output_derivation(
        &mut self,
        output: u8,
        value: kspt::Derivation,
    ) -> Result<(), Self::Error> {
        let target = self
            .transaction_mut()?
            .outputs
            .get_mut(usize::from(output))
            .ok_or_else(|| "KSPT output derivation position is invalid".to_string())?;
        target.derivation = Some((value.branch, value.index));
        Ok(())
    }
    fn input_ms45(&mut self, input: u8, value: kspt::Ms45Derivation) -> Result<(), Self::Error> {
        let target = self
            .transaction_mut()?
            .inputs
            .get_mut(usize::from(input))
            .ok_or_else(|| "KSPT input multisig position is invalid".to_string())?;
        target.ms45 = Some((value.cosigner, value.chain, value.index));
        Ok(())
    }
    fn output_ms45(&mut self, output: u8, value: kspt::Ms45Derivation) -> Result<(), Self::Error> {
        let target = self
            .transaction_mut()?
            .outputs
            .get_mut(usize::from(output))
            .ok_or_else(|| "KSPT output multisig position is invalid".to_string())?;
        target.ms45 = Some((value.cosigner, value.chain, value.index));
        Ok(())
    }
    fn covenant(
        &mut self,
        output: u8,
        authorizing_input: u16,
        id: [u8; 32],
    ) -> Result<(), Self::Error> {
        let target = self
            .transaction_mut()?
            .outputs
            .get_mut(usize::from(output))
            .ok_or_else(|| "KSPT covenant position is invalid".to_string())?;
        target.covenant = Some((authorizing_input, id));
        Ok(())
    }
}
