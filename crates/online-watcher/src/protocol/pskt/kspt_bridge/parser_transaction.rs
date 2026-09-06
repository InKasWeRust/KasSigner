use kassigner_protocol::wire::kspt::{
    self, DecodeError, DecodeSink, Derivation, Global, Input, Ms45Derivation, Output, Signature,
};

use crate::protocol::pskt::model::{
    CompactKsptInput, CompactKsptOutput, CompactKsptSignature, CompactKsptTransaction,
};

pub(crate) fn parse_compact_kspt_transaction(
    data: &[u8],
) -> Result<CompactKsptTransaction, String> {
    let mut sink = KasSeeSink::default();
    let envelope = kspt::decode(data, &mut sink).map_err(decode_error)?;
    sink.finish(envelope.flags)
}

#[derive(Default)]
pub(crate) struct KasSeeSink {
    version: Option<u16>,
    locktime: u64,
    subnetwork_id: [u8; 20],
    gas: u64,
    payload: Vec<u8>,
    network: Option<u8>,
    inputs: Vec<CompactKsptInput>,
    outputs: Vec<CompactKsptOutput>,
    stealth_tweak: Option<[u8; 32]>,
}

impl KasSeeSink {
    pub(crate) fn finish(self, flags: u8) -> Result<CompactKsptTransaction, String> {
        Ok(CompactKsptTransaction {
            generation: kspt::GENERATION_CURRENT,
            flags,
            version: self
                .version
                .ok_or_else(|| "compact KSPT global record is missing".to_string())?,
            locktime: self.locktime,
            subnetwork_id: self.subnetwork_id,
            gas: self.gas,
            payload: self.payload,
            network: self
                .network
                .ok_or_else(|| "compact KSPT network is missing".to_string())?,
            inputs: self.inputs,
            outputs: self.outputs,
            stealth_tweak: self.stealth_tweak,
        })
    }
}

impl DecodeSink for KasSeeSink {
    type Error = String;

    fn global(&mut self, value: Global<'_>) -> Result<(), Self::Error> {
        // KasSee runs on wasm32 or wider native hosts, so every wire u32 index/count
        // is representable as usize. Canonical decoding enforces resource limits first.
        let input_count = value.input_count as usize;
        self.inputs
            .try_reserve(input_count)
            .map_err(|_| "compact KSPT input count exceeds available memory".to_string())?;
        self.outputs
            .try_reserve(usize::from(value.output_count))
            .map_err(|_| "compact KSPT output count exceeds available memory".to_string())?;
        self.version = Some(value.version);
        self.locktime = value.locktime;
        self.subnetwork_id = value.subnetwork_id;
        self.gas = value.gas;
        self.payload = value.payload.to_vec();
        Ok(())
    }

    fn input(
        &mut self,
        index: u32,
        value: Input<'_>,
        signature_count: u8,
    ) -> Result<(), Self::Error> {
        if signature_count > 5 {
            return Err("compact KSPT has too many signatures for one input".into());
        }
        let expected = index as usize;
        if expected != self.inputs.len() {
            return Err("compact KSPT input order is invalid".into());
        }
        let mut signatures = Vec::new();
        signatures
            .try_reserve(usize::from(signature_count))
            .map_err(|_| "compact KSPT signature count exceeds available memory".to_string())?;
        self.inputs.push(CompactKsptInput {
            previous_tx_id: value.previous_tx_id,
            previous_index: value.previous_index,
            amount: value.amount,
            sequence: value.sequence,
            sig_op_count: value.sig_op_count,
            script_version: value.script_version,
            script: value.script.to_vec(),
            signatures,
            redeem_script: Vec::new(),
            derivation: None,
            ms45_derivation: None,
        });
        Ok(())
    }

    fn signature(&mut self, input: u32, slot: u8, value: Signature) -> Result<(), Self::Error> {
        let _ = slot;
        let target = self
            .inputs
            .get_mut(input as usize)
            .ok_or_else(|| "compact KSPT signature input is invalid".to_string())?;
        target.signatures.push(CompactKsptSignature {
            pubkey_pos: value.position,
            sighash_type: value.sighash,
            signature: value.bytes,
        });
        Ok(())
    }

    fn redeem(&mut self, input: u32, value: &[u8]) -> Result<(), Self::Error> {
        self.inputs
            .get_mut(input as usize)
            .ok_or_else(|| "compact KSPT redeem input is invalid".to_string())?
            .redeem_script = value.to_vec();
        Ok(())
    }

    fn output(&mut self, index: u8, value: Output<'_>) -> Result<(), Self::Error> {
        if usize::from(index) != self.outputs.len() {
            return Err("compact KSPT output order is invalid".into());
        }
        self.outputs.push(CompactKsptOutput {
            value: value.amount,
            script_version: value.script_version,
            script: value.script.to_vec(),
            covenant: None,
            derivation: None,
            ms45_derivation: None,
        });
        Ok(())
    }

    fn network(&mut self, code: u8) -> Result<(), Self::Error> {
        self.network = Some(code);
        Ok(())
    }
    fn stealth(&mut self, tweak: [u8; 32]) -> Result<(), Self::Error> {
        self.stealth_tweak = Some(tweak);
        Ok(())
    }

    fn input_derivation(&mut self, input: u8, value: Derivation) -> Result<(), Self::Error> {
        self.inputs
            .get_mut(usize::from(input))
            .ok_or_else(|| "compact KSPT input derivation target is invalid".to_string())?
            .derivation = Some((value.branch, value.index));
        Ok(())
    }

    fn output_derivation(&mut self, output: u8, value: Derivation) -> Result<(), Self::Error> {
        self.outputs
            .get_mut(usize::from(output))
            .ok_or_else(|| "compact KSPT output derivation target is invalid".to_string())?
            .derivation = Some((value.branch, value.index));
        Ok(())
    }

    fn input_ms45(&mut self, input: u8, value: Ms45Derivation) -> Result<(), Self::Error> {
        self.inputs
            .get_mut(usize::from(input))
            .ok_or_else(|| "compact KSPT multisig input target is invalid".to_string())?
            .ms45_derivation = Some((value.cosigner, value.chain, value.index));
        Ok(())
    }

    fn output_ms45(&mut self, output: u8, value: Ms45Derivation) -> Result<(), Self::Error> {
        self.outputs
            .get_mut(usize::from(output))
            .ok_or_else(|| "compact KSPT multisig output target is invalid".to_string())?
            .ms45_derivation = Some((value.cosigner, value.chain, value.index));
        Ok(())
    }

    fn covenant(
        &mut self,
        output: u8,
        authorizing_input: u16,
        id: [u8; 32],
    ) -> Result<(), Self::Error> {
        self.outputs
            .get_mut(usize::from(output))
            .ok_or_else(|| "compact KSPT covenant output target is invalid".to_string())?
            .covenant = Some((authorizing_input, id));
        Ok(())
    }
}

fn decode_error(error: DecodeError<String>) -> String {
    match error {
        DecodeError::Wire(error) => error.to_string(),
        DecodeError::Sink(error) => error,
    }
}

#[cfg(test)]
pub(crate) fn decode_error_for_test(error: DecodeError<String>) -> String {
    decode_error(error)
}

#[cfg(test)]
pub(crate) fn require_compact_trailer_progress(
    before_remaining: usize,
    after_remaining: usize,
) -> Result<(), String> {
    shared_signer::bytes::strict_forward_progress(before_remaining, after_remaining)
        .then_some(())
        .ok_or_else(|| "compact KSPT trailer made no forward progress".to_string())
}
