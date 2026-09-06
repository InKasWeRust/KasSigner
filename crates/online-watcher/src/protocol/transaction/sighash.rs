const NATIVE_SUBNETWORK_ID: [u8; 20] = [0; 20];

#[derive(Clone, Debug)]
pub struct SighashOutput {
    pub value: u64,
    pub spk_version: u16,
    pub spk_script: Vec<u8>,
    pub covenant: Option<(u16, [u8; 32])>,
}

pub struct SighashContext<'a> {
    pub subnetwork_id: &'a [u8; 20],
    pub gas: u64,
    pub locktime: u64,
    pub payload: &'a [u8],
}

fn finalize(hash: blake2b_simd::State) -> [u8; 32] {
    let mut result = [0u8; 32];
    result.copy_from_slice(hash.finalize().as_bytes());
    result
}

#[derive(Clone, Copy)]
pub(crate) struct FullSighashInput<'a> {
    pub transaction_id: &'a [u8; 32],
    pub index: u32,
    pub amount: u64,
    pub sequence: u64,
    pub sig_op_count: u8,
    pub spk_version: u16,
    pub spk_script: &'a [u8],
}

pub(crate) struct FullSighashRequest<'a> {
    pub tx_version: u16,
    pub inputs: &'a [FullSighashInput<'a>],
    pub input_index: usize,
    pub outputs: &'a [SighashOutput],
    pub context: &'a SighashContext<'a>,
    pub sighash_type: u8,
}

pub(crate) fn compute_full_sighash(request: FullSighashRequest<'_>) -> Result<[u8; 32], String> {
    let mode = SighashMode::parse(request.sighash_type)?;
    let input = request
        .inputs
        .get(request.input_index)
        .ok_or_else(|| "sighash input index is out of range".to_string())?;
    let parameters = signing_hash_parameters();
    let previous_outputs = full_previous_outputs_hash(&parameters, request.inputs, mode);
    let sequences = full_sequences_hash(&parameters, request.inputs, mode);
    let outputs = full_outputs_hash(
        &parameters,
        request.outputs,
        request.tx_version,
        request.input_index,
        mode,
    );
    let payload = full_payload_hash(&parameters, request.context);

    let mut hash = parameters.to_state();
    hash.update(&request.tx_version.to_le_bytes());
    hash.update(&previous_outputs);
    hash.update(&sequences);
    if request.tx_version < 1 {
        hash.update(&full_sig_op_counts_hash(&parameters, request.inputs, mode));
    }
    hash.update(input.transaction_id.as_ref());
    hash.update(&input.index.to_le_bytes());
    hash.update(&input.spk_version.to_le_bytes());
    hash.update(&(input.spk_script.len() as u64).to_le_bytes());
    hash.update(input.spk_script);
    hash.update(&input.amount.to_le_bytes());
    hash.update(&input.sequence.to_le_bytes());
    if request.tx_version < 1 {
        hash.update(&[input.sig_op_count]);
    }
    hash.update(&outputs);
    hash.update(&request.context.locktime.to_le_bytes());
    hash.update(request.context.subnetwork_id);
    hash.update(&request.context.gas.to_le_bytes());
    hash.update(&payload);
    hash.update(&[request.sighash_type]);
    Ok(finalize(hash))
}

#[derive(Clone, Copy)]
struct SighashMode {
    anyone_can_pay: bool,
    base: u8,
}

impl SighashMode {
    fn parse(value: u8) -> Result<Self, String> {
        let base = value & 0x7f;
        if !matches!(base, 0x01 | 0x02 | 0x04) || value & 0x78 != 0 {
            return Err("invalid Kaspa sighash type".into());
        }
        Ok(Self {
            anyone_can_pay: value & 0x80 != 0,
            base,
        })
    }

    fn is_none(self) -> bool {
        self.base == 0x02
    }
    fn is_single(self) -> bool {
        self.base == 0x04
    }
}

fn signing_hash_parameters() -> blake2b_simd::Params {
    blake2b_simd::Params::new()
        .hash_length(32)
        .key(b"TransactionSigningHash")
        .clone()
}

fn full_previous_outputs_hash(
    parameters: &blake2b_simd::Params,
    inputs: &[FullSighashInput<'_>],
    mode: SighashMode,
) -> [u8; 32] {
    if mode.anyone_can_pay {
        return [0u8; 32];
    }
    let mut hash = parameters.to_state();
    for input in inputs {
        hash.update(input.transaction_id.as_ref());
        hash.update(&input.index.to_le_bytes());
    }
    finalize(hash)
}

fn full_sequences_hash(
    parameters: &blake2b_simd::Params,
    inputs: &[FullSighashInput<'_>],
    mode: SighashMode,
) -> [u8; 32] {
    if mode.anyone_can_pay || mode.is_single() || mode.is_none() {
        return [0u8; 32];
    }
    let mut hash = parameters.to_state();
    for input in inputs {
        hash.update(&input.sequence.to_le_bytes());
    }
    finalize(hash)
}

fn full_sig_op_counts_hash(
    parameters: &blake2b_simd::Params,
    inputs: &[FullSighashInput<'_>],
    mode: SighashMode,
) -> [u8; 32] {
    if mode.anyone_can_pay {
        return [0u8; 32];
    }
    let mut hash = parameters.to_state();
    for input in inputs {
        hash.update(&[input.sig_op_count]);
    }
    finalize(hash)
}

fn full_outputs_hash(
    parameters: &blake2b_simd::Params,
    outputs: &[SighashOutput],
    tx_version: u16,
    input_index: usize,
    mode: SighashMode,
) -> [u8; 32] {
    if mode.is_none() || (mode.is_single() && input_index >= outputs.len()) {
        return [0u8; 32];
    }
    let mut hash = parameters.to_state();
    if mode.is_single() {
        hash_full_output(&mut hash, &outputs[input_index], tx_version);
    } else {
        for output in outputs {
            hash_full_output(&mut hash, output, tx_version);
        }
    }
    finalize(hash)
}

fn hash_full_output(hash: &mut blake2b_simd::State, output: &SighashOutput, tx_version: u16) {
    hash.update(&output.value.to_le_bytes());
    hash.update(&output.spk_version.to_le_bytes());
    hash.update(&(output.spk_script.len() as u64).to_le_bytes());
    hash.update(&output.spk_script);
    if tx_version >= 1 {
        match output.covenant {
            None => {
                hash.update(&[0]);
            }
            Some((authorizing_input, covenant_id)) => {
                hash.update(&[1]);
                hash.update(&authorizing_input.to_le_bytes());
                hash.update(&covenant_id);
            }
        }
    }
}

fn full_payload_hash(parameters: &blake2b_simd::Params, context: &SighashContext<'_>) -> [u8; 32] {
    if *context.subnetwork_id == NATIVE_SUBNETWORK_ID && context.payload.is_empty() {
        return [0u8; 32];
    }
    let mut hash = parameters.to_state();
    hash.update(&(context.payload.len() as u64).to_le_bytes());
    hash.update(context.payload);
    finalize(hash)
}
