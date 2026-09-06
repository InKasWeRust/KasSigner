use crate::{
    network::{codec::primitives::WireWriter, error::NetworkError},
    protocol::transaction::consensus::{
        ConsensusInput, ConsensusOutput, ConsensusTransaction, InputEncoding,
    },
};

pub fn encode_submit_request(
    transaction: &ConsensusTransaction,
    allow_orphan: bool,
) -> Result<Vec<u8>, NetworkError> {
    let transaction_bytes = encode_transaction(transaction)?;
    let mut request = WireWriter::new();
    request.write_u16(1);
    request.write_bytes(&transaction_bytes)?;
    request.write_u8(u8::from(allow_orphan));
    Ok(request.into_vec())
}

fn encode_transaction(transaction: &ConsensusTransaction) -> Result<Vec<u8>, NetworkError> {
    let mut writer = WireWriter::new();
    writer.write_u16(1);
    writer.write_u16(transaction.tx_version);
    writer.write_bytes(&encode_inputs(transaction)?)?;
    writer.write_bytes(&encode_outputs(&transaction.outputs)?)?;
    writer.write_u64(transaction.locktime);
    writer.write_raw(&transaction.subnetwork_id);
    writer.write_u64(transaction.gas);
    writer.write_bytes(&transaction.payload)?;
    writer.write_u64(transaction.storage_mass);
    writer.write_bytes(&[0])?;
    Ok(writer.into_vec())
}

fn encode_inputs(transaction: &ConsensusTransaction) -> Result<Vec<u8>, NetworkError> {
    let mut writer = WireWriter::new();
    writer.write_count(transaction.inputs.len())?;
    for input in &transaction.inputs {
        writer.write_bytes(&encode_input(
            input,
            transaction.tx_version,
            transaction.input_encoding,
        )?)?;
    }
    Ok(writer.into_vec())
}

fn encode_input_suffix(
    writer: &mut WireWriter,
    input: &ConsensusInput,
    transaction_version: u16,
    encoding: InputEncoding,
) -> Result<(), NetworkError> {
    match encoding {
        InputEncoding::Compact => writer.write_u8(input.sig_op_count),
        InputEncoding::Budgeted => {
            let (sig_op_count, compute_budget) = if transaction_version >= 1 {
                (0, u16::from(input.sig_op_count) * 10)
            } else {
                (input.sig_op_count, 0)
            };
            writer.write_u8(sig_op_count);
            writer.write_bytes(&[0])?;
            writer.write_u16(compute_budget);
            return Ok(());
        }
    }
    writer.write_bytes(&[0])
}

fn encode_input(
    input: &ConsensusInput,
    transaction_version: u16,
    encoding: InputEncoding,
) -> Result<Vec<u8>, NetworkError> {
    let mut writer = WireWriter::new();
    writer.write_u8(match encoding {
        InputEncoding::Compact => 1,
        InputEncoding::Budgeted => 2,
    });
    let mut outpoint = WireWriter::new();
    outpoint.write_u8(1);
    outpoint.write_raw(&input.prev_tx_id);
    outpoint.write_u32(input.prev_index);
    writer.write_bytes(&outpoint.into_vec())?;
    writer.write_bytes(&input.sig_script)?;
    writer.write_u64(input.sequence);
    encode_input_suffix(&mut writer, input, transaction_version, encoding)?;
    Ok(writer.into_vec())
}

fn encode_outputs(outputs: &[ConsensusOutput]) -> Result<Vec<u8>, NetworkError> {
    let mut writer = WireWriter::new();
    writer.write_count(outputs.len())?;
    for output in outputs {
        writer.write_bytes(&encode_output(output)?)?;
    }
    Ok(writer.into_vec())
}

fn encode_output(output: &ConsensusOutput) -> Result<Vec<u8>, NetworkError> {
    let mut writer = WireWriter::new();
    writer.write_u8(if output.covenant.is_some() { 2 } else { 1 });
    writer.write_u64(output.value);
    writer.write_u16(output.spk_version);
    writer.write_bytes(&output.spk_script)?;
    writer.write_bytes(&[0])?;

    if let Some((authorizing_input, covenant_id)) = output.covenant {
        let mut binding = WireWriter::with_capacity(35);
        binding.write_u8(1);
        binding.write_u16(authorizing_input);
        binding.write_raw(&covenant_id);

        let mut optional = WireWriter::new();
        optional.write_u8(1);
        optional.write_bytes(&binding.into_vec())?;
        writer.write_bytes(&optional.into_vec())?;
    }
    Ok(writer.into_vec())
}
