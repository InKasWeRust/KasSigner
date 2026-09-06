use super::io::Writer;
use super::{
    valid_derivation, valid_ms45, valid_network, valid_sighash, Covenant, Derivation, Global,
    Input, Ms45Derivation, Output, Signature, WireError, ALLOWED_FLAGS, COVENANT_MARKER,
    GENERATION_CURRENT, INPUT_DERIVATION_MARKER, MAGIC, MAX_SIGNATURE_RECORDS, MS45_INPUT_MARKER,
    MS45_OUTPUT_MARKER, NETWORK_MARKER, OUTPUT_DERIVATION_MARKER, STEALTH_MARKER,
};

pub trait EncodeSource {
    fn global(&self) -> Global<'_>;
    fn input(&self, index: usize) -> Input<'_>;
    fn signature_count(&self, input: usize) -> usize;
    fn signature(&self, input: usize, slot: usize) -> Signature;
    fn redeem(&self, input: usize) -> &[u8];
    fn output(&self, index: usize) -> Output<'_>;
    fn network(&self) -> u8;
    fn stealth(&self) -> Option<[u8; 32]>;
    fn input_derivation(&self, index: usize) -> Option<Derivation>;
    fn output_derivation(&self, index: usize) -> Option<Derivation>;
    fn input_ms45(&self, index: usize) -> Option<Ms45Derivation>;
    fn output_ms45(&self, index: usize) -> Option<Ms45Derivation>;
    fn covenant(&self, index: usize) -> Option<Covenant>;
}

pub fn encode<S: EncodeSource>(source: &S, output: &mut [u8]) -> Result<usize, WireError> {
    let global = source.global();
    validate_global(global)?;
    let mut writer = Writer::new(output);
    write_header(&mut writer, global.flags)?;
    write_global(&mut writer, global)?;
    for index in 0..usize::try_from(global.input_count).map_err(|_| WireError::CountOverflow)? {
        write_input(&mut writer, source, index)?;
    }
    for index in 0..usize::from(global.output_count) {
        write_output(&mut writer, source.output(index))?;
    }
    write_trailers(&mut writer, source, global)?;
    Ok(writer.written())
}

fn validate_global(global: Global<'_>) -> Result<(), WireError> {
    if global.flags & !ALLOWED_FLAGS != 0 {
        return Err(WireError::InvalidFlags);
    }
    if global.payload.len() > usize::from(u16::MAX) {
        return Err(WireError::CountOverflow);
    }
    Ok(())
}

fn write_header(writer: &mut Writer<'_>, flags: u8) -> Result<(), WireError> {
    writer.bytes(&MAGIC)?;
    writer.u8(GENERATION_CURRENT)?;
    writer.u8(flags)
}

fn write_global(writer: &mut Writer<'_>, value: Global<'_>) -> Result<(), WireError> {
    writer.u16(value.version)?;
    writer.u32(value.input_count)?;
    writer.u8(value.output_count)?;
    writer.u64(value.locktime)?;
    writer.bytes(&value.subnetwork_id)?;
    writer.u64(value.gas)?;
    writer.u16(u16::try_from(value.payload.len()).map_err(|_| WireError::CountOverflow)?)?;
    writer.bytes(value.payload)
}

fn write_input<S: EncodeSource>(
    writer: &mut Writer<'_>,
    source: &S,
    index: usize,
) -> Result<(), WireError> {
    write_input_value(writer, source.input(index))?;
    write_signatures(writer, source, index)?;
    write_redeem(writer, source.redeem(index))
}

fn write_input_value(writer: &mut Writer<'_>, value: Input<'_>) -> Result<(), WireError> {
    writer.bytes(&value.previous_tx_id)?;
    writer.u32(value.previous_index)?;
    writer.u64(value.amount)?;
    writer.u64(value.sequence)?;
    writer.u8(value.sig_op_count)?;
    writer.u16(value.script_version)?;
    writer.script(value.script)
}

fn write_signatures<S: EncodeSource>(
    writer: &mut Writer<'_>,
    source: &S,
    index: usize,
) -> Result<(), WireError> {
    let count = source.signature_count(index);
    validate_signature_count(count)?;
    writer.u8(count as u8)?;
    let mut seen = [false; 256];
    for slot in 0..count {
        write_signature(writer, source.signature(index, slot), &mut seen)?;
    }
    Ok(())
}

fn validate_signature_count(count: usize) -> Result<(), WireError> {
    if count > MAX_SIGNATURE_RECORDS {
        return Err(WireError::TooManySignatures);
    }
    Ok(())
}

fn write_signature(
    writer: &mut Writer<'_>,
    signature: Signature,
    seen: &mut [bool; 256],
) -> Result<(), WireError> {
    if seen[usize::from(signature.position)] {
        return Err(WireError::DuplicateSignaturePosition);
    }
    seen[usize::from(signature.position)] = true;
    if !valid_sighash(signature.sighash) {
        return Err(WireError::InvalidSigHashType);
    }
    writer.u8(signature.position)?;
    writer.u8(signature.sighash)?;
    writer.bytes(&signature.bytes)
}

fn write_redeem(writer: &mut Writer<'_>, redeem: &[u8]) -> Result<(), WireError> {
    writer.u16(u16::try_from(redeem.len()).map_err(|_| WireError::RedeemTooLong)?)?;
    writer.bytes(redeem)
}

fn write_output(writer: &mut Writer<'_>, value: Output<'_>) -> Result<(), WireError> {
    writer.u64(value.amount)?;
    writer.u16(value.script_version)?;
    writer.script(value.script)
}

fn write_trailers<S: EncodeSource>(
    writer: &mut Writer<'_>,
    source: &S,
    global: Global<'_>,
) -> Result<(), WireError> {
    let inputs = usize::try_from(global.input_count).map_err(|_| WireError::CountOverflow)?;
    let outputs = usize::from(global.output_count);
    write_network(writer, source.network())?;
    write_ms45_trailers(writer, source, inputs, outputs)?;
    write_stealth(writer, source.stealth())?;
    write_covenant_trailers(writer, source, outputs)?;
    write_derivation_trailers(writer, source, inputs, outputs)
}

fn write_ms45_trailers<S: EncodeSource>(
    writer: &mut Writer<'_>,
    source: &S,
    inputs: usize,
    outputs: usize,
) -> Result<(), WireError> {
    for index in 0..inputs {
        if let Some(value) = source.input_ms45(index) {
            write_ms45(writer, MS45_INPUT_MARKER, index, value)?;
        }
    }
    for index in 0..outputs {
        if let Some(value) = source.output_ms45(index) {
            write_ms45(writer, MS45_OUTPUT_MARKER, index, value)?;
        }
    }
    Ok(())
}

fn write_stealth(writer: &mut Writer<'_>, value: Option<[u8; 32]>) -> Result<(), WireError> {
    if let Some(value) = value {
        writer.u8(STEALTH_MARKER)?;
        writer.bytes(&value)?;
    }
    Ok(())
}

fn write_covenant_trailers<S: EncodeSource>(
    writer: &mut Writer<'_>,
    source: &S,
    outputs: usize,
) -> Result<(), WireError> {
    for index in 0..outputs {
        if let Some(value) = source.covenant(index) {
            write_covenant(writer, index, value)?;
        }
    }
    Ok(())
}

fn write_derivation_trailers<S: EncodeSource>(
    writer: &mut Writer<'_>,
    source: &S,
    inputs: usize,
    outputs: usize,
) -> Result<(), WireError> {
    for index in 0..inputs {
        if let Some(value) = source.input_derivation(index) {
            write_derivation(writer, INPUT_DERIVATION_MARKER, index, value)?;
        }
    }
    for index in 0..outputs {
        if let Some(value) = source.output_derivation(index) {
            write_derivation(writer, OUTPUT_DERIVATION_MARKER, index, value)?;
        }
    }
    Ok(())
}

fn position(index: usize) -> Result<u8, WireError> {
    u8::try_from(index).map_err(|_| WireError::CountOverflow)
}
fn write_network(writer: &mut Writer<'_>, code: u8) -> Result<(), WireError> {
    if !valid_network(code) {
        return Err(WireError::InvalidNetwork);
    }
    writer.u8(NETWORK_MARKER)?;
    writer.u8(code)
}
fn write_derivation(
    writer: &mut Writer<'_>,
    marker: u8,
    index: usize,
    value: Derivation,
) -> Result<(), WireError> {
    if !valid_derivation(value) {
        return Err(WireError::InvalidTrailer);
    }
    writer.u8(marker)?;
    writer.u8(position(index)?)?;
    writer.u8(value.branch)?;
    writer.u32(value.index)
}
fn write_ms45(
    writer: &mut Writer<'_>,
    marker: u8,
    index: usize,
    value: Ms45Derivation,
) -> Result<(), WireError> {
    if !valid_ms45(value) {
        return Err(WireError::InvalidTrailer);
    }
    writer.u8(marker)?;
    writer.u8(position(index)?)?;
    writer.u32(value.cosigner)?;
    writer.u32(value.chain)?;
    writer.u32(value.index)
}
fn write_covenant(writer: &mut Writer<'_>, index: usize, value: Covenant) -> Result<(), WireError> {
    writer.u8(COVENANT_MARKER)?;
    writer.u8(position(index)?)?;
    writer.u16(value.authorizing_input)?;
    writer.bytes(&value.id)
}
