use super::super::io::Reader;
use super::super::{
    valid_derivation, valid_ms45, valid_network, DecodeError, Derivation, Ms45Derivation,
    WireError, COVENANT_MARKER, INPUT_DERIVATION_MARKER, MS45_INPUT_MARKER, MS45_OUTPUT_MARKER,
    NETWORK_MARKER, OUTPUT_DERIVATION_MARKER, STEALTH_MARKER,
};
use super::DecodeSink;

struct TrailerState {
    network: bool,
    stealth: bool,
    input_derivation: [bool; 256],
    output_derivation: [bool; 256],
    input_ms45: [bool; 256],
    output_ms45: [bool; 256],
    covenant: [bool; 256],
}
impl TrailerState {
    const fn new() -> Self {
        Self {
            network: false,
            stealth: false,
            input_derivation: [false; 256],
            output_derivation: [false; 256],
            input_ms45: [false; 256],
            output_ms45: [false; 256],
            covenant: [false; 256],
        }
    }
}

pub(super) fn read_trailers<S: DecodeSink>(
    reader: &mut Reader<'_>,
    inputs: u32,
    outputs: u8,
    sink: &mut S,
) -> Result<(), DecodeError<S::Error>> {
    let mut state = TrailerState::new();
    while let Some(marker) = reader.peek() {
        read_trailer(marker, reader, inputs, outputs, sink, &mut state)?;
    }
    if !state.network {
        return Err(WireError::MissingNetwork.into());
    }
    Ok(())
}

fn read_trailer<S: DecodeSink>(
    marker: u8,
    reader: &mut Reader<'_>,
    inputs: u32,
    outputs: u8,
    sink: &mut S,
    state: &mut TrailerState,
) -> Result<(), DecodeError<S::Error>> {
    match marker {
        NETWORK_MARKER => read_network(reader, sink, state),
        MS45_INPUT_MARKER => read_ms45_input(reader, inputs, sink, state),
        MS45_OUTPUT_MARKER => read_ms45_output(reader, outputs, sink, state),
        STEALTH_MARKER => read_stealth(reader, sink, state),
        COVENANT_MARKER => read_covenant(reader, inputs, outputs, sink, state),
        INPUT_DERIVATION_MARKER => read_input_derivation(reader, inputs, sink, state),
        OUTPUT_DERIVATION_MARKER => read_output_derivation(reader, outputs, sink, state),
        _ => Err(WireError::TrailingData.into()),
    }
}

fn read_network<S: DecodeSink>(
    reader: &mut Reader<'_>,
    sink: &mut S,
    state: &mut TrailerState,
) -> Result<(), DecodeError<S::Error>> {
    reader.u8()?;
    let code = reader.u8()?;
    if state.network || !valid_network(code) {
        return Err(WireError::InvalidNetwork.into());
    }
    state.network = true;
    sink.network(code).map_err(DecodeError::Sink)
}

fn read_stealth<S: DecodeSink>(
    reader: &mut Reader<'_>,
    sink: &mut S,
    state: &mut TrailerState,
) -> Result<(), DecodeError<S::Error>> {
    reader.u8()?;
    if state.stealth {
        return Err(WireError::InvalidTrailer.into());
    }
    state.stealth = true;
    sink.stealth(reader.array::<32>()?)
        .map_err(DecodeError::Sink)
}

fn read_derivation_body(reader: &mut Reader<'_>) -> Result<Derivation, WireError> {
    let value = Derivation {
        branch: reader.u8()?,
        index: reader.u32()?,
    };
    if !valid_derivation(value) {
        return Err(WireError::InvalidTrailer);
    }
    Ok(value)
}

fn read_input_derivation<S: DecodeSink>(
    reader: &mut Reader<'_>,
    inputs: u32,
    sink: &mut S,
    state: &mut TrailerState,
) -> Result<(), DecodeError<S::Error>> {
    reader.u8()?;
    let position = reader.u8()?;
    if u32::from(position) >= inputs || state.input_derivation[usize::from(position)] {
        return Err(WireError::InvalidTrailer.into());
    }
    let value = read_derivation_body(reader)?;
    state.input_derivation[usize::from(position)] = true;
    sink.input_derivation(position, value)
        .map_err(DecodeError::Sink)
}

fn read_output_derivation<S: DecodeSink>(
    reader: &mut Reader<'_>,
    outputs: u8,
    sink: &mut S,
    state: &mut TrailerState,
) -> Result<(), DecodeError<S::Error>> {
    reader.u8()?;
    let position = reader.u8()?;
    if position >= outputs || state.output_derivation[usize::from(position)] {
        return Err(WireError::InvalidTrailer.into());
    }
    let value = read_derivation_body(reader)?;
    state.output_derivation[usize::from(position)] = true;
    sink.output_derivation(position, value)
        .map_err(DecodeError::Sink)
}

fn read_ms45_body(reader: &mut Reader<'_>) -> Result<Ms45Derivation, WireError> {
    let value = Ms45Derivation {
        cosigner: reader.u32()?,
        chain: reader.u32()?,
        index: reader.u32()?,
    };
    if !valid_ms45(value) {
        return Err(WireError::InvalidTrailer);
    }
    Ok(value)
}

fn read_ms45_input<S: DecodeSink>(
    reader: &mut Reader<'_>,
    inputs: u32,
    sink: &mut S,
    state: &mut TrailerState,
) -> Result<(), DecodeError<S::Error>> {
    reader.u8()?;
    let position = reader.u8()?;
    if u32::from(position) >= inputs || state.input_ms45[usize::from(position)] {
        return Err(WireError::InvalidTrailer.into());
    }
    let value = read_ms45_body(reader)?;
    state.input_ms45[usize::from(position)] = true;
    sink.input_ms45(position, value).map_err(DecodeError::Sink)
}

fn read_ms45_output<S: DecodeSink>(
    reader: &mut Reader<'_>,
    outputs: u8,
    sink: &mut S,
    state: &mut TrailerState,
) -> Result<(), DecodeError<S::Error>> {
    reader.u8()?;
    let position = reader.u8()?;
    if position >= outputs || state.output_ms45[usize::from(position)] {
        return Err(WireError::InvalidTrailer.into());
    }
    let value = read_ms45_body(reader)?;
    state.output_ms45[usize::from(position)] = true;
    sink.output_ms45(position, value).map_err(DecodeError::Sink)
}

fn read_covenant<S: DecodeSink>(
    reader: &mut Reader<'_>,
    inputs: u32,
    outputs: u8,
    sink: &mut S,
    state: &mut TrailerState,
) -> Result<(), DecodeError<S::Error>> {
    reader.u8()?;
    let position = reader.u8()?;
    let authorizing = reader.u16()?;
    if position >= outputs
        || u32::from(authorizing) >= inputs
        || state.covenant[usize::from(position)]
    {
        return Err(WireError::InvalidTrailer.into());
    }
    let id = reader.array::<32>()?;
    state.covenant[usize::from(position)] = true;
    sink.covenant(position, authorizing, id)
        .map_err(DecodeError::Sink)
}
