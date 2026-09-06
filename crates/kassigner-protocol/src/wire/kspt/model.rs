pub const MAGIC: [u8; 4] = *b"KSPT";
pub const GENERATION_CURRENT: u8 = 0x04;
pub const FLAG_SIGNED_OR_COMPLETE: u8 = 0x01;
pub const ALLOWED_FLAGS: u8 = FLAG_SIGNED_OR_COMPLETE;
pub const MAX_SCRIPT_SIZE: usize = 512;
pub const MAX_SIGNATURE_RECORDS: usize = 16;
pub const EXTENDED_SCRIPT_LENGTH: u8 = 0xff;

pub const NETWORK_MARKER: u8 = b'N';
pub const MS45_INPUT_MARKER: u8 = b'I';
pub const MS45_OUTPUT_MARKER: u8 = b'O';
pub const STEALTH_MARKER: u8 = b'S';
pub const COVENANT_MARKER: u8 = b'C';
pub const INPUT_DERIVATION_MARKER: u8 = b'A';
pub const OUTPUT_DERIVATION_MARKER: u8 = b'D';

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecodeLimits {
    max_inputs: u32,
    max_outputs: u8,
    max_payload: usize,
}

impl DecodeLimits {
    pub const fn new(max_inputs: u32, max_outputs: u8, max_payload: usize) -> Self {
        Self {
            max_inputs,
            max_outputs,
            max_payload,
        }
    }

    pub const fn unbounded() -> Self {
        Self::new(u32::MAX, u8::MAX, usize::MAX)
    }

    pub(crate) fn validate_inputs(self, input_count: u32) -> Result<(), super::WireError> {
        if input_count > self.max_inputs {
            return Err(super::WireError::TooManyInputs);
        }
        Ok(())
    }

    pub(crate) fn validate_outputs(self, output_count: u8) -> Result<(), super::WireError> {
        if output_count > self.max_outputs {
            return Err(super::WireError::TooManyOutputs);
        }
        Ok(())
    }

    pub(crate) fn validate_payload(self, payload_len: usize) -> Result<(), super::WireError> {
        if payload_len > self.max_payload {
            return Err(super::WireError::PayloadTooLong);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Global<'a> {
    pub flags: u8,
    pub version: u16,
    pub input_count: u32,
    pub output_count: u8,
    pub locktime: u64,
    pub subnetwork_id: [u8; 20],
    pub gas: u64,
    pub payload: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Input<'a> {
    pub previous_tx_id: [u8; 32],
    pub previous_index: u32,
    pub amount: u64,
    pub sequence: u64,
    pub sig_op_count: u8,
    pub script_version: u16,
    pub script: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Signature {
    pub position: u8,
    pub sighash: u8,
    pub bytes: [u8; 64],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Output<'a> {
    pub amount: u64,
    pub script_version: u16,
    pub script: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Derivation {
    pub branch: u8,
    pub index: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ms45Derivation {
    pub cosigner: u32,
    pub chain: u32,
    pub index: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Covenant {
    pub authorizing_input: u16,
    pub id: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecodedEnvelope {
    pub flags: u8,
}

pub const fn valid_sighash(value: u8) -> bool {
    matches!(value, 0x01 | 0x02 | 0x04 | 0x81 | 0x82 | 0x84)
}

pub const fn valid_network(value: u8) -> bool {
    value >= 1 && value <= 4
}

pub const fn valid_derivation(value: Derivation) -> bool {
    value.branch <= 1 && value.index < 0x8000_0000
}

pub const fn valid_ms45(value: Ms45Derivation) -> bool {
    value.chain <= 1 && value.cosigner < 0x8000_0000 && value.index < 0x8000_0000
}
