use alloc::vec::Vec;

use crate::transaction::model::SigHashType;

use super::{
    error::PsktError,
    format::{KSSN_MAGIC, KSSN_VERSION_CURRENT},
    kssn_io::{ByteReader, ByteWriter},
};

#[derive(Debug, Clone)]
pub struct InputSignature {
    pub input_index: u32,
    pub sighash_type: SigHashType,
    pub signature: [u8; 64],
}

#[derive(Debug, Default)]
pub struct SignedResponse {
    pub signatures: Vec<InputSignature>,
}

fn read_response_count(reader: &mut ByteReader<'_>) -> Result<usize, PsktError> {
    if reader.read_bytes(4)? != KSSN_MAGIC {
        return Err(PsktError::InvalidMagic);
    }
    if reader.read_u8()? != KSSN_VERSION_CURRENT {
        return Err(PsktError::UnsupportedVersion);
    }
    usize::try_from(reader.read_u32_le()?).map_err(|_| PsktError::TooManySignatures)
}

fn read_input_signature(reader: &mut ByteReader<'_>) -> Result<InputSignature, PsktError> {
    let input_index = reader.read_u32_le()?;
    let sighash_type =
        SigHashType::from_byte(reader.read_u8()?).ok_or(PsktError::InvalidSigHashType)?;
    let mut signature = [0u8; 64];
    signature.copy_from_slice(reader.read_bytes(64)?);
    Ok(InputSignature {
        input_index,
        sighash_type,
        signature,
    })
}

impl SignedResponse {
    pub const fn new() -> Self {
        Self {
            signatures: Vec::new(),
        }
    }

    pub fn add_signature(
        &mut self,
        input_index: u32,
        sighash_type: SigHashType,
        signature: &[u8; 64],
    ) -> Result<(), PsktError> {
        if self
            .signatures
            .iter()
            .any(|existing| existing.input_index == input_index)
        {
            return Err(PsktError::InvalidSignatureState);
        }
        self.signatures
            .try_reserve(1)
            .map_err(|_| PsktError::TooManySignatures)?;
        self.signatures.push(InputSignature {
            input_index,
            sighash_type,
            signature: *signature,
        });
        Ok(())
    }

    pub fn serialize(&self, output: &mut [u8]) -> Result<usize, PsktError> {
        let count =
            u32::try_from(self.signatures.len()).map_err(|_| PsktError::TooManySignatures)?;
        let mut writer = ByteWriter::new(output);
        writer.write_bytes(&KSSN_MAGIC)?;
        writer.write_u8(KSSN_VERSION_CURRENT)?;
        writer.write_u32_le(count)?;
        for signature in &self.signatures {
            writer.write_u32_le(signature.input_index)?;
            writer.write_u8(signature.sighash_type.to_byte())?;
            writer.write_bytes(&signature.signature)?;
        }
        Ok(writer.written())
    }

    pub fn parse(data: &[u8]) -> Result<Self, PsktError> {
        let mut reader = ByteReader::new(data);
        let count = read_response_count(&mut reader)?;
        let mut response = Self {
            signatures: Vec::new(),
        };
        response
            .signatures
            .try_reserve(count)
            .map_err(|_| PsktError::TooManySignatures)?;
        for _ in 0..count {
            let input = read_input_signature(&mut reader)?;
            response.add_signature(input.input_index, input.sighash_type, &input.signature)?;
        }
        reader.finish()?;
        Ok(response)
    }
}
