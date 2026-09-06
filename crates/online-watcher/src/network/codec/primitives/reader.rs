use crate::network::error::NetworkError;

/// Bounds-checked reader used by all hand-written wire decoders.
pub struct WireReader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> WireReader<'a> {
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    #[cfg(any(target_arch = "wasm32", test))]
    pub fn remaining(&self) -> &'a [u8] {
        &self.bytes[self.position..]
    }

    pub fn read_u8(&mut self) -> Result<u8, NetworkError> {
        Ok(self.read_exact(1)?[0])
    }

    pub fn read_u16(&mut self) -> Result<u16, NetworkError> {
        let bytes = self.read_exact(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    pub fn read_u32(&mut self) -> Result<u32, NetworkError> {
        let bytes = self.read_exact(4)?;
        Ok(u32::from_le_bytes(
            bytes
                .try_into()
                .map_err(|_| NetworkError::TruncatedPayload)?,
        ))
    }

    pub fn read_u64(&mut self) -> Result<u64, NetworkError> {
        let bytes = self.read_exact(8)?;
        Ok(u64::from_le_bytes(
            bytes
                .try_into()
                .map_err(|_| NetworkError::TruncatedPayload)?,
        ))
    }

    pub fn read_f64(&mut self) -> Result<f64, NetworkError> {
        let bytes = self.read_exact(8)?;
        Ok(f64::from_le_bytes(
            bytes
                .try_into()
                .map_err(|_| NetworkError::TruncatedPayload)?,
        ))
    }

    pub fn read_bool(&mut self) -> Result<bool, NetworkError> {
        match self.read_u8()? {
            0 => Ok(false),
            1 => Ok(true),
            value => Err(NetworkError::InvalidEncoding(format!(
                "invalid bool tag {value}"
            ))),
        }
    }

    pub fn read_exact(&mut self, length: usize) -> Result<&'a [u8], NetworkError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(NetworkError::InvalidLength)?;
        if end > self.bytes.len() {
            return Err(NetworkError::TruncatedPayload);
        }
        let result = &self.bytes[self.position..end];
        self.position = end;
        Ok(result)
    }

    pub fn read_bytes(&mut self, maximum: usize) -> Result<&'a [u8], NetworkError> {
        let length = usize::try_from(self.read_u32()?).map_err(|_| NetworkError::InvalidLength)?;
        if length > maximum {
            return Err(NetworkError::InvalidLength);
        }
        self.read_exact(length)
    }
}
