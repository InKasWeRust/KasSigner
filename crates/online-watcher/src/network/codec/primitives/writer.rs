use crate::network::error::NetworkError;

/// Checked little-endian writer for Kaspa's wRPC/Borsh envelope.
#[derive(Default)]
pub struct WireWriter {
    bytes: Vec<u8>,
}

impl WireWriter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity),
        }
    }

    pub fn write_u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    pub fn write_u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    pub fn write_u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    pub fn write_u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    pub fn write_raw(&mut self, value: &[u8]) {
        self.bytes.extend_from_slice(value);
    }

    pub fn write_bytes(&mut self, value: &[u8]) -> Result<(), NetworkError> {
        let length = u32::try_from(value.len()).map_err(|_| NetworkError::InvalidLength)?;
        self.write_u32(length);
        self.write_raw(value);
        Ok(())
    }

    pub fn write_count(&mut self, count: usize) -> Result<(), NetworkError> {
        self.write_u32(u32::try_from(count).map_err(|_| NetworkError::InvalidLength)?);
        Ok(())
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.bytes
    }
}
