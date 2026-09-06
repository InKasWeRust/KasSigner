//! KSSN-only bounded byte reader/writer helpers. KSPT wire I/O lives in `kassigner-protocol`.

use super::error::PsktError;

pub(crate) struct ByteReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> ByteReader<'a> {
    pub(crate) const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub(crate) fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    pub(crate) fn finish(self) -> Result<(), PsktError> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(PsktError::TrailingData)
        }
    }

    pub(crate) fn read_u8(&mut self) -> Result<u8, PsktError> {
        if self.pos >= self.data.len() {
            return Err(PsktError::BufferTooShort);
        }
        let value = self.data[self.pos];
        self.pos += 1;
        Ok(value)
    }

    pub(crate) fn read_u32_le(&mut self) -> Result<u32, PsktError> {
        let bytes = self.read_bytes(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub(crate) fn read_bytes(&mut self, count: usize) -> Result<&'a [u8], PsktError> {
        if self.remaining() < count {
            return Err(PsktError::BufferTooShort);
        }
        let bytes = &self.data[self.pos..self.pos + count];
        self.pos += count;
        Ok(bytes)
    }
}

pub(crate) struct ByteWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> ByteWriter<'a> {
    pub(crate) fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub(crate) const fn written(&self) -> usize {
        self.pos
    }

    pub(crate) fn write_bytes(&mut self, data: &[u8]) -> Result<(), PsktError> {
        let end = self
            .pos
            .checked_add(data.len())
            .ok_or(PsktError::OutputBufferTooSmall)?;
        let destination = self
            .buf
            .get_mut(self.pos..end)
            .ok_or(PsktError::OutputBufferTooSmall)?;
        destination.copy_from_slice(data);
        self.pos = end;
        Ok(())
    }

    pub(crate) fn write_u8(&mut self, value: u8) -> Result<(), PsktError> {
        self.write_bytes(&[value])
    }

    pub(crate) fn write_u32_le(&mut self, value: u32) -> Result<(), PsktError> {
        self.write_bytes(&value.to_le_bytes())
    }
}
