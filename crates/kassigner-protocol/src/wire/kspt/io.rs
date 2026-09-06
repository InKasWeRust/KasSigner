use super::{WireError, EXTENDED_SCRIPT_LENGTH, MAX_SCRIPT_SIZE};

pub(super) struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }
    pub fn peek(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
    }
    pub fn u8(&mut self) -> Result<u8, WireError> {
        Ok(self.bytes(1)?[0])
    }
    pub fn u16(&mut self) -> Result<u16, WireError> {
        Ok(u16::from_le_bytes(self.array()?))
    }
    pub fn u32(&mut self) -> Result<u32, WireError> {
        Ok(u32::from_le_bytes(self.array()?))
    }
    pub fn u64(&mut self) -> Result<u64, WireError> {
        Ok(u64::from_le_bytes(self.array()?))
    }
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], WireError> {
        self.bytes(N)?
            .try_into()
            .map_err(|_| WireError::BufferTooShort)
    }
    pub fn bytes(&mut self, count: usize) -> Result<&'a [u8], WireError> {
        let end = self
            .pos
            .checked_add(count)
            .ok_or(WireError::BufferTooShort)?;
        let bytes = self
            .data
            .get(self.pos..end)
            .ok_or(WireError::BufferTooShort)?;
        self.pos = end;
        Ok(bytes)
    }
    pub fn script(&mut self) -> Result<&'a [u8], WireError> {
        let prefix = self.u8()?;
        let len = if prefix == EXTENDED_SCRIPT_LENGTH {
            usize::from(self.u16()?)
        } else {
            usize::from(prefix)
        };
        if len > MAX_SCRIPT_SIZE {
            return Err(WireError::ScriptTooLong);
        }
        self.bytes(len)
    }
}

pub(super) struct Writer<'a> {
    output: &'a mut [u8],
    pos: usize,
}

impl<'a> Writer<'a> {
    pub fn new(output: &'a mut [u8]) -> Self {
        Self { output, pos: 0 }
    }
    pub const fn written(&self) -> usize {
        self.pos
    }
    pub fn bytes(&mut self, value: &[u8]) -> Result<(), WireError> {
        let end = self
            .pos
            .checked_add(value.len())
            .ok_or(WireError::OutputBufferTooSmall)?;
        let target = self
            .output
            .get_mut(self.pos..end)
            .ok_or(WireError::OutputBufferTooSmall)?;
        target.copy_from_slice(value);
        self.pos = end;
        Ok(())
    }
    pub fn u8(&mut self, value: u8) -> Result<(), WireError> {
        self.bytes(&[value])
    }
    pub fn u16(&mut self, value: u16) -> Result<(), WireError> {
        self.bytes(&value.to_le_bytes())
    }
    pub fn u32(&mut self, value: u32) -> Result<(), WireError> {
        self.bytes(&value.to_le_bytes())
    }
    pub fn u64(&mut self, value: u64) -> Result<(), WireError> {
        self.bytes(&value.to_le_bytes())
    }
    pub fn script(&mut self, value: &[u8]) -> Result<(), WireError> {
        if value.len() > MAX_SCRIPT_SIZE {
            return Err(WireError::ScriptTooLong);
        }
        if value.len() < usize::from(EXTENDED_SCRIPT_LENGTH) {
            self.u8(value.len() as u8)?;
        } else {
            self.u8(EXTENDED_SCRIPT_LENGTH)?;
            self.u16(u16::try_from(value.len()).map_err(|_| WireError::ScriptTooLong)?)?;
        }
        self.bytes(value)
    }
}
