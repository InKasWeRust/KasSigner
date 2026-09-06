//! JPEG canonical Huffman tables and entropy bit I/O.

use super::PictureError;

pub(super) struct HuffmanTable {
    pub(super) present: bool,
    minimum_code: [i32; 17],
    maximum_code: [i32; 17],
    value_pointer: [i32; 17],
    values: [u8; 256],
    encode_code: [u16; 256],
    encode_size: [u8; 256],
}

impl HuffmanTable {
    pub(super) const fn empty() -> Self {
        Self {
            present: false,
            minimum_code: [0; 17],
            maximum_code: [-1; 17],
            value_pointer: [0; 17],
            values: [0; 256],
            encode_code: [0; 256],
            encode_size: [0; 256],
        }
    }

    pub(super) fn rebuild(&mut self, counts: &[u8; 16], values: &[u8]) -> Result<(), PictureError> {
        self.reset_for_rebuild(values)?;
        let mut code = 0i32;
        let mut value_index = 0usize;
        for length in 1..=16usize {
            self.rebuild_length(
                length,
                counts[length - 1],
                values,
                &mut value_index,
                &mut code,
            )?;
        }
        if value_index != values.len() {
            return Err(PictureError::Malformed);
        }
        self.present = true;
        Ok(())
    }

    fn reset_for_rebuild(&mut self, values: &[u8]) -> Result<(), PictureError> {
        if values.len() > self.values.len() {
            return Err(PictureError::Malformed);
        }
        self.present = false;
        self.minimum_code.fill(0);
        self.maximum_code.fill(-1);
        self.value_pointer.fill(0);
        self.values.fill(0);
        self.encode_code.fill(0);
        self.encode_size.fill(0);
        self.values[..values.len()].copy_from_slice(values);
        Ok(())
    }

    fn rebuild_length(
        &mut self,
        length: usize,
        count: u8,
        values: &[u8],
        value_index: &mut usize,
        code: &mut i32,
    ) -> Result<(), PictureError> {
        let count = usize::from(count);
        let end = value_index
            .checked_add(count)
            .ok_or(PictureError::Malformed)?;
        if end > values.len() {
            return Err(PictureError::Malformed);
        }
        if count == 0 {
            self.maximum_code[length] = -1;
        } else {
            self.install_symbols(length, *value_index, count, values, *code)?;
            *value_index = end;
            let count_i32 = i32::try_from(count).map_err(|_| PictureError::Malformed)?;
            *code = code.checked_add(count_i32).ok_or(PictureError::Malformed)?;
            self.maximum_code[length] = *code - 1;
        }
        *code = code.checked_mul(2).ok_or(PictureError::Malformed)?;
        Ok(())
    }

    fn install_symbols(
        &mut self,
        length: usize,
        value_index: usize,
        count: usize,
        values: &[u8],
        code: i32,
    ) -> Result<(), PictureError> {
        self.value_pointer[length] = value_index as i32;
        self.minimum_code[length] = code;
        for offset in 0..count {
            let symbol = usize::from(
                *values
                    .get(value_index + offset)
                    .ok_or(PictureError::Malformed)?,
            );
            let offset_i32 = i32::try_from(offset).map_err(|_| PictureError::Malformed)?;
            self.encode_code[symbol] = code
                .checked_add(offset_i32)
                .ok_or(PictureError::Malformed)? as u16;
            self.encode_size[symbol] = length as u8;
        }
        Ok(())
    }

    pub(super) fn encoded(&self, symbol: u8) -> Result<(u16, u8), PictureError> {
        let size = self.encode_size[symbol as usize];
        if size == 0 {
            return Err(PictureError::Unencodable);
        }
        Ok((self.encode_code[symbol as usize], size))
    }
}

pub(super) struct BitReader<'a> {
    data: &'a [u8],
    position: usize,
    byte: u32,
    remaining: u32,
}

impl<'a> BitReader<'a> {
    pub(super) fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            position: 0,
            byte: 0,
            remaining: 0,
        }
    }

    #[inline]
    fn bit(&mut self) -> u32 {
        if self.remaining == 0 {
            if self.position >= self.data.len() {
                return 0;
            }
            let byte = self.data[self.position];
            self.position = self.position.saturating_add(1);
            if byte == 0xFF && self.position < self.data.len() && self.data[self.position] == 0x00 {
                self.position = self.position.saturating_add(1);
            }
            self.byte = u32::from(byte);
            self.remaining = 8;
        }
        self.remaining -= 1;
        (self.byte >> self.remaining) & 1
    }

    pub(super) fn bits(&mut self, count: u32) -> i32 {
        let mut value = 0i32;
        for _ in 0..count {
            value = (value << 1) | self.bit() as i32;
        }
        value
    }

    pub(super) fn decode(&mut self, table: &HuffmanTable) -> Result<u8, PictureError> {
        let mut code = self.bit() as i32;
        for length in 1..=16usize {
            if table.maximum_code[length] >= 0 && code <= table.maximum_code[length] {
                let index = table.value_pointer[length] + code - table.minimum_code[length];
                if index < 0 || index as usize >= table.values.len() {
                    return Err(PictureError::Malformed);
                }
                return Ok(table.values[index as usize]);
            }
            code = (code << 1) | self.bit() as i32;
        }
        Err(PictureError::Malformed)
    }

    pub(super) fn resync(&mut self) {
        self.remaining = 0;
        while self.data.len().saturating_sub(self.position) >= 2 {
            if self.data[self.position] == 0xFF
                && (0xD0..=0xD7).contains(&self.data[self.position + 1])
            {
                self.position = self.position.saturating_add(2);
                return;
            }
            self.position = self.position.saturating_add(1);
        }
        self.position = self.data.len();
    }
}

pub(super) struct BitWriter<'a> {
    output: &'a mut [u8],
    pub(super) position: usize,
    byte: u32,
    remaining: u32,
    pub(super) overflowed: bool,
}

impl<'a> BitWriter<'a> {
    pub(super) fn new(output: &'a mut [u8]) -> Self {
        Self {
            output,
            position: 0,
            byte: 0,
            remaining: 0,
            overflowed: false,
        }
    }

    pub(super) fn put(&mut self, byte: u8) {
        if self.position < self.output.len() {
            self.output[self.position] = byte;
            self.position = self.position.saturating_add(1);
        } else {
            self.overflowed = true;
        }
    }

    fn bit(&mut self, bit: u32) {
        self.byte = (self.byte << 1) | (bit & 1);
        self.remaining += 1;
        if self.remaining == 8 {
            let byte = self.byte as u8;
            self.put(byte);
            if byte == 0xFF {
                self.put(0x00);
            }
            self.byte = 0;
            self.remaining = 0;
        }
    }

    pub(super) fn bits(&mut self, value: u32, count: u32) {
        for index in (0..count).rev() {
            self.bit((value >> index) & 1);
        }
    }

    pub(super) fn code(&mut self, table: &HuffmanTable, symbol: u8) -> Result<(), PictureError> {
        let (code, size) = table.encoded(symbol)?;
        self.bits(u32::from(code), u32::from(size));
        Ok(())
    }

    pub(super) fn flush(&mut self) {
        while self.remaining != 0 {
            self.bit(1);
        }
    }
}

pub(super) fn magnitude_category(value: i32) -> u32 {
    let mut magnitude = value.unsigned_abs();
    let mut bits = 0;
    while magnitude != 0 {
        bits += 1;
        magnitude >>= 1;
    }
    bits
}

pub(super) fn extend(value: i32, bits: u32) -> i32 {
    if bits == 0 {
        0
    } else if value < (1 << (bits - 1)) {
        value - (1 << bits) + 1
    } else {
        value
    }
}

pub(super) fn magnitude_bits(value: i32, bits: u32) -> u32 {
    let mask = (1u32 << bits) - 1;
    if value > 0 {
        value as u32 & mask
    } else {
        (value + (1 << bits) - 1) as u32 & mask
    }
}
