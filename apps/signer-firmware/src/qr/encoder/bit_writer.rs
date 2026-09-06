pub(super) struct BitWriter<'a> {
    buffer: &'a mut [u8],
    pub(super) bit_pos: usize,
}

impl<'a> BitWriter<'a> {
    pub(super) fn new(buffer: &'a mut [u8]) -> Self {
        buffer.fill(0);
        Self { buffer, bit_pos: 0 }
    }

    pub(super) fn write_bits(&mut self, value: u32, count: usize) {
        for i in (0..count).rev() {
            let bit = (value >> i) & 1;
            let byte_index = self.bit_pos / 8;
            let bit_index = 7 - (self.bit_pos % 8);
            if byte_index < self.buffer.len() && bit != 0 {
                self.buffer[byte_index] |= 1 << bit_index;
            }
            self.bit_pos += 1;
        }
    }
}
