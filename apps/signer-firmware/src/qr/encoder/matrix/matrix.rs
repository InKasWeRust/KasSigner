use super::super::constants::BITMAP_BYTES;
use super::format::alignment_positions;

/// Fixed-storage QR matrix.
pub struct QrCode {
    pub(super) modules: [u8; BITMAP_BYTES],
    is_function: [u8; BITMAP_BYTES],
    pub size: u8,
    pub(crate) version: u8,
}

impl QrCode {
    pub(super) fn new(version: u8) -> Self {
        Self {
            modules: [0u8; BITMAP_BYTES],
            is_function: [0u8; BITMAP_BYTES],
            size: 17 + version * 4,
            version,
        }
    }

    #[inline]
    pub(super) fn index(&self, x: u8, y: u8) -> usize {
        (y as usize) * (self.size as usize) + (x as usize)
    }

    /// Get the module value at `(x, y)`.
    #[inline]
    pub fn get(&self, x: u8, y: u8) -> bool {
        let index = self.index(x, y);
        (self.modules[index / 8] >> (index % 8)) & 1 != 0
    }

    #[inline]
    pub(super) fn set(&mut self, x: u8, y: u8, dark: bool) {
        let index = self.index(x, y);
        if dark {
            self.modules[index / 8] |= 1 << (index % 8);
        } else {
            self.modules[index / 8] &= !(1 << (index % 8));
        }
    }

    #[inline]
    pub(super) fn is_function(&self, x: u8, y: u8) -> bool {
        let index = self.index(x, y);
        (self.is_function[index / 8] >> (index % 8)) & 1 != 0
    }

    #[inline]
    fn set_function(&mut self, x: u8, y: u8, dark: bool) {
        let index = self.index(x, y);
        self.is_function[index / 8] |= 1 << (index % 8);
        if dark {
            self.modules[index / 8] |= 1 << (index % 8);
        } else {
            self.modules[index / 8] &= !(1 << (index % 8));
        }
    }

    pub(super) fn draw_function_patterns(&mut self) {
        let size = self.size;
        self.draw_finder(3, 3);
        self.draw_finder(size as i16 - 4, 3);
        self.draw_finder(3, size as i16 - 4);

        for index in 8..size - 8 {
            self.set_function(index, 6, index % 2 == 0);
            self.set_function(6, index, index % 2 == 0);
        }
        self.set_function(8, 4 * self.version + 9, true);

        if self.version >= 2 {
            let (count, positions) = alignment_positions(self.version);
            for row in 0..count {
                for column in 0..count {
                    if (row == 0 && column == 0)
                        || (row == 0 && column == count - 1)
                        || (row == count - 1 && column == 0)
                    {
                        continue;
                    }
                    self.draw_alignment(positions[row], positions[column]);
                }
            }
        }

        for index in 0..9u8 {
            if index < size {
                self.set_function(index, 8, false);
                self.set_function(8, index, false);
            }
        }
        for index in 0..8u8 {
            self.set_function(size - 1 - index, 8, false);
        }
        for index in 0..7u8 {
            self.set_function(8, size - 1 - index, false);
        }
    }

    pub(super) fn place_data(&mut self, data: &[u8]) {
        let size = self.size as i16;
        let mut bit_index = 0usize;
        let total_bits = data.len() * 8;
        let mut right = size - 1;

        while right >= 0 {
            if right == 6 {
                right -= 1;
                continue;
            }
            let upward = ((size - 1 - right) / 2) % 2 == 0;
            for row_index in 0..size {
                let y = if upward { size - 1 - row_index } else { row_index };
                for delta_x in 0..2i16 {
                    let x = right - delta_x;
                    if x < 0 || x >= size || y < 0 || y >= size {
                        continue;
                    }
                    if self.is_function(x as u8, y as u8) {
                        continue;
                    }

                    let dark = if bit_index < total_bits {
                        let byte = data[bit_index / 8];
                        let bit = 7 - (bit_index % 8);
                        bit_index += 1;
                        (byte >> bit) & 1 != 0
                    } else {
                        false
                    };
                    self.set(x as u8, y as u8, dark);
                }
            }
            right -= 2;
        }
    }

    fn draw_finder(&mut self, center_x: i16, center_y: i16) {
        for delta_y in -4i16..=4 {
            for delta_x in -4i16..=4 {
                let x = center_x + delta_x;
                let y = center_y + delta_y;
                if x < 0 || y < 0 || x >= self.size as i16 || y >= self.size as i16 {
                    continue;
                }
                let distance = delta_x.abs().max(delta_y.abs());
                self.set_function(x as u8, y as u8, distance != 2 && distance != 4);
            }
        }
    }

    fn draw_alignment(&mut self, center_x: u8, center_y: u8) {
        for delta_y in -2i8..=2 {
            for delta_x in -2i8..=2 {
                let x = (center_x as i8 + delta_x) as u8;
                let y = (center_y as i8 + delta_y) as u8;
                let dark = delta_x.abs().max(delta_y.abs()) != 1;
                self.set_function(x, y, dark);
            }
        }
    }
}
