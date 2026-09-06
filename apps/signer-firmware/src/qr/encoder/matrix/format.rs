use super::matrix::QrCode;

impl QrCode {
    pub(super) fn write_format_info(&mut self, mask: u8) {
        let format_data = (0b01 << 3) | (mask as u16 & 7);
        let format_bits = format_info_bits(format_data);
        let size = self.size;

        let top_left: [(u8, u8); 15] = [
            (0, 8), (1, 8), (2, 8), (3, 8), (4, 8), (5, 8), (7, 8), (8, 8),
            (8, 7), (8, 5), (8, 4), (8, 3), (8, 2), (8, 1), (8, 0),
        ];
        for (index, &(x, y)) in top_left.iter().enumerate() {
            self.set(x, y, (format_bits >> (14 - index)) & 1 != 0);
        }

        let opposite: [(u8, u8); 15] = [
            (8, size - 1), (8, size - 2), (8, size - 3), (8, size - 4),
            (8, size - 5), (8, size - 6), (8, size - 7), (size - 8, 8),
            (size - 7, 8), (size - 6, 8), (size - 5, 8), (size - 4, 8),
            (size - 3, 8), (size - 2, 8), (size - 1, 8),
        ];
        for (index, &(x, y)) in opposite.iter().enumerate() {
            self.set(x, y, (format_bits >> (14 - index)) & 1 != 0);
        }
    }
}

fn format_info_bits(data: u16) -> u16 {
    let mut bits = data << 10;
    let generator = 0b10100110111u16;
    for index in (0..5).rev() {
        if bits & (1 << (index + 10)) != 0 {
            bits ^= generator << index;
        }
    }
    ((data << 10) | bits) ^ 0b101010000010010
}

pub(super) fn alignment_positions(version: u8) -> (usize, [u8; 7]) {
    match version {
        2 => (2, [6, 18, 0, 0, 0, 0, 0]),
        3 => (2, [6, 22, 0, 0, 0, 0, 0]),
        4 => (2, [6, 26, 0, 0, 0, 0, 0]),
        5 => (2, [6, 30, 0, 0, 0, 0, 0]),
        6 => (2, [6, 34, 0, 0, 0, 0, 0]),
        _ => (0, [0; 7]),
    }
}
