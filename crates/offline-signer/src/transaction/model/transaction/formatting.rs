//! Human-readable transaction amount formatting.

use super::Transaction;

impl Transaction {
    /// Format a sompi value as KAS (no-alloc, returns in buffer)
    /// Example: 123_456_789 sompi -> "1.23456789"
    pub fn format_kas(sompi: u64, buf: &mut [u8]) -> usize {
        let kas = sompi / 100_000_000;
        let frac = sompi % 100_000_000;
        let mut pos = 0;

        // Integer part
        pos += Self::write_u64(kas, &mut buf[pos..]);

        // Decimal point
        if pos < buf.len() {
            buf[pos] = b'.';
            pos += 1;
        }

        // Fractional part (8 digits with leading zeros)
        let mut frac_buf = [b'0'; 8];
        let mut f = frac;
        for byte in frac_buf.iter_mut().rev() {
            *byte = b'0' + (f % 10) as u8;
            f /= 10;
        }

        // Write fraction (trim unnecessary trailing zeros)
        let mut last_nonzero = 0;
        for (index, &byte) in frac_buf.iter().enumerate() {
            if byte != b'0' {
                last_nonzero = index;
            }
        }
        let frac_digits = if frac == 0 { 2 } else { last_nonzero + 1 };
        for &byte in frac_buf.iter().take(frac_digits) {
            if pos < buf.len() {
                buf[pos] = byte;
                pos += 1;
            }
        }

        pos
    }

    fn write_u64(mut val: u64, buf: &mut [u8]) -> usize {
        if val == 0 {
            if !buf.is_empty() {
                buf[0] = b'0';
            }
            return 1;
        }
        let mut digits = [0u8; 20];
        let mut count = 0;
        while val > 0 {
            digits[count] = b'0' + (val % 10) as u8;
            val /= 10;
            count += 1;
        }
        let written = count.min(buf.len());
        for i in 0..written {
            buf[i] = digits[count - 1 - i];
        }
        written
    }
}
