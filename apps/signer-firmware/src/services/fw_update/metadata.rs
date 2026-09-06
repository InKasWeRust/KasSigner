//! Firmware version formatting for boot/update guidance screens.

/// Current semantic firmware version, derived from the package metadata.
pub const CURRENT_VERSION: u32 = crate::version::NUMERIC;

pub fn format_version(version: u32, buf: &mut [u8]) -> usize {
    let major = version / 10_000;
    let minor = (version % 10_000) / 100;
    let patch = version % 100;

    let mut position = 0;
    position += write_u32(major, &mut buf[position..]);
    if position < buf.len() {
        buf[position] = b'.';
        position += 1;
    }
    position += write_u32(minor, &mut buf[position..]);
    if position < buf.len() {
        buf[position] = b'.';
        position += 1;
    }
    position += write_u32(patch, &mut buf[position..]);
    position
}

fn write_u32(mut value: u32, buf: &mut [u8]) -> usize {
    if value == 0 {
        if !buf.is_empty() {
            buf[0] = b'0';
        }
        return 1;
    }

    let mut digits = [0u8; 10];
    let mut count = 0;
    while value > 0 {
        digits[count] = b'0' + (value % 10) as u8;
        value /= 10;
        count += 1;
    }
    let written = count.min(buf.len());
    for index in 0..written {
        buf[index] = digits[count - 1 - index];
    }
    written
}
