//! SD command CRC7 generation.

pub(super) fn command_crc(cmd: u8, frame: &[u8; 5]) -> u8 {
    if cmd == 0 { return 0x95; }
    if cmd == 8 { return 0x87; }
    crc7(frame)
}

fn crc7(data: &[u8]) -> u8 {
    let mut crc = 0u8;
    for &byte in data {
        for bit in (0..8).rev() {
            let incoming = (byte >> bit) & 1;
            let top = (crc >> 6) & 1;
            crc = (crc << 1) & 0x7F;
            if top ^ incoming != 0 { crc ^= 0x09; }
        }
    }
    (crc << 1) | 1
}
