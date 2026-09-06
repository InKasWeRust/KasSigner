//! Metadata-preserving EXIF carrier.

mod copyforward;
mod template;

pub use copyforward::build_copyforward;
pub use template::{build_template, format_datetime, jpeg_dimensions, SOFTWARE_TABLE};

pub(super) const EXIF_HEADER: [u8; 6] = *b"Exif\0\0";
pub(super) const TAG_IMAGE_DESCRIPTION: u16 = 0x010E;
pub(super) const TAG_USER_COMMENT: u16 = 0x9286;

pub(super) fn read_u16(bytes: &[u8], little_endian: bool) -> u16 {
    if little_endian {
        u16::from_le_bytes([bytes[0], bytes[1]])
    } else {
        u16::from_be_bytes([bytes[0], bytes[1]])
    }
}

pub(super) fn read_u32(bytes: &[u8], little_endian: bool) -> u32 {
    if little_endian {
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    } else {
        u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    }
}

pub(super) fn write_u16(bytes: &mut [u8], value: u16, little_endian: bool) {
    let encoded = if little_endian { value.to_le_bytes() } else { value.to_be_bytes() };
    bytes[..2].copy_from_slice(&encoded);
}

pub(super) fn write_u32(bytes: &mut [u8], value: u32, little_endian: bool) {
    let encoded = if little_endian { value.to_le_bytes() } else { value.to_be_bytes() };
    bytes[..4].copy_from_slice(&encoded);
}

pub(super) fn byte_order(app1: &[u8]) -> Option<bool> {
    if app1.len() < 20 || !app1.starts_with(&[0xFF, 0xE1]) || app1[4..10] != EXIF_HEADER {
        return None;
    }
    match (app1[10], app1[11]) {
        (b'I', b'I') => Some(true),
        (b'M', b'M') => Some(false),
        _ => None,
    }
}

/// Locate the first pre-scan EXIF APP1 segment.
pub fn find_app1(jpeg: &[u8]) -> Option<(usize, usize)> {
    if jpeg.len() < 4 || !jpeg.starts_with(&[0xFF, 0xD8]) {
        return None;
    }
    let mut position = 2usize;
    while position + 4 <= jpeg.len() {
        if jpeg[position] != 0xFF {
            position += 1;
            continue;
        }
        let marker = jpeg[position + 1];
        if marker == 0xDA || marker == 0xD9 {
            break;
        }
        if position + 4 > jpeg.len() {
            break;
        }
        let segment_length = usize::from(u16::from_be_bytes([
            jpeg[position + 2],
            jpeg[position + 3],
        ]));
        let total = segment_length.checked_add(2)?;
        let end = position.checked_add(total)?;
        if segment_length < 2 || end > jpeg.len() {
            return None;
        }
        if marker == 0xE1 && position + 10 <= end && jpeg[position + 4..position + 10] == EXIF_HEADER {
            return Some((position, total));
        }
        position = end;
    }
    None
}

/// Extract binary UserComment bytes after the eight-byte EXIF charset field.
pub fn extract_user_comment(app1: &[u8], output: &mut [u8]) -> usize {
    let Some(little_endian) = byte_order(app1) else {
        return 0;
    };
    let tiff_start = 10usize;
    let ifd_offset = read_u32(&app1[tiff_start + 4..tiff_start + 8], little_endian) as usize;
    let Some(ifd_position) = tiff_start.checked_add(ifd_offset) else {
        return 0;
    };
    if ifd_position + 2 > app1.len() {
        return 0;
    }
    let entry_count = usize::from(read_u16(&app1[ifd_position..ifd_position + 2], little_endian)).min(200);
    for entry_index in 0..entry_count {
        let Some(entry_position) = ifd_position.checked_add(2 + entry_index * 12) else {
            return 0;
        };
        if entry_position + 12 > app1.len() {
            return 0;
        }
        let tag = read_u16(&app1[entry_position..entry_position + 2], little_endian);
        if tag != TAG_USER_COMMENT {
            continue;
        }
        let count = read_u32(&app1[entry_position + 4..entry_position + 8], little_endian) as usize;
        if count <= 8 {
            return 0;
        }
        let value_offset = read_u32(&app1[entry_position + 8..entry_position + 12], little_endian) as usize;
        let Some(data_start) = tiff_start.checked_add(value_offset).and_then(|value| value.checked_add(8)) else {
            return 0;
        };
        let payload_length = count - 8;
        if payload_length > output.len() {
            return 0;
        }
        let Some(data_end) = data_start.checked_add(payload_length) else {
            return 0;
        };
        if data_end > app1.len() {
            return 0;
        }
        output[..payload_length].copy_from_slice(&app1[data_start..data_end]);
        return payload_length;
    }
    0
}
