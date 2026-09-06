//! Plausible software-export EXIF for images that carry no metadata.

use super::{write_u16, write_u32, EXIF_HEADER, TAG_IMAGE_DESCRIPTION, TAG_USER_COMMENT};

pub const SOFTWARE_TABLE: [&str; 8] = [
    "GIMP 2.10.34",
    "ImageMagick 6.9.12",
    "Paint.NET 5.0.13",
    "IrfanView 4.62",
    "XnView MP 1.4.2",
    "Photos 1.0",
    "Image Editor 2.4",
    "PhotoScape X 4.2",
];

pub fn jpeg_dimensions(jpeg: &[u8]) -> Option<(u16, u16)> {
    if jpeg.len() < 4 || !jpeg.starts_with(&[0xFF, 0xD8]) {
        return None;
    }
    let mut position = 2usize;
    while position + 9 < jpeg.len() {
        if jpeg[position] != 0xFF {
            position += 1;
            continue;
        }
        let marker = jpeg[position + 1];
        if (0xC0..=0xCF).contains(&marker)
            && marker != 0xC4
            && marker != 0xC8
            && marker != 0xCC
        {
            let height = u16::from_be_bytes([jpeg[position + 5], jpeg[position + 6]]);
            let width = u16::from_be_bytes([jpeg[position + 7], jpeg[position + 8]]);
            return (width != 0 && height != 0).then_some((width, height));
        }
        if marker == 0xDA || position + 4 > jpeg.len() {
            break;
        }
        let segment_length = usize::from(u16::from_be_bytes([
            jpeg[position + 2],
            jpeg[position + 3],
        ]));
        let Some(next) = position.checked_add(2).and_then(|value| value.checked_add(segment_length)) else {
            break;
        };
        if segment_length < 2 || next <= position || next > jpeg.len() {
            break;
        }
        position = next;
    }
    None
}

pub fn format_datetime(random: &[u8], output: &mut [u8; 19]) {
    let byte = |index: usize| u32::from(random.get(index).copied().unwrap_or(0));
    let values = [
        2019 + byte(0) % 7,
        1 + byte(1) % 12,
        1 + byte(2) % 28,
        6 + byte(3) % 17,
        byte(4) % 60,
        byte(5) % 60,
    ];
    output[0] = b'0' + ((values[0] / 1000) % 10) as u8;
    output[1] = b'0' + ((values[0] / 100) % 10) as u8;
    output[2] = b'0' + ((values[0] / 10) % 10) as u8;
    output[3] = b'0' + (values[0] % 10) as u8;
    output[4] = b':';
    write_two(values[1], &mut output[5..7]);
    output[7] = b':';
    write_two(values[2], &mut output[8..10]);
    output[10] = b' ';
    write_two(values[3], &mut output[11..13]);
    output[13] = b':';
    write_two(values[4], &mut output[14..16]);
    output[16] = b':';
    write_two(values[5], &mut output[17..19]);
}

pub fn build_template(
    description: &[u8],
    user_comment: &[u8],
    width: u16,
    height: u16,
    software: &[u8],
    datetime: &[u8; 19],
    output: &mut [u8],
) -> usize {
    let description_length = description.len() + 1;
    let software_length = software.len() + 1;
    let comment_length = 8 + user_comment.len();
    let external_description_length = if description_length > 4 { description_length } else { 0 };
    let ifd0_offset = 8usize;
    let ifd0_entries = 9usize;
    let exif_entries = 5usize;
    let data_offset = ifd0_offset + 2 + ifd0_entries * 12 + 4;
    let data_length = external_description_length + 8 + 8 + software_length + 20 + comment_length;
    let mut exif_offset = data_offset + data_length;
    if exif_offset % 2 == 1 {
        exif_offset += 1;
    }
    let tiff_length = exif_offset + 2 + exif_entries * 12 + 4;
    let total = 10 + tiff_length;
    if output.len() < total || tiff_length + 8 > u16::MAX as usize {
        return 0;
    }
    output[..total].fill(0);
    output[0..2].copy_from_slice(&[0xFF, 0xE1]);
    output[4..10].copy_from_slice(&EXIF_HEADER);
    let tiff_start = 10usize;
    output[tiff_start..tiff_start + 2].copy_from_slice(b"II");
    output[tiff_start + 2..tiff_start + 4].copy_from_slice(&[0x2A, 0]);
    write_u32(&mut output[tiff_start + 4..], ifd0_offset as u32, true);
    let mut data_position = data_offset;
    let description_offset = if external_description_length > 0 {
        let offset = data_position;
        data_position += description_length;
        offset
    } else {
        0
    };
    let x_resolution_offset = data_position;
    data_position += 8;
    let y_resolution_offset = data_position;
    data_position += 8;
    let software_offset = data_position;
    data_position += software_length;
    let datetime_offset = data_position;
    data_position += 20;
    let comment_offset = data_position;
    let mut entry_position = tiff_start + ifd0_offset;
    write_u16(&mut output[entry_position..], ifd0_entries as u16, true);
    entry_position += 2;
    write_description_entry(
        output,
        &mut entry_position,
        description,
        description_length,
        description_offset,
    );
    write_entry(output, &mut entry_position, 0x0112, 3, 1, 1);
    write_entry(output, &mut entry_position, 0x011A, 5, 1, x_resolution_offset as u32);
    write_entry(output, &mut entry_position, 0x011B, 5, 1, y_resolution_offset as u32);
    write_entry(output, &mut entry_position, 0x0128, 3, 1, 2);
    write_entry(output, &mut entry_position, 0x0131, 2, software_length as u32, software_offset as u32);
    write_entry(output, &mut entry_position, 0x0132, 2, 20, datetime_offset as u32);
    write_entry(output, &mut entry_position, 0x8769, 4, 1, exif_offset as u32);
    write_entry(output, &mut entry_position, TAG_USER_COMMENT, 7, comment_length as u32, comment_offset as u32);
    write_u32(&mut output[entry_position..], 0, true);
    if external_description_length > 0 {
        let start = tiff_start + description_offset;
        output[start..start + description.len()].copy_from_slice(description);
    }
    write_rational(output, tiff_start + x_resolution_offset, 72, 1);
    write_rational(output, tiff_start + y_resolution_offset, 72, 1);
    let software_start = tiff_start + software_offset;
    output[software_start..software_start + software.len()].copy_from_slice(software);
    let datetime_start = tiff_start + datetime_offset;
    output[datetime_start..datetime_start + 19].copy_from_slice(datetime);
    let comment_start = tiff_start + comment_offset + 8;
    output[comment_start..comment_start + user_comment.len()].copy_from_slice(user_comment);
    write_exif_ifd(output, tiff_start + exif_offset, width, height, exif_entries);
    let app1_length = total - 2;
    output[2..4].copy_from_slice(&(app1_length as u16).to_be_bytes());
    total
}

fn write_two(value: u32, output: &mut [u8]) {
    output[0] = b'0' + ((value / 10) % 10) as u8;
    output[1] = b'0' + (value % 10) as u8;
}

fn write_entry(output: &mut [u8], position: &mut usize, tag: u16, kind: u16, count: u32, value: u32) {
    write_u16(&mut output[*position..], tag, true);
    write_u16(&mut output[*position + 2..], kind, true);
    write_u32(&mut output[*position + 4..], count, true);
    write_u32(&mut output[*position + 8..], value, true);
    *position += 12;
}

fn write_description_entry(
    output: &mut [u8],
    position: &mut usize,
    description: &[u8],
    stored_length: usize,
    offset: usize,
) {
    write_u16(&mut output[*position..], TAG_IMAGE_DESCRIPTION, true);
    write_u16(&mut output[*position + 2..], 2, true);
    write_u32(&mut output[*position + 4..], stored_length as u32, true);
    if stored_length <= 4 {
        output[*position + 8..*position + 12].fill(0);
        output[*position + 8..*position + 8 + description.len()].copy_from_slice(description);
    } else {
        write_u32(&mut output[*position + 8..], offset as u32, true);
    }
    *position += 12;
}

fn write_rational(output: &mut [u8], position: usize, numerator: u32, denominator: u32) {
    write_u32(&mut output[position..], numerator, true);
    write_u32(&mut output[position + 4..], denominator, true);
}

fn write_exif_ifd(output: &mut [u8], mut position: usize, width: u16, height: u16, entry_count: usize) {
    write_u16(&mut output[position..], entry_count as u16, true);
    position += 2;
    write_inline_ascii(output, &mut position, 0x9000, b"0232");
    write_inline_ascii(output, &mut position, 0xA000, b"0100");
    write_entry(output, &mut position, 0xA001, 3, 1, 1);
    write_entry(output, &mut position, 0xA002, 4, 1, u32::from(width));
    write_entry(output, &mut position, 0xA003, 4, 1, u32::from(height));
    write_u32(&mut output[position..], 0, true);
}

fn write_inline_ascii(output: &mut [u8], position: &mut usize, tag: u16, value: &[u8; 4]) {
    write_u16(&mut output[*position..], tag, true);
    write_u16(&mut output[*position + 2..], 7, true);
    write_u32(&mut output[*position + 4..], 4, true);
    output[*position + 8..*position + 12].copy_from_slice(value);
    *position += 12;
}
