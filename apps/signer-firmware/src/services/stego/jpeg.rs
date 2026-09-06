//! JPEG segment insertion for descriptor steganography.

const EXIF_HEADER: &[u8; 6] = b"Exif\0\0";

/// Replace every pre-scan EXIF APP1 segment with one new segment.
///
/// The first host EXIF segment is replaced in place so the encoder's original
/// marker order is retained. Non-EXIF APP1 segments such as XMP are preserved.
/// If the host has no EXIF, the new segment is inserted after leading APP0
/// segments, matching conventional JFIF/EXIF ordering.
pub fn inject_exif(jpeg: &[u8], app1: &[u8], output: &mut [u8]) -> usize {
    if jpeg.len() < 2 || !jpeg.starts_with(&[0xFF, 0xD8]) || !is_exif_app1(app1, 0, app1.len()) {
        return 0;
    }
    let Some(soi) = output.get_mut(..2) else {
        return 0;
    };
    soi.copy_from_slice(&jpeg[..2]);
    let mut input_position = 2usize;
    let mut output_position = 2usize;
    let mut inserted = false;
    let mut leading_app0 = true;

    loop {
        let Some((marker, end)) = next_segment(jpeg, input_position) else {
            return 0;
        };
        if marker == 0xDA || marker == 0xD9 {
            if !inserted {
                let Some(next) = append(output, output_position, app1) else {
                    return 0;
                };
                output_position = next;
            }
            let Some(next) = append(output, output_position, &jpeg[input_position..]) else {
                return 0;
            };
            return next;
        }

        let host_exif = marker == 0xE1 && is_exif_app1(jpeg, input_position, end);
        if host_exif {
            if !inserted {
                let Some(next) = append(output, output_position, app1) else {
                    return 0;
                };
                output_position = next;
                inserted = true;
            }
            input_position = end;
            leading_app0 = false;
            continue;
        }

        if !inserted && leading_app0 && marker != 0xE0 {
            let Some(next) = append(output, output_position, app1) else {
                return 0;
            };
            output_position = next;
            inserted = true;
        }
        let Some(next) = append(output, output_position, &jpeg[input_position..end]) else {
            return 0;
        };
        output_position = next;
        input_position = end;
        leading_app0 &= marker == 0xE0;
    }
}

fn append(output: &mut [u8], position: usize, bytes: &[u8]) -> Option<usize> {
    let end = position.checked_add(bytes.len())?;
    output.get_mut(position..end)?.copy_from_slice(bytes);
    Some(end)
}

fn is_exif_app1(jpeg: &[u8], position: usize, end: usize) -> bool {
    end >= position.saturating_add(10)
        && jpeg
            .get(position..position + 2)
            .is_some_and(|marker| marker == [0xFF, 0xE1])
        && jpeg
            .get(position + 4..position + 10)
            .is_some_and(|header| header == EXIF_HEADER)
}

fn next_segment(jpeg: &[u8], position: usize) -> Option<(u8, usize)> {
    if position + 2 > jpeg.len() || jpeg[position] != 0xFF {
        return None;
    }
    let marker = jpeg[position + 1];
    if marker == 0xDA || marker == 0xD9 {
        return Some((marker, position));
    }
    if marker == 0xD8 || marker == 0x01 || (0xD0..=0xD7).contains(&marker) {
        return Some((marker, position + 2));
    }
    if position + 4 > jpeg.len() {
        return None;
    }
    let segment_length = usize::from(u16::from_be_bytes([
        jpeg[position + 2],
        jpeg[position + 3],
    ]));
    let end = position.checked_add(2)?.checked_add(segment_length)?;
    (segment_length >= 2 && end <= jpeg.len()).then_some((marker, end))
}
