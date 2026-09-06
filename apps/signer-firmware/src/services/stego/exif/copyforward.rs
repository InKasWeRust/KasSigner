//! Copy-forward EXIF builder that preserves the host TIFF block verbatim.

use super::{byte_order, read_u16, read_u32, write_u16, write_u32, EXIF_HEADER, TAG_IMAGE_DESCRIPTION, TAG_USER_COMMENT};

struct HostLayout<'a> {
    tiff: &'a [u8],
    ifd0: usize,
    entry_count: usize,
    entries_end: usize,
    kept_count: usize,
    little_endian: bool,
}

struct EntryLayout {
    total_entries: usize,
    new_ifd0: usize,
    description_length: usize,
    comment_length: usize,
    description_offset: usize,
    comment_offset: usize,
}

pub fn build_copyforward(
    host_app1: &[u8],
    description: &[u8],
    user_comment: &[u8],
    output: &mut [u8],
) -> usize {
    let Some(host) = copyforward_host_layout(host_app1) else {
        return 0;
    };
    if output.len() < 10 {
        return 0;
    }
    output[0..2].copy_from_slice(&[0xFF, 0xE1]);
    output[4..10].copy_from_slice(&EXIF_HEADER);
    let tiff_output = 10usize;
    if tiff_output + host.tiff.len() > output.len() {
        return 0;
    }
    output[tiff_output..tiff_output + host.tiff.len()].copy_from_slice(host.tiff);
    let Some(position) = aligned_copyforward_position(output, tiff_output + host.tiff.len(), tiff_output) else {
        return 0;
    };
    finish_copyforward(&host, description, user_comment, output, tiff_output, position)
}

fn copyforward_host_layout(host_app1: &[u8]) -> Option<HostLayout<'_>> {
    let little_endian = byte_order(host_app1)?;
    let tiff = host_app1.get(10..)?;
    if tiff.len() < 8 {
        return None;
    }
    let ifd0 = read_u32(&tiff[4..8], little_endian) as usize;
    let entries_start = ifd0.checked_add(2)?;
    if entries_start > tiff.len() {
        return None;
    }
    let entry_count = usize::from(read_u16(&tiff[ifd0..entries_start], little_endian));
    if entry_count > 200 {
        return None;
    }
    let entries_end = entries_start.checked_add(entry_count.checked_mul(12)?)?;
    if entries_end.checked_add(4)? > tiff.len() {
        return None;
    }
    let kept_count = (0..entry_count)
        .filter(|entry_index| keep_host_entry(tiff, ifd0, *entry_index, little_endian))
        .count();
    Some(HostLayout { tiff, ifd0, entry_count, entries_end, kept_count, little_endian })
}

fn keep_host_entry(tiff: &[u8], ifd0: usize, entry_index: usize, little_endian: bool) -> bool {
    let position = ifd0 + 2 + entry_index * 12;
    let tag = read_u16(&tiff[position..position + 2], little_endian);
    tag != TAG_IMAGE_DESCRIPTION && tag != TAG_USER_COMMENT
}

fn aligned_copyforward_position(
    output: &mut [u8],
    mut position: usize,
    tiff_output: usize,
) -> Option<usize> {
    if (position - tiff_output) % 2 == 0 {
        return Some(position);
    }
    let byte = output.get_mut(position)?;
    *byte = 0;
    position += 1;
    Some(position)
}

fn finish_copyforward(
    host: &HostLayout<'_>,
    description: &[u8],
    user_comment: &[u8],
    output: &mut [u8],
    tiff_output: usize,
    mut position: usize,
) -> usize {
    let layout = entry_layout(host, description.len(), user_comment.len(), tiff_output, position);
    let required = tiff_output + layout.comment_offset + layout.comment_length;
    if required > output.len() || layout.total_entries > u16::MAX as usize {
        return 0;
    }
    write_u16(&mut output[position..], layout.total_entries as u16, host.little_endian);
    position += 2;
    position = write_copyforward_entries(host, &layout, description, output, position);
    output[position..position + 4]
        .copy_from_slice(&host.tiff[host.entries_end..host.entries_end + 4]);
    position += 4;
    position = write_copyforward_values(
        output,
        position,
        description,
        layout.description_length,
        user_comment,
    );
    write_u32(
        &mut output[tiff_output + 4..],
        layout.new_ifd0 as u32,
        host.little_endian,
    );
    let app1_length = position - 2;
    if app1_length > u16::MAX as usize {
        return 0;
    }
    output[2..4].copy_from_slice(&(app1_length as u16).to_be_bytes());
    position
}

fn entry_layout(
    host: &HostLayout<'_>,
    description_len: usize,
    user_comment_len: usize,
    tiff_output: usize,
    position: usize,
) -> EntryLayout {
    let total_entries = host.kept_count + 2;
    let new_ifd0 = position - tiff_output;
    let description_length = description_len + 1;
    let comment_length = 8 + user_comment_len;
    let data_offset = new_ifd0 + 2 + total_entries * 12 + 4;
    EntryLayout {
        total_entries,
        new_ifd0,
        description_length,
        comment_length,
        description_offset: data_offset,
        comment_offset: data_offset + description_length,
    }
}

fn write_copyforward_entries(
    host: &HostLayout<'_>,
    layout: &EntryLayout,
    description: &[u8],
    output: &mut [u8],
    mut position: usize,
) -> usize {
    let mut host_index = 0usize;
    let mut description_written = false;
    let mut comment_written = false;
    for _ in 0..layout.total_entries {
        let (host_tag, host_position, next_host_index) = next_kept_host_entry(
            host.tiff,
            host.ifd0,
            host.entry_count,
            host_index,
            host.little_endian,
        );
        let description_tag = if description_written { u16::MAX } else { TAG_IMAGE_DESCRIPTION };
        let comment_tag = if comment_written { u16::MAX } else { TAG_USER_COMMENT };
        if description_tag <= host_tag && description_tag <= comment_tag {
            write_description_entry(
                &mut output[position..position + 12],
                description,
                layout.description_length,
                layout.description_offset,
                host.little_endian,
            );
            description_written = true;
        } else if comment_tag <= host_tag {
            write_entry(
                &mut output[position..position + 12],
                TAG_USER_COMMENT,
                7,
                layout.comment_length as u32,
                layout.comment_offset as u32,
                host.little_endian,
            );
            comment_written = true;
        } else {
            output[position..position + 12]
                .copy_from_slice(&host.tiff[host_position..host_position + 12]);
            host_index = next_host_index;
        }
        position += 12;
    }
    position
}

fn write_copyforward_values(
    output: &mut [u8],
    mut position: usize,
    description: &[u8],
    description_length: usize,
    user_comment: &[u8],
) -> usize {
    if description_length > 4 {
        output[position..position + description.len()].copy_from_slice(description);
        position += description.len();
        output[position] = 0;
        position += 1;
    } else {
        output[position..position + description_length].fill(0);
        position += description_length;
    }
    output[position..position + 8].fill(0);
    position += 8;
    output[position..position + user_comment.len()].copy_from_slice(user_comment);
    position + user_comment.len()
}

fn next_kept_host_entry(
    tiff: &[u8],
    ifd0: usize,
    entry_count: usize,
    start: usize,
    little_endian: bool,
) -> (u16, usize, usize) {
    for index in start..entry_count {
        let position = ifd0 + 2 + index * 12;
        let tag = read_u16(&tiff[position..position + 2], little_endian);
        if tag != TAG_IMAGE_DESCRIPTION && tag != TAG_USER_COMMENT {
            return (tag, position, index + 1);
        }
    }
    (u16::MAX, 0, entry_count)
}

fn write_description_entry(
    entry: &mut [u8],
    description: &[u8],
    stored_length: usize,
    offset: usize,
    little_endian: bool,
) {
    write_u16(entry, TAG_IMAGE_DESCRIPTION, little_endian);
    write_u16(&mut entry[2..], 2, little_endian);
    write_u32(&mut entry[4..], stored_length as u32, little_endian);
    if stored_length <= 4 {
        entry[8..12].fill(0);
        entry[8..8 + description.len()].copy_from_slice(description);
    } else {
        write_u32(&mut entry[8..], offset as u32, little_endian);
    }
}

fn write_entry(
    entry: &mut [u8],
    tag: u16,
    kind: u16,
    count: u32,
    value: u32,
    little_endian: bool,
) {
    write_u16(entry, tag, little_endian);
    write_u16(&mut entry[2..], kind, little_endian);
    write_u32(&mut entry[4..], count, little_endian);
    write_u32(&mut entry[8..], value, little_endian);
}
