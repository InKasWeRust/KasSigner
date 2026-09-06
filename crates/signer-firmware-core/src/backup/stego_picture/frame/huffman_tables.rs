//! Baseline JPEG Huffman-table segment parsing.

use super::super::{huffman::HuffmanTable, PictureError};
use super::checked_add;

pub(crate) fn parse_huffman_tables(
    segment: &[u8],
    dc_tables: &mut [HuffmanTable],
    ac_tables: &mut [HuffmanTable],
) -> Result<(), PictureError> {
    let mut position = 0usize;
    while segment.len().saturating_sub(position) >= 17 {
        position = parse_huffman_table_at(segment, position, dc_tables, ac_tables)?;
    }
    if position != segment.len() {
        return Err(PictureError::Malformed);
    }
    Ok(())
}

fn parse_huffman_table_at(
    segment: &[u8],
    position: usize,
    dc_tables: &mut [HuffmanTable],
    ac_tables: &mut [HuffmanTable],
) -> Result<usize, PictureError> {
    let (selector, counts, values_start, values_end) = huffman_table_descriptor(segment, position)?;
    let table = huffman_table_slot(
        selector >> 4,
        usize::from(selector & 0x0F),
        dc_tables,
        ac_tables,
    )?;
    table.rebuild(
        &counts,
        segment
            .get(values_start..values_end)
            .ok_or(PictureError::Malformed)?,
    )?;
    Ok(values_end)
}

fn huffman_table_descriptor(
    segment: &[u8],
    position: usize,
) -> Result<(u8, [u8; 16], usize, usize), PictureError> {
    let selector = *segment.get(position).ok_or(PictureError::Malformed)?;
    let counts_start = checked_add(position, 1)?;
    let values_start = checked_add(position, 17)?;
    let mut counts = [0u8; 16];
    counts.copy_from_slice(
        segment
            .get(counts_start..values_start)
            .ok_or(PictureError::Malformed)?,
    );
    let value_count: usize = counts.iter().map(|count| usize::from(*count)).sum();
    let values_end = checked_add(values_start, value_count)?;
    if values_end > segment.len() || value_count > 256 {
        return Err(PictureError::Malformed);
    }
    Ok((selector, counts, values_start, values_end))
}

fn huffman_table_slot<'a>(
    class: u8,
    index: usize,
    dc_tables: &'a mut [HuffmanTable],
    ac_tables: &'a mut [HuffmanTable],
) -> Result<&'a mut HuffmanTable, PictureError> {
    match class {
        0 => dc_tables.get_mut(index).ok_or(PictureError::Malformed),
        1 => ac_tables.get_mut(index).ok_or(PictureError::Malformed),
        _ => Err(PictureError::Malformed),
    }
}
