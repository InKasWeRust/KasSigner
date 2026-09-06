//! Streaming JPEG block decode, mutation, and re-encode.

use super::permutation::PositionPermutation;
use super::{
    frame::Frame,
    huffman::{extend, magnitude_bits, magnitude_category, BitReader, BitWriter, HuffmanTable},
    PictureError,
};

/// Hard CPU-work ceiling for baseline JPEG carrier traversal. This permits
/// ordinary multi-megapixel photos while rejecting hostile dimensions that
/// would otherwise drive millions of entropy blocks despite a 40k rank window.
const MAX_DECODE_BLOCKS: u32 = 320_000;

pub(super) enum WalkMode<'a> {
    Collect {
        coefficients: &'a mut [i16],
        present: &'a mut [u8],
    },
    Apply {
        coefficients: &'a [i16],
        changed: &'a [u8],
    },
}

#[inline]
pub(super) fn bit_get(bits: &[u8], index: u32) -> bool {
    let byte = (index >> 3) as usize;
    byte < bits.len() && ((bits[byte] >> (index & 7)) & 1) == 1
}

#[inline]
pub(super) fn bit_set(bits: &mut [u8], index: u32) {
    let byte = (index >> 3) as usize;
    if byte < bits.len() {
        bits[byte] |= 1 << (index & 7);
    }
}

pub(super) fn walk(
    jpeg: &[u8],
    frame: &Frame,
    permutation: &PositionPermutation,
    rank_window: u32,
    mode: &mut WalkMode<'_>,
    output: Option<&mut [u8]>,
) -> Result<usize, PictureError> {
    let scan = jpeg
        .get(frame.scan_start..frame.scan_end)
        .ok_or(PictureError::Malformed)?;
    let mut reader = BitReader::new(scan);
    let mut empty: [u8; 0] = [];
    let writing = output.is_some();
    let output_buffer = output.unwrap_or(&mut empty);
    let mut writer = BitWriter::new(output_buffer);
    let mut block_index = 0u32;
    let settings = WalkSettings {
        frame,
        permutation,
        rank_window,
        writing,
    };

    let mcu_count = frame
        .mcu_columns
        .checked_mul(frame.mcu_rows)
        .ok_or(PictureError::Malformed)?;
    let block_count = mcu_count
        .checked_mul(frame.blocks_per_mcu)
        .ok_or(PictureError::Malformed)?;
    if block_count > MAX_DECODE_BLOCKS {
        return Err(PictureError::WorkLimitExceeded);
    }
    for mcu in 0..mcu_count {
        handle_restart(
            frame.restart_interval,
            mcu,
            writing,
            &mut reader,
            &mut writer,
        );
        walk_mcu(&settings, mode, &mut reader, &mut writer, &mut block_index)?;
    }
    finish_walk(writing, &mut writer)
}

fn handle_restart(
    restart_interval: u32,
    mcu: u32,
    writing: bool,
    reader: &mut BitReader<'_>,
    writer: &mut BitWriter<'_>,
) {
    if restart_interval == 0 || mcu == 0 || !mcu.is_multiple_of(restart_interval) {
        return;
    }
    reader.resync();
    if writing {
        writer.flush();
        let marker = 0xD0 + (((mcu / restart_interval) - 1) % 8) as u8;
        writer.put(0xFF);
        writer.put(marker);
    }
}

struct WalkSettings<'a> {
    frame: &'a Frame,
    permutation: &'a PositionPermutation,
    rank_window: u32,
    writing: bool,
}

fn walk_mcu(
    settings: &WalkSettings<'_>,
    mode: &mut WalkMode<'_>,
    reader: &mut BitReader<'_>,
    writer: &mut BitWriter<'_>,
    block_index: &mut u32,
) -> Result<(), PictureError> {
    for component_index in 0..settings.frame.component_count {
        let component = *settings
            .frame
            .components
            .get(component_index)
            .ok_or(PictureError::Malformed)?;
        let block_count = component
            .horizontal
            .checked_mul(component.vertical)
            .ok_or(PictureError::Malformed)?;
        for _ in 0..block_count {
            walk_block(component, settings, mode, reader, writer, *block_index)?;
            *block_index = block_index.checked_add(1).ok_or(PictureError::Malformed)?;
        }
    }
    Ok(())
}

fn walk_block(
    component: super::frame::Component,
    settings: &WalkSettings<'_>,
    mode: &mut WalkMode<'_>,
    reader: &mut BitReader<'_>,
    writer: &mut BitWriter<'_>,
    block_index: u32,
) -> Result<(), PictureError> {
    let mut coefficients = [0i16; 64];
    decode_block(
        reader,
        &settings.frame.dc_tables[component.dc_table],
        &settings.frame.ac_tables[component.ac_table],
        &mut coefficients,
    )?;
    apply_window(
        settings.permutation,
        settings.rank_window,
        mode,
        block_index.checked_mul(63).ok_or(PictureError::Malformed)?,
        &mut coefficients,
    )?;
    if settings.writing {
        encode_block(
            writer,
            &settings.frame.dc_tables[component.dc_table],
            &settings.frame.ac_tables[component.ac_table],
            &coefficients,
        )?;
    }
    Ok(())
}

fn apply_window(
    permutation: &PositionPermutation,
    rank_window: u32,
    mode: &mut WalkMode<'_>,
    base: u32,
    coefficients: &mut [i16; 64],
) -> Result<(), PictureError> {
    match mode {
        WalkMode::Collect {
            coefficients: window,
            present,
        } => collect_window(
            permutation,
            rank_window,
            base,
            coefficients,
            window,
            present,
        ),
        WalkMode::Apply {
            coefficients: window,
            changed,
        } => apply_changed_window(
            permutation,
            rank_window,
            base,
            coefficients,
            window,
            changed,
        ),
    }
}

fn collect_window(
    permutation: &PositionPermutation,
    rank_window: u32,
    base: u32,
    coefficients: &[i16; 64],
    window: &mut [i16],
    present: &mut [u8],
) -> Result<(), PictureError> {
    for coefficient_index in 1..64usize {
        let rank = coefficient_rank(permutation, base, coefficient_index)?;
        if rank >= rank_window {
            continue;
        }
        let value = *coefficients
            .get(coefficient_index)
            .ok_or(PictureError::Malformed)?;
        let target = window
            .get_mut(rank as usize)
            .ok_or(PictureError::Malformed)?;
        *target = value;
        bit_set(present, rank);
    }
    Ok(())
}

fn apply_changed_window(
    permutation: &PositionPermutation,
    rank_window: u32,
    base: u32,
    coefficients: &mut [i16; 64],
    window: &[i16],
    changed: &[u8],
) -> Result<(), PictureError> {
    for coefficient_index in 1..64usize {
        let rank = coefficient_rank(permutation, base, coefficient_index)?;
        if rank >= rank_window || !bit_get(changed, rank) {
            continue;
        }
        let value = *window.get(rank as usize).ok_or(PictureError::Malformed)?;
        let target = coefficients
            .get_mut(coefficient_index)
            .ok_or(PictureError::Malformed)?;
        *target = value;
    }
    Ok(())
}

fn coefficient_rank(
    permutation: &PositionPermutation,
    base: u32,
    coefficient_index: usize,
) -> Result<u32, PictureError> {
    let offset = coefficient_index
        .checked_sub(1)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or(PictureError::Malformed)?;
    let position = base.checked_add(offset).ok_or(PictureError::Malformed)?;
    Ok(permutation.rank(position))
}

fn finish_walk(writing: bool, writer: &mut BitWriter<'_>) -> Result<usize, PictureError> {
    if !writing {
        return Ok(0);
    }
    writer.flush();
    if writer.overflowed {
        return Err(PictureError::BufferTooSmall);
    }
    Ok(writer.position)
}

pub(super) fn decode_block(
    reader: &mut BitReader<'_>,
    dc_table: &HuffmanTable,
    ac_table: &HuffmanTable,
    coefficients: &mut [i16; 64],
) -> Result<(), PictureError> {
    *coefficients = [0; 64];
    coefficients[0] = decode_dc(reader, dc_table)?;
    decode_ac(reader, ac_table, coefficients)
}

fn decode_dc(reader: &mut BitReader<'_>, table: &HuffmanTable) -> Result<i16, PictureError> {
    let bits = u32::from(reader.decode(table)?);
    if bits > 15 {
        return Err(PictureError::Malformed);
    }
    Ok(if bits == 0 {
        0
    } else {
        extend(reader.bits(bits), bits) as i16
    })
}

fn decode_ac(
    reader: &mut BitReader<'_>,
    table: &HuffmanTable,
    coefficients: &mut [i16; 64],
) -> Result<(), PictureError> {
    let mut coefficient_index = 1usize;
    while coefficient_index < 64 {
        let run_size = reader.decode(table)?;
        let run = usize::from(run_size >> 4);
        let size = u32::from(run_size & 0x0F);
        if size == 0 {
            if run != 15 {
                break;
            }
            coefficient_index = advance_zero_run(coefficient_index)?;
            continue;
        }
        coefficient_index = decode_ac_value(reader, coefficients, coefficient_index, run, size)?;
    }
    Ok(())
}

fn advance_zero_run(coefficient_index: usize) -> Result<usize, PictureError> {
    let next = coefficient_index
        .checked_add(16)
        .ok_or(PictureError::Malformed)?;
    if next > 64 {
        Err(PictureError::Malformed)
    } else {
        Ok(next)
    }
}

fn decode_ac_value(
    reader: &mut BitReader<'_>,
    coefficients: &mut [i16; 64],
    coefficient_index: usize,
    run: usize,
    size: u32,
) -> Result<usize, PictureError> {
    let target_index = coefficient_index
        .checked_add(run)
        .ok_or(PictureError::Malformed)?;
    let target = coefficients
        .get_mut(target_index)
        .ok_or(PictureError::Malformed)?;
    *target = extend(reader.bits(size), size) as i16;
    target_index.checked_add(1).ok_or(PictureError::Malformed)
}

pub(super) fn encode_block(
    writer: &mut BitWriter<'_>,
    dc_table: &HuffmanTable,
    ac_table: &HuffmanTable,
    coefficients: &[i16; 64],
) -> Result<(), PictureError> {
    encode_dc(writer, dc_table, i32::from(coefficients[0]))?;
    encode_ac(writer, ac_table, coefficients)
}

fn encode_dc(
    writer: &mut BitWriter<'_>,
    table: &HuffmanTable,
    dc: i32,
) -> Result<(), PictureError> {
    let bits = magnitude_category(dc);
    writer.code(table, bits as u8)?;
    if bits != 0 {
        writer.bits(magnitude_bits(dc, bits), bits);
    }
    Ok(())
}

fn encode_ac(
    writer: &mut BitWriter<'_>,
    table: &HuffmanTable,
    coefficients: &[i16; 64],
) -> Result<(), PictureError> {
    let mut run = 0u32;
    for coefficient in coefficients.iter().skip(1) {
        let value = i32::from(*coefficient);
        if value == 0 {
            run += 1;
            continue;
        }
        run = write_zero_runs(writer, table, run)?;
        write_ac_value(writer, table, run, value)?;
        run = 0;
    }
    if run > 0 {
        writer.code(table, 0x00)?;
    }
    Ok(())
}

fn write_zero_runs(
    writer: &mut BitWriter<'_>,
    table: &HuffmanTable,
    mut run: u32,
) -> Result<u32, PictureError> {
    while run > 15 {
        writer.code(table, 0xF0)?;
        run -= 16;
    }
    Ok(run)
}

fn write_ac_value(
    writer: &mut BitWriter<'_>,
    table: &HuffmanTable,
    run: u32,
    value: i32,
) -> Result<(), PictureError> {
    let size = magnitude_category(value);
    writer.code(table, ((run << 4) | size) as u8)?;
    writer.bits(magnitude_bits(value, size), size);
    Ok(())
}
