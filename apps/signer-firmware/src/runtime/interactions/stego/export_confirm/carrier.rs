//! JPEG carrier-specific read/modify/write operations.

use super::super::{AppData, sdcard, stego};
use crate::services::{entropy, memory::psram::PsramAllocation};
use shared_signer::bytes::zeroize_bytes;

const MAX_JPEG_SIZE: usize = 2_000_000;
const MAX_APP1_SIZE: usize = 65_537;
const STEGO_WORK_HEADROOM: usize = 1_048_576;
const STEGO_CODEC_MARGIN: usize = 262_144;
const PICTURE_OUTPUT_SLACK_CHUNK: usize = 1_024;

#[inline(never)]
pub(super) fn write(
    ad: &AppData,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    payload: &[u8],
) -> Result<(), &'static str> {
    let filename = ad.stego.export_flow.jpeg_file_names
        [ad.stego.export_flow.jpeg_selected as usize];
    let description =
        &ad.stego.export_flow.jpeg_desc_buf[..ad.stego.export_flow.jpeg_desc_len];
    sdcard::with_sd_card!(i2c, delay, |card| {
        write_on_card(ad, payload, description, filename, card)
    })
}

fn write_on_card(
    ad: &AppData,
    payload: &[u8],
    description: &[u8],
    filename: [u8; 11],
    card: sdcard::SdCardType,
) -> Result<(), &'static str> {
    let fat32 = sdcard::mount_fat32(card)?;
    let (jpeg, length) = load_jpeg(card, &fat32, &filename, ad.stego.export_flow.carrier)?;
    let written = write_carrier(
        ad.stego.export_flow.carrier,
        &jpeg.as_bytes()[..length],
        description,
        payload,
        card,
        &fat32,
        &filename,
    )?;
    if written == 0 { return Err("JPEG write failed"); }
    Ok(())
}

fn load_jpeg(
    card: sdcard::SdCardType,
    fat32: &sdcard::Fat32Info,
    filename: &[u8; 11],
    carrier: stego::StegoCarrier,
) -> Result<(PsramAllocation, usize), &'static str> {
    let (entry, _, _) = sdcard::find_file_in_root(card, fat32, filename)?;
    let size = entry.file_size as usize;
    if size == 0 || size > MAX_JPEG_SIZE { return Err("JPEG size unsupported"); }
    let output_budget = carrier_output_budget(carrier, size)?;
    ensure_operation_headroom(size, output_budget)?;
    let reserve = output_budget + STEGO_CODEC_MARGIN + STEGO_WORK_HEADROOM;
    let mut jpeg = PsramAllocation::allocate_with_reserve(size, 8, reserve)
        .map_err(|_| "Not enough PSRAM for JPEG operation")?;
    let length = sdcard::read_file(card, fat32, &entry, jpeg.as_mut_bytes())?;
    if length < 4 || !jpeg.as_bytes()[..length].starts_with(&[0xFF, 0xD8]) {
        return Err("Not a valid JPEG");
    }
    Ok((jpeg, length))
}

#[inline(never)]
fn carrier_output_budget(
    carrier: stego::StegoCarrier,
    size: usize,
) -> Result<usize, &'static str> {
    match carrier {
        stego::StegoCarrier::Descriptor => size.checked_add(MAX_APP1_SIZE + 16),
        stego::StegoCarrier::Picture => picture_output_capacity(size),
    }
    .ok_or("JPEG memory budget overflow")
}

#[inline(never)]
fn add_picture_output_slack_chunk(value: usize) -> Option<usize> {
    value.checked_add(PICTURE_OUTPUT_SLACK_CHUNK)
}

#[inline(never)]
fn picture_output_capacity(size: usize) -> Option<usize> {
    let doubled = size.checked_mul(2)?;
    let plus_one_kib = add_picture_output_slack_chunk(doubled)?;
    let plus_two_kib = add_picture_output_slack_chunk(plus_one_kib)?;
    let plus_three_kib = add_picture_output_slack_chunk(plus_two_kib)?;
    add_picture_output_slack_chunk(plus_three_kib)
}

fn ensure_operation_headroom(size: usize, output_budget: usize) -> Result<(), &'static str> {
    let planned = size
        .checked_add(output_budget)
        .and_then(|n| n.checked_add(STEGO_CODEC_MARGIN))
        .and_then(|n| n.checked_add(STEGO_WORK_HEADROOM))
        .ok_or("JPEG memory budget overflow")?;
    if crate::services::memory::psram::free_bytes() < planned {
        return Err("Not enough PSRAM for JPEG operation");
    }
    Ok(())
}

fn write_carrier(
    carrier: stego::StegoCarrier,
    jpeg: &[u8],
    description: &[u8],
    payload: &[u8],
    card: sdcard::SdCardType,
    fat32: &sdcard::Fat32Info,
    filename: &[u8; 11],
) -> Result<usize, &'static str> {
    match carrier {
        stego::StegoCarrier::Descriptor => {
            write_descriptor(jpeg, description, payload, card, fat32, filename)
        }
        stego::StegoCarrier::Picture => {
            write_picture(jpeg, description, payload, card, fat32, filename)
        }
    }
}

fn write_descriptor(
    jpeg: &[u8],
    description: &[u8],
    payload: &[u8],
    card: sdcard::SdCardType,
    fat32: &sdcard::Fat32Info,
    filename: &[u8; 11],
) -> Result<usize, &'static str>
{
    let mut app1 = PsramAllocation::allocate_with_reserve(MAX_APP1_SIZE, 8, STEGO_WORK_HEADROOM)
        .map_err(|_| "Not enough PSRAM for EXIF operation")?;
    let app1_length = if let Some((offset, length)) = stego::find_exif_app1(jpeg) {
        stego::build_exif_copyforward(
            &jpeg[offset..offset + length],
            description,
            payload,
            app1.as_mut_bytes(),
        )
    } else {
        build_template(jpeg, description, payload, app1.as_mut_bytes())?
    };
    if app1_length == 0 {
        return Err("EXIF build failed");
    }
    let output_size = jpeg.len().checked_add(app1_length).and_then(|n| n.checked_add(16)).ok_or("JPEG output too large")?;
    let mut output = PsramAllocation::allocate_with_reserve(output_size, 8, STEGO_WORK_HEADROOM)
        .map_err(|_| "Not enough PSRAM for JPEG output")?;
    let output_length = stego::inject_exif(jpeg, &app1.as_bytes()[..app1_length], output.as_mut_bytes());
    if output_length == 0 {
        return Err("EXIF inject failed");
    }
    sdcard::overwrite_file(card, fat32, filename, &output.as_bytes()[..output_length])?;
    Ok(output_length)
}

fn build_template(
    jpeg: &[u8],
    description: &[u8],
    payload: &[u8],
    output: &mut [u8],
) -> Result<usize, &'static str> {
    let (width, height) = stego::jpeg_dimensions(jpeg).ok_or("JPEG dimensions unavailable")?;
    let mut random = [0u8; 16];
    entropy::fill(&mut random).map_err(|_| "RNG health failed")?;
    let software = stego::SOFTWARE_TABLE[usize::from(random[0]) % stego::SOFTWARE_TABLE.len()];
    let mut datetime = [0u8; 19];
    stego::format_exif_datetime(&random[1..], &mut datetime);
    let length = stego::build_exif_template(
        description,
        payload,
        width,
        height,
        software.as_bytes(),
        &datetime,
        output,
    );
    zeroize_bytes(&mut random);
    Ok(length)
}

#[inline(never)]
fn write_picture(
    jpeg: &[u8],
    description: &[u8],
    payload: &[u8],
    card: sdcard::SdCardType,
    fat32: &sdcard::Fat32Info,
    filename: &[u8; 11],
) -> Result<usize, &'static str>
{
    let required_bits = (payload.len() + 2)
        .checked_mul(8)
        .ok_or("Payload too large")? as u32;
    let capacity = stego::capacity_bits(jpeg, description)?;
    if capacity < required_bits {
        return Err("Photo has insufficient capacity");
    }
    let output_capacity = picture_output_capacity(jpeg.len()).ok_or("JPEG output too large")?;
    let mut output = PsramAllocation::allocate_with_reserve(output_capacity, 8, STEGO_CODEC_MARGIN + STEGO_WORK_HEADROOM)
        .map_err(|_| "Not enough PSRAM for JPEG output")?;
    let output_length = stego::embed_picture(jpeg, payload, description, output.as_mut_bytes())?;
    sdcard::overwrite_file(card, fat32, filename, &output.as_bytes()[..output_length])?;
    Ok(output_length)
}
