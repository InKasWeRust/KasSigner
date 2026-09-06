//! SD-card startup state machine over the shared SPI wire layer.

use signer_firmware_core::storage::retry::{ocr_is_high_capacity, validate_cmd8_echo};

use super::{legacy_data_speed, wire::require_success};
use super::wire::{
    command, finish_transaction_at, startup_idle_clocks, CMD0, CMD8,
};
use crate::hw::m5stack::storage::SdCardType;

const CMD16: u8 = 16;
const CMD55: u8 = 55;
const CMD58: u8 = 58;
const ACMD41: u8 = 41;
const CMD0_RETRIES: usize = 10;
const ACMD41_RETRIES: usize = 1_000;

pub(in crate::hw::m5stack::storage::transport) fn initialize_card(
    delay: &mut esp_hal::delay::Delay,
) -> Result<SdCardType, &'static str> {
    startup_idle_clocks()
        .and_then(|_| enter_idle(delay))
        .and_then(|_| detect_v2())
        .and_then(|sd_v2| wait_until_ready(delay, sd_v2).map(|_| sd_v2))
        .and_then(read_card_type)
        .and_then(set_block_length)
        .and_then(|card_type| {
            finish_transaction_at(legacy_data_speed(card_type)).map(|_| card_type)
        })
}

fn enter_idle(delay: &mut esp_hal::delay::Delay) -> Result<(), &'static str> {
    for attempt in 0..CMD0_RETRIES {
        let response = command(CMD0, 0, true, &mut [])?;
        if response == 0x01 {
            crate::log!("[SD] CMD0 OK (idle)");
            return Ok(());
        }
        crate::log!("[SD] CMD0 attempt {} unexpected R1=0x{:02x}", attempt + 1, response);
        delay.delay_millis(10);
    }
    Err("CMD0 failed")
}

fn detect_v2() -> Result<bool, &'static str> {
    let mut tail = [0u8; 4];
    let response = command(CMD8, 0x0000_01AA, true, &mut tail)?;
    if response != 0x01 {
        crate::log!("[SD] CMD8 rejected — SDv1");
        return Ok(false);
    }
    if !validate_cmd8_echo(tail) { return Err("CMD8 voltage mismatch"); }
    crate::log!("[SD] CMD8 OK — SDv2");
    Ok(true)
}

fn wait_until_ready(
    delay: &mut esp_hal::delay::Delay,
    sd_v2: bool,
) -> Result<(), &'static str> {
    let hcs = host_capacity_arg(sd_v2);
    for attempt in 0..ACMD41_RETRIES {
        let ready = acmd41_ready(hcs)?;
        if ready {
            crate::log!("[SD] ACMD41 OK after {} attempts", attempt + 1);
            return Ok(());
        }
        delay.delay_millis(1);
    }
    Err("ACMD41 timeout")
}

const fn host_capacity_arg(sd_v2: bool) -> u32 {
    if sd_v2 { 1u32 << 30 } else { 0 }
}

fn acmd41_ready(hcs: u32) -> Result<bool, &'static str> {
    command(CMD55, 0, true, &mut [])
        .and_then(|_| command(ACMD41, hcs, true, &mut []))
        .and_then(classify_acmd41)
}

fn classify_acmd41(response: u8) -> Result<bool, &'static str> {
    if response == 0x00 { return Ok(true); }
    if response == 0x01 { return Ok(false); }
    Err("ACMD41 rejected")
}

fn read_card_type(sd_v2: bool) -> Result<SdCardType, &'static str> {
    if !sd_v2 { return Ok(SdCardType::SdV1); }
    let ocr = read_ocr()?;
    let high_capacity = ocr_is_high_capacity(ocr[0]);
    crate::log!(
        "[SD] OCR: {:02x}{:02x}{:02x}{:02x} CCS={}",
        ocr[0], ocr[1], ocr[2], ocr[3], u8::from(high_capacity),
    );
    Ok(card_type_from_capacity(high_capacity))
}

fn read_ocr() -> Result<[u8; 4], &'static str> {
    let mut ocr = [0u8; 4];
    command(CMD58, 0, true, &mut ocr)
        .and_then(|response| require_success(response, "CMD58 failed"))
        .map(|_| ocr)
}

const fn card_type_from_capacity(high_capacity: bool) -> SdCardType {
    if high_capacity { SdCardType::SdV2Hc } else { SdCardType::SdV2Sc }
}

fn set_block_length(card_type: SdCardType) -> Result<SdCardType, &'static str> {
    if card_type == SdCardType::SdV2Hc { return Ok(card_type); }
    let response = command(CMD16, 512, true, &mut [])?;
    if response != 0x00 {
        crate::log!("[SD] CMD16 rejected: R1=0x{:02x}", response);
        return Err("CMD16 failed");
    }
    crate::log!("[SD] CMD16 OK — 512-byte blocks");
    Ok(card_type)
}
