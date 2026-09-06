//! SD password-lock status, unlock, and destructive recovery.

use super::{force_erase_trace, status::card_status_r2, wire::require_success};

use esp_hal::{Blocking, delay::Delay, spi::master::Spi};
use signer_firmware_core::storage::retry::write_response_accepted;
use super::wire::{
    command, command_data_at, command_data_diagnostic_at, finish_transaction_at, transfer_byte,
    write_all,
};
use super::wire::SdBusyProbe;
use crate::hw::m5stack::storage::SdCardType;

const CARD_LOCKED: u8 = 0x01;
const LOCK_UNLOCK_FAILED: u8 = 0x02;
const CMD16: u8 = 16;
const CMD42: u8 = 42;
const FORCE_ERASE_MODE: u8 = 0x08;
const UNLOCK_MODE: u8 = 0x00;
const MAX_PASSWORD_LEN: usize = 16;
const FORCE_ERASE_POLL_MS: u32 = 10;
const FORCE_ERASE_NOMINAL_MS: u32 = 180_000;
const FORCE_ERASE_PROGRESS_MS: u32 = 30_000;

pub(in crate::hw::m5stack::storage::transport) fn card_is_locked(initialization_speed: bool) -> Result<bool, &'static str> {
    let [r1, r2] = card_status_r2(initialization_speed)?;
    require_success(r1, "CMD13 failed")?;
    Ok(r2 & CARD_LOCKED != 0)
}

pub(in crate::hw::m5stack::storage::transport) fn unlock_card(
    card_type: SdCardType,
    password: &[u8],
) -> Result<(), &'static str> {
    if password.is_empty() { return Err("SD password is empty"); }
    if password.len() > MAX_PASSWORD_LEN { return Err("SD password exceeds 16 bytes"); }
    let required = 2 + password.len();
    let block_len = lock_block_len(card_type, required)?;
    let result = run_unlock(password, block_len)
        .and_then(|_| validate_unlock_status())
        .and_then(|_| restore_normal_block_len(card_type));
    let _ = finish_transaction_at(true);
    result
}

fn lock_block_len(card_type: SdCardType, required: usize) -> Result<usize, &'static str> {
    if matches!(card_type, SdCardType::SdV2Hc) { return Ok(512); }
    set_block_length(required as u32)?;
    Ok(required)
}

fn restore_normal_block_len(card_type: SdCardType) -> Result<(), &'static str> {
    if matches!(card_type, SdCardType::SdV2Hc) { return Ok(()); }
    set_block_length(512)
}

fn run_unlock(password: &[u8], block_len: usize) -> Result<(), &'static str> {
    command_data_at(CMD42, 0, true, |spi, response| {
        require_unlock_command(response)
            .and_then(|_| send_unlock_data(spi, password, block_len))
            .and_then(|_| wait_card_ready(spi, "CMD42 unlock busy timeout"))
    })
    .and_then(|_| finish_transaction_at(true))
}

fn require_unlock_command(response: u8) -> Result<(), &'static str> {
    if response == 0x00 { return Ok(()); }
    crate::log!("[SD] CMD42 unlock command rejected R1=0x{:02x}", response);
    Err("CMD42 unlock rejected")
}

fn send_unlock_data(
    spi: &mut Spi<'static, Blocking>,
    password: &[u8],
    block_len: usize,
) -> Result<(), &'static str> {
    let mut payload = [0u8; 512];
    build_unlock_payload(&mut payload, password);
    let result = write_lock_payload(spi, &payload[..block_len], "CMD42 unlock payload flush failed")
        .and_then(|_| poll_data_response(spi))
        .and_then(validate_unlock_data_response);
    shared_signer::bytes::zeroize_bytes(&mut payload);
    result
}

fn build_unlock_payload(payload: &mut [u8; 512], password: &[u8]) {
    payload[0] = UNLOCK_MODE;
    payload[1] = password.len() as u8;
    payload[2..2 + password.len()].copy_from_slice(password);
}

fn write_lock_payload(
    spi: &mut Spi<'static, Blocking>,
    payload: &[u8],
    flush_error: &'static str,
) -> Result<(), &'static str> {
    let crc = crc16_ccitt(payload);
    write_all(spi, &[0xFE])?;
    write_all(spi, payload)?;
    write_all(spi, &[(crc >> 8) as u8, crc as u8])?;
    embedded_hal::spi::SpiBus::flush(spi).map_err(|_| flush_error)
}

fn validate_unlock_data_response(response: u8) -> Result<(), &'static str> {
    if write_response_accepted(response) { return Ok(()); }
    crate::log!("[SD] CMD42 unlock data rejected token=0x{:02x}", response);
    Err("CMD42 unlock data rejected")
}

fn validate_unlock_status() -> Result<(), &'static str> {
    let [r1, r2] = card_status_r2(true)?;
    require_success(r1, "CMD13 after unlock failed")?;
    validate_unlock_status_byte(r2)
}

fn validate_unlock_status_byte(r2: u8) -> Result<(), &'static str> {
    if r2 & CARD_LOCKED != 0 { return Err("SD password incorrect"); }
    if r2 & LOCK_UNLOCK_FAILED != 0 { return Err("SD card rejected unlock"); }
    Ok(())
}

fn wait_card_ready(
    spi: &mut Spi<'static, Blocking>,
    timeout_error: &'static str,
) -> Result<(), &'static str> {
    for _ in 0..10_000 {
        if transfer_byte(spi, 0xFF)? == 0xFF { return Ok(()); }
    }
    Err(timeout_error)
}

fn crc16_ccitt(data: &[u8]) -> u16 {
    let mut crc = 0u16;
    for &byte in data {
        crc ^= u16::from(byte) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 { (crc << 1) ^ 0x1021 } else { crc << 1 };
        }
    }
    crc
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::hw::m5stack::storage::transport) enum ForceEraseAttempt {
    Completed,
    BusyTimedOut,
}

pub(in crate::hw::m5stack::storage::transport) fn force_erase_locked_card(
    card_type: SdCardType,
    delay: &mut Delay,
    liveness: &mut dyn FnMut(),
    timeout_ms: Option<u32>,
) -> Result<ForceEraseAttempt, &'static str> {
    crate::log!("[SD] password-locked media detected");
    force_erase_trace::log_pre_force_erase_status()?;
    crate::log!("[SD] CMD42 force erase BEGIN - DESTRUCTIVE");
    classify_force_erase_result(erase_locked_card(card_type, delay, liveness, timeout_ms))
}

fn classify_force_erase_result(
    result: Result<(), &'static str>,
) -> Result<ForceEraseAttempt, &'static str> {
    match result {
        Ok(()) => Ok(ForceEraseAttempt::Completed),
        Err("CMD42 force erase busy timeout") => Ok(ForceEraseAttempt::BusyTimedOut),
        Err(error) => Err(error),
    }
}

fn erase_locked_card(
    card_type: SdCardType,
    delay: &mut Delay,
    liveness: &mut dyn FnMut(),
    timeout_ms: Option<u32>,
) -> Result<(), &'static str> {
    let block_len = force_erase_block_len()?;
    run_force_erase(delay, block_len, liveness, timeout_ms)
        .and_then(|_| finish_force_erase(card_type))
}

fn force_erase_block_len() -> Result<usize, &'static str> {
    // SD Physical Layer SPI path: basic Force Erase uses exactly one mode byte.
    set_block_length(1)?;
    Ok(1)
}

fn run_force_erase(
    delay: &mut Delay,
    block_len: usize,
    liveness: &mut dyn FnMut(),
    timeout_ms: Option<u32>,
) -> Result<(), &'static str> {
    command_data_diagnostic_at(CMD42, 0, true, |spi, response, probe| {
        force_erase_transaction(
            spi, response, probe, delay, block_len, liveness, timeout_ms,
        )
    })
    .and_then(|_| finish_transaction_at(true))
}

fn force_erase_transaction(
    spi: &mut Spi<'static, Blocking>,
    response: u8,
    probe: &mut SdBusyProbe<'_>,
    delay: &mut Delay,
    block_len: usize,
    liveness: &mut dyn FnMut(),
    timeout_ms: Option<u32>,
) -> Result<(), &'static str> {
    require_force_erase_command(response)
        .and_then(|_| send_force_erase_data(spi, block_len))
        .and_then(|_| wait_force_erase_complete(spi, probe, delay, liveness, timeout_ms))
}

fn require_force_erase_command(response: u8) -> Result<(), &'static str> {
    let accepted = response == 0x00;
    crate::log!(
        "[SD] CMD42 force erase command R1=0x{:02x} accepted={}",
        response,
        accepted,
    );
    if accepted { return Ok(()); }
    crate::log!("[SD] CMD42 force erase command rejected R1=0x{:02x}", response);
    Err("CMD42 force erase rejected")
}

fn finish_force_erase(card_type: SdCardType) -> Result<(), &'static str> {
    validate_force_erase_status()
        .and_then(|_| restore_normal_block_len(card_type))
        .and_then(|_| finish_transaction_at(true))
}

fn validate_force_erase_status() -> Result<(), &'static str> {
    let [r1, r2] = card_status_r2(true)?;
    let card_locked = r2 & CARD_LOCKED != 0;
    let lock_unlock_failed = r2 & LOCK_UNLOCK_FAILED != 0;
    crate::log!(
        "[SD] CMD42 post-erase CMD13 R1=0x{:02x} R2=0x{:02x} CARD_LOCKED={} LOCK_UNLOCK_FAILED={}",
        r1,
        r2,
        card_locked,
        lock_unlock_failed,
    );
    require_success(r1, "CMD13 after force erase failed")?;
    validate_force_erase_status_byte(r2)
}

fn validate_force_erase_status_byte(r2: u8) -> Result<(), &'static str> {
    if r2 & CARD_LOCKED != 0 { return Err("SD card remained locked after force erase"); }
    if r2 & LOCK_UNLOCK_FAILED != 0 {
        return Err("SD card reported lock/unlock failure after force erase");
    }
    Ok(())
}

fn set_block_length(length: u32) -> Result<(), &'static str> {
    command(CMD16, length, true, &mut [])
        .and_then(|response| require_success(response, "CMD16 lock-data length failed"))
}

fn send_force_erase_data(
    spi: &mut Spi<'static, Blocking>,
    block_len: usize,
) -> Result<(), &'static str> {
    let mut payload = [0u8; 512];
    payload[0] = FORCE_ERASE_MODE;
    log_force_erase_data_frame(&payload[..block_len]);
    let result = write_lock_payload(
        spi,
        &payload[..block_len],
        "CMD42 force erase payload flush failed",
    )
    .and_then(|_| poll_force_erase_data_response(spi))
    .and_then(validate_force_erase_data_response);
    shared_signer::bytes::zeroize_bytes(&mut payload);
    result
}

fn log_force_erase_data_frame(payload: &[u8]) {
    let crc = crc16_ccitt(payload);
    crate::log!(
        "[SD] CMD42 force erase data frame token=0xfe len={} mode=0x{:02x} crc16=0x{:04x}",
        payload.len(),
        payload.first().copied().unwrap_or_default(),
        crc,
    );
}

fn validate_force_erase_data_response(response: u8) -> Result<(), &'static str> {
    if write_response_accepted(response) { return Ok(()); }
    crate::log!("[SD] CMD42 force erase data rejected token=0x{:02x}", response);
    Err("CMD42 force erase data rejected")
}

fn poll_force_erase_data_response(
    spi: &mut Spi<'static, Blocking>,
) -> Result<u8, &'static str> {
    for leading_ff in 0..64 {
        let response = transfer_byte(spi, 0xFF)?;
        if response != 0xFF {
            crate::log!(
                "[SD] CMD42 force erase data response leading_ff={} raw=0x{:02x} code=0x{:02x} accepted={}",
                leading_ff,
                response,
                response & 0x1f,
                write_response_accepted(response),
            );
            return Ok(response);
        }
    }
    crate::log!("[SD] CMD42 force erase data response timeout after 64 x 0xff bytes");
    Err("CMD42 force erase data response timeout")
}

fn poll_data_response(spi: &mut Spi<'static, Blocking>) -> Result<u8, &'static str> {
    for _ in 0..64 {
        let response = transfer_byte(spi, 0xFF)?;
        if response != 0xFF { return Ok(response); }
    }
    Err("CMD42 force erase data response timeout")
}

fn wait_force_erase_complete(
    spi: &mut Spi<'static, Blocking>,
    probe: &mut SdBusyProbe<'_>,
    delay: &mut Delay,
    liveness: &mut dyn FnMut(),
    timeout_ms: Option<u32>,
) -> Result<(), &'static str> {
    crate::log!("[SD] CMD42 force erase data accepted; busy wait begin");
    let max_polls = force_erase_poll_limit(timeout_ms);
    let mut last_sample = 0x00;
    for poll in 0..=max_polls {
        let sample = force_erase_busy_sample(spi, probe, poll)?;
        last_sample = sample;
        if sample == 0xFF { return force_erase_ready(poll, sample); }
        service_force_erase_liveness(liveness, poll);
        log_force_erase_progress(poll, sample, timeout_ms);
        delay.delay_millis(FORCE_ERASE_POLL_MS);
    }
    force_erase_busy_timeout(last_sample, timeout_ms.unwrap_or_default())
}

fn force_erase_busy_sample(
    spi: &mut Spi<'static, Blocking>,
    probe: &mut SdBusyProbe<'_>,
    poll: u64,
) -> Result<u8, &'static str> {
    transfer_byte(spi, 0xFF).and_then(|sample| {
        log_force_erase_initial_busy_sample(poll, sample);
        log_busy_provenance_if_due(spi, probe, poll).map(|_| sample)
    })
}

fn log_busy_provenance_if_due(
    spi: &mut Spi<'static, Blocking>,
    probe: &mut SdBusyProbe<'_>,
    poll: u64,
) -> Result<(), &'static str> {
    let elapsed_ms = poll.saturating_mul(u64::from(FORCE_ERASE_POLL_MS));
    if !force_erase_trace::probe_due(elapsed_ms) { return Ok(()); }
    let samples = probe.sample(spi)?;
    force_erase_trace::log_provenance_samples(elapsed_ms, samples);
    Ok(())
}

fn force_erase_poll_limit(timeout_ms: Option<u32>) -> u64 {
    timeout_ms.map(|timeout| u64::from(timeout / FORCE_ERASE_POLL_MS)).unwrap_or(u64::MAX)
}

fn service_force_erase_liveness(liveness: &mut dyn FnMut(), poll: u64) {
    if poll % 100 == 0 { liveness(); }
}

fn log_force_erase_initial_busy_sample(poll: u64, sample: u8) {
    if poll < 8 {
        crate::log!(
            "[SD] CMD42 post-token MISO sample[{}] t={}ms raw=0x{:02x}",
            poll,
            poll.saturating_mul(u64::from(FORCE_ERASE_POLL_MS)),
            sample,
        );
    }
}

fn force_erase_ready(poll: u64, sample: u8) -> Result<(), &'static str> {
    let elapsed_ms = poll.saturating_mul(u64::from(FORCE_ERASE_POLL_MS));
    crate::log!(
        "[SD] CMD42 busy released t={}ms MISO=0x{:02x}",
        elapsed_ms,
        sample,
    );
    crate::log!("[SD] CMD42 force erase ready after {}s", elapsed_ms / 1_000);
    Ok(())
}

fn force_erase_busy_timeout(sample: u8, timeout_ms: u32) -> Result<(), &'static str> {
    crate::log!(
        "[SD] CMD42 force erase still busy at {}s MISO=0x{:02x}; HIL host wait ceiling reached without resetting card",
        timeout_ms / 1_000, sample,
    );
    crate::log!("[SD] CMD42 HIL timeout leaves card powered and does not restart or reset it");
    Err("CMD42 force erase busy timeout")
}

fn log_force_erase_progress(poll: u64, sample: u8, timeout_ms: Option<u32>) {
    let elapsed_ms = poll.saturating_mul(u64::from(FORCE_ERASE_POLL_MS));
    if nominal_extension_log_due(elapsed_ms) {
        log_force_erase_nominal_extension(elapsed_ms, sample, timeout_ms);
        return;
    }
    if periodic_progress_log_due(elapsed_ms) {
        crate::log!(
            "[SD] CMD42 force erase busy {}s MISO=0x{:02x}",
            elapsed_ms / 1_000, sample,
        );
    }
}

fn log_force_erase_nominal_extension(
    elapsed_ms: u64,
    sample: u8,
    timeout_ms: Option<u32>,
) {
    match timeout_ms {
        Some(timeout) => crate::log!(
            "[SD] CMD42 force erase still busy at {}s MISO=0x{:02x}; HIL continues through {}s observation ceiling",
            elapsed_ms / 1_000, sample, timeout / 1_000,
        ),
        None => crate::log!(
            "[SD] CMD42 force erase still busy at {}s MISO=0x{:02x}; production keeps waiting until card ready",
            elapsed_ms / 1_000, sample,
        ),
    }
}

fn nominal_extension_log_due(elapsed_ms: u64) -> bool {
    elapsed_ms == u64::from(FORCE_ERASE_NOMINAL_MS)
}

fn periodic_progress_log_due(elapsed_ms: u64) -> bool {
    elapsed_ms != 0 && elapsed_ms % u64::from(FORCE_ERASE_PROGRESS_MS) == 0
}
