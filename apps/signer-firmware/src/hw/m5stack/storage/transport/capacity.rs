//! SD CSD capacity and write-protect queries over the CoreS3 shared SPI2 bus.

use esp_hal::{Blocking, spi::master::Spi};
use signer_firmware_core::storage::{card::csd_sector_count, retry::poll_read_token};

use super::protocol::{
    command_data_at, finish_transaction_at, read_exact, require_success, transfer_byte,
};

const CMD9: u8 = 9;
const CMD10: u8 = 10;
const CSD_WRITE_PROTECT_BYTE: usize = 14;
const CSD_PERMANENT_WRITE_PROTECT: u8 = 0x20;
const CSD_TEMPORARY_WRITE_PROTECT: u8 = 0x10;

#[derive(Clone, Copy)]
pub(in crate::hw::m5stack::storage::transport) struct SdWriteProtectFlags {
    pub(in crate::hw::m5stack::storage::transport) permanent: bool,
    pub(in crate::hw::m5stack::storage::transport) temporary: bool,
}

pub(crate) fn sd_sector_count() -> Result<u32, &'static str> {
    read_csd().and_then(|csd| csd_sector_count(&csd))
}

pub(in crate::hw::m5stack::storage::transport) fn sd_write_protect_flags(
) -> Result<SdWriteProtectFlags, &'static str> {
    read_csd().map(|csd| write_protect_flags(&csd))
}

pub(in crate::hw::m5stack::storage::transport) fn log_card_register_diagnostics() {
    log_csd_result(read_csd());
    log_cid_result(read_cid());
}

fn log_csd_result(result: Result<[u8; 16], &'static str>) {
    match result {
        Ok(csd) => log_csd_diagnostics(&csd),
        Err(error) => crate::log!("[SD-DIAG] CSD unavailable: {}", error),
    }
}

fn log_cid_result(result: Result<[u8; 16], &'static str>) {
    match result {
        Ok(cid) => log_cid_diagnostics(&cid),
        Err(error) => crate::log!("[SD-DIAG] CID unavailable: {}", error),
    }
}

fn log_csd_diagnostics(csd: &[u8; 16]) {
    crate::log!(
        "[SD-DIAG] CSD raw={:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        csd[0], csd[1], csd[2], csd[3], csd[4], csd[5], csd[6], csd[7],
        csd[8], csd[9], csd[10], csd[11], csd[12], csd[13], csd[14], csd[15],
    );
    match csd_sector_count(csd) {
        Ok(sectors) => {
            let bytes = u64::from(sectors).saturating_mul(512);
            crate::log!(
                "[SD-DIAG] CSD capacity sectors={} bytes={} MiB={}",
                sectors, bytes, bytes / (1024 * 1024),
            );
        },
        Err(error) => crate::log!("[SD-DIAG] CSD capacity decode failed: {}", error),
    }
}

fn log_cid_diagnostics(cid: &[u8; 16]) {
    crate::log!(
        "[SD-DIAG] CID raw={:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        cid[0], cid[1], cid[2], cid[3], cid[4], cid[5], cid[6], cid[7],
        cid[8], cid[9], cid[10], cid[11], cid[12], cid[13], cid[14], cid[15],
    );
    crate::log!(
        "[SD-DIAG] CID MID=0x{:02x} OID={:02x}{:02x} PNM={:02x}{:02x}{:02x}{:02x}{:02x} PRV=0x{:02x} PSN={:02x}{:02x}{:02x}{:02x}",
        cid[0], cid[1], cid[2], cid[3], cid[4], cid[5], cid[6], cid[7], cid[8],
        cid[9], cid[10], cid[11], cid[12],
    );
}

fn write_protect_flags(csd: &[u8; 16]) -> SdWriteProtectFlags {
    let protection = csd[CSD_WRITE_PROTECT_BYTE];
    SdWriteProtectFlags {
        permanent: protection & CSD_PERMANENT_WRITE_PROTECT != 0,
        temporary: protection & CSD_TEMPORARY_WRITE_PROTECT != 0,
    }
}

fn read_cid() -> Result<[u8; 16], &'static str> {
    let mut cid = [0u8; 16];
    command_data_at(CMD10, 0, true, |spi, response| {
        read_register_response(spi, response, &mut cid, "CMD10 failed", "CID")
    })?;
    finish_transaction_at(true)?;
    Ok(cid)
}

fn read_csd() -> Result<[u8; 16], &'static str> {
    let mut csd = [0u8; 16];
    command_data_at(CMD9, 0, true, |spi, response| {
        read_csd_response(spi, response, &mut csd)
    })?;
    finish_transaction_at(true)?;
    Ok(csd)
}

fn read_csd_response(
    spi: &mut Spi<'static, Blocking>,
    response: u8,
    csd: &mut [u8; 16],
) -> Result<(), &'static str> {
    require_success(response, "CMD9 failed")?;
    wait_for_csd_token(spi)?;
    read_exact(spi, csd)?;
    discard_crc(spi)
}

fn read_register_response(
    spi: &mut Spi<'static, Blocking>,
    response: u8,
    register: &mut [u8; 16],
    command_error: &'static str,
    register_name: &'static str,
) -> Result<(), &'static str> {
    require_success(response, command_error)?;
    wait_for_register_token(spi, register_name)?;
    read_exact(spi, register)?;
    discard_crc(spi)
}

fn wait_for_csd_token(spi: &mut Spi<'static, Blocking>) -> Result<(), &'static str> {
    wait_for_register_token(spi, "CSD")
}

fn wait_for_register_token(
    spi: &mut Spi<'static, Blocking>,
    register_name: &'static str,
) -> Result<(), &'static str> {
    poll_read_token(10_000, || transfer_byte(spi, 0xFF).unwrap_or(0xFF))
        .map(|_| ())
        .map_err(|error| match register_name {
            "CID" => error.message("CID read error token", "CID read timeout"),
            _ => error.message("CSD read error token", "CSD read timeout"),
        })
}

fn discard_crc(spi: &mut Spi<'static, Blocking>) -> Result<(), &'static str> {
    let mut crc = [0u8; 2];
    read_exact(spi, &mut crc)
}
