//! SD command framing and byte transfers over the shared SPI2 owner.

use esp_hal::{Blocking, spi::master::Spi};
use signer_firmware_core::storage::card::command_frame;

pub(in crate::hw::m5stack::storage::transport) use crate::hw::m5stack::spi_bus::SdBusyProbe;

use super::{crc::command_crc, diagnostics::{log_response_if_timeout, prepare_command}};


pub(super) const CMD0: u8 = 0;
pub(super) const CMD8: u8 = 8;

pub(in crate::hw::m5stack::storage::transport) fn command_data_at<T>(
    cmd: u8,
    arg: u32,
    initialization_speed: bool,
    operation: impl FnOnce(&mut Spi<'static, Blocking>, u8) -> Result<T, &'static str>,
) -> Result<T, &'static str> {
    crate::hw::m5stack::spi_bus::with_sd_selected(initialization_speed, |spi| {
        send_command(spi, cmd, arg, initialization_speed)
            .and_then(|response| operation(spi, response))
    })
}

pub(in crate::hw::m5stack::storage::transport) fn command_data_diagnostic_at<T>(
    cmd: u8,
    arg: u32,
    initialization_speed: bool,
    operation: impl FnOnce(
        &mut Spi<'static, Blocking>,
        u8,
        &mut crate::hw::m5stack::spi_bus::SdBusyProbe<'_>,
    ) -> Result<T, &'static str>,
) -> Result<T, &'static str> {
    crate::hw::m5stack::spi_bus::with_sd_selected_diagnostics(initialization_speed, |spi, probe| {
        send_command(spi, cmd, arg, initialization_speed)
            .and_then(|response| operation(spi, response, probe))
    })
}

pub(in crate::hw::m5stack::storage::transport) fn transfer_byte(
    spi: &mut Spi<'static, Blocking>,
    tx: u8,
) -> Result<u8, &'static str> {
    let mut byte = [tx];
    embedded_hal::spi::SpiBus::transfer_in_place(spi, &mut byte)
        .map(|_| byte[0])
        .map_err(|_| "SD SPI transfer failed")
}

pub(in crate::hw::m5stack::storage::transport) fn read_exact(
    spi: &mut Spi<'static, Blocking>,
    output: &mut [u8],
) -> Result<(), &'static str> {
    output.fill(0xFF);
    embedded_hal::spi::SpiBus::transfer_in_place(spi, output)
        .map_err(|_| "SD SPI read failed")
}

pub(in crate::hw::m5stack::storage::transport) fn write_all(
    spi: &mut Spi<'static, Blocking>,
    input: &[u8],
) -> Result<(), &'static str> {
    embedded_hal::spi::SpiBus::write(spi, input).map_err(|_| "SD SPI write failed")
}

pub(super) fn startup_idle_clocks() -> Result<(), &'static str> {
    crate::hw::m5stack::spi_bus::sd_idle_clocks(true, 10)
}

pub(in crate::hw::m5stack::storage::transport) fn quiesce_for_power_cycle(
) -> Result<(), &'static str> {
    crate::hw::m5stack::spi_bus::quiesce_sd_power_lines()
}

pub(in crate::hw::m5stack::storage::transport) fn restore_after_power_on(
) -> Result<(), &'static str> {
    crate::hw::m5stack::spi_bus::restore_sd_power_lines()
}

pub(in crate::hw::m5stack::storage::transport) fn finish_transaction_at(
    initialization_speed: bool,
) -> Result<(), &'static str> {
    crate::hw::m5stack::spi_bus::sd_idle_clocks(initialization_speed, 1)
}

pub(in crate::hw::m5stack::storage::transport) fn require_success(
    response: u8,
    error: &'static str,
) -> Result<(), &'static str> {
    if response == 0x00 { Ok(()) } else { Err(error) }
}

pub(super) fn command(
    cmd: u8,
    arg: u32,
    initialization_speed: bool,
    tail: &mut [u8],
) -> Result<u8, &'static str> {
    crate::hw::m5stack::spi_bus::with_sd_selected(initialization_speed, |spi| {
        send_command(spi, cmd, arg, initialization_speed)
            .and_then(|response| super::wire_helpers::read_tail(spi, response, tail))
    })
}

pub(super) fn send_command(
    spi: &mut Spi<'static, Blocking>,
    cmd: u8,
    arg: u32,
    initialization_speed: bool,
) -> Result<u8, &'static str> {
    prepare_command(spi, cmd == CMD0, cmd, arg, initialization_speed)?;
    let frame = command_frame(cmd, arg);
    let crc = command_crc(cmd, &frame);
    write_command_frame(spi, &frame, crc)?;
    let response = poll_r1(spi)?;
    log_response_if_timeout(response, cmd, arg, initialization_speed, crc);
    Ok(response)
}

fn write_command_frame(
    spi: &mut Spi<'static, Blocking>,
    frame: &[u8; 5],
    crc: u8,
) -> Result<(), &'static str> {
    write_all(spi, &[0xFF])
        .and_then(|_| write_all(spi, frame))
        .and_then(|_| write_all(spi, &[crc]))
}

fn poll_r1(spi: &mut Spi<'static, Blocking>) -> Result<u8, &'static str> {
    for _ in 0..64 {
        let response = transfer_byte(spi, 0xFF)?;
        if response & 0x80 == 0 { return Ok(response); }
    }
    Ok(0xFF)
}
