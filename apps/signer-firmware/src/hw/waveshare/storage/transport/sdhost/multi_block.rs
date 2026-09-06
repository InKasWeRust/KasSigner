mod fifo;

use super::{sd_read_block, sd_write_block, sdhost_wait_not_busy, SdCardType};
use super::super::registers::{
    reg_read, reg_set_bits, reg_write, CMD_CHECK_RESP_CRC, CMD_DATA_EXPECTED,
    CMD_RESP_EXPECT, CMD_SEND_AUTO_STOP, CMD_START, CMD_USE_HOLE, CMD_WAIT_PRVDATA,
    CMD_WRITE, CTRL_FIFO_RESET, INT_CD, INT_HLE,
    SDHOST_BLKSIZ, SDHOST_BYTCNT, SDHOST_CMD, SDHOST_CMDARG, SDHOST_CTRL,
    SDHOST_RINTSTS,
};
use signer_firmware_core::storage::fifo::{plan_transfer, transfer_mode, TransferMode, TransferPlan};
use fifo::{read_fifo, write_fifo};
use signer_firmware_core::storage::retry::{poll_bits_clear, poll_register};

const BLOCK_BYTES: u32 = 512;

/// Multi-block read: CMD18 + auto CMD12 stop.
pub fn fast_read_multi_block(
    card_type: SdCardType,
    block: u32,
    output: &mut [u8],
    count: u32,
) -> Result<(), &'static str> {
    read_blocks(card_type, block, output, count)
}

fn read_blocks(
    card_type: SdCardType,
    block: u32,
    output: &mut [u8],
    count: u32,
) -> Result<(), &'static str> {
    let plan = plan_transfer(
        card_type == SdCardType::SdV2Hc,
        block,
        count,
        output.len(),
    )
    .map_err(|_| "Multi-read buffer or address")?;
    dispatch_read(transfer_mode(count), card_type, block, output, plan)
}

fn dispatch_read(
    mode: TransferMode,
    card_type: SdCardType,
    block: u32,
    output: &mut [u8],
    plan: TransferPlan,
) -> Result<(), &'static str> {
    match mode {
        TransferMode::Empty => Ok(()),
        TransferMode::Single => read_single(card_type, block, output),
        TransferMode::Multi => unsafe { read_multiple(output, plan) },
    }
}

fn read_single(
    card_type: SdCardType,
    block: u32,
    output: &mut [u8],
) -> Result<(), &'static str> {
    let buffer: &mut [u8; 512] = (&mut output[..512])
        .try_into()
        .map_err(|_| "buf align")?;
    sd_read_block(card_type, block, buffer)
}

unsafe fn read_multiple(output: &mut [u8], plan: TransferPlan) -> Result<(), &'static str> {
    configure_transfer(plan.total_bytes as u32);
    reset_fifo();
    issue_multi_command(18, plan.address, false);
    wait_for_command()?;
    read_fifo(output, plan.total_bytes)
}

/// Multi-block write: CMD25 + auto CMD12 stop.
pub fn fast_write_multi_block(
    card_type: SdCardType,
    block: u32,
    data: &[u8],
    count: u32,
) -> Result<(), &'static str> {
    write_blocks(card_type, block, data, count)
}

fn write_blocks(
    card_type: SdCardType,
    block: u32,
    data: &[u8],
    count: u32,
) -> Result<(), &'static str> {
    let plan = plan_transfer(
        card_type == SdCardType::SdV2Hc,
        block,
        count,
        data.len(),
    )
    .map_err(|_| "Multi-write buffer or address")?;
    dispatch_write(transfer_mode(count), card_type, block, data, plan)
}

fn dispatch_write(
    mode: TransferMode,
    card_type: SdCardType,
    block: u32,
    data: &[u8],
    plan: TransferPlan,
) -> Result<(), &'static str> {
    match mode {
        TransferMode::Empty => Ok(()),
        TransferMode::Single => write_single(card_type, block, data),
        TransferMode::Multi => unsafe { write_multiple(data, plan) },
    }
}

fn write_single(card_type: SdCardType, block: u32, data: &[u8]) -> Result<(), &'static str> {
    let buffer: &[u8; 512] = data[..512].try_into().map_err(|_| "buf align")?;
    sd_write_block(card_type, block, buffer)
}

unsafe fn write_multiple(data: &[u8], plan: TransferPlan) -> Result<(), &'static str> {
    configure_transfer(plan.total_bytes as u32);
    reset_fifo();
    issue_multi_command(25, plan.address, true);
    write_fifo(data, plan.total_bytes)?;
    sdhost_wait_not_busy()
}

unsafe fn configure_transfer(byte_count: u32) {
    reg_write(SDHOST_BLKSIZ, BLOCK_BYTES);
    reg_write(SDHOST_BYTCNT, byte_count);
    reg_write(SDHOST_RINTSTS, u32::MAX);
}

unsafe fn reset_fifo() {
    reg_set_bits(SDHOST_CTRL, CTRL_FIFO_RESET);
    let _ = poll_bits_clear(10_000, CTRL_FIFO_RESET, || unsafe { reg_read(SDHOST_CTRL) });
}

unsafe fn issue_multi_command(command: u32, address: u32, write: bool) {
    reg_write(SDHOST_CMDARG, address);
    let mut flags = CMD_START
        | CMD_USE_HOLE
        | command
        | CMD_RESP_EXPECT
        | CMD_CHECK_RESP_CRC
        | CMD_DATA_EXPECTED
        | CMD_WAIT_PRVDATA
        | CMD_SEND_AUTO_STOP;
    if write {
        flags |= CMD_WRITE;
    }
    reg_write(SDHOST_CMD, flags);
}

unsafe fn wait_for_command() -> Result<(), &'static str> {
    poll_register(1_000_000, INT_HLE, INT_CD, || unsafe { reg_read(SDHOST_RINTSTS) })
        .map(|_| ())
        .map_err(|error| error.message("Multi-block HLE", "Multi-block command timeout"))
}

