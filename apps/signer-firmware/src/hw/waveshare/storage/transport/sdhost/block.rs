use super::{sdhost_wait_not_busy, SdCardType};
use super::super::registers::{
    reg_read, reg_set_bits, reg_write, CMD_CHECK_RESP_CRC, CMD_DATA_EXPECTED,
    CMD_RESP_EXPECT, CMD_START, CMD_USE_HOLE, CMD_WAIT_PRVDATA, CMD_WRITE,
    CTRL_FIFO_RESET, INT_ALL_ERRORS, INT_CD, INT_DTO, INT_HLE, INT_RTO,
    SDHOST_BLKSIZ, SDHOST_BUFFIFO, SDHOST_BYTCNT, SDHOST_CMD, SDHOST_CMDARG,
    SDHOST_CTRL, SDHOST_RINTSTS, SDHOST_STATUS, STATUS_FIFO_EMPTY,
};
use signer_firmware_core::storage::fifo::{
    drive_fifo_read, plan_transfer, write_words, FifoReadIo, FifoTransferError,
};
use signer_firmware_core::storage::retry::{poll_bits_clear, poll_register};

const BLOCK_BYTES: u32 = 512;

/// Read a single 512-byte block.
pub fn sd_read_block(
    card_type: SdCardType,
    block: u32,
    buffer: &mut [u8; 512],
) -> Result<(), &'static str> {
    let plan = plan_transfer(card_type == SdCardType::SdV2Hc, block, 1, buffer.len())
        .map_err(|_| "Block address overflow")?;

    unsafe {
        configure_transfer(BLOCK_BYTES);
        reset_fifo();
        issue_data_command(17, plan.address, false);
        wait_for_read_command()?;
        read_fifo(buffer)?;
    }
    Ok(())
}

/// Write a single 512-byte block.
pub(crate) fn sd_write_block(
    card_type: SdCardType,
    block: u32,
    buffer: &[u8; 512],
) -> Result<(), &'static str> {
    let plan = plan_transfer(card_type == SdCardType::SdV2Hc, block, 1, buffer.len())
        .map_err(|_| "Block address overflow")?;
    unsafe { write_planned_block(plan.address, buffer) }
}

unsafe fn write_planned_block(
    address: u32,
    buffer: &[u8; 512],
) -> Result<(), &'static str> {
    configure_transfer(BLOCK_BYTES);
    reset_fifo();
    prefill_fifo(buffer)?;
    issue_data_command(24, address, true);
    wait_for_write_complete()?;
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

unsafe fn issue_data_command(command: u32, address: u32, write: bool) {
    reg_write(SDHOST_CMDARG, address);
    let mut flags = CMD_START
        | CMD_USE_HOLE
        | command
        | CMD_RESP_EXPECT
        | CMD_CHECK_RESP_CRC
        | CMD_DATA_EXPECTED
        | CMD_WAIT_PRVDATA;
    if write {
        flags |= CMD_WRITE;
    }
    reg_write(SDHOST_CMD, flags);
}

unsafe fn wait_for_read_command() -> Result<(), &'static str> {
    poll_register(1_000_000, INT_HLE, INT_CD, || unsafe { reg_read(SDHOST_RINTSTS) })
        .map_err(|error| error.message("CMD17 HLE", "CMD17 timeout"))?;
    check_read_response()
}

unsafe fn check_read_response() -> Result<(), &'static str> {
    if reg_read(SDHOST_RINTSTS) & INT_RTO != 0 {
        Err("CMD17 RTO")
    } else {
        Ok(())
    }
}

struct BlockReadIo;

impl FifoReadIo for BlockReadIo {
    fn interrupts(&mut self) -> u32 {
        unsafe { reg_read(SDHOST_RINTSTS) }
    }

    fn fifo_empty(&mut self) -> bool {
        unsafe { reg_read(SDHOST_STATUS) & STATUS_FIFO_EMPTY != 0 }
    }

    fn read_word(&mut self) -> u32 {
        unsafe { reg_read(SDHOST_BUFFIFO) }
    }

    fn clear_interrupts(&mut self, mask: u32) {
        unsafe { reg_write(SDHOST_RINTSTS, mask) }
    }
}

unsafe fn read_fifo(output: &mut [u8]) -> Result<(), &'static str> {
    let total_bytes = output.len();
    let mut io = BlockReadIo;
    drive_fifo_read(
        &mut io,
        output,
        total_bytes,
        5_000_000,
        INT_ALL_ERRORS,
        INT_DTO,
    )
    .map_err(block_read_error)
}

const fn block_read_error(error: FifoTransferError) -> &'static str {
    error.message("Read error", "Read incomplete", "Read timeout", "Read alignment")
}

unsafe fn prefill_fifo(input: &[u8]) -> Result<(), &'static str> {
    write_words(input, |word| unsafe { reg_write(SDHOST_BUFFIFO, word) })
        .map_err(|_| "Write alignment")
}

unsafe fn wait_for_write_complete() -> Result<(), &'static str> {
    poll_register(5_000_000, INT_ALL_ERRORS, INT_DTO, || unsafe {
        reg_read(SDHOST_RINTSTS)
    })
    .map_err(write_poll_error)?;
    reg_write(SDHOST_RINTSTS, INT_DTO | INT_CD);
    Ok(())
}

fn write_poll_error(error: signer_firmware_core::storage::retry::RegisterPollError) -> &'static str {
    if error == signer_firmware_core::storage::retry::RegisterPollError::Error {
        unsafe {
            let interrupts = reg_read(SDHOST_RINTSTS);
            reg_write(SDHOST_RINTSTS, interrupts);
        }
    }
    error.message("Write error", "Write timeout")
}
