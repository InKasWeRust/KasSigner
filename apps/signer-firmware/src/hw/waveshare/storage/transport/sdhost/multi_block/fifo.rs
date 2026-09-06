use super::super::super::registers::{
    reg_read, reg_write, INT_ALL_ERRORS, INT_DTO, SDHOST_BUFFIFO, SDHOST_RINTSTS,
    SDHOST_STATUS, STATUS_FIFO_EMPTY, STATUS_FIFO_FULL,
};
use signer_firmware_core::storage::fifo::{
    drive_fifo_read, drive_fifo_write, FifoReadIo, FifoTransferError, FifoWriteIo,
};

struct MultiReadIo;

impl FifoReadIo for MultiReadIo {
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

pub(super) unsafe fn read_fifo(
    output: &mut [u8],
    total_bytes: usize,
) -> Result<(), &'static str> {
    let mut io = MultiReadIo;
    drive_fifo_read(
        &mut io,
        output,
        total_bytes,
        50_000_000,
        INT_ALL_ERRORS,
        INT_DTO,
    )
    .map_err(multi_read_error)
}

const fn multi_read_error(error: FifoTransferError) -> &'static str {
    error.message(
        "Multi-read error",
        "Multi-read incomplete",
        "Multi-read timeout",
        "Multi-read alignment",
    )
}

struct MultiWriteIo;

impl FifoWriteIo for MultiWriteIo {
    fn interrupts(&mut self) -> u32 {
        unsafe { reg_read(SDHOST_RINTSTS) }
    }

    fn fifo_full(&mut self) -> bool {
        unsafe { reg_read(SDHOST_STATUS) & STATUS_FIFO_FULL != 0 }
    }

    fn write_word(&mut self, word: u32) {
        unsafe { reg_write(SDHOST_BUFFIFO, word) }
    }

    fn clear_interrupts(&mut self, mask: u32) {
        unsafe { reg_write(SDHOST_RINTSTS, mask) }
    }
}

pub(super) unsafe fn write_fifo(
    input: &[u8],
    total_bytes: usize,
) -> Result<(), &'static str> {
    let mut io = MultiWriteIo;
    drive_fifo_write(
        &mut io,
        input,
        total_bytes,
        50_000_000,
        INT_ALL_ERRORS,
        INT_DTO,
    )
    .map_err(multi_write_error)
}

const fn multi_write_error(error: FifoTransferError) -> &'static str {
    error.message(
        "Multi-write error",
        "Multi-write incomplete",
        "Multi-write timeout",
        "Multi-write alignment",
    )
}
