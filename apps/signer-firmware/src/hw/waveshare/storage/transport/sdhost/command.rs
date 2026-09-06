use signer_firmware_core::storage::retry::{
    SdHostCommandError, SdHostCommandPoll, poll_bits_clear, poll_sdhost_command,
};

use super::super::registers::{
    CMD_CHECK_RESP_CRC, CMD_START, CMD_USE_HOLE, INT_CD, INT_HLE, INT_RCRC,
    INT_RTO, SDHOST_CMD, SDHOST_CMDARG, SDHOST_RESP0, SDHOST_RINTSTS,
    SDHOST_STATUS, STATUS_DATA_BUSY, reg_read, reg_write,
};

/// Send a command via SDHOST and wait for completion.
pub(crate) fn sdhost_send_cmd(
    cmd_idx: u32,
    arg: u32,
    flags: u32,
) -> Result<u32, &'static str> {
    unsafe {
        reg_write(SDHOST_RINTSTS, 0xFFFF_FFFF);
        reg_write(SDHOST_CMDARG, arg);
        reg_write(
            SDHOST_CMD,
            CMD_START | CMD_USE_HOLE | (cmd_idx & 0x3F) | flags,
        );
    }
    poll_sdhost_command(
        SdHostCommandPoll {
            limit: 1_000_000,
            require_crc: flags & CMD_CHECK_RESP_CRC != 0,
            hardware_locked_mask: INT_HLE,
            command_done_mask: INT_CD,
            response_timeout_mask: INT_RTO,
            response_crc_mask: INT_RCRC,
        },
        || unsafe { reg_read(SDHOST_RINTSTS) },
        || unsafe { reg_read(SDHOST_RESP0) },
        |mask| unsafe { reg_write(SDHOST_RINTSTS, mask) },
    )
    .map_err(command_error_message)
}

fn command_error_message(error: SdHostCommandError) -> &'static str {
    error.message("HLE", "RTO", "RCRC", "CMD timeout")
}

/// Wait for card data busy to clear (for R1b responses).
pub(crate) fn sdhost_wait_not_busy() -> Result<(), &'static str> {
    poll_bits_clear(5_000_000, STATUS_DATA_BUSY, || unsafe {
        reg_read(SDHOST_STATUS)
    })
    .then_some(())
    .ok_or("Data busy timeout")
}
