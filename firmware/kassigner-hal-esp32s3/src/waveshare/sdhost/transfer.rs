// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Blocks in and out through SDHOST's FIFO, polled: one block at a time,
//! and the multi-block reads and writes the storage uses.

use super::*;

// ═══════════════════════════════════════════════════════════════
// Block I/O via SDHOST FIFO (polled, non-DMA)
// ═══════════════════════════════════════════════════════════════

/// The command argument for a block: its index on a block-addressed card, its
/// byte offset otherwise, as the M5's `sdspi::block_addr`.
///
/// Checked: past block 8,388,607 the byte offset overflows 32 bits, a panic
/// with overflow checks on. The storage bounds a block by the card's size
/// first, but not when the size read failed (zero), so a crafted card's FAT
/// block numbers can reach here.
fn block_addr(card_type: Kind, block: u32) -> Result<u32, &'static str> {
    match card_type {
        Kind::SdV2High => Ok(block),
        _ => block.checked_mul(512).ok_or("Address past the card"),
    }
}

/// Bytes in `count` blocks, as the transfer's byte count: `None` past 32 bits.
fn transfer_bytes(count: u32) -> Option<u32> {
    count.checked_mul(512)
}

/// Read a single 512-byte block.
pub fn sd_read_block(card_type: Kind, block: u32, buf: &mut [u8; 512]) -> Result<(), &'static str> {
    let addr = block_addr(card_type, block)?;

    // SAFETY: runs a single-block read through SDHOST's registers and FIFO,
    // draining at most 512 bytes into the caller's exclusive buffer.
    unsafe {
        // Setup for single block read
        reg_write(SDHOST_BLKSIZ, 512);
        reg_write(SDHOST_BYTCNT, 512);

        // Clear interrupts
        reg_write(SDHOST_RINTSTS, 0xFFFF_FFFF);

        // Reset FIFO before read
        reg_set_bits(SDHOST_CTRL, CTRL_FIFO_RESET);
        // A FIFO reset that does not clear is not refused here; the transfer
        // after it is, if it fails.
        within(REG_US, || reg_read(SDHOST_CTRL) & CTRL_FIFO_RESET == 0);

        // CMD17: READ_SINGLE_BLOCK (R1 + data)
        reg_write(SDHOST_CMDARG, addr);
        let cmd_flags = CMD_START
            | CMD_USE_HOLE
            | 17
            | CMD_RESP_EXPECT
            | CMD_CHECK_RESP_CRC
            | CMD_DATA_EXPECTED
            | CMD_WAIT_PRVDATA;
        reg_write(SDHOST_CMD, cmd_flags);

        // Wait for command done: without it the data phase does not start.
        let mut hle = false;
        let done = within(CMD_US, || {
            let rint = reg_read(SDHOST_RINTSTS);
            hle = rint & INT_HLE != 0;
            hle || rint & INT_CD != 0
        });
        if hle {
            return Err("CMD17 HLE");
        }
        if !done {
            return Err("CMD17 timeout");
        }

        // Check command response errors
        let rint = reg_read(SDHOST_RINTSTS);
        if rint & INT_RTO != 0 {
            return Err("CMD17 RTO");
        }

        // Read 512 bytes from FIFO (128 x 32-bit words)
        let mut bytes_read = 0usize;

        let mut deadline = Deadline::after(&SysTimer, DATA_US);
        while !deadline.expired(&SysTimer) {
            let rint = reg_read(SDHOST_RINTSTS);
            if rint & INT_ALL_ERRORS != 0 {
                log!(
                    "[SDHOST] Read error RINT=0x{:08x} at byte {}",
                    rint,
                    bytes_read
                );
                reg_write(SDHOST_RINTSTS, rint);
                return Err(if rint & INT_RTO != 0 {
                    "Read RTO"
                } else {
                    "Read error"
                });
            }
            if rint & INT_DTO != 0 {
                // Data transfer over — drain remaining FIFO
                while bytes_read < 512 {
                    let status = reg_read(SDHOST_STATUS);
                    if status & STATUS_FIFO_EMPTY != 0 {
                        break;
                    }
                    let word = reg_read(SDHOST_BUFFIFO);
                    let base = bytes_read;
                    for j in 0..4 {
                        if base + j < 512 {
                            buf[base + j] = ((word >> (j * 8)) & 0xFF) as u8;
                        }
                    }
                    bytes_read += 4;
                }
                // The status again, after the drain: a data CRC or end-bit
                // error raised just after "data over" is not in the read
                // taken before it.
                let after = reg_read(SDHOST_RINTSTS);
                if after & INT_ALL_ERRORS != 0 {
                    log!("[SDHOST] Read error after drain RINT=0x{:08x}", after);
                    reg_write(SDHOST_RINTSTS, after);
                    return Err("Read error");
                }
                reg_write(SDHOST_RINTSTS, INT_DTO);
                break;
            }

            // Read available words from FIFO
            let status = reg_read(SDHOST_STATUS);
            if status & STATUS_FIFO_EMPTY == 0 {
                let word = reg_read(SDHOST_BUFFIFO);
                let base = bytes_read;
                for j in 0..4 {
                    if base + j < 512 {
                        buf[base + j] = ((word >> (j * 8)) & 0xFF) as u8;
                    }
                }
                bytes_read += 4;
                deadline = Deadline::after(&SysTimer, DATA_US);
            }
        }

        if bytes_read < 512 {
            log!("[SDHOST] Read incomplete: {} bytes", bytes_read);
            return Err("Read incomplete");
        }
    }
    Ok(())
}

/// Write a single 512-byte block. Done only when the controller says the
/// transfer is over; a poll that runs out of time is an error.
fn sd_write_block(card_type: Kind, block: u32, buf: &[u8; 512]) -> Result<(), &'static str> {
    let addr = block_addr(card_type, block)?;

    // SAFETY: runs a single-block write through SDHOST's registers and FIFO,
    // feeding the 512 bytes of the caller's buffer.
    unsafe {
        // Setup
        reg_write(SDHOST_BLKSIZ, 512);
        reg_write(SDHOST_BYTCNT, 512);
        reg_write(SDHOST_RINTSTS, 0xFFFF_FFFF);

        // Reset FIFO
        reg_set_bits(SDHOST_CTRL, CTRL_FIFO_RESET);
        // Not refused here, as in `sd_read_block`.
        within(REG_US, || reg_read(SDHOST_CTRL) & CTRL_FIFO_RESET == 0);

        // Pre-fill the FIFO: 128 words, which fit its 512 bytes.
        for i in 0..128 {
            let base = i * 4;
            let word = (buf[base] as u32)
                | ((buf[base + 1] as u32) << 8)
                | ((buf[base + 2] as u32) << 16)
                | ((buf[base + 3] as u32) << 24);
            reg_write(SDHOST_BUFFIFO, word);
        }

        // CMD24: WRITE_BLOCK (R1 + data)
        reg_write(SDHOST_CMDARG, addr);
        let cmd_flags = CMD_START
            | CMD_USE_HOLE
            | 24
            | CMD_RESP_EXPECT
            | CMD_CHECK_RESP_CRC
            | CMD_DATA_EXPECTED
            | CMD_WRITE
            | CMD_WAIT_PRVDATA;
        reg_write(SDHOST_CMD, cmd_flags);

        // Wait for command + data transfer over
        let mut over = false;
        let deadline = Deadline::after(&SysTimer, DATA_US);
        while !deadline.expired(&SysTimer) {
            let rint = reg_read(SDHOST_RINTSTS);
            if rint & INT_ALL_ERRORS != 0 {
                log!("[SDHOST] Write error RINT=0x{:08x}", rint);
                reg_write(SDHOST_RINTSTS, rint);
                return Err(if rint & INT_RTO != 0 {
                    "Write RTO"
                } else {
                    "Write error"
                });
            }
            if rint & INT_DTO != 0 {
                reg_write(SDHOST_RINTSTS, INT_DTO | INT_CD);
                over = true;
                break;
            }
        }
        if !over {
            return Err("Write timeout");
        }

        // Wait for card not busy
        sdhost_wait_not_busy()?;
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// Multi-block I/O
// ═══════════════════════════════════════════════════════════════

/// Multi-block read: CMD18 + auto CMD12 stop.
pub fn fast_read_multi_block(
    card_type: Kind,
    block: u32,
    out: &mut [u8],
    count: u32,
) -> Result<(), &'static str> {
    if count == 0 {
        return Ok(());
    }
    // Bounds before any indexing: an undersized buffer would panic below,
    // and every caller already handles this `Result`.
    let total_bytes = transfer_bytes(count).ok_or("buffer too small")?;
    if out.len() < total_bytes as usize {
        return Err("buffer too small");
    }
    if count == 1 {
        let buf: &mut [u8; 512] = (&mut out[..512]).try_into().map_err(|_| "buf align")?;
        return sd_read_block(card_type, block, buf);
    }

    let addr = block_addr(card_type, block)?;

    // SAFETY: runs a multi-block read through SDHOST's registers and FIFO,
    // draining `count` blocks into the caller's buffer, checked above.
    unsafe {
        reg_write(SDHOST_BLKSIZ, 512);
        reg_write(SDHOST_BYTCNT, total_bytes);
        reg_write(SDHOST_RINTSTS, 0xFFFF_FFFF);

        // Reset FIFO
        reg_set_bits(SDHOST_CTRL, CTRL_FIFO_RESET);
        // Not refused here, as in `sd_read_block`.
        within(REG_US, || reg_read(SDHOST_CTRL) & CTRL_FIFO_RESET == 0);

        // CMD18: READ_MULTIPLE_BLOCK with auto-stop
        reg_write(SDHOST_CMDARG, addr);
        let cmd_flags = CMD_START
            | CMD_USE_HOLE
            | 18
            | CMD_RESP_EXPECT
            | CMD_CHECK_RESP_CRC
            | CMD_DATA_EXPECTED
            | CMD_WAIT_PRVDATA
            | CMD_SEND_AUTO_STOP;
        reg_write(SDHOST_CMD, cmd_flags);

        // Wait for command done; refused without it or on a hardware locked
        // error.
        let mut hle = false;
        let done = within(CMD_US, || {
            let rint = reg_read(SDHOST_RINTSTS);
            hle = rint & INT_HLE != 0;
            hle || rint & INT_CD != 0
        });
        if hle {
            return Err("CMD18 HLE");
        }
        if !done {
            return Err("CMD18 timeout");
        }

        // Read all data from FIFO, the time limit from the last word moved.
        let mut bytes_read = 0usize;
        let total = total_bytes as usize;

        let mut deadline = Deadline::after(&SysTimer, DATA_US);
        while !deadline.expired(&SysTimer) {
            let rint = reg_read(SDHOST_RINTSTS);
            if rint & INT_ALL_ERRORS != 0 {
                reg_write(SDHOST_RINTSTS, rint);
                return Err(if rint & INT_RTO != 0 {
                    "Multi-read RTO"
                } else {
                    "Multi-read error"
                });
            }

            // Read from FIFO while data available
            let status = reg_read(SDHOST_STATUS);
            if status & STATUS_FIFO_EMPTY == 0 && bytes_read < total {
                let word = reg_read(SDHOST_BUFFIFO);
                for j in 0..4 {
                    if bytes_read + j < total {
                        out[bytes_read + j] = ((word >> (j * 8)) & 0xFF) as u8;
                    }
                }
                bytes_read += 4;
                deadline = Deadline::after(&SysTimer, DATA_US);
            }

            if rint & INT_DTO != 0 {
                // Drain remaining
                while bytes_read < total {
                    let st = reg_read(SDHOST_STATUS);
                    if st & STATUS_FIFO_EMPTY != 0 {
                        break;
                    }
                    let word = reg_read(SDHOST_BUFFIFO);
                    for j in 0..4 {
                        if bytes_read + j < total {
                            out[bytes_read + j] = ((word >> (j * 8)) & 0xFF) as u8;
                        }
                    }
                    bytes_read += 4;
                }
                // The status again, after the drain, as in `sd_read_block`.
                let after = reg_read(SDHOST_RINTSTS);
                if after & INT_ALL_ERRORS != 0 {
                    reg_write(SDHOST_RINTSTS, after);
                    return Err("Multi-read error");
                }
                reg_write(SDHOST_RINTSTS, INT_DTO);
                break;
            }
        }

        if bytes_read < total {
            return Err("Multi-read incomplete");
        }
    }
    Ok(())
}

/// Multi-block write: CMD25 + auto CMD12 stop. Done only when every byte went
/// into the FIFO and the controller says the transfer is over; a timeout or
/// a short transfer is an error.
pub fn fast_write_multi_block(
    card_type: Kind,
    block: u32,
    data: &[u8],
    count: u32,
) -> Result<(), &'static str> {
    if count == 0 {
        return Ok(());
    }
    // Bounds before any indexing, as in `fast_read_multi_block`.
    let total_bytes = transfer_bytes(count).ok_or("buffer too small")?;
    if data.len() < total_bytes as usize {
        return Err("buffer too small");
    }
    if count == 1 {
        let buf: &[u8; 512] = (&data[..512]).try_into().map_err(|_| "buf align")?;
        return sd_write_block(card_type, block, buf);
    }

    let addr = block_addr(card_type, block)?;

    // SAFETY: runs a multi-block write through SDHOST's registers and FIFO,
    // feeding `count` blocks from the caller's buffer, checked above.
    unsafe {
        reg_write(SDHOST_BLKSIZ, 512);
        reg_write(SDHOST_BYTCNT, total_bytes);
        reg_write(SDHOST_RINTSTS, 0xFFFF_FFFF);

        // Reset FIFO
        reg_set_bits(SDHOST_CTRL, CTRL_FIFO_RESET);
        // Not refused here, as in `sd_read_block`.
        within(REG_US, || reg_read(SDHOST_CTRL) & CTRL_FIFO_RESET == 0);

        // CMD25: WRITE_MULTIPLE_BLOCK with auto-stop
        reg_write(SDHOST_CMDARG, addr);
        let cmd_flags = CMD_START
            | CMD_USE_HOLE
            | 25
            | CMD_RESP_EXPECT
            | CMD_CHECK_RESP_CRC
            | CMD_DATA_EXPECTED
            | CMD_WRITE
            | CMD_WAIT_PRVDATA
            | CMD_SEND_AUTO_STOP;
        reg_write(SDHOST_CMD, cmd_flags);

        // Feed data through FIFO
        let total = total_bytes as usize;
        let mut bytes_written = 0usize;
        let mut over = false;

        // The time limit from the last word moved, and once all are in, the
        // card's last block and the stop.
        let mut deadline = Deadline::after(&SysTimer, DATA_US);
        while !deadline.expired(&SysTimer) {
            let rint = reg_read(SDHOST_RINTSTS);
            if rint & INT_ALL_ERRORS != 0 {
                reg_write(SDHOST_RINTSTS, rint);
                return Err(if rint & INT_RTO != 0 {
                    "Multi-write RTO"
                } else {
                    "Multi-write error"
                });
            }

            // Write to FIFO when not full
            let status = reg_read(SDHOST_STATUS);
            if status & STATUS_FIFO_FULL == 0 && bytes_written < total {
                let base = bytes_written;
                let word = (data[base] as u32)
                    | ((data[base + 1] as u32) << 8)
                    | ((data[base + 2] as u32) << 16)
                    | ((data[base + 3] as u32) << 24);
                reg_write(SDHOST_BUFFIFO, word);
                bytes_written += 4;
                deadline = Deadline::after(&SysTimer, DATA_US);
            }

            if rint & INT_DTO != 0 {
                reg_write(SDHOST_RINTSTS, INT_DTO);
                over = true;
                break;
            }
        }
        if !over {
            return Err("Multi-write timeout");
        }
        if bytes_written < total {
            return Err("Multi-write short");
        }

        sdhost_wait_not_busy()?;
    }
    Ok(())
}
