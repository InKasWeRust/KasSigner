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

//! The SDHOST controller: its clock and reset, the card clock, the command
//! engine, and the card's start-up in native SD mode.

use super::*;

// ═══════════════════════════════════════════════════════════════
// SDHOST Controller Init / Clock / Reset
// ═══════════════════════════════════════════════════════════════

/// Enable SDHOST peripheral clock and deassert reset
pub(super) fn sdhost_enable_peripheral() {
    // SAFETY: sets SDHOST's clock-enable bit and pulses its reset bit,
    // read-modify-write so no other peripheral's bit changes, then writes
    // SDHOST's own clock-edge register.
    unsafe {
        // Enable SDHOST clock (bit 7 in PERIP_CLK_EN1)
        reg_set_bits(SYSTEM_PERIP_CLK_EN1, SDHOST_CLK_EN_BIT);
        // Pulse reset
        reg_set_bits(SYSTEM_PERIP_RST_EN1, SDHOST_CLK_EN_BIT);
        for _ in 0..200u32 {
            reg_read(SDHOST_VERID);
        } // barrier
        reg_clear_bits(SYSTEM_PERIP_RST_EN1, SDHOST_CLK_EN_BIT);
        for _ in 0..200u32 {
            reg_read(SDHOST_VERID);
        } // barrier

        // The internal clock source, BEFORE anything else.
        // SDHOST_CLK_DIV_EDGE_REG (0x0800):
        //   bit 23: CLK_SOURCE_REG — 0=40MHz XTAL, 1=160MHz PLL
        //   bits 20:17: CCLKIN_EDGE_N (must equal CCLKIN_EDGE_L)
        //   bits 16:13: CCLKIN_EDGE_L (low phase count)
        //   bits 12:9:  CCLKIN_EDGE_H (high phase count, must be < L)
        //   bits 8:6:   CCLKIN_EDGE_SLF_SEL (phase for internal/core)
        //   bits 5:3:   CCLKIN_EDGE_SAM_SEL (phase for sampling/din)
        //   bits 2:0:   CCLKIN_EDGE_DRV_SEL (phase for driving/dout)
        //
        // As ESP-IDF: the 160 MHz PLL divided by 2 (H=0, L=1, N=1), an
        // 80 MHz base into CLKDIV; dout on phase 90°, din and core on 0.
        let clk_edge = (1u32 << 23)     // CLK_SOURCE=1: 160MHz PLL (MUST use PLL, not XTAL!)
            | (1u32 << 17)              // CCLKIN_EDGE_N = 1 (must equal L)
            | (1u32 << 13)              // CCLKIN_EDGE_L = 1
            // CCLKIN_EDGE_H (bit 9), SLF_SEL (bit 6, core) and SAM_SEL
            // (bit 3, din sampling) stay 0: edge H low, both on phase 0.
            | (1u32 << 0); // DRV_SEL = phase90 (dout driving)
        reg_write(SDHOST_CLK_EDGE, clk_edge);
    }
}

/// Reset SDHOST controller and FIFO
fn sdhost_reset() {
    // SAFETY: writes SDHOST's control register to reset its own controller
    // and FIFO; nothing else is attached to SDHOST.
    unsafe {
        // Controller and FIFO reset. It needs sdhost_cclk_in cycles, so the
        // pins are routed and the clock source set BEFORE this.
        reg_write(SDHOST_CTRL, CTRL_CONTROLLER_RESET | CTRL_FIFO_RESET);
        // The bits clear themselves after 2 AHB + 2 cclk cycles.
        if within(REG_US, || {
            reg_read(SDHOST_CTRL) & (CTRL_CONTROLLER_RESET | CTRL_FIFO_RESET) == 0
        }) {
            return;
        }
        log!("[SDHOST] WARNING: reset bits did not auto-clear, forcing");
        // Force them clear.
        reg_write(SDHOST_CTRL, 0);
    }
}

/// Update card clock settings (CLKDIV, CLKENA, CLKSRC) into CIU
fn sdhost_update_clock() -> Result<(), &'static str> {
    // SAFETY: writes SDHOST's interrupt-status and command registers to latch
    // a clock update, and polls them; SDHOST registers only.
    unsafe {
        // Clear pending interrupts
        reg_write(SDHOST_RINTSTS, 0xFFFF_FFFF);
        // "Update clock only", without CMD_WAIT_PRVDATA
        reg_write(SDHOST_CMD, CMD_START | CMD_USE_HOLE | CMD_UPDATE_CLK_ONLY);
        // Wait for START_CMD to clear
        let deadline = Deadline::after(&SysTimer, REG_US);
        while !deadline.expired(&SysTimer) {
            let cmd = reg_read(SDHOST_CMD);
            if cmd & CMD_START == 0 {
                return Ok(());
            }
            let rint = reg_read(SDHOST_RINTSTS);
            if rint & INT_HLE != 0 {
                reg_write(SDHOST_RINTSTS, INT_HLE);
                return Err("HLE during clock update");
            }
        }
        Err("Clock update timeout")
    }
}

/// Set the card clock divider: f_card = 80 MHz / (2 * divider), 0 being
/// bypass (80 MHz); 100 gives 400 kHz, 2 gives 20 MHz.
pub(super) fn sdhost_set_clock(divider: u32) -> Result<(), &'static str> {
    // SAFETY: writes SDHOST's clock enable, divider and source registers and
    // latches them through `sdhost_update_clock`; SDHOST registers only.
    unsafe {
        // Disable clock first
        reg_write(SDHOST_CLKENA, 0);
        sdhost_update_clock()?;

        // Set divider (divider 0 in CLKDIV register = bypass = /1)
        reg_write(SDHOST_CLKSRC, 0); // card 0 uses clock divider 0
        reg_write(SDHOST_CLKDIV, divider); // divider 0 value
        sdhost_update_clock()?;

        // Enable clock for card 0
        reg_write(SDHOST_CLKENA, 0x01);
        sdhost_update_clock()?;
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// SDHOST Command Engine
// ═══════════════════════════════════════════════════════════════

/// Send a command via SDHOST and wait for completion.
/// Returns RESP0 (short response) on success.
pub(super) fn sdhost_send_cmd(cmd_idx: u32, arg: u32, flags: u32) -> Result<u32, &'static str> {
    // SAFETY: writes SDHOST's argument and command registers and polls its
    // interrupt status; single-threaded, so one command at a time.
    unsafe {
        reg_write(SDHOST_RINTSTS, 0xFFFF_FFFF);

        reg_write(SDHOST_CMDARG, arg);

        let cmd_val = CMD_START | CMD_USE_HOLE | (cmd_idx & 0x3F) | flags;
        reg_write(SDHOST_CMD, cmd_val);

        // Wait for Command Done or error
        let deadline = Deadline::after(&SysTimer, CMD_US);
        while !deadline.expired(&SysTimer) {
            let rint = reg_read(SDHOST_RINTSTS);
            if rint & INT_HLE != 0 {
                reg_write(SDHOST_RINTSTS, INT_HLE);
                return Err("HLE");
            }
            if rint & INT_CD != 0 {
                // Command done — check for errors
                reg_write(SDHOST_RINTSTS, INT_CD);
                if rint & INT_RTO != 0 {
                    reg_write(SDHOST_RINTSTS, INT_RTO);
                    return Err("RTO");
                }
                if rint & INT_RCRC != 0 {
                    reg_write(SDHOST_RINTSTS, INT_RCRC);
                    // Ignored unless the caller asked for the check:
                    // ACMD41's response has no valid CRC.
                    if flags & CMD_CHECK_RESP_CRC != 0 {
                        return Err("RCRC");
                    }
                }
                return Ok(reg_read(SDHOST_RESP0));
            }
        }
        Err("CMD timeout")
    }
}

/// Wait for card data busy to clear (for R1b responses)
pub(super) fn sdhost_wait_not_busy() -> Result<(), &'static str> {
    let idle = || {
        // SAFETY: polls SDHOST's status register, which has no side effect.
        let status = unsafe { reg_read(SDHOST_STATUS) };
        status & STATUS_DATA_BUSY == 0
    };
    if within(BUSY_US, idle) {
        return Ok(());
    }
    Err("Data busy timeout")
}

// ═══════════════════════════════════════════════════════════════
// SD Native Protocol — Card Initialization
// ═══════════════════════════════════════════════════════════════

/// Full SD card initialization using SDHOST in native SD mode.
/// Returns card type on success.
pub(super) fn sdhost_init_card(delay: &mut SysTimer) -> Result<Kind, &'static str> {
    log!("[SDHOST] Initializing...");

    // Read hardware version for sanity
    // SAFETY: reads SDHOST's version register, which has no side effect.
    let ver = unsafe { reg_read(SDHOST_VERID) };
    log!("[SDHOST] VERID=0x{:08x}", ver);

    // Reset controller and FIFO
    sdhost_reset();

    // Configure: 1-bit mode, 512-byte blocks, max timeout, FIFO polling
    // SAFETY: writes SDHOST's configuration registers before any transfer
    // starts; SDHOST registers only.
    unsafe {
        reg_write(SDHOST_CTYPE, 0x00000000); // 1-bit mode for card 0
        reg_write(SDHOST_BLKSIZ, 512);
        reg_write(SDHOST_BYTCNT, 512);
        reg_write(SDHOST_TMOUT, 0xFFFF_FF40); // data timeout max, response timeout 64
        reg_write(SDHOST_INTMASK, 0); // mask all interrupts (we poll RINTSTS)
        reg_write(SDHOST_FIFOTH, 1 << 16); // RX watermark=1, TX watermark=0
        reg_write(SDHOST_CTRL, CTRL_INT_ENABLE); // enable global int flag but all masked
        reg_write(SDHOST_RST_N, 0x01); // card 0 not in reset
        reg_write(SDHOST_DEBNCE, 0x00FFFFFF); // max debounce
    }

    // 400 kHz for init: 80 / (2 * 100)
    sdhost_set_clock(100)?;
    delay.delay_ms(50); // Give card time with clock running

    // CMD0: GO_IDLE_STATE (with 80 init clocks, no response)
    let _ = sdhost_send_cmd(0, 0, CMD_SEND_INIT);
    // SAFETY: clears SDHOST's interrupt status (write one to clear).
    unsafe {
        reg_write(SDHOST_RINTSTS, 0xFFFF_FFFF);
    }
    delay.delay_ms(10);
    let _ = sdhost_send_cmd(0, 0, 0); // retry without init flag
                                      // SAFETY: clears SDHOST's interrupt status, as above.
    unsafe {
        reg_write(SDHOST_RINTSTS, 0xFFFF_FFFF);
    }
    delay.delay_ms(10);

    // CMD8: SEND_IF_COND (SDv2 detection)
    let sd_v2 = match sdhost_send_cmd(8, 0x000001AA, CMD_RESP_EXPECT | CMD_CHECK_RESP_CRC) {
        Ok(resp) => resp & 0xFFF == 0x1AA,
        Err(_) => false,
    };

    // ACMD41: SD_SEND_OP_COND — wait for card ready
    let hcs = if sd_v2 { 1u32 << 30 } else { 0 };
    let mut ocr = 0u32;
    let mut ready = false;
    for _i in 0..200u32 {
        let _ = sdhost_send_cmd(55, 0, CMD_RESP_EXPECT | CMD_CHECK_RESP_CRC);
        if let Ok(resp) = sdhost_send_cmd(41, 0x00FF_8000 | hcs, CMD_RESP_EXPECT) {
            ocr = resp;
            if resp & (1 << 31) != 0 {
                ready = true;
                break;
            }
        }
        delay.delay_ms(10);
    }
    if !ready {
        return Err("ACMD41 timeout");
    }

    // Determine card type from OCR
    let card_type = if sd_v2 {
        if ocr & (1 << 30) != 0 {
            Kind::SdV2High
        } else {
            Kind::SdV2Standard
        }
    } else {
        Kind::SdV1
    };

    // CMD2: ALL_SEND_CID
    sdhost_send_cmd(2, 0, CMD_RESP_EXPECT | CMD_RESP_LONG | CMD_CHECK_RESP_CRC)?;

    // CMD3: SEND_RELATIVE_ADDR
    let resp3 = sdhost_send_cmd(3, 0, CMD_RESP_EXPECT | CMD_CHECK_RESP_CRC)?;
    let rca = (resp3 >> 16) as u16;
    CARD_RCA.store(rca, core::sync::atomic::Ordering::Relaxed);

    // CMD9: SEND_CSD, while the card is still in stand-by. After CMD7 below
    // it is in transfer state and CMD9 is refused.
    CARD_SECTORS.store(0, core::sync::atomic::Ordering::Relaxed);
    if sdhost_send_cmd(
        9,
        (rca as u32) << 16,
        CMD_RESP_EXPECT | CMD_RESP_LONG | CMD_CHECK_RESP_CRC,
    )
    .is_ok()
    {
        // SAFETY: reads SDHOST's four response registers, with no side
        // effect, after the command that filled them completed.
        let (r0, r1, r2, r3) = unsafe {
            (
                reg_read(SDHOST_RESP0),
                reg_read(SDHOST_RESP1),
                reg_read(SDHOST_RESP2),
                reg_read(SDHOST_RESP3),
            )
        };
        log!(
            "[SDHOST] CSD regs {:08x} {:08x} {:08x} {:08x}",
            r0,
            r1,
            r2,
            r3
        );
        // Which end of the response lands in RESP0 is a controller property,
        // so both orders are parsed and the believable one wins.
        let mut csd = [0u8; 16];
        for (i, w) in [r3, r2, r1, r0].iter().enumerate() {
            csd[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
        }
        let mut found = match csd_sectors(&csd) {
            Ok(n) if csd_plausible(n) => n,
            _ => 0,
        };
        if found == 0 {
            for (i, w) in [r0, r1, r2, r3].iter().enumerate() {
                csd[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
            }
            if let Ok(n) = csd_sectors(&csd) {
                if csd_plausible(n) {
                    found = n;
                }
            }
        }
        if found != 0 {
            log!("[SDHOST] Card capacity {} sectors", found);
        } else {
            log!("[SDHOST] CSD not understood");
        }
        CARD_SECTORS.store(found, core::sync::atomic::Ordering::Relaxed);
    } else {
        log!("[SDHOST] CMD9 failed");
    }

    // CMD7: SELECT_CARD
    sdhost_send_cmd(7, (rca as u32) << 16, CMD_RESP_EXPECT | CMD_CHECK_RESP_CRC)?;
    sdhost_wait_not_busy()?;

    // CMD16: SET_BLOCKLEN = 512
    sdhost_send_cmd(16, 512, CMD_RESP_EXPECT | CMD_CHECK_RESP_CRC)?;

    // 20 MHz for data transfers: 80 / (2 * 2)
    sdhost_set_clock(2)?;
    log!("[SDHOST] Clock set to 20MHz for data transfers");

    log!("[SDHOST] SD card init complete: {:?}", card_type);
    Ok(card_type)
}
