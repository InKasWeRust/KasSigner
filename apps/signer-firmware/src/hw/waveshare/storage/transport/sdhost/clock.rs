use super::super::registers::{
    CMD_START, CMD_UPDATE_CLK_ONLY, CMD_USE_HOLE, CTRL_CONTROLLER_RESET,
    CTRL_FIFO_RESET, INT_HLE, SDHOST_CLKDIV, SDHOST_CLKENA, SDHOST_CLKSRC,
    SDHOST_CLK_EDGE, SDHOST_CLK_EN_BIT, SDHOST_CMD, SDHOST_CTRL, SDHOST_RINTSTS,
    SDHOST_VERID, SYSTEM_PERIP_CLK_EN1, SYSTEM_PERIP_RST_EN1, reg_clear_bits,
    reg_read, reg_set_bits, reg_write,
};
// ═══════════════════════════════════════════════════════════════
// SDHOST Controller Init / Clock / Reset
// ═══════════════════════════════════════════════════════════════

/// Enable SDHOST peripheral clock and deassert reset
pub(crate) fn sdhost_enable_peripheral() {
    unsafe {
        // Enable SDHOST clock (bit 7 in PERIP_CLK_EN1)
        reg_set_bits(SYSTEM_PERIP_CLK_EN1, SDHOST_CLK_EN_BIT);
        // Pulse reset
        reg_set_bits(SYSTEM_PERIP_RST_EN1, SDHOST_CLK_EN_BIT);
        for _ in 0..200u32 { reg_read(SDHOST_VERID); } // barrier
        reg_clear_bits(SYSTEM_PERIP_RST_EN1, SDHOST_CLK_EN_BIT);
        for _ in 0..200u32 { reg_read(SDHOST_VERID); } // barrier

        // CRITICAL: Configure SDHOST internal clock source BEFORE anything else.
        // SDHOST_CLK_DIV_EDGE_REG (0x0800):
        //   bit 23: CLK_SOURCE_REG — 0=40MHz XTAL, 1=160MHz PLL
        //   bits 20:17: CCLKIN_EDGE_N (must equal CCLKIN_EDGE_L)
        //   bits 16:13: CCLKIN_EDGE_L (low phase count)
        //   bits 12:9:  CCLKIN_EDGE_H (high phase count, must be < L)
        //   bits 8:6:   CCLKIN_EDGE_SLF_SEL (phase for internal/core)
        //   bits 5:3:   CCLKIN_EDGE_SAM_SEL (phase for sampling/din)
        //   bits 2:0:   CCLKIN_EDGE_DRV_SEL (phase for driving/dout)
        //
        // ESP-IDF uses: clk_sel=1 (160MHz PLL), div=2 minimum → H=0, L=1, N=1
        // This gives 160/2 = 80MHz base clock into the CLKDIV stage.
        // phase_dout=1 (90° for output driving), phase_din=0, phase_core=0.
        let clk_edge = (1u32 << 23)     // CLK_SOURCE=1: 160MHz PLL (MUST use PLL, not XTAL!)
            | (1u32 << 17)              // CCLKIN_EDGE_N = 1 (must equal L)
            | (1u32 << 13)              // CCLKIN_EDGE_L = 1
            | (0u32 << 9)               // CCLKIN_EDGE_H = 0
            | (0u32 << 6)               // SLF_SEL = phase0 (core)
            | (0u32 << 3)               // SAM_SEL = phase0 (din sampling)
            | (1u32 << 0);              // DRV_SEL = phase90 (dout driving)
        reg_write(SDHOST_CLK_EDGE, clk_edge);
    }
}

/// Reset SDHOST controller and FIFO
pub(crate) fn sdhost_reset() {
    unsafe {
        // Controller reset + FIFO reset
        // NOTE: reset needs sdhost_cclk_in cycles to complete, so GPIO must be
        // routed and clock source configured BEFORE calling this.
        reg_write(SDHOST_CTRL, CTRL_CONTROLLER_RESET | CTRL_FIFO_RESET);
        // Wait for reset to complete (bits auto-clear after 2 AHB + 2 cclk cycles)
        for _ in 0..1_000_000u32 {
            if reg_read(SDHOST_CTRL) & (CTRL_CONTROLLER_RESET | CTRL_FIFO_RESET) == 0 {
                return;
            }
        }
        log!("[SDHOST] WARNING: reset bits did not auto-clear, forcing");
        // Force clear — write 0 to the reset bits
        reg_write(SDHOST_CTRL, 0);
    }
}

/// Update card clock settings (CLKDIV, CLKENA, CLKSRC) into CIU
pub(crate) fn sdhost_update_clock() -> Result<(), &'static str> {
    unsafe {
        // Clear pending interrupts
        reg_write(SDHOST_RINTSTS, 0xFFFF_FFFF);
        // Send "update clock only" command — do NOT use CMD_WAIT_PRVDATA for clock updates
        reg_write(SDHOST_CMD, CMD_START | CMD_USE_HOLE | CMD_UPDATE_CLK_ONLY);
        // Wait for START_CMD to clear
        for _ in 0..1_000_000u32 {
            let cmd = reg_read(SDHOST_CMD);
            if cmd & CMD_START == 0 { return Ok(()); }
            let rint = reg_read(SDHOST_RINTSTS);
            if rint & INT_HLE != 0 {
                reg_write(SDHOST_RINTSTS, INT_HLE);
                return Err("HLE during clock update");
            }
        }
        Err("Clock update timeout")
    }
}

/// Set SDHOST card clock divider.
/// f_card = f_base / (2 * divider), where f_base = 80MHz (160MHz PLL / edge_div=2).
/// divider=0 means bypass → 80MHz, divider=100 → 400kHz, divider=4 → 10MHz.
pub(crate) fn sdhost_set_clock(divider: u32) -> Result<(), &'static str> {
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
