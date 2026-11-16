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

//! The pins the card shares with the display: SPI2's routing saved, the
//! pins handed to SDHOST for the card session, and SPI2's put back.

use super::*;

// ═══════════════════════════════════════════════════════════════
// Saved SPI2 state for display coexistence
// ═══════════════════════════════════════════════════════════════

pub struct SavedDisplayState {
    fout_sck: u32,
    fout_mosi: u32,
    fout_miso: u32,
    fin_fspiq: u32,
    iomux_sck: u32,
    iomux_mosi: u32,
    iomux_miso: u32,
}

pub(super) fn save_display_state() -> SavedDisplayState {
    // SAFETY: reads the IO_MUX and GPIO matrix registers for the display's
    // pins and FSPIQ's input, with no side effect.
    unsafe {
        SavedDisplayState {
            fout_sck: reg_read(func_out_sel_addr(PIN_SCK)),
            fout_mosi: reg_read(func_out_sel_addr(PIN_MOSI)),
            fout_miso: reg_read(func_out_sel_addr(PIN_MISO)),
            fin_fspiq: reg_read(func_in_sel_addr(FSPIQ_IN_SIGNAL)),
            iomux_sck: reg_read(iomux_addr(PIN_SCK)),
            iomux_mosi: reg_read(iomux_addr(PIN_MOSI)),
            iomux_miso: reg_read(iomux_addr(PIN_MISO)),
        }
    }
}

pub(super) fn restore_display_state(s: &SavedDisplayState) {
    // SAFETY: writes back the routing `save_display_state` read from these
    // same registers, so the display gets exactly what it had.
    unsafe {
        reg_write(func_out_sel_addr(PIN_SCK), s.fout_sck);
        reg_write(func_out_sel_addr(PIN_MOSI), s.fout_mosi);
        reg_write(func_out_sel_addr(PIN_MISO), s.fout_miso);
        reg_write(func_in_sel_addr(FSPIQ_IN_SIGNAL), s.fin_fspiq);
        reg_write(iomux_addr(PIN_SCK), s.iomux_sck);
        reg_write(iomux_addr(PIN_MOSI), s.iomux_mosi);
        reg_write(iomux_addr(PIN_MISO), s.iomux_miso);
        // Re-enable MISO output for SPI2
        gpio_enable_output(PIN_MISO);
    }
}

// ═══════════════════════════════════════════════════════════════
// SDHOST GPIO routing
// ═══════════════════════════════════════════════════════════════

/// Route GPIO38/39/40 to SDHOST controller via GPIO matrix
pub(super) fn route_pins_to_sdhost() {
    // SAFETY: writes the IO_MUX and GPIO matrix entries for GPIO38/39/40 and
    // for the SDHOST and FSPIQ input signals, and sets LCD CS high. These
    // pins are shared with the display, which does not drive them during an
    // SD session.
    unsafe {
        // Disconnect FSPIQ_IN from GPIO40 (prevent SPI2 interference)
        reg_write(func_in_sel_addr(FSPIQ_IN_SIGNAL), 0xBC); // 0x3C | (1<<7) = constant LOW via matrix

        // --- GPIO39 → sdhost_cclk_out_1 (output-only, signal 172) ---
        // IOMUX: MCU_SEL=1 (GPIO), FUN_DRV=2 (20 mA, to drive through
        // C26 = 1 µF), no IE
        reg_write(iomux_addr(PIN_SCK), 0x0000_1800); // MCU_SEL=1, FUN_DRV=2(bits11:10=10)
                                                     // FUNC_OUT_SEL: signal 172, OEN_SEL=1 (always output via GPIO_ENABLE)
        reg_write(func_out_sel_addr(PIN_SCK), SDHOST_CCLK_OUT_1 | (1 << 10));
        gpio_enable_output(PIN_SCK);

        // --- GPIO38 → sdhost_ccmd (BIDIRECTIONAL, signal 178) ---
        // IOMUX 0x1300: MCU_SEL=1 (bit 12, GPIO), FUN_IE=1 (bit 9, input
        // enable), FUN_WPU=1 (bit 8, pull-up)
        reg_write(iomux_addr(PIN_MOSI), 0x0000_1300);
        // FUNC_OUT_SEL: signal 178, OEN_SEL=0, so the peripheral's
        // sdhost_ccmd_out_en_1 controls OE
        reg_write(func_out_sel_addr(PIN_MOSI), SDHOST_CCMD_OUT_1);
        // GPIO_ENABLE must be set for the peripheral's OE to work
        gpio_enable_output(PIN_MOSI);
        // Input: route pin to sdhost_ccmd_in_1 via GPIO matrix (SIG_IN_SEL=1)
        reg_write(
            func_in_sel_addr(SDHOST_CCMD_IN_1),
            PIN_MOSI as u32 | (1 << 7),
        );

        // --- GPIO40 → sdhost_cdata[0] (BIDIRECTIONAL, signal 180) ---
        // IOMUX 0x1300, as for GPIO38
        reg_write(iomux_addr(PIN_MISO), 0x0000_1300);
        // FUNC_OUT_SEL: signal 180, OEN_SEL=0, so the peripheral's
        // sdhost_cdata_out_en_10 controls OE
        reg_write(func_out_sel_addr(PIN_MISO), SDHOST_CDATA_OUT_10);
        gpio_enable_output(PIN_MISO);
        // Input: route pin to sdhost_cdata_in_10 via GPIO matrix
        reg_write(
            func_in_sel_addr(SDHOST_CDATA_IN_10),
            PIN_MISO as u32 | (1 << 7),
        );

        // --- Card detect: constant LOW (no detect switch: always present) ---
        reg_write(func_in_sel_addr(SDHOST_CARD_DETECT_1), 0x3C | (1 << 7));

        // LCD CS HIGH during SD access
        gpio_set(PIN_LCD_CS);
    }
}
