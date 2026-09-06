use super::super::gpio::{
    func_in_sel_addr, func_out_sel_addr, gpio_enable_output, gpio_set, iomux_addr,
};
use super::super::registers::{
    FSPIQ_IN_SIGNAL, PIN_LCD_CS, PIN_MISO, PIN_MOSI, PIN_SCK,
    SDHOST_CARD_DETECT_1, SDHOST_CCLK_OUT_1, SDHOST_CCMD_IN_1,
    SDHOST_CCMD_OUT_1, SDHOST_CDATA_IN_10, SDHOST_CDATA_OUT_10, reg_write,
};
// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Waveshare SDHOST controller and native-card transfers.

// ═══════════════════════════════════════════════════════════════
// SDHOST GPIO routing
// ═══════════════════════════════════════════════════════════════

/// Route GPIO38/39/40 to SDHOST controller via GPIO matrix
pub(crate) fn route_pins_to_sdhost() {
    unsafe {
        // Disconnect FSPIQ_IN from GPIO40 (prevent SPI2 interference)
        reg_write(func_in_sel_addr(FSPIQ_IN_SIGNAL), 0xBC); // 0x3C | (1<<7) = constant LOW via matrix

        // --- GPIO39 → sdhost_cclk_out_1 (output-only, signal 172) ---
        // IOMUX: MCU_SEL=1(GPIO), FUN_DRV=2(20mA for driving through C26=1µF), no IE
        reg_write(iomux_addr(PIN_SCK), 0x0000_1800); // MCU_SEL=1, FUN_DRV=2(bits11:10=10)
        // FUNC_OUT_SEL: signal 172, OEN_SEL=1 (always output via GPIO_ENABLE)
        reg_write(func_out_sel_addr(PIN_SCK), SDHOST_CCLK_OUT_1 | (1 << 10));
        gpio_enable_output(PIN_SCK);

        // --- GPIO38 → sdhost_ccmd (BIDIRECTIONAL, signal 178) ---
        // IOMUX: MCU_SEL=1(GPIO), FUN_IE=1(input enable), FUN_WPU=1(pullup), drive=2
        // 0x1300 = bits: MCU_SEL=1(bit12), FUN_IE=1(bit9), FUN_WPU=1(bit8)
        reg_write(iomux_addr(PIN_MOSI), 0x0000_1300);
        // FUNC_OUT_SEL: signal 178, OEN_SEL=0 → peripheral's sdhost_ccmd_out_en_1 controls OE
        reg_write(func_out_sel_addr(PIN_MOSI), SDHOST_CCMD_OUT_1);
        // GPIO_ENABLE must be set for the peripheral OE to work through the matrix
        gpio_enable_output(PIN_MOSI);
        // Input: route pin to sdhost_ccmd_in_1 via GPIO matrix (SIG_IN_SEL=1)
        reg_write(func_in_sel_addr(SDHOST_CCMD_IN_1), PIN_MOSI as u32 | (1 << 7));

        // --- GPIO40 → sdhost_cdata[0] (BIDIRECTIONAL, signal 180) ---
        // IOMUX: MCU_SEL=1(GPIO), FUN_IE=1(input enable), FUN_WPU=1(pullup)
        reg_write(iomux_addr(PIN_MISO), 0x0000_1300);
        // FUNC_OUT_SEL: signal 180, OEN_SEL=0 → peripheral's sdhost_cdata_out_en_10 controls OE
        reg_write(func_out_sel_addr(PIN_MISO), SDHOST_CDATA_OUT_10);
        gpio_enable_output(PIN_MISO);
        // Input: route pin to sdhost_cdata_in_10 via GPIO matrix
        reg_write(func_in_sel_addr(SDHOST_CDATA_IN_10), PIN_MISO as u32 | (1 << 7));

        // --- Card detect: route to constant LOW (card always present, no detect switch) ---
        reg_write(func_in_sel_addr(SDHOST_CARD_DETECT_1), 0x3C | (1 << 7));

        // LCD CS HIGH during SD access
        gpio_set(PIN_LCD_CS);
    }
}
