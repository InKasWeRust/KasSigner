use super::registers::{
    FSPIQ_IN_SIGNAL, GPIO_ENABLE1_W1TS, GPIO_ENABLE_W1TS,
    GPIO_FUNC_IN_SEL_BASE, GPIO_FUNC_OUT_SEL_BASE, GPIO_OUT1_W1TC,
    GPIO_OUT1_W1TS, GPIO_OUT_W1TC,
    GPIO_OUT_W1TS, IO_MUX_BASE, PIN_MISO, PIN_MOSI, PIN_SCK, reg_read, reg_write,
};
// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Waveshare SD GPIO routing and display-state helpers.

// ═══════════════════════════════════════════════════════════════
// GPIO helpers
// ═══════════════════════════════════════════════════════════════

#[inline(always)]
pub(super) fn gpio_set(pin: u8) {
    unsafe {
        if pin < 32 {
            reg_write(GPIO_OUT_W1TS, 1u32 << pin);
        } else {
            reg_write(GPIO_OUT1_W1TS, 1u32 << (pin - 32));
        }
    }
}

#[inline(always)]
pub(super) fn gpio_clear(pin: u8) {
    unsafe {
        if pin < 32 {
            reg_write(GPIO_OUT_W1TC, 1u32 << pin);
        } else {
            reg_write(GPIO_OUT1_W1TC, 1u32 << (pin - 32));
        }
    }
}

#[inline(always)]
pub(super) fn gpio_enable_output(pin: u8) {
    unsafe {
        if pin < 32 {
            reg_write(GPIO_ENABLE_W1TS, 1u32 << pin);
        } else {
            reg_write(GPIO_ENABLE1_W1TS, 1u32 << (pin - 32));
        }
    }
}

#[inline(always)]
pub(super) fn iomux_addr(pin: u8) -> u32 {
    IO_MUX_BASE + (pin as u32) * 4
}

#[inline(always)]
pub(super) fn func_out_sel_addr(pin: u8) -> u32 {
    GPIO_FUNC_OUT_SEL_BASE + (pin as u32) * 4
}

#[inline(always)]
pub(super) fn func_in_sel_addr(signal: u32) -> u32 {
    GPIO_FUNC_IN_SEL_BASE + signal * 4
}

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
    unsafe {
        SavedDisplayState {
            fout_sck:  reg_read(func_out_sel_addr(PIN_SCK)),
            fout_mosi: reg_read(func_out_sel_addr(PIN_MOSI)),
            fout_miso: reg_read(func_out_sel_addr(PIN_MISO)),
            fin_fspiq: reg_read(func_in_sel_addr(FSPIQ_IN_SIGNAL)),
            iomux_sck:  reg_read(iomux_addr(PIN_SCK)),
            iomux_mosi: reg_read(iomux_addr(PIN_MOSI)),
            iomux_miso: reg_read(iomux_addr(PIN_MISO)),
        }
    }
}

pub(super) fn restore_display_state(s: &SavedDisplayState) {
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
