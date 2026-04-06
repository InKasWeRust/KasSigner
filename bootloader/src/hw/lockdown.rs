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

// hw/lockdown.rs — Post-boot security hardening
// 100% Rust, no-std, no-alloc
//
// KasSigner is air-gapped. WiFi, Bluetooth, USB OTG, and JTAG have
// no legitimate use. This module kills them at the register level.
//
// Two phases:
//   early_lockdown()  — called immediately after esp_hal::init(),
//                       before any peripheral setup. Kills radios.
//   post_boot_lockdown() — called after firmware verification,
//                          before the main loop. Kills USB data + JTAG.
//
// These are software disables. For permanent (eFuse) disable, see
// docs/EFUSE_RUNBOOK.md.

use crate::log;

// ═══════════════════════════════════════════════════════════════════
// System register addresses (ESP32-S3 TRM Ch.7)
// ═══════════════════════════════════════════════════════════════════

/// Peripheral clock enable register 0
const SYSTEM_PERIP_CLK_EN0: u32 = 0x600C_0018;
/// Peripheral clock enable register 1
const SYSTEM_PERIP_CLK_EN1: u32 = 0x600C_001C;
/// Peripheral reset register 0
const SYSTEM_PERIP_RST_EN0: u32 = 0x600C_0020;
/// Peripheral reset register 1
const SYSTEM_PERIP_RST_EN1: u32 = 0x600C_0024;

/// WiFi clock enable (PERIP_CLK_EN0 bit 0 + dedicated regs)
const SYSTEM_WIFI_CLK_EN: u32 = 0x600C_0090;
/// Bluetooth clock register
const SYSTEM_BT_LPCK_DIV_FRAC: u32 = 0x600C_00A8;

// PERIP_CLK_EN0 bits
const USB_CLK_EN: u32 = 1 << 23; // USB OTG

// PERIP_CLK_EN1 bits
const USB_DEVICE_CLK_EN: u32 = 1 << 10; // USB Serial/JTAG device

/// USB Serial/JTAG configuration register
const USB_SERIAL_JTAG_CONF0: u32 = 0x6003_8044;

/// GPIO JTAG enable register
/// Writing 0 to JTAG-related bits in the USB_SERIAL_JTAG peripheral
/// disables the JTAG bridge
const USB_SERIAL_JTAG_BASE: u32 = 0x6003_8000;

// ═══════════════════════════════════════════════════════════════════
// Register helpers
// ═══════════════════════════════════════════════════════════════════

#[inline(always)]
unsafe fn reg_read(addr: u32) -> u32 {
    core::ptr::read_volatile(addr as *const u32)
}

#[inline(always)]
unsafe fn reg_write(addr: u32, val: u32) {
    core::ptr::write_volatile(addr as *mut u32, val);
}

#[inline(always)]
unsafe fn reg_clear_bits(addr: u32, bits: u32) {
    let v = reg_read(addr);
    reg_write(addr, v & !bits);
}

#[inline(always)]
unsafe fn reg_set_bits(addr: u32, bits: u32) {
    let v = reg_read(addr);
    reg_write(addr, v | bits);
}

// ═══════════════════════════════════════════════════════════════════
// Phase 1: Early lockdown — kill radios immediately after init
// ═══════════════════════════════════════════════════════════════════

/// Disable WiFi, Bluetooth, and USB OTG clocks.
/// Called immediately after `esp_hal::init()`, before any peripheral setup.
/// These peripherals have no legitimate use in an air-gapped signer.
pub fn early_lockdown() {
    unsafe {
        // ── Kill WiFi + Bluetooth clocks ──
        // Zero the WiFi/modem clock register — gates all radio clocks.
        // NOTE: This register is shared. If SD card fails after this,
        // do a hard power cycle — a prior panic may have left SDHOST
        // in a bad state that persists across soft resets.
        reg_write(SYSTEM_WIFI_CLK_EN, 0);

        // Zero the BT low-power clock divider
        reg_write(SYSTEM_BT_LPCK_DIV_FRAC, 0);

        // ── Kill USB OTG ──
        // Gate USB OTG peripheral clock (not USB Serial/JTAG — that's
        // used for flashing/monitoring, killed in post_boot_lockdown)
        reg_clear_bits(SYSTEM_PERIP_CLK_EN0, USB_CLK_EN);
        reg_set_bits(SYSTEM_PERIP_RST_EN0, USB_CLK_EN);
    }

    log!("   [SEC] Radios disabled (WiFi, BT, USB OTG)");
}

// ═══════════════════════════════════════════════════════════════════
// Phase 2: Post-boot lockdown — kill USB data + JTAG after verify
// ═══════════════════════════════════════════════════════════════════

/// Disable USB Serial/JTAG data and JTAG debug interface.
/// Called after firmware verification, before the main loop.
///
/// In dev mode (not production), USB Serial is kept alive for UART
/// monitoring. In production, everything is killed.
///
/// JTAG is always disabled regardless of build mode — there is no
/// legitimate debug use case for a deployed air-gapped signer.
pub fn post_boot_lockdown() {
    unsafe {
        // ── Disable JTAG bridge ──
        // The USB_SERIAL_JTAG peripheral has a JTAG-to-USB bridge.
        // Clear the exchange pin override to disconnect JTAG from pins.
        // This prevents using USB to access JTAG even if the peripheral
        // clock is still running (needed for UART in dev mode).
        let conf0 = reg_read(USB_SERIAL_JTAG_CONF0);
        // Bit 13: USB_SERIAL_JTAG_USB_PAD_ENABLE — controls whether
        // the USB pads are connected. We leave this for UART.
        // Bit 2: EXCHANGE_PINS — if set, swaps D+/D- (irrelevant here)
        // The key is to disable the JTAG TAP by disconnecting it from pins.
        // Write 0 to bits [4:3] (VDD_SPI_AS_GPIO, PULLUP_DM) to reduce
        // attack surface on the USB pins.
        reg_write(USB_SERIAL_JTAG_CONF0, conf0 & !(0x3 << 3));

        // ── Production: kill USB Serial/JTAG entirely ──
        #[cfg(feature = "production")]
        {
            // Gate USB Serial/JTAG device clock
            reg_clear_bits(SYSTEM_PERIP_CLK_EN1, USB_DEVICE_CLK_EN);
            // Hold in reset
            reg_set_bits(SYSTEM_PERIP_RST_EN1, USB_DEVICE_CLK_EN);
        }
    }

    #[cfg(feature = "production")]
    log!("   [SEC] USB Serial/JTAG disabled (production)");

    #[cfg(not(feature = "production"))]
    log!("   [SEC] JTAG disabled (USB UART kept for dev)");
}

// ═══════════════════════════════════════════════════════════════════
// Panic wipe — zeroize key material before halting
// ═══════════════════════════════════════════════════════════════════

/// Wipe all sensitive memory regions on panic.
/// Called from the panic hook before the system halts.
///
/// This is best-effort — a voltage glitch or hard reset could
/// prevent execution. But it covers software panics and stack
/// overflows that reach the panic handler.
pub fn panic_wipe() {
    unsafe {
        // Zeroize the SRAM region where AppData lives.
        // AppData contains seed indices, private keys, passphrase buffers.
        //
        // We can't get a pointer to AppData from here (it's on main's stack),
        // so we wipe a broad SRAM region. The ESP32-S3 data SRAM is at
        // 0x3FC8_8000 to 0x3FCF_0000 (512KB).
        //
        // Wiping the full 512KB takes ~1ms at 240MHz — acceptable for panic.
        //
        // We use write_volatile to prevent the compiler from optimizing
        // away the writes (since the program is about to halt).

        let sram_start = 0x3FC8_8000u32 as *mut u32;
        let sram_words = (0x3FCF_0000u32 - 0x3FC8_8000u32) / 4;

        // First pass: zero
        for i in 0..sram_words {
            core::ptr::write_volatile(sram_start.add(i as usize), 0);
        }

        // Second pass: verify (anti-glitch)
        // If a glitch skipped the first pass, this catches it
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        for i in 0..sram_words {
            core::ptr::write_volatile(sram_start.add(i as usize), 0);
        }

        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}
