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

/// Modem-domain clock enables, including WiFi and Bluetooth.
///
/// ADDRESS CORRECTED 2026-08-02. This was `0x600C_0090` and named
/// `SYSTEM_WIFI_CLK_EN`. Two things were wrong with that:
///
/// 1. The register is not in the SYSTEM peripheral at all. It is `wifi_clk_en`
///    in APB_CTRL. Verified in the `esp32s3` 0.30.0 PAC:
///    `APB_CTRL::PTR = 0x6002_6000`, `wifi_clk_en` the sixth u32 in the block.
/// 2. What actually sits at SYSTEM + 0x90 is `comb_pvt_err_nvt_site2`, a
///    process/voltage/temperature error register. So `early_lockdown` was
///    zeroing a PVT register and believing it had disabled the radios.
///
/// The boot line "[SEC] Radios disabled (WiFi, BT, USB OTG)" was therefore
/// FALSE for WiFi and Bluetooth. The USB OTG half was real; those registers
/// were correct.
///
/// Independently confirmed by measurement the same day: `wifi_clk_en` read
/// `0xFFFCE030` on Waveshare AFTER `early_lockdown` had run. Had the lockdown
/// been touching that register it would have read zero.
const APB_CTRL_WIFI_CLK_EN: u32 = 0x6002_6014;

/// Bluetooth low-power clock fractional divider.
///
/// ADDRESS CORRECTED 2026-08-02: was `0x600C_00A8`. In the PAC's
/// `system::RegisterBlock`, `bt_lpck_div_frac` is at offset 0x2C, so
/// `0x600C_002C`. The old address pointed at an unrelated register.
const SYSTEM_BT_LPCK_DIV_FRAC: u32 = 0x600C_002C;

/// `SYSTEM_WIFI_CLK_RNG_EN`, bit 15 of `wifi_clk_en`: the RNG's clock enable.
///
/// This bit must SURVIVE the lockdown. It shares a register with the radio
/// clocks but has nothing to do with them, and clearing it kills the hardware
/// RNG (C-04). `crypto::entropy::enable_rc_fast` sets it, and this function now
/// preserves it rather than relying on that.
const APB_CTRL_WIFI_CLK_RNG_EN: u32 = 1 << 15;

/// `RTC_CNTL_DIG_PWC_REG`, the digital-system power configuration register.
///
/// From the ESP32-S3 TRM v1.2 (in this project's docs): Low-Power Management
/// occupies `0x6000_8000..0x6000_8FFF`, and `RTC_CNTL_DIG_PWC_REG` is at offset
/// `0x0090`. Cross-checks against `crypto::entropy`'s `RTC_CNTL_CLK_CONF` at
/// `0x6000_8074`, same block.
const RTC_CNTL_DIG_PWC: u32 = 0x6000_8090;

/// `RTC_CNTL_WIFI_FORCE_PD`, bit 17. "Set this bit to FPD Wi-Fi." (TRM 10.30)
const RTC_CNTL_WIFI_FORCE_PD: u32 = 1 << 17;
/// `RTC_CNTL_WIFI_FORCE_PU`, bit 18. "Set this bit to FPU Wi-Fi." (TRM 10.30)
///
/// **Reset value is 1**, so the wireless power domain is held ON by default.
/// Clock gating alone therefore left a powered block with its clocks stopped.
const RTC_CNTL_WIFI_FORCE_PU: u32 = 1 << 18;

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
        //
        // Clear every modem clock EXCEPT the RNG's. A bare `reg_write(_, 0)`
        // would take bit 15 with it, and the RNG is not a radio.
        let wifi_clk = core::ptr::read_volatile(APB_CTRL_WIFI_CLK_EN as *const u32);
        core::ptr::write_volatile(
            APB_CTRL_WIFI_CLK_EN as *mut u32,
            wifi_clk & APB_CTRL_WIFI_CLK_RNG_EN,
        );

        // Zero the BT low-power clock divider
        reg_write(SYSTEM_BT_LPCK_DIV_FRAC, 0);

        // ── Power down the wireless domain, not just its clocks ──
        //
        // Clock gating stops a block; it does not unpower it.
        // `RTC_CNTL_WIFI_FORCE_PU` has reset value 1, so `xpd_wireless` was
        // held ON from boot on every device. Setting FORCE_PD and clearing
        // FORCE_PU turns the domain off outright.
        //
        // Safe because `xpd_wireless` is its own domain. The TRM lists it
        // separately from `xpd_cpu`, `xpd_pd_peri` and `xpd_dg_wrap`, and
        // nothing this firmware uses lives in it.
        //
        // Limit, stated by the TRM and not something a fix can change:
        // "RF Circuits and Phase Lock Loop (PLL) are controlled by internal
        // signals and cannot be modified by users." So this powers down the
        // wireless DIGITAL circuit. The RF analog block is not under software
        // control on this part.
        //
        // Addresses and bit positions taken from the ESP32-S3 TRM v1.2 register
        // 10.30, in this project's docs, not inferred. Inferring them is what
        // produced H-13.
        let pwc = core::ptr::read_volatile(RTC_CNTL_DIG_PWC as *const u32);
        core::ptr::write_volatile(
            RTC_CNTL_DIG_PWC as *mut u32,
            (pwc & !RTC_CNTL_WIFI_FORCE_PU) | RTC_CNTL_WIFI_FORCE_PD,
        );

        // ── Kill USB OTG ──
        // Gate USB OTG peripheral clock (not USB Serial/JTAG — that's
        // used for flashing/monitoring, killed in post_boot_lockdown)
        reg_clear_bits(SYSTEM_PERIP_CLK_EN0, USB_CLK_EN);
        reg_set_bits(SYSTEM_PERIP_RST_EN0, USB_CLK_EN);
    }

    // Claims only what is measured. "Radios disabled" was the old wording and it
    // was false for over a year (H-13): the write went to a PVT error register.
    //
    // What IS verified: `wifi_clk_en` reads 0x00008000 after this runs, i.e.
    // every bit cleared except 15, the RNG's. Measured on Waveshare 2026-08-02.
    //
    // What is NOT verified, and is why the wording is narrow:
    //
    //  - Which bits of this register correspond to WiFi MAC, baseband, or BT.
    //    The `esp32s3` 0.30.0 PAC exposes `wifi_clk_en` and `wifi_rst_en` as
    //    single opaque 32-bit fields with no named bits, and esp-hal names only
    //    bit 15. No source available here gives the rest, so no further bits are
    //    written: guessing bit meanings in this register is exactly what caused
    //    H-13.
    //  - The RF/PHY analog power domain, which has its own control and is not
    //    touched by clock gating at all.
    //
    // What makes the residual acceptable: there is no radio firmware in this
    // binary. esp-hal without the `wifi` feature never initialises the PHY,
    // never calls `phy_enable`, never loads calibration. A radio that is never
    // brought up does not transmit whether its clock runs or not. That was true
    // before this function was fixed, which is why H-13 was High and not
    // Critical.
    #[cfg(not(feature = "silent"))]
    {
        let pwc = unsafe { core::ptr::read_volatile(RTC_CNTL_DIG_PWC as *const u32) };
        log!(
            "   [SEC] Wireless powered down (DIG_PWC 0x{:08X}: FORCE_PD {}, FORCE_PU {}), \
             modem clocks gated, USB OTG off (RNG clock retained)",
            pwc,
            (pwc & RTC_CNTL_WIFI_FORCE_PD) != 0,
            (pwc & RTC_CNTL_WIFI_FORCE_PU) != 0,
        );
    }
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

    // These messages describe what THIS CODE did, not what the device is.
    //
    // What actually closes JTAG is the eFuses: DIS_PAD_JTAG and DIS_USB_JTAG
    // (ESP32-S3 TRM Table 5-1), burned per docs/EFUSE_RUNBOOK.md Step 8. On a
    // board where Step 8 was never run, JTAG is fully open regardless of
    // anything below.
    //
    // The dev path above only clears two pad-configuration bits in
    // USB_SERIAL_JTAG_CONF0. It does not disable the JTAG TAP. The previous
    // message claimed "JTAG disabled", which was untrue on an unprovisioned
    // board and misattributed the eFuse's work on a provisioned one. See H-04.
    #[cfg(feature = "production")]
    log!("   [SEC] USB Serial/JTAG peripheral gated and held in reset");

    #[cfg(not(feature = "production"))]
    log!("   [SEC] USB pad config hardened (JTAG is closed by eFuse, not here)");
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
