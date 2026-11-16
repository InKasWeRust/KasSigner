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

//! Pin map for the pins `board::init()` does not consume: wiring the
//! compiler cannot check. Pins esp-hal takes (LCD, I2C, touch, audio) are
//! named only where taken, in `board::init()` and, for I2S, `unit::bring_up`.
//!
//! Where Waveshare's sources are wrong:
//!
//!   * GPIO29 is TP_RST and GPIO30 is TP_INT. Neither is in `lcd35_board.h`,
//!     and GPIO30 is not a free header pin: twelve J6 GPIOs are free, not
//!     thirteen, exactly what an 8-bit DVP camera needs.
//!   * The wiki describes a MIPI-DSI panel, copied from the round-display
//!     models. The panel is an ST7796 on SPI; the DSI pads are unpopulated.

#![allow(missing_docs)] // pin numbers; documented by the section comments

// ── USB: two ports, two roles ───────────────────────────────────────────
//
//   CH343 port    DATA. A CH343P USB-to-UART bridge: the connector's D+/D-
//                 go to the bridge, not the SoC, so the P4 sees only UART.
//                 The flashing and debug path, and the only way into
//                 serial download mode.
//
//   OTG port      CHARGE ONLY. Wired to the P4's USB 2.0 High-Speed PHY,
//                 on its own pads (USB1_N/P through R70/R72); no driver,
//                 by design. A host enumerates nothing on it: it is not
//                 on GPIO24/25, the USB-Serial-JTAG pads, so it is no
//                 second flashing path, and a firmware USB stack would die
//                 with the application.
//
// No USB stack: an air-gapped signer takes data in by QR and out on the
// display, with SD for backups, and a USB stack would parse
// host-controlled descriptors on a device holding keys. esp-hal supports
// the port (usb/otg/ll/esp32p4.rs, `Usb::new_hs`); it is left dead.
//
// eFuse plan: serial download stays open on the CH343, behind Secure Boot
// v2, so only signed images run. Both ways into download mode go through
// the CH343: if it or its connector dies, no firmware can reflash the
// board. Get a spare board before burning eFuses.

// ── ESP32-C6 co-processor, SDIO ─────────────────────────────────────────
// Held powered down on an air-gapped signer; never ship hosted firmware.
// C6_RST is GPIO54, wired to the C6's CHIP_PU through R54 (0R) and pulled up
// by R25: low powers it down. `board::hold_c6_down` drives it low before
// anything else in bring-up.
pub const C6_D0: u8 = 14;
pub const C6_D1: u8 = 15;
pub const C6_D2: u8 = 16;
pub const C6_D3: u8 = 17;
pub const C6_CLK: u8 = 18;
pub const C6_CMD: u8 = 19;
pub const C6_RST: u8 = 54;

// ── microSD, SDIO 4-bit ─────────────────────────────────────────────────
// The chip's dedicated IOMUX functions for SD slot 1, not GPIO-matrix
// routing, so full speed is available:
//   GPIO39-42 = SD1_DATA0-3, GPIO43 = SD1_CLK, GPIO44 = SD1_CMD
//
// The slot has no card-detect line: esp-hal's `Slot::is_card_present()`
// says yes with the slot empty. Presence is whether the card answers
// CMD0/CMD8.
//
// Verified with an 8 GB SDHC card (CMD8 echo 0x1AA, CCS=1, CSD v2). The
// OEM ID is not always ASCII: this card reports 0x000c.
pub const SD_D0: u8 = 39;
pub const SD_D1: u8 = 40;
pub const SD_D2: u8 = 41;
pub const SD_D3: u8 = 42;
pub const SD_CLK: u8 = 43;
pub const SD_CMD: u8 = 44;

// ── Buttons ─────────────────────────────────────────────────────────────
// Three on the board; one is usable as a UI input (measured on hardware).
//
//   MIDDLE            K2 pulls ESP_EN low: the chip's reset, and the
//                     AXP2101's PWROK (pin 29). Invisible to software;
//                     with `board::reset_cuts_power` on (the signer, while
//                     it holds a secret), the PMU cycles every rail on a
//                     press.
//
//   PWR_KEY           K1 -> AXP2101 PWRON (pin 30) AND GPIO49 via T2, one
//   (GPIO49 + PMU)    switch on both paths. T2 inverts: pressed reads HIGH.
//                     Not for UI, as firmware cannot override the PMU:
//                     short press  -> the PMU resets the board (REG 49
//                                     latches 0x05, SHORT_PRESS |
//                                     POSITIVE_EDGE).
//                     ~6 s hold    -> the PMU cuts all rails until
//                                     replugged: REG 27's OFFLEVEL
//                                     default, even with PWROFF_EN 0x00.
//
//   GPIO35            The UI button: plain input, idles HIGH, reads LOW
//                     when pressed. Also the BOOT strap.
//
// Download mode: unplug USB, hold BOOT, plug USB, release BOOT. The strap
// is latched at power-on, not on a reset: BOOT held through a plain
// middle-button reset does nothing (GPIO.strap, 0x500E_0038, still reads
// 0x30f). With `reset_cuts_power` on, that press is a power-on and BOOT
// held through it enters download mode (measured), but the setting stays
// on (the datasheet resets it only at the PMU's own power-on), so a
// flasher must then leave the reset line alone (espflash `--before
// no-reset`). The replug with BOOT held and espflash's DTR/RTS
// handshake on the CH343 are the two recovery paths; confirm both before
// burning DIS_DOWNLOAD_MODE.
pub const PWR_KEY: u8 = 49;
pub const USER_KEY: u8 = 35;

// ── Free J6 header pins ─────────────────────────────────────────────────
/// Twelve: GPIO29/30 are the touch controller's.
pub const FREE_J6: [u8; 12] = [2, 3, 4, 5, 31, 32, 33, 46, 47, 48, 51, 52];

/// GPIO34-38 are strapping pins (GPIO35 low at power-on enters the serial
/// bootloader; GPIO36 must be high). GPIO24/25 are USB-JTAG by default.
pub const AVOID: [u8; 7] = [24, 25, 34, 35, 36, 37, 38];

// ── Camera, MIPI-CSI (connector J13) ────────────────────────────────────
// No GPIOs: the lanes are differential pairs straight to the SoC.
//   pins 2/3 D0-/D0+   5/6 D1-/D1+   8/9 CLK-/CLK+
//   pin 11 CSI_IO0 (10K pull-up, not wired to a GPIO)
//   pin 12 CSI_IO1 (NC)
//   pins 13/14 SCL/SDA, the shared I2C bus (GPIO7/8)
// No XCLK pin or camera clock net exists on the board; the only MCLK on the
// schematic is the ES8311's. The module clocks itself.
