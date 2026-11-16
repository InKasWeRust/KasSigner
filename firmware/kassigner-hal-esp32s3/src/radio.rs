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

//! The radio, powered down.
//!
//! The S3 carries Wi-Fi and Bluetooth in one power domain, the modem domain
//! the TRM calls Wi-Fi. Nothing here turns them on, but the domain's
//! force-power-up bit is set at reset, so bring-up isolates the domain and
//! forces it off until the next reset: an air-gapped signer wants no idle
//! radio.
//!
//! Two low-power controller registers (TRM section 10, registers 10.30 and
//! 10.31), in the order esp-hal's deep-sleep entry uses on this chip:
//! isolate first, so the rest of the chip never sees the domain's outputs
//! float, then power down. The force-up and force-no-isolation bits are
//! cleared on the way, leaving no opposing pair of force bits set.
//!
//! The random generator loses no source: its high-speed ADC feed runs only
//! while Wi-Fi or Bluetooth is enabled, which this firmware never does.
//!
//! Device only: it names the peripheral.

use esp_hal::peripherals::LPWR;

/// Isolate the modem domain and force it off, then read both registers
/// back: true when isolated and off, with neither opposing force bit set.
pub fn power_down() -> bool {
    let rtc = LPWR::regs();
    rtc.dig_iso().modify(|_, w| {
        w.wifi_force_noiso().clear_bit();
        w.wifi_force_iso().set_bit()
    });
    rtc.dig_pwc().modify(|_, w| {
        w.wifi_force_pu().clear_bit();
        w.wifi_force_pd().set_bit()
    });
    let iso = rtc.dig_iso().read();
    let pwc = rtc.dig_pwc().read();
    iso.wifi_force_iso().bit_is_set()
        && iso.wifi_force_noiso().bit_is_clear()
        && pwc.wifi_force_pd().bit_is_set()
        && pwc.wifi_force_pu().bit_is_clear()
}
