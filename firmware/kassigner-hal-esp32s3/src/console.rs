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

//! USB Serial/JTAG, closed.
//!
//! The S3's USB Serial/JTAG controller is two things on one pair of pads:
//! the console the examples and the binary print to, and a JTAG bridge into
//! the CPU. Provisioning burns the JTAG side off (`DIS_USB_JTAG`); the
//! console side stays, as it is also the download path an update needs, and
//! provisioning keeps download mode.
//!
//! So a provisioned unit closes it itself, after verifying its fuses and
//! before it holds a seed: the controller's interrupts off and cleared, then
//! the transceiver's pad function in `USB_SERIAL_JTAG_CONF0` off, and the
//! pads stay quiet until the next reset. Nothing leaves or arrives by USB
//! after that. The ROM's download mode is unaffected: it runs after a reset,
//! which this register does not survive.
//!
//! esp-hal clears the same bit when a program takes GPIO 19 or 20
//! (`gpio::disable_usb_pads`), so this is a supported operation.
//!
//! Device only: it names the peripheral.

use kassigner_hal::provisioning::Console;

/// The port. A unit type: there is one controller, and nothing else in the
/// tree owns it.
#[derive(Clone, Copy, Debug, Default)]
pub struct UsbSerialJtag;

impl Console for UsbSerialJtag {
    fn close(&mut self) {
        let usb = esp_hal::peripherals::USB_DEVICE::regs();
        // Every interrupt of the controller off and cleared before its pads
        // go. Nothing in the firmware handles them, so one the ROM left
        // enabled would fire against lines the host still drives once the
        // pads are off and keep core 0 busy with nobody clearing it: on a
        // provisioned M5 with the cable in, taps then lagged half a second.
        // SAFETY: zero clears every enable bit, a plain register write with
        // no other effect.
        usb.int_ena().write(|w| unsafe { w.bits(0) });
        // SAFETY: all ones sets every clear bit, likewise.
        usb.int_clr().write(|w| unsafe { w.bits(0xFFFF_FFFF) });
        usb.conf0().modify(|_, w| {
            w.usb_pad_enable().clear_bit();
            w.dm_pullup().clear_bit();
            w.dm_pulldown().clear_bit();
            w.dp_pullup().clear_bit();
            w.dp_pulldown().clear_bit()
        });
    }
}
