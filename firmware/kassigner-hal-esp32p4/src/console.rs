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

//! The console, behind `kassigner-hal`'s `Console`.
//!
//! The console is UART0 on GPIO 37 and 38, as the native USB port does not
//! enumerate. With no transceiver pad to switch off as on the S3, `close`
//! takes the two pads from UART0 and leaves them plain inputs, no pull,
//! until reset: nothing the binary still writes reaches the USB bridge, and
//! the bridge's line reaches nothing.
//!
//! What was written before the close goes out first, so the binary's line
//! saying the console is closing is the last a host sees.

use core::sync::atomic::{AtomicBool, Ordering};

use esp_hal::{
    delay::Delay,
    gpio::{Input, InputConfig, Pull},
    peripherals::{GPIO37, GPIO38},
};
use kassigner_hal::provisioning::Console;
use static_cell::StaticCell;

/// Microseconds for the byte left in UART0's shifter once its FIFO is
/// empty: two characters at 115,200 baud, the bootloader's rate, with room.
const LAST_BYTE_US: u32 = 200;

/// Set by the first close: the pads are taken once.
static CLOSED: AtomicBool = AtomicBool::new(false);

/// GPIO 37 and 38's drivers, plain inputs, kept until reset.
///
/// Never dropped, so the pads stay inputs whatever a later esp-hal does when
/// a driver goes. `mem::forget` would not do: `Input` has no `Drop`, so
/// forgetting one is dropping it (clippy's `forget_non_drop`).
static PADS: StaticCell<(Input<'static>, Input<'static>)> = StaticCell::new();

/// The port. A unit type; there is one console.
#[derive(Clone, Copy, Debug, Default)]
pub struct Uart0;

impl Console for Uart0 {
    fn close(&mut self) {
        crate::soc::uart::drain();
        Delay::new().delay_micros(LAST_BYTE_US);
        // A second close finds the pads taken and leaves them as they are.
        if CLOSED.swap(true, Ordering::AcqRel) {
            return;
        }
        // SAFETY: GPIO 37 and 38 are UART0's pads, which `board::init` leaves
        // unused and esp-println never takes (it writes UART0's registers,
        // not the pins). The flag above makes sure they are taken only once.
        let (tx, rx) = unsafe { (GPIO37::steal(), GPIO38::steal()) };
        let plain = InputConfig::default().with_pull(Pull::None);
        // The flag makes this the only call, so it cannot fail.
        let _ = PADS.try_init((Input::new(tx, plain), Input::new(rx, plain)));
    }
}
