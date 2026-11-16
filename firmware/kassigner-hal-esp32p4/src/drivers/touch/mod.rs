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

//! Capacitive touch: an FT6336 at 0x38, which Waveshare's product page
//! names and whose board support package (2.0.2) uses only the FT5x06
//! driver; or a GT911 at 0x5D or 0x14, should a panel carry one.
//!
//! R32 (10K) pulls TP_RST on GPIO29 low, so the controller powers up held
//! in reset and answers nothing on I2C until it is released.
//!
//! A GT911 latches INT at the reset edge to select its address, so INT is
//! set while RST is still asserted, held 1 ms, then RST released, as
//! Espressif's `esp_lcd_touch_gt911.c` does. The FT6336 ignores INT.
//!
//! [`Touch::read`] gives the controller's frame; [`Touch::read_screen`]
//! maps it with `board::touch_map` onto what `drivers::st7796` draws.

pub mod ft6336;
pub mod gt911;

use crate::board::i2c::{self, Bus};
use esp_hal::{
    delay::Delay,
    gpio::{Flex, Level, Output},
};

/// Which part answered.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Controller {
    /// FT6336 / FT5x06 at 0x38 — what this board carries.
    Ft6336,
    /// GT911 at 0x5D.
    Gt911Primary,
    /// GT911 at 0x14.
    Gt911Backup,
}

impl Controller {
    /// I2C address of this controller.
    pub fn addr(self) -> u8 {
        match self {
            Controller::Ft6336 => ft6336::ADDR,
            Controller::Gt911Primary => gt911::ADDR_PRIMARY,
            Controller::Gt911Backup => gt911::ADDR_BACKUP,
        }
    }
}

/// A touch point. Frame depends on which method produced it.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Point {
    /// Column.
    pub x: u16,
    /// Row.
    pub y: u16,
}

/// The controller could not be read, or none was found: not "nothing
/// touching".
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ReadFailed;

/// Reset timing shared by both parts, from Espressif's driver.
pub const RESET_ASSERT_MS: u32 = 10;
/// GT911: INT held at the selecting level before RST releases.
pub const INT_HOLD_MS: u32 = 1;
/// After RST release, before INT is handed back.
pub const RESET_RELEASE_MS: u32 = 10;
/// Controller boot after INT is released.
pub const BOOT_MS: u32 = 50;

/// Touch controller handle.
pub struct Touch<'d> {
    rst: Output<'d>,
    /// An output only during the GT911 reset sequence, then an input the
    /// controller drives to signal a touch.
    int: Flex<'d>,
    controller: Option<Controller>,
}

impl<'d> Touch<'d> {
    /// `rst` must start LOW (matching R32). `int` is any GPIO in `Flex`.
    pub fn new(rst: Output<'d>, mut int: Flex<'d>) -> Self {
        int.set_input_enable(true);
        Self {
            rst,
            int,
            controller: None,
        }
    }

    /// Which controller `probe()` found, if any.
    pub fn controller(&self) -> Option<Controller> {
        self.controller
    }

    /// Release the controller from reset and find it: an FT6336, or a GT911
    /// at each address in turn, selected by INT.
    pub fn probe(&mut self, bus: &mut Bus<'_>, delay: &Delay) -> Option<Controller> {
        for want in [Controller::Gt911Primary, Controller::Gt911Backup] {
            let int_high = gt911::int_level_for(want.addr());

            self.rst.set_low();
            self.int.set_output_enable(true);
            self.int.set_level(Level::Low);
            delay.delay_millis(RESET_ASSERT_MS);

            self.int
                .set_level(if int_high { Level::High } else { Level::Low });
            delay.delay_millis(INT_HOLD_MS);

            self.rst.set_high();
            delay.delay_millis(RESET_RELEASE_MS);

            // Hand INT back to the controller.
            self.int.set_output_enable(false);
            self.int.set_input_enable(true);
            delay.delay_millis(BOOT_MS);

            // The FT6336 needs only RST released.
            if i2c::present(bus, ft6336::ADDR) {
                self.controller = Some(Controller::Ft6336);
                return self.controller;
            }
            if i2c::present(bus, want.addr()) {
                self.controller = Some(want);
                return self.controller;
            }
        }
        None
    }

    /// True while the controller asserts INT: cheaper than polling I2C when
    /// nothing touches the screen.
    pub fn interrupt_asserted(&self) -> bool {
        // Pulled high by R58; the controller drives it low on touch.
        self.int.level() == Level::Low
    }

    /// Poll for a touch in the controller's frame: `Ok(None)` when nothing
    /// is down, an error when it could not be read (not a lift).
    pub fn read(&mut self, bus: &mut Bus<'_>) -> Result<Option<Point>, ReadFailed> {
        match self.controller.ok_or(ReadFailed)? {
            Controller::Ft6336 => {
                // The whole report in one read. A point counts only with a
                // count of 1 to 5 and the event pressed or held: after a
                // lift the part can go on reporting the last point as
                // "lifted", count 15. The weight is always 0 on this part.
                let mut buf = [0u8; 5];
                if !i2c::read8_n(bus, ft6336::ADDR, ft6336::reg::TD_STATUS, &mut buf) {
                    return Err(ReadFailed);
                }
                let raw = ft6336::decode_raw(&buf);
                let point = Point { x: raw.x, y: raw.y };
                let down = (1..=5).contains(&raw.touches) && raw.event_down();
                Ok((down && crate::board::touch_map::on_panel(point)).then_some(point))
            }
            c => {
                let addr = c.addr();
                let st = i2c::read16(bus, addr, gt911::reg::STATUS).ok_or(ReadFailed)?;
                // Nothing new since the last report was cleared.
                if st & 0x80 == 0 {
                    return Ok(None);
                }
                // A report is ready, with points or none (a lift's). Each is
                // cleared once read, or the controller stops updating; a
                // failed clear is a failed read, and the next poll clears
                // the same report again.
                let count = st & 0x0f;
                let mut buf = [0u8; 4];
                let read = count == 0 || i2c::read16_n(bus, addr, gt911::reg::POINT1, &mut buf);
                let cleared = i2c::write16(bus, addr, gt911::reg::STATUS, 0x00);
                if !(read && cleared) {
                    return Err(ReadFailed);
                }
                Ok((count > 0).then(|| gt911::decode_point(&buf)))
            }
        }
    }

    /// Poll for a touch in panel pixels (`board::touch_map`), for UI code.
    pub fn read_screen(&mut self, bus: &mut Bus<'_>) -> Result<Option<Point>, ReadFailed> {
        Ok(self.read(bus)?.map(crate::board::touch_map::to_screen))
    }
}
