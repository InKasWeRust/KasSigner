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

//! Freeing an I2C bus a device is holding, on either S3 unit.
//!
//! # A held SDA is not seen by esp-hal
//!
//! A transfer cut short (a reset, a glitch) can leave a device mid-byte,
//! holding SDA low. esp-hal 1.2.2 recovers (nine clocks and a stop) only
//! when the controller reports the bus busy or a transfer times out; with
//! the Waveshare's IMU holding SDA mid-read neither happens, and the next
//! read returns `Ok` with another register's value.
//!
//! So `Recovering` looks before every transfer: SDA is high between
//! transfers, and a low SDA is freed by [`clock_free`] through the pins.
//! The units also turn on the controller's arbitration check, which esp-hal
//! leaves off, so a device driving SDA against a transfer ends it with an
//! error instead of data.
//!
//! # Through the pins, not the peripheral
//!
//! Routed through the GPIO matrix, the pins' output and enable are the I2C
//! controller's, not `GPIO_OUT` and `GPIO_ENABLE` (TRM register 6.20,
//! `OUT_SEL` and `OEN_SEL`). `MatrixLines` sets both pins to `OUT_SEL` 256,
//! where those two registers drive them, and puts back what it found when
//! dropped.
//!
//! # The sequence
//!
//! [`clock_free`] is esp-hal's, kept apart from the registers so a host
//! test can run it on a model device: clock until the device lets SDA go,
//! at most nine times (a byte and its acknowledge); then, with SCL high,
//! SDA low and high again, a start and a stop, which end whatever any
//! device was doing.

/// Clock pulses at most: eight bits and an acknowledge.
pub const PULSES: u32 = 9;

/// Half a clock period, in microseconds: 100 kHz, as esp-hal's recovery.
pub const HALF_PERIOD_US: u32 = 5;

/// The two lines, driven open drain: `true` lets a line go, `false` pulls it
/// low.
pub trait Lines {
    /// Whether SDA reads high.
    fn sda_high(&mut self) -> bool;
    fn set_scl(&mut self, high: bool);
    fn set_sda(&mut self, high: bool);
    /// Wait half a clock period.
    fn half(&mut self);
}

/// Clock a held SDA free and end with a start and a stop.
///
/// Called with SCL high, as between transfers. True when SDA is high at the
/// end; false when a device still holds it after [`PULSES`], and then there
/// is no stop, since the line cannot rise.
pub fn clock_free<L: Lines>(lines: &mut L) -> bool {
    lines.set_sda(true);
    lines.set_scl(true);
    lines.half();
    let mut pulses = 0;
    while !lines.sda_high() {
        if pulses == PULSES {
            return false;
        }
        lines.set_scl(false);
        lines.half();
        lines.set_scl(true);
        lines.half();
        pulses += 1;
    }
    // SCL is high and SDA is free: a start, then a stop.
    lines.set_sda(false);
    lines.half();
    lines.set_sda(true);
    lines.half();
    lines.sda_high()
}

/// The GPIO block. TRM, peripheral address map.
const GPIO_BASE: u32 = 0x6000_4000;

/// The highest GPIO on the S3.
pub const MAX_GPIO: u8 = 48;

/// A pin's bit in its bank's `OUT`, `ENABLE` and `IN` registers. GPIO0 to 31
/// are bank 0, 32 to 48 bank 1, each bit the pin's number within its bank.
pub const fn bit(pin: u8) -> u32 {
    assert!(pin <= MAX_GPIO, "no such GPIO");
    1 << (pin % 32)
}

/// `GPIO_OUT_W1TS_REG` or `GPIO_OUT1_W1TS_REG`, TRM 6.14.1.
pub const fn out_set(pin: u8) -> u32 {
    GPIO_BASE + if pin < 32 { 0x0008 } else { 0x0014 }
}

/// `GPIO_OUT_W1TC_REG` or `GPIO_OUT1_W1TC_REG`.
pub const fn out_clear(pin: u8) -> u32 {
    GPIO_BASE + if pin < 32 { 0x000C } else { 0x0018 }
}

/// `GPIO_ENABLE_W1TS_REG` or `GPIO_ENABLE1_W1TS_REG`.
pub const fn enable_set(pin: u8) -> u32 {
    GPIO_BASE + if pin < 32 { 0x0024 } else { 0x0030 }
}

/// `GPIO_ENABLE_REG` or `GPIO_ENABLE1_REG`.
pub const fn enable(pin: u8) -> u32 {
    GPIO_BASE + if pin < 32 { 0x0020 } else { 0x002C }
}

/// `GPIO_IN_REG` or `GPIO_IN1_REG`.
pub const fn input(pin: u8) -> u32 {
    GPIO_BASE + if pin < 32 { 0x003C } else { 0x0040 }
}

/// `GPIO_FUNCn_OUT_SEL_CFG_REG`, register 6.20.
pub const fn out_sel_cfg(pin: u8) -> u32 {
    assert!(pin <= MAX_GPIO, "no such GPIO");
    GPIO_BASE + 0x0554 + 4 * pin as u32
}

/// `OUT_SEL` 256: the pin's output and its enable are its bits in `GPIO_OUT`
/// and `GPIO_ENABLE`, whatever `OEN_SEL` says. Register 6.20.
pub const OUT_SEL_GPIO: u32 = 0x100;

#[cfg(target_arch = "xtensa")]
pub use device::{line_high, MatrixLines, Recovering};

#[cfg(target_arch = "xtensa")]
mod device {
    use embedded_hal::i2c::{ErrorType, I2c, Operation, SevenBitAddress};
    use kassigner_hal::timer::Timer;

    use super::*;
    use crate::systimer::SysTimer;

    fn read(reg: u32) -> u32 {
        // SAFETY: a volatile read of a GPIO register named by the functions
        // above, a fixed and always mapped word.
        unsafe { core::ptr::read_volatile(reg as *const u32) }
    }

    fn write(reg: u32, value: u32) {
        // SAFETY: a volatile write to a GPIO register named above: a set or
        // clear register, which touches only the bits written, or the output
        // select of a pin the caller owns.
        unsafe { core::ptr::write_volatile(reg as *mut u32, value) };
    }

    /// Whether `pin` reads high. Its input buffer is on: esp-hal turns it on
    /// for both I2C pins.
    pub fn line_high(pin: u8) -> bool {
        read(input(pin)) & bit(pin) != 0
    }

    /// Both I2C pins off the matrix, driven open drain (as esp-hal set them)
    /// through `GPIO_OUT` while this lives; a one lets a line go. Each is let
    /// go before it is taken, so taking them moves neither line; dropped,
    /// both go back to the controller.
    pub struct MatrixLines {
        sda: u8,
        scl: u8,
        saved: [u32; 2],
        timer: SysTimer,
    }

    impl MatrixLines {
        pub fn take(sda: u8, scl: u8) -> Self {
            let saved = [read(out_sel_cfg(sda)), read(out_sel_cfg(scl))];
            for pin in [sda, scl] {
                write(out_set(pin), bit(pin));
                // Set by esp-hal already; ignored while the controller has
                // the pin, and what drives it once off the matrix.
                write(enable_set(pin), bit(pin));
                write(out_sel_cfg(pin), OUT_SEL_GPIO);
            }
            Self {
                sda,
                scl,
                saved,
                timer: SysTimer,
            }
        }

        /// Whether both pins' `GPIO_ENABLE` bits are set: what drives them
        /// off the matrix, here and in esp-hal's recovery.
        pub fn enables_set(sda: u8, scl: u8) -> bool {
            read(enable(sda)) & bit(sda) != 0 && read(enable(scl)) & bit(scl) != 0
        }
    }

    impl Lines for MatrixLines {
        fn sda_high(&mut self) -> bool {
            line_high(self.sda)
        }

        fn set_scl(&mut self, high: bool) {
            let reg = if high {
                out_set(self.scl)
            } else {
                out_clear(self.scl)
            };
            write(reg, bit(self.scl));
        }

        fn set_sda(&mut self, high: bool) {
            let reg = if high {
                out_set(self.sda)
            } else {
                out_clear(self.sda)
            };
            write(reg, bit(self.sda));
        }

        fn half(&mut self) {
            self.timer.delay_us(HALF_PERIOD_US);
        }
    }

    impl Drop for MatrixLines {
        fn drop(&mut self) {
            self.set_sda(true);
            self.set_scl(true);
            write(out_sel_cfg(self.sda), self.saved[0]);
            write(out_sel_cfg(self.scl), self.saved[1]);
        }
    }

    /// An I2C bus that frees a held SDA before every transfer.
    pub struct Recovering<I> {
        inner: I,
        sda: u8,
        scl: u8,
        freed: u32,
        stuck: u32,
    }

    impl<I> Recovering<I> {
        /// The bus on these two pins, which must be the ones `inner` drives.
        pub fn new(inner: I, sda: u8, scl: u8) -> Self {
            Self {
                inner,
                sda,
                scl,
                freed: 0,
                stuck: 0,
            }
        }

        /// The bus itself, without the check.
        pub fn inner(&mut self) -> &mut I {
            &mut self.inner
        }

        /// How many times a held SDA was freed, and how many it was not.
        pub fn recoveries(&self) -> (u32, u32) {
            (self.freed, self.stuck)
        }

        /// Free the bus if a device holds SDA. True when the bus is free.
        pub fn free(&mut self) -> bool {
            if line_high(self.sda) {
                return true;
            }
            let free = clock_free(&mut MatrixLines::take(self.sda, self.scl));
            if free {
                self.freed = self.freed.saturating_add(1);
            } else {
                self.stuck = self.stuck.saturating_add(1);
            }
            free
        }
    }

    impl<I: ErrorType> ErrorType for Recovering<I> {
        type Error = I::Error;
    }

    impl<I: I2c> I2c for Recovering<I> {
        fn transaction(
            &mut self,
            address: SevenBitAddress,
            operations: &mut [Operation<'_>],
        ) -> Result<(), Self::Error> {
            // Still held after the pulses: the transfer goes out anyway,
            // and the controller's arbitration check refuses it.
            self.free();
            self.inner.transaction(address, operations)
        }
    }
}
