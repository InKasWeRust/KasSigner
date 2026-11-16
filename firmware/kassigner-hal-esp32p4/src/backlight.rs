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

//! The backlight's brightness: LEDC channel 0 driving GPIO28, which switches
//! the backlight through a transistor. esp-hal has no LEDC driver for this
//! chip, so this uses the `esp32p4` PAC (ESP32-P4 TRM chapter 58 for the
//! controller, chapter 11 for its clocks and reset).
//!
//! Timer 0 counts to 256 on the 40 MHz crystal divided by 8: a 19.5 kHz
//! PWM, far above anything a panel shows or an ear hears. The output reaches
//! GPIO28 through the GPIO matrix as signal 126. A level is the duty in
//! 256ths, as on the S3 Waveshare (`kassigner-hal-esp32s3`'s `duty_for`).

use esp32p4::{GPIO, HP_SYS_CLKRST, IO_MUX, LEDC};
use kassigner_hal::display::Backlight;

/// The pin the backlight transistor hangs on.
const PIN: usize = 28;
/// `ledc_ls_sig_out_pad_out0`, the channel's output in the GPIO matrix.
const SIGNAL: u16 = 126;
/// The GPIO matrix's plain output: the pin follows its `OUT` bit.
const GPIO_OUT: u16 = 256;
/// IO MUX function 1: the pin through the GPIO matrix.
const GPIO_FUNCTION: u8 = 1;
/// The counter's range: 2^8, so a level is a duty directly.
const DUTY_BITS: u8 = 8;
/// The divider, 8.0: the low eight bits are the fraction.
const DIVIDER: u32 = 8 << 8;
/// The duty register's value is in sixteenths of a count.
const DUTY_SHIFT: u32 = 4;

/// The duty for a level, in the register's units.
pub const fn duty_for(level: Backlight) -> u32 {
    match level {
        Backlight::Off => 0,
        Backlight::Level(n) => (n as u32) << DUTY_SHIFT,
    }
}

/// Drive GPIO28 low through its registers alone, before esp-hal starts: the
/// first thing the binary does. From a reset until then the pin is undriven
/// and the board lights the backlight, over a panel that still holds its
/// last picture, perhaps a SeedQR: a reset clears neither. Only the chip's
/// ROM and the bootloader run before this; nothing of ours can run earlier.
pub fn dark_at_reset() {
    // SAFETY: fixed MMIO blocks, always mapped; nothing else runs yet, and
    // only GPIO28's bits and registers are written.
    let (gpio, io_mux) = unsafe { (&*GPIO::PTR, &*IO_MUX::PTR) };
    let mask = 1u32 << PIN;
    // Low first, so the pin never drives high on the way.
    // SAFETY: one bank-0 pin's mask, within the field's 32 bits.
    gpio.out_w1tc()
        .write(|w| unsafe { w.out_w1tc().bits(mask) });
    // SAFETY: the plain output, a signal number the matrix defines.
    gpio.func_out_sel_cfg(PIN)
        .write(|w| unsafe { w.out_sel().bits(GPIO_OUT) });
    // SAFETY: function 1 is the GPIO matrix on this chip, within 3 bits.
    io_mux
        .gpio(PIN)
        .modify(|_, w| unsafe { w.mcu_sel().bits(GPIO_FUNCTION) });
    // SAFETY: as above, the one pin's mask.
    gpio.enable_w1ts()
        .write(|w| unsafe { w.enable_w1ts().bits(mask) });
}

/// Clock the controller, set up its timer and channel, and hand GPIO28 to
/// it, dark. Once, at bring-up, once the pin is an output.
pub fn init() {
    // SAFETY: fixed MMIO blocks, always mapped. esp-hal, with no LEDC
    // driver, never touches the LEDC bits of HP_SYS_CLKRST; LEDC and
    // GPIO28's output select are this module's.
    let (clk, ledc, gpio) = unsafe { (&*HP_SYS_CLKRST::PTR, &*LEDC::PTR, &*GPIO::PTR) };

    // Bus clock, working clock from the 40 MHz crystal, then a reset.
    clk.soc_clk_ctrl3()
        .modify(|_, w| w.ledc_apb_clk_en().set_bit());
    clk.peri_clk_ctrl22().modify(|_, w| {
        // SAFETY: 0 is XTAL_40M_CLK, a value the field defines.
        unsafe { w.ledc_clk_src_sel().bits(0) };
        w.ledc_clk_en().set_bit()
    });
    clk.hp_rst_en1().modify(|_, w| w.rst_en_ledc().set_bit());
    clk.hp_rst_en1().modify(|_, w| w.rst_en_ledc().clear_bit());

    // The register clock gate, and the crystal for the timers.
    ledc.conf().modify(|_, w| {
        // SAFETY: 2 is XTAL_CLK, a value the field defines.
        unsafe { w.apb_clk_sel().bits(2) };
        w.clk_en().set_bit()
    });

    // Timer 0, written whole: its reset value holds the counter in reset.
    ledc.timer(0).conf().write(|w| {
        // SAFETY: an 8-bit range and a divider of 8.0, within the fields.
        unsafe { w.duty_res().bits(DUTY_BITS).clk_div().bits(DIVIDER) };
        w.pause().clear_bit().rst().clear_bit().para_up().set_bit()
    });

    // Channel 0 on timer 0, its output on, starting dark.
    ledc.ch(0).hpoint().write(|w| {
        // SAFETY: the output rises at count 0, within the field's width.
        unsafe { w.hpoint().bits(0) }
    });
    ledc.ch(0).conf0().write(|w| {
        // SAFETY: 0 is timer 0, a value the field defines.
        unsafe { w.timer_sel().bits(0) };
        w.sig_out_en().set_bit().idle_lv().clear_bit()
    });
    set(Backlight::Off);

    // GPIO28 takes the channel's output; its enable stays the pin's own.
    gpio.func_out_sel_cfg(PIN).write(|w| {
        // SAFETY: a signal number the matrix defines, under 256.
        unsafe { w.out_sel().bits(SIGNAL) };
        w.oen_sel().set_bit()
    });
}

/// Set the level. [`init`] must have run.
pub fn set(level: Backlight) {
    // SAFETY: the fixed LEDC block, as in `init`.
    let ch = unsafe { (*LEDC::PTR).ch(0) };
    ch.duty().write(|w| {
        // SAFETY: at most 255 << 4, within the field's 25 bits.
        unsafe { w.duty().bits(duty_for(level)) }
    });
    ch.conf1().write(|w| w.duty_start().set_bit());
    ch.conf0().modify(|_, w| w.para_up().set_bit());
}
