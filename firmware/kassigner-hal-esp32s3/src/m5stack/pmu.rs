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

//! The AXP2101 power manager and the AW9523B I/O expander, on the one I2C
//! bus at the addresses `kassigner_hal::power` and `kassigner_hal::expander`
//! record. Most of what looks like a pin on this board is one of them: the
//! rails are AXP2101 LDOs, and the display, touch, camera and amplifier
//! resets are AW9523B outputs.
//!
//! The power-up sequences are tables, so a test can check them byte for
//! byte. The direction bytes, [`CONFIG_P0`] `0x18` and [`CONFIG_P1`]
//! `0x0C`, make the netlist's four input lines inputs, as M5GFX's CoreS3
//! autodetect does; `P0.4` is `TF_SW`, the card-detect switch, not a camera
//! power-down.
//!
//! [`set_rails`] and [`set_output`] write nothing after a failed read: a
//! value built from it would switch off every other rail, backlight and
//! camera included, or pull every other line of the port low.

use embedded_hal::i2c::I2c;
use kassigner_hal::timer::Timer;

/// AXP2101 I2C address.
pub const AXP2101: u8 = kassigner_hal::power::ADDRESS;
/// AW9523B I2C address.
pub const AW9523B: u8 = kassigner_hal::expander::ADDRESS;

// ── AXP2101 registers ───────────────────────────────────────────────────────

/// `LDO_ONOFF_CTRL0`: one enable bit per LDO rail.
pub const REG_LDO_EN: u8 = 0x90;
/// ALDO1 voltage.
const REG_ALDO1_V: u8 = 0x92;
/// ALDO2 voltage.
const REG_ALDO2_V: u8 = 0x93;
/// ALDO3 voltage.
const REG_ALDO3_V: u8 = 0x94;
/// ALDO4 voltage.
const REG_ALDO4_V: u8 = 0x95;
/// BLDO1 voltage.
const REG_BLDO1_V: u8 = 0x96;
/// BLDO2 voltage.
const REG_BLDO2_V: u8 = 0x97;
/// DLDO1 voltage, which on this board is the backlight.
pub const REG_DLDO1_V: u8 = 0x99;
/// Power key timing. `0x00` is hold one second, power off at four.
const REG_PWRKEY: u8 = 0x27;
/// Charge LED behaviour.
const REG_CHGLED: u8 = 0x69;
/// PMU common configuration.
const REG_COMMON: u8 = 0x10;
/// ADC channel enable, which the battery reading needs.
const REG_ADC_EN: u8 = 0x30;

// ── Rail enable bits in `REG_LDO_EN` ────────────────────────────────────────

/// ALDO1, the amplifier's 1.8 V.
pub const ALDO1: u8 = 1 << 0;
/// ALDO2, the codec's 3.3 V.
pub const ALDO2: u8 = 1 << 1;
/// ALDO3, the camera's 3.3 V and its oscillator.
pub const ALDO3: u8 = 1 << 2;
/// ALDO4, the card slot.
pub const ALDO4: u8 = 1 << 3;
/// BLDO1, the camera sensor's analogue supply.
pub const BLDO1: u8 = 1 << 4;
/// BLDO2, the camera connector's `DVDD` (not a GC0308 supply).
pub const BLDO2: u8 = 1 << 5;
/// DLDO1, the backlight.
pub const DLDO1: u8 = 1 << 7;

/// Every rail on once the unit is up: `0xBF`, all but bit 6. The boot
/// sequence turns on all but the backlight, which comes on once the panel
/// is black: the panel keeps its last picture through a reset.
pub const BOOT_RAILS: u8 = DLDO1 | BLDO2 | BLDO1 | ALDO4 | ALDO3 | ALDO2 | ALDO1;

/// The camera's three rails, switched in one write: ALDO3, which feeds the
/// sensor and its clock oscillator, and BLDO1 and BLDO2, the camera
/// connector's other two.
pub const CAMERA: u8 = ALDO3 | BLDO1 | BLDO2;
/// The card slot's rail.
pub const SD_CARD: u8 = ALDO4;
/// The backlight's rail.
pub const BACKLIGHT: u8 = DLDO1;

/// The enable bit for a rail, by the name `kassigner_hal::power` uses;
/// `None` for the DC-DC converters, which have their own register and are
/// never switched here.
pub fn rail_bit(name: &str) -> Option<u8> {
    match name {
        "ALDO1" => Some(ALDO1),
        "ALDO2" => Some(ALDO2),
        "ALDO3" => Some(ALDO3),
        "ALDO4" => Some(ALDO4),
        "BLDO1" => Some(BLDO1),
        "BLDO2" => Some(BLDO2),
        "DLDO1" => Some(DLDO1),
        _ => None,
    }
}

/// An LDO voltage code: 500 mV plus 100 mV a step.
pub const fn ldo_code(millivolts: u16) -> u8 {
    ((millivolts - 500) / 100) as u8
}

// ── AW9523B registers ───────────────────────────────────────────────────────

/// Input levels of port 0. Reading it also clears the expander's interrupt.
const AW_INPUT_P0: u8 = 0x00;
/// Output latch of port 0.
const AW_OUTPUT_P0: u8 = 0x02;
/// Output latch of port 1.
const AW_OUTPUT_P1: u8 = 0x03;
/// Direction of port 0. A set bit is an input.
const AW_CONFIG_P0: u8 = 0x04;
/// Direction of port 1.
const AW_CONFIG_P1: u8 = 0x05;
/// Chip ID.
const AW_ID: u8 = 0x10;
/// Global control. Bit 4 puts port 0 in push-pull.
const AW_GCR: u8 = 0x11;
/// LED or GPIO mode for port 0. A set bit is GPIO.
const AW_LEDMODE_P0: u8 = 0x12;
/// LED or GPIO mode for port 1.
const AW_LEDMODE_P1: u8 = 0x13;
/// Software reset.
const AW_RESET: u8 = 0x7F;

/// What the chip ID register holds; M5GFX checks for it too.
pub const EXPANDER_ID: u8 = 0x23;

/// Port 0 in push-pull. Open drain is the reset default, and in it `AW_RST`
/// does not drive high reliably.
pub const GCR_P0_PUSH_PULL: u8 = 0x10;

/// Port 0 directions: `ES_INT` and `TF_SW` are inputs.
pub const CONFIG_P0: u8 = ES_INT.mask() | TF_SW.mask();
/// Port 1 directions: `TOUCH_INT` and `AW_INT` are inputs.
pub const CONFIG_P1: u8 = TOUCH_INT.mask() | AW_INT.mask();

/// One expander line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signal {
    /// Port, 0 or 1.
    pub port: u8,
    /// Bit within the port.
    pub bit: u8,
    /// The net, as `kassigner_hal::expander` names it.
    pub net: &'static str,
}

impl Signal {
    const fn new(port: u8, bit: u8, net: &'static str) -> Self {
        Self { port, bit, net }
    }

    /// The line's bit within its port's registers.
    pub const fn mask(&self) -> u8 {
        1 << self.bit
    }
}

/// Touch controller reset, active low.
pub const TOUCH_RST: Signal = Signal::new(0, 0, "TOUCH_RST");
/// Amplifier reset, active low.
pub const AW_RST: Signal = Signal::new(0, 2, "AW_RST");
/// Codec interrupt, an input.
pub const ES_INT: Signal = Signal::new(0, 3, "ES_INT");
/// Card-detect switch, an input with a 10K pull-up. Low when a card is fitted.
pub const TF_SW: Signal = Signal::new(0, 4, "TF_SW");
/// Camera reset, active low.
pub const CAM_RST: Signal = Signal::new(1, 0, "CAM_RST");
/// Display reset, active low.
pub const LCD_RST: Signal = Signal::new(1, 1, "LCD_RST");
/// Touch interrupt, an input.
pub const TOUCH_INT: Signal = Signal::new(1, 2, "TOUCH_INT");
/// Amplifier interrupt, an input.
pub const AW_INT: Signal = Signal::new(1, 3, "AW_INT");
/// Boost converter enable for the amplifier's supply.
pub const BOOST_EN: Signal = Signal::new(1, 7, "BOOST_EN");

// ── Sequences ───────────────────────────────────────────────────────────────

/// One step of a power-up sequence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// Write `val` to `reg`.
    Write { reg: u8, val: u8 },
    /// Wait, in milliseconds.
    Wait(u32),
}

/// The AXP2101 at boot: voltages first, then the enable register written
/// whole, the backlight left off. Every value but BLDO1's and BLDO2's (the
/// camera's) and the enable register's is also M5Unified's for this board.
pub const AXP_SEQUENCE: [Step; 14] = [
    Step::Write {
        reg: REG_DLDO1_V,
        val: ldo_code(3300),
    },
    Step::Write {
        reg: REG_ALDO1_V,
        val: ldo_code(1800),
    },
    Step::Write {
        reg: REG_ALDO2_V,
        val: ldo_code(3300),
    },
    Step::Write {
        reg: REG_BLDO1_V,
        val: ldo_code(2800),
    },
    Step::Write {
        reg: REG_BLDO2_V,
        val: ldo_code(1500),
    },
    Step::Write {
        reg: REG_ALDO3_V,
        val: ldo_code(3300),
    },
    Step::Write {
        reg: REG_ALDO4_V,
        val: ldo_code(3300),
    },
    Step::Write {
        reg: REG_PWRKEY,
        val: 0x00,
    },
    Step::Write {
        reg: REG_CHGLED,
        val: 0x11,
    },
    Step::Write {
        reg: REG_COMMON,
        val: 0x30,
    },
    Step::Write {
        reg: REG_ADC_EN,
        val: 0x0F,
    },
    Step::Wait(10),
    Step::Write {
        reg: REG_LDO_EN,
        val: BOOT_RAILS & !BACKLIGHT,
    },
    // Rails settling.
    Step::Wait(50),
];

/// The AW9523B at boot. The amplifier needs its boost supply stable before
/// its reset is released, so port 1, carrying `BOOST_EN`, comes up before
/// port 0.
pub const AW_SEQUENCE: [Step; 17] = [
    Step::Write {
        reg: AW_RESET,
        val: 0x00,
    },
    Step::Wait(20),
    Step::Write {
        reg: AW_GCR,
        val: GCR_P0_PUSH_PULL,
    },
    Step::Write {
        reg: AW_LEDMODE_P1,
        val: 0xFF,
    },
    Step::Write {
        reg: AW_CONFIG_P1,
        val: CONFIG_P1,
    },
    Step::Write {
        reg: AW_LEDMODE_P0,
        val: 0xFF,
    },
    Step::Write {
        reg: AW_CONFIG_P0,
        val: CONFIG_P0,
    },
    // Every port 1 output low: display, camera and boost held.
    Step::Write {
        reg: AW_OUTPUT_P1,
        val: 0x00,
    },
    Step::Wait(20),
    // Display out of reset and the boost on.
    Step::Write {
        reg: AW_OUTPUT_P1,
        val: LCD_RST.mask() | BOOST_EN.mask(),
    },
    Step::Wait(50),
    // All of port 1 high, the camera's reset among them, and the lines the
    // netlist leaves unresolved too.
    Step::Write {
        reg: AW_OUTPUT_P1,
        val: 0xFF,
    },
    Step::Wait(10),
    // Touch and amplifier held in reset.
    Step::Write {
        reg: AW_OUTPUT_P0,
        val: 0x00,
    },
    Step::Wait(20),
    // Both released. The amplifier reaches standby, where it answers on I2C,
    // inside the wait that follows.
    Step::Write {
        reg: AW_OUTPUT_P0,
        val: TOUCH_RST.mask() | AW_RST.mask(),
    },
    Step::Wait(120),
];

/// Which part failed during a power-up sequence, and at which register.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InitError {
    /// The AXP2101 did not acknowledge a write.
    Axp2101 { reg: u8 },
    /// The AW9523B did not acknowledge a write.
    Aw9523b { reg: u8 },
}

/// Run a sequence against one device. Stops at the first write that fails
/// and returns its register, so a caller knows how far the part got.
fn run<I: I2c, T: Timer + ?Sized>(
    i2c: &mut I,
    timer: &mut T,
    addr: u8,
    steps: &[Step],
) -> Result<(), u8> {
    for step in steps {
        match *step {
            Step::Write { reg, val } => i2c.write(addr, &[reg, val]).map_err(|_| reg)?,
            Step::Wait(ms) => timer.delay_ms(ms),
        }
    }
    Ok(())
}

/// Tries of the PMU's first write before boot gives up on it.
///
/// On one cold boot in three (measured; never on a warm reboot) the AXP2101
/// refuses the first write: it may still be powering up alongside the
/// processor it powers, or the new bus may glitch. Asking again fixes both;
/// fifty tries 10 ms apart is half a second.
const FIRST_WRITE_TRIES: u32 = 50;
/// Between tries of the first write.
const FIRST_WRITE_EVERY_MS: u32 = 10;

/// Bring the rails up. Call before anything else on the bus is addressed.
///
/// A refusal of the **first** write is retried (`FIRST_WRITE_TRIES`); every
/// write is idempotent, so starting over is safe. A later refusal is
/// reported at once.
///
/// # Errors
///
/// `Axp2101` with the first register that was not acknowledged.
pub fn init_axp2101<I: I2c, T: Timer + ?Sized>(
    i2c: &mut I,
    timer: &mut T,
) -> Result<(), InitError> {
    // The table writes this register once, so a refusal naming it is a
    // refusal at the first step.
    let first = match AXP_SEQUENCE.first() {
        Some(Step::Write { reg, .. }) => Some(*reg),
        _ => None,
    };
    let mut tries = 1;
    loop {
        match run(i2c, timer, AXP2101, &AXP_SEQUENCE) {
            Ok(()) => return Ok(()),
            Err(reg) if Some(reg) == first && tries < FIRST_WRITE_TRIES => {
                tries += 1;
                timer.delay_ms(FIRST_WRITE_EVERY_MS);
            }
            Err(reg) => return Err(InitError::Axp2101 { reg }),
        }
    }
}

/// Configure the expander and release the resets it holds.
///
/// Call after [`init_axp2101`]: the expander is held in reset by the PMU's
/// power-good line until the rails are up.
///
/// # Errors
///
/// `Aw9523b` with the first register that was not acknowledged.
pub fn init_aw9523b<I: I2c, T: Timer + ?Sized>(
    i2c: &mut I,
    timer: &mut T,
) -> Result<(), InitError> {
    run(i2c, timer, AW9523B, &AW_SEQUENCE).map_err(|reg| InitError::Aw9523b { reg })
}

// ── Register access ─────────────────────────────────────────────────────────

/// Read one register.
pub(crate) fn read_reg<I: I2c>(i2c: &mut I, addr: u8, reg: u8) -> Result<u8, I::Error> {
    let mut buf = [0u8; 1];
    i2c.write_read(addr, &[reg], &mut buf)?;
    Ok(buf[0])
}

/// Write one register.
pub(crate) fn write_reg<I: I2c>(i2c: &mut I, addr: u8, reg: u8, val: u8) -> Result<(), I::Error> {
    i2c.write(addr, &[reg, val])
}

/// Which rails are on: the raw `REG_LDO_EN` byte.
///
/// # Errors
///
/// The bus error.
pub fn rails<I: I2c>(i2c: &mut I) -> Result<u8, I::Error> {
    read_reg(i2c, AXP2101, REG_LDO_EN)
}

/// Switch the rails in `mask` on or off, leaving the others as they are.
///
/// Read-modify-write: no write after a failed read, or when the rails are
/// already as asked.
///
/// # Errors
///
/// The bus error.
pub fn set_rails<I: I2c>(i2c: &mut I, mask: u8, on: bool) -> Result<(), I::Error> {
    let current = rails(i2c)?;
    let next = if on { current | mask } else { current & !mask };
    if next != current {
        write_reg(i2c, AXP2101, REG_LDO_EN, next)?;
    }
    Ok(())
}

/// Drive an expander output high or low, leaving the rest of its port alone.
///
/// Read-modify-write of the port's output latch: no write after a failed
/// read.
///
/// # Errors
///
/// The bus error.
pub fn set_output<I: I2c>(i2c: &mut I, signal: Signal, high: bool) -> Result<(), I::Error> {
    let reg = AW_OUTPUT_P0 + signal.port;
    let current = read_reg(i2c, AW9523B, reg)?;
    let next = if high {
        current | signal.mask()
    } else {
        current & !signal.mask()
    };
    write_reg(i2c, AW9523B, reg, next)
}

/// The level on an expander line: `true` is high.
///
/// Meaningful for the inputs: `TF_SW` reads low with a card fitted and high
/// without (measured on the unit).
///
/// # Errors
///
/// The bus error.
pub fn input<I: I2c>(i2c: &mut I, signal: Signal) -> Result<bool, I::Error> {
    let v = read_reg(i2c, AW9523B, AW_INPUT_P0 + signal.port)?;
    Ok(v & signal.mask() != 0)
}

/// The expander's chip ID. [`EXPANDER_ID`] on a working board.
///
/// # Errors
///
/// The bus error.
pub fn expander_id<I: I2c>(i2c: &mut I) -> Result<u8, I::Error> {
    read_reg(i2c, AW9523B, AW_ID)
}

/// Both direction registers, port 0 first. [`CONFIG_P0`] and [`CONFIG_P1`]
/// after [`init_aw9523b`].
///
/// # Errors
///
/// The bus error.
pub fn directions<I: I2c>(i2c: &mut I) -> Result<(u8, u8), I::Error> {
    let p0 = read_reg(i2c, AW9523B, AW_CONFIG_P0)?;
    let p1 = read_reg(i2c, AW9523B, AW_CONFIG_P1)?;
    Ok((p0, p1))
}
