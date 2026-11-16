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

//! Waveshare ESP32-P4-WIFI6-Touch-LCD-3.5 board definition and init.
//!
//! Pin assignments are checked against both Waveshare's `lcd35_board.h` and
//! the schematic; where they disagree, the schematic wins. Pins esp-hal
//! takes are numbered in [`init`] (the I2S pins in `unit::bring_up`);
//! [`pins`] has the rest.

pub mod i2c;
pub mod pins;

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use static_cell::StaticCell;

use crate::drivers::{
    axp2101::{common, Axp2101},
    st7796::Display,
    touch::Touch,
};
use esp_hal::{
    delay::Delay,
    gpio::{Flex, Level, Output, OutputConfig},
    i2c::master::{Config as I2cConfig, I2c},
    peripherals::{Peripherals, GPIO28, GPIO54},
    spi::master::{Config as SpiConfig, Spi},
    time::Rate,
};

/// Panel is 480x320 landscape, as the board is held (`MADCTL_DEFAULT`).
pub const LCD_W: u16 = 480;
/// Panel is 480x320 landscape, as the board is held (`MADCTL_DEFAULT`).
pub const LCD_H: u16 = 320;

/// Shared I2C bus. Camera SCCB, touch, PMIC and audio codec all sit here.
pub const I2C_HZ: u32 = 100_000;

/// 80 MHz, what the board is rated for. At 40 MHz, sending a full redraw's
/// 307,200 bytes took 84 ms.
pub const LCD_SPI_HZ: u32 = 80_000_000;

/// The panel's DMA buffer: one band of the screen, 16 rows of 480 pixels.
pub const LCD_DMA_BYTES: usize = 16 * 480 * 2;

/// The one MCLK the board provides, on GPIO13, feeds the ES8311. 12.288 MHz
/// divides cleanly to every rate in the codec's coefficient table.
pub const AUDIO_MCLK_HZ: u32 = 12_288_000;

/// I2C addresses on this board.
///
/// Each driver owns its chip's address, a property of the part, not the
/// board. These are re-exports, with a compile-time check that board and
/// driver agree.
pub mod i2c_addr {
    pub use crate::audio::es8311::ADDR as ES8311;
    pub use crate::camera::ov5647::ADDR as OV5647;
    pub use crate::drivers::axp2101::ADDR as AXP2101;
    pub use crate::drivers::touch::ft6336::ADDR as FT6336;
    pub use crate::drivers::touch::gt911::{
        ADDR_BACKUP as GT911_BACKUP, ADDR_PRIMARY as GT911_PRIMARY,
    };

    // What the bus scan on this board reports: an edited driver constant
    // stops the build, not the unit.
    const _: () = assert!(ES8311 == 0x18);
    const _: () = assert!(AXP2101 == 0x34);
    const _: () = assert!(OV5647 == 0x36);
    const _: () = assert!(FT6336 == 0x38);
    const _: () = assert!(GT911_PRIMARY == 0x5D);
    const _: () = assert!(GT911_BACKUP == 0x14);

    /// Every address expected to ACK on a healthy board, with the touch
    /// controller released from reset.
    pub const EXPECTED: [u8; 4] = [ES8311, AXP2101, OV5647, FT6336];
}

/// Touch → display coordinate mapping, the one place it lives: the FT6336
/// reports in its own frame, the panel is oriented by
/// `drivers::st7796::cmds::MADCTL_DEFAULT`, and a confirm tap must land
/// where it is drawn. With these flags (FT6336 at 0x38) the self-test's
/// marker lands under the finger; if a GT911 batch ships mirrored, flip a
/// flag here, and the self-test shows it.
pub mod touch_map {
    use super::{LCD_H, LCD_W};
    use crate::drivers::touch::Point;

    /// Set when the marker appears on the opposite side from the finger.
    /// Measured on the signer: with `true`, left taps read as right.
    pub const MIRROR_X: bool = false;
    /// Set when the marker appears upside down. Measured on the harness:
    /// with `false`, a tap at the top left read (74, 249) and one at the
    /// bottom right (452, 62): x right, y reversed.
    pub const MIRROR_Y: bool = true;
    /// The FT6336 reports in the panel's portrait frame, 320 across and
    /// 480 down; the panel runs landscape, so the axes are exchanged and one
    /// mirror turns the frame as `MADCTL` turns the pixels. The harness
    /// prints every touch; the marker under the finger is the check.
    pub const SWAP_XY: bool = true;

    /// Whether a native point lies on the panel. One past it is a bad
    /// report, not a touch at the edge, and is dropped rather than clamped:
    /// a y past the panel, clamped then mirrored, reads as 0.
    pub fn on_panel(p: Point) -> bool {
        let (x, y) = if SWAP_XY { (p.y, p.x) } else { (p.x, p.y) };
        x < LCD_W && y < LCD_H
    }

    /// Native controller coordinates → panel pixel coordinates, clamped.
    pub fn to_screen(p: Point) -> Point {
        let (mut x, mut y) = if SWAP_XY { (p.y, p.x) } else { (p.x, p.y) };
        x = x.min(LCD_W - 1);
        y = y.min(LCD_H - 1);
        if MIRROR_X {
            x = LCD_W - 1 - x;
        }
        if MIRROR_Y {
            y = LCD_H - 1 - y;
        }
        Point { x, y }
    }
}

/// Everything a binary needs, configured once.
///
/// Not the camera, which is register-level and needs no esp-hal handle
/// beyond the I2C bus, nor the I2S and its DMA channel, which
/// `unit::bring_up` claims.
pub struct Board<'d> {
    /// Shared I2C0 on GPIO7/8.
    pub bus: i2c::Bus<'d>,
    /// ST7796 panel, not yet initialised (`Display::init`), backlight off.
    pub lcd: Display<'d>,
    /// Touch controller, still held in reset. Call `probe()`.
    pub touch: Touch<'d>,
    /// NS4150B amplifier enable on GPIO53, low = off. Left off here.
    pub amp_en: Output<'d>,
    /// Blocking delay.
    pub delay: Delay,
}

/// The panel's transfer buffer, place and length, as [`init`] made it, for
/// a panic to clear without the driver, which holds it. Zero before `init`.
static PANEL_AT: AtomicUsize = AtomicUsize::new(0);
static PANEL_LEN: AtomicUsize = AtomicUsize::new(0);

/// Zero the panel's transfer buffer, for the unit's `quiesce`: it holds the
/// last band sent, perhaps a SeedQR's, which nothing would overwrite after
/// a panic. A transfer the panic cut short may still be reading it and send
/// the panel zeros; the backlight goes off after. Does nothing before
/// [`init`].
pub fn clear_panel_for_panic() {
    let (at, len) = (
        PANEL_AT.load(Ordering::Acquire),
        PANEL_LEN.load(Ordering::Acquire),
    );
    if at == 0 || len == 0 {
        return;
    }
    let p = core::ptr::with_exposed_provenance_mut::<u8>(at);
    // SAFETY: `len` bytes at `p`, the transfer buffer `init` made, a static
    // that lives for the program. The driver it was lent to never runs
    // again: the other core is parked and this one is halting.
    unsafe { crate::stack::clear(p, len) };
}

/// The panel's transfer buffer, by place and length, for the panic probe to
/// look in; at zero before [`init`] has made it.
#[cfg(feature = "panic-probe")]
pub(crate) fn probe_panel() -> (usize, usize) {
    (
        PANEL_AT.load(Ordering::Acquire),
        PANEL_LEN.load(Ordering::Acquire),
    )
}

/// Bring the board up to a known state. Touch is not probed: that needs a
/// delay and the bus, the caller's once this returns (`Touch::probe`).
///
/// # Errors
///
/// The part whose driver refused its set-up: `"I2C0"`, `"SPI2"` or
/// `"LCD DMA buffer"`, which the unit returns as `Error::Peripheral`.
pub fn init(p: Peripherals) -> Result<Board<'static>, &'static str> {
    let delay = Delay::new();

    // ── Shared I2C ──────────────────────────────────────────────────────
    let bus = I2c::new(
        p.I2C0,
        I2cConfig::default().with_frequency(Rate::from_hz(I2C_HZ)),
    )
    .map_err(|_| "I2C0")?
    .with_sda(p.GPIO7)
    .with_scl(p.GPIO8);

    // ── Display: ST7796 over SPI2 ──────────────────────────────────────
    let spi = Spi::new(
        p.SPI2,
        SpiConfig::default()
            .with_frequency(Rate::from_hz(LCD_SPI_HZ))
            .with_mode(esp_hal::spi::Mode::_0),
    )
    .map_err(|_| "SPI2")?
    .with_sck(p.GPIO21)
    .with_mosi(p.GPIO20)
    // Pixels go out by DMA while the CPU draws the next band
    // (`st7796::Display::push_pixels`). On the P4 the SPI peripherals are
    // served by the AXI GDMA, not the AHB one the audio uses; nothing else
    // here takes an AXI channel.
    .with_dma(p.DMA_AXI_CH0);
    let mut lcd_buf = esp_hal::dma_tx_buffer!(LCD_DMA_BYTES).map_err(|_| "LCD DMA buffer")?;
    let band = lcd_buf.as_mut_slice();
    PANEL_LEN.store(band.len(), Ordering::Release);
    PANEL_AT.store(band.as_mut_ptr().expose_provenance(), Ordering::Release);

    let lcd = Display::new(
        spi,
        lcd_buf,
        Output::new(p.GPIO26, Level::Low, OutputConfig::default()), // DC
        Output::new(p.GPIO23, Level::High, OutputConfig::default()), // CS
        Output::new(p.GPIO27, Level::High, OutputConfig::default()), // RST
        // Backlight through Q3 (DMG1012T), high = on; `crate::backlight`
        // dims it through LEDC's registers (esp-hal has no LEDC for P4).
        Output::new(p.GPIO28, Level::Low, OutputConfig::default()), // BL
    );

    // ── Touch: FT6336 (or GT911 on other batches) ──────────────────────
    // GPIO29 TP_RST: R32 (10K) pulls it LOW, so the controller powers up
    //   held in reset and answers nothing on I2C until this goes high.
    // GPIO30 TP_INT: R58 (4.7K) pulls it high. On a GT911 the level at the
    //   moment reset releases selects the I2C address; FT6336 ignores it.
    let touch = Touch::new(
        Output::new(p.GPIO29, Level::Low, OutputConfig::default()),
        Flex::new(p.GPIO30),
    );

    // ── Audio amp enable (codec + I2S claimed separately) ──────────────
    //   GPIO13 MCLK   GPIO12 BCLK   GPIO10 LRCK   GPIO9 DOUT   GPIO11 DIN
    //   GPIO53 -> NS4150B CTRL. Kept LOW until something wants to be heard,
    //   so codec setup noise never reaches the speaker.
    let amp_en = Output::new(p.GPIO53, Level::Low, OutputConfig::default());

    Ok(Board {
        bus,
        lcd,
        touch,
        amp_en,
        delay,
    })
}

/// The backlight's first driver, kept so it is never released.
static BL_DARK: StaticCell<Output<'static>> = StaticCell::new();

/// Drive the backlight's pin, GPIO28, low before the PSRAM clear and the
/// rest of the bring-up. The panel keeps its last picture through a reset of
/// the chip, perhaps a SeedQR, and this keeps it dark until it is black.
///
/// The driver stays in `BL_DARK`, as GPIO54's does: a later esp-hal could
/// release a dropped pin before [`init`] takes it, again low.
pub fn backlight_dark() {
    // SAFETY: run once, from `unit::bring_up` past `hold_c6_down`'s flag and
    // before `init` takes `p.GPIO28`. This driver is never used again;
    // `init`'s own, also low, takes the pin over.
    let gpio = unsafe { GPIO28::steal() };
    let _ = BL_DARK.try_init(Output::new(gpio, Level::Low, OutputConfig::default()));
}

/// Make the reset button a power cut (`on`), or a plain reset again. The
/// button pulls ESP_EN low, and ESP_EN is both the P4's CHIP_PU and the
/// AXP2101's PWROK (pin 29); with the PMU set to restart on PWROK, a press
/// switches every rail off and back on, as the power button does. The panel
/// and its backlight run on 3V3, the PMU's DCDC1, so the panel loses its
/// last picture, perhaps a SeedQR, and the chip's RAM goes with it.
///
/// The CH343 runs on that 3V3 too, and its auto-reset pulls the same line:
/// with the cut on, a flasher's reset takes the USB bridge down with the
/// unit and cannot connect. So it is on only while the unit holds a secret,
/// and off from boot: the cut does not turn it off, as the datasheet resets
/// it only at the PMU's own power-on. REG 10 before and after; `None` if the
/// PMU did not answer.
pub fn reset_cuts_power(bus: &mut i2c::Bus<'_>, on: bool) -> Option<(u8, u8)> {
    // SAFETY: configuration bits only, as `set_common` asks; nothing
    // switches off now. Off-discharge is on by default, and set with the cut
    // so the rails drain in it whatever came before; never cleared.
    unsafe {
        if on {
            Axp2101::set_common(bus, common::PWROK_RESTART | common::OFF_DISCHARGE, true)
        } else {
            Axp2101::set_common(bus, common::PWROK_RESTART, false)
        }
    }
}

static C6_HELD: AtomicBool = AtomicBool::new(false);

/// GPIO54's driver, held low, for as long as the unit runs.
static C6_PIN: StaticCell<Output<'static>> = StaticCell::new();

/// Power the board's ESP32-C6, its Wi-Fi and Bluetooth radio, down and keep
/// it down.
///
/// CHIP_PU is pulled up to 3V3 by R25 (10K, C113 1uF to ground), so the C6
/// runs its own firmware from power-on until this is called. GPIO54 reaches
/// CHIP_PU through R54 (0R): low powers it down, the only control, as its
/// 3V3 is the board's.
///
/// Separate from [`init`] so it comes first, before even the checks that
/// can stop a unit, and a halted unit has its radio off; GPIO54, which
/// [`init`] never touches, is taken by `steal`. Its driver stays in
/// `C6_PIN` until reset: a later esp-hal could release a dropped pin and
/// let R25 pull the C6 back up, and a failed bring-up drops all it made.
///
/// Whether the pin reads back low (what the P4 drives, not what the C6
/// does), or `None` if this already ran.
pub fn hold_c6_down() -> Option<bool> {
    if C6_HELD.swap(true, Ordering::AcqRel) {
        return None;
    }
    // SAFETY: the one place GPIO54 is taken, which the flag above makes
    // once; `init` leaves `p.GPIO54` unused.
    let gpio = unsafe { GPIO54::steal() };
    let pin = Output::new(gpio, Level::Low, OutputConfig::default());
    let low = pin.is_set_low();
    // The flag above makes this the first and only time.
    let _ = C6_PIN.try_init(pin);
    Some(low)
}
