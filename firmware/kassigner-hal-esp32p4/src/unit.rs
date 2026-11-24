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

//! The Waveshare ESP32-P4-WIFI6-Touch-LCD-3.5, brought up in one call as
//! the S3 units are: the drivers behind `kassigner-hal`'s traits as
//! `impl Trait`, and [`Checks`], what the bring-up found.
//!
//! Two ECO2 rules set the order after the radio and the ROM check: PSRAM
//! before any LDO is set, since esp-hal's PSRAM driver clobbers every PMU
//! LDO, the MIPI D-PHY supply included; and the D-PHY LDO on
//! (`camera::mipi_ldo`) before the pipeline, since it is off by default on
//! this silicon. The decoder's plane is a static in L2MEM; the camera's
//! frame is in PSRAM (see `cam`).

use core::cell::RefCell;

use esp_hal::delay::Delay;
use esp_hal::peripherals::{Peripherals, DMA_CH0, GPIO10, GPIO12, GPIO13, GPIO9, I2S0, PSRAM};
use esp_hal::system::{CpuControl, Stack};
use kassigner_hal::battery::{self, Reading};
use kassigner_hal::camera::Camera;
use kassigner_hal::decoder::Decoder;
use kassigner_hal::display::{Backlight, Display, Rect};
use kassigner_hal::input::Touch;
use kassigner_hal::or_fail;
use static_cell::StaticCell;

use crate::audio::es8311::{Es8311, Resolution};
use crate::audio::player::{self, Player};
use crate::audio::ring::{self, DmaRing};
use crate::board;
use crate::cam::{P4Camera, PipeError, SharedBus};
use crate::decode_core;
use crate::decoder::{P4Decoder, PLANE_H, PLANE_W};
use crate::drivers::axp2101::common;
use crate::drivers::touch::Controller;
use crate::entropy::{self, HwSource};
use crate::input::P4Touch;
use crate::panel::Panel;
use crate::soc::rom;
use crate::speaker::P4Speaker;
use crate::storage::Card;
use crate::systimer::SysTimer;
use crate::Rng;

/// Why the unit could not be brought up.
#[derive(Clone, Copy, Debug)]
pub enum Error {
    /// The bus is already up: `bring_up` was called twice.
    AlreadyUp,
    /// The camera pipeline refused; the pipeline says which block.
    Camera(PipeError),
    /// The decoder was already made.
    Decoder,
    /// The entropy source would not enable, or the generator would not seed.
    Entropy,
    /// The external RAM's driver found no chip (the heap would be empty),
    /// or the boot's clear did not cover it all (the heap would hold the
    /// last run's bytes).
    Psram,
    /// The peripheral whose driver refused its set-up in `board::init`.
    Peripheral(&'static str),
    /// The chip's ROM is not the one this build was made for: the build
    /// links ECO2's ROM table, keeps esp-hal's CLIC workaround off and
    /// lowers the RAM ceiling for ECO2.
    Silicon {
        /// The version word the ROM reports.
        rom_eco: u32,
    },
}

/// A bring-up that failed, [`kassigner_hal::unit::Failed`] with this
/// board's [`Error`]: the panel comes back lit when it was up.
pub type Failed<L> = kassigner_hal::unit::Failed<Error, L>;

/// What the bring-up found out.
#[derive(Clone, Copy, Debug)]
pub struct Checks {
    /// Core 1 runs the decode worker; without it `submit` is busy forever.
    pub core1: bool,
    /// Which touch controller answered, if any.
    pub touch: Option<Controller>,
    /// Whether the generator seeded and passed its start-up health tests.
    pub rng: bool,
    /// Whether three calls through ROM routines that moved in the ECO2
    /// table came back right: the linked table is this ROM's.
    pub rom_table: bool,
    /// Whether the pin that holds the ESP32-C6 (the radio) powered down
    /// reads back low: what the P4 drives, not what the C6 does.
    pub radio_off: bool,
    /// The brown-out detector as the bootloader left it: said at boot, its
    /// analog reset part of the verdict.
    pub brownout: crate::brownout::State,
    /// Whether the codec set up and the I2S stream is ready to play.
    pub speaker: bool,
}

/// The unit's drivers.
pub struct Unit<L, C, D, T> {
    /// The panel.
    pub lcd: L,
    /// The camera.
    pub cam: C,
    /// The decoder.
    pub dec: D,
    /// The touch controller.
    pub touch: T,
    /// The generator.
    pub rng: Rng,
    /// The clock.
    pub timer: SysTimer,
    /// A delay, for the loop's pauses.
    pub delay: Delay,
    /// The speaker.
    pub speaker: P4Speaker,
    /// The SD host and the card last found in it, or `None` if the host
    /// would not set up: the unit works without a card.
    pub card: Option<Card>,
    bus: &'static SharedBus,
}

impl<L, C, D, T> Unit<L, C, D, T> {
    /// The shared bus, for the PMU beside the sensor and the touch
    /// controller.
    pub fn bus(&self) -> &'static SharedBus {
        self.bus
    }

    /// The cell, through the PMU.
    ///
    /// # Errors
    ///
    /// As [`crate::battery::read`].
    pub fn battery(&self) -> Result<Reading, battery::Error> {
        crate::battery::read(self.bus)
    }

    /// The reset button a power cut or not, as [`board::reset_cuts_power`]
    /// on the shared bus: whether the PMU now reads as asked. False if the
    /// bus was busy or the PMU did not answer; the caller asks again.
    pub fn reset_cuts_power(&self, on: bool) -> bool {
        self.bus
            .try_borrow_mut()
            .ok()
            .and_then(|mut b| board::reset_cuts_power(&mut b, on))
            .is_some_and(|(_, after)| (after & common::PWROK_RESTART != 0) == on)
    }
}

static BUS: StaticCell<SharedBus> = StaticCell::new();

/// Core 1's stack, 24 KB, for `rqrr` on the [`PLANE_W`] by [`PLANE_H`]
/// plane; the guard esp-hal places at its bottom says if it is short.
const CORE1_STACK_BYTES: usize = 24 * 1024;
static mut APP_CORE_STACK: Stack<CORE1_STACK_BYTES> = Stack::new();

/// The backlight level the unit comes up at: 40%, as on the M5; full is too
/// bright.
pub const DEFAULT_BRIGHTNESS: u8 = 102;

/// What a panic stops besides the stacks, for `stack::wipe_and_halt` (both
/// stacks cleared, core 1 parked): the decode worker's plane, payload and
/// scratch; the panel's transfer buffer; the camera's transfer, stopped,
/// and its frame, which may hold a SeedQR's picture mid-scan, zeroed; and
/// the backlight, off, through LEDC's registers whatever state the drivers
/// are in. Lit, the panel would show its last screen, perhaps a SeedQR,
/// until the power went.
pub fn quiesce() {
    decode_core::clear_for_panic();
    board::clear_panel_for_panic();
    crate::cam::clear_for_panic();
    crate::backlight::set(Backlight::Off);
}

/// What [`quiesce`] clears besides the decoder's buffers, each named with
/// the bytes set in it, for the panic probe: the panel's transfer buffer,
/// and the camera's frame once the camera is up.
#[cfg(feature = "panic-probe")]
pub fn probe_quiesced(mut each: impl FnMut(&'static str, usize)) {
    let spans = [
        ("panel buffer", board::probe_panel()),
        ("camera frame", crate::cam::probe_span()),
    ];
    for (name, (at, len)) in spans {
        if at != 0 {
            each(name, crate::stack::set_in(at, at + len));
        }
    }
}

/// Bring the unit up: the radio down, then the ROM checked, before anything
/// else (`esp_hal::init` already ran on the build's ECO2 assumptions; this
/// is the earliest check there can be).
///
/// `heap` makes the external RAM the allocator and returns the bytes it
/// gave; zero (the RAM not up, or not all cleared) stops with
/// [`Error::Psram`]. `heap` is a function pointer, not an `impl FnOnce`, as
/// on the S3 units: there a generic body's DMA descriptor statics compile in
/// the calling crate, where the Xtensa backend cannot always place them. A
/// closure that captures nothing coerces to it.
///
/// # Errors
///
/// [`Error`] names the part that refused; [`Error::Silicon`] a ROM this
/// build was not made for.
pub fn bring_up(
    p: Peripherals,
    heap: fn(PSRAM<'static>) -> usize,
) -> Result<
    (
        Unit<impl Display, impl Camera, impl Decoder, impl Touch>,
        Checks,
    ),
    Failed<impl Display>,
> {
    // The radio first, so every path out, a halt included, leaves the
    // ESP32-C6 down. A plain GPIO, safe on any ROM.
    let radio_off = board::hold_c6_down().ok_or(Error::AlreadyUp)?;
    // The backlight dark next: the panel may still hold the last screen.
    board::backlight_dark();

    // The ROM next: every call below leans on the ECO2 table.
    if !rom::is_verified_silicon() {
        return Err(Error::Silicon {
            rom_eco: rom::rom_eco_version(),
        }
        .into());
    }

    // The heap, before `board::init` takes the peripherals whole. That init
    // never touches `p.PSRAM`, so it is stolen here, once: a second call
    // stops at the radio's flag above.
    // SAFETY: the one place this peripheral is taken; `p.PSRAM` is dropped
    // unused inside `board::init`.
    if heap(unsafe { PSRAM::steal() }) == 0 {
        return Err(Error::Psram.into());
    }
    let board::Board {
        bus,
        mut lcd,
        mut touch,
        amp_en,
        delay,
    } = board::init(p).map_err(Error::Peripheral)?;
    let bus: &'static SharedBus = BUS.try_init(RefCell::new(bus)).ok_or(Error::AlreadyUp)?;
    // The PMU measures the cell once its channel is on; without a PMU the
    // battery reads as an error.
    crate::battery::enable(bus);
    // The reset button a plain reset again, so a flasher can reach the unit:
    // a watchdog or panic reset keeps the PMU's setting, and the run before
    // may have left the cut on. The binary turns it on while a secret is
    // held.
    if let Ok(mut b) = bus.try_borrow_mut() {
        let _ = board::reset_cuts_power(&mut b, false);
    }

    // ── Core 1, parked in the decode worker ─────────────────────────────
    //
    // `board::init` took `CPU_CTRL` with the rest; stolen back here once,
    // as the bus cell above guarantees.
    // SAFETY: the one place this peripheral is taken, after the check above.
    let mut cpu_control = CpuControl::new(unsafe { esp_hal::peripherals::CPU_CTRL::steal() });
    // SAFETY: the only reference ever made to this static, and only once.
    let stack = unsafe { &mut *core::ptr::addr_of_mut!(APP_CORE_STACK) };
    // The stack's bottom, for the worker to clear after each job, and both
    // ends for a panic to clear: named before core 1 runs on it.
    let bottom = stack.bottom() as usize;
    crate::stack::core1_started(bottom, stack.top() as usize);
    let core1 = match cpu_control.start_app_core(stack, move || decode_core::core1_main(bottom)) {
        // Parked on drop: kept, as the S3 units keep it.
        Ok(guard) => {
            core::mem::forget(guard);
            true
        }
        Err(_) => false,
    };

    // ── The panel ───────────────────────────────────────────────────────
    //
    // Black before any light: a reset clears neither the panel's memory nor
    // its picture, so the backlight comes on only once it is cleared.
    //
    // A panel that refuses its init or its clear stops the boot dark, as the
    // S3 units stop at their panel's init: lit, it could show the last run's
    // picture, perhaps a SeedQR, and it has nothing to say the refusal on.
    // The panel is kept, not dropped, so its pins hold the backlight off.
    if lcd.init(&delay).is_err() {
        core::mem::forget(lcd);
        return Err(Error::Peripheral("ST7796").into());
    }
    let mut panel = Panel::new(lcd);
    if panel.clear(0x0000).is_err() {
        core::mem::forget(panel);
        return Err(Error::Peripheral("ST7796").into());
    }
    crate::backlight::init();
    let _ = panel.set_backlight(Backlight::Level(DEFAULT_BRIGHTNESS));

    // ── Touch ───────────────────────────────────────────────────────────
    let controller = touch.probe(&mut bus.borrow_mut(), &delay);
    let touch = P4Touch::new(touch, bus);

    // ── The generator ───────────────────────────────────────────────────
    or_fail!(entropy::enable(&delay).map_err(|_| Error::Entropy), panel);
    let rng = or_fail!(
        crate::rng(HwSource::new(Delay::new())).map_err(|_| Error::Entropy),
        panel
    );

    // ── The camera and the decoder ──────────────────────────────────────
    let cam = or_fail!(
        P4Camera::bring_up(bus, Delay::new()).map_err(Error::Camera),
        panel
    );
    let dec = or_fail!(P4Decoder::new().ok_or(Error::Decoder), panel);

    // ── The speaker ─────────────────────────────────────────────────────
    //
    // As the bring-up's audio test: amplifier off, codec set up and
    // unmuted, I2S0 claimed with the codec's MCLK, amplifier on. A codec or
    // I2S that will not set up leaves a silent speaker; the unit still
    // signs. `board::init` dropped these unused; stolen back once, as above.
    // SAFETY: the one place each of these is taken, after that check.
    let (i2s, dma, mclk, bclk, ws, dout) = unsafe {
        (
            I2S0::steal(),
            DMA_CH0::steal(),
            GPIO13::steal(),
            GPIO12::steal(),
            GPIO10::steal(),
            GPIO9::steal(),
        )
    };
    let codec = Es8311::init(
        &mut bus.borrow_mut(),
        board::AUDIO_MCLK_HZ,
        player::SAMPLE_RATE,
        Resolution::Bits16,
        &delay,
    )
    .is_ok();
    let _ = Es8311::set_mute(&mut bus.borrow_mut(), false);
    let player = if codec {
        Player::new(i2s, dma, mclk, bclk, ws, dout).ok()
    } else {
        None
    };
    let mut amp_en = amp_en;
    if player.is_some() {
        amp_en.set_high();
        delay.delay_millis(20);
    }
    let stream = esp_hal::dma_tx_stream_buffer!(player::STREAM_BYTES, player::STREAM_CHUNK);
    // The tick's ring, in internal RAM: played only while a long job runs.
    let (ring_buffer, ring_descriptors) =
        esp_hal::dma_buffers_impl!(ring::RING_BYTES, ring::RING_CHUNK);
    let ring = DmaRing::new(ring_descriptors, ring_buffer).ok();
    let speaker = P4Speaker::new(player, stream, ring, bus, amp_en);
    let sounds = speaker.plays();

    // The SD host, set up once: the card's supply on, nothing sent to it.
    let card = Card::new().ok();

    let (table_passed, table_total) = rom::table_probe();
    Ok((
        Unit {
            lcd: panel,
            cam,
            dec,
            touch,
            rng,
            timer: SysTimer,
            delay,
            speaker,
            card,
            bus,
        },
        Checks {
            core1,
            touch: controller,
            // True by construction: a generator that would not enable or
            // seed fails the bring-up above (`Failed`).
            rng: true,
            rom_table: table_passed == table_total,
            radio_off,
            brownout: crate::brownout::read(),
            speaker: sounds,
        },
    ))
}

/// Transpose the plane onto the panel: the sensor is mounted a quarter turn
/// from the landscape panel. With [`VIEW_FLIP_Y`], a printed code shows
/// upright and the scene slides against a pan as a viewfinder's does
/// (measured on the unit).
pub const VIEW_TRANSPOSE: bool = true;
/// Reverse the panel's x.
pub const VIEW_FLIP_X: bool = false;
/// Reverse the panel's y. The transpose is one mirror and this a second;
/// together they make the rotation that shows the scene the right way round
/// (see `MADCTL_DEFAULT`).
pub const VIEW_FLIP_Y: bool = true;
/// Panel pixels per plane pixel. One shows the whole plane, [`PLANE_W`] by
/// [`PLANE_H`], a panel pixel each.
pub const VIEW_SCALE: usize = 1;

/// Draw a frame's green plane on the panel through the `VIEW_` settings,
/// centred in `area` and cut to it; returns where it went, for the scan's
/// edge. Transposed, it is [`PLANE_H`] wide and [`PLANE_W`] tall. The plane
/// is every other column of every other row of the 480-wide Bayer frame
/// (`camera::bayer`); a frame of any length but [`crate::cam::FORMAT`]'s
/// draws nothing.
pub fn viewfinder<L: Display>(lcd: &mut L, frame: &[u8], area: Rect) -> Rect {
    if frame.len() != crate::cam::FORMAT.frame_bytes() {
        return Rect::new(area.x, area.y, 0, 0);
    }
    let stride = crate::camera::ov5647::WIDTH as usize;
    // Plane pixels shown, then panel pixels drawn: the panel clips the
    // scaled size to itself and the plane is centred inside.
    let (pw, ph): (usize, usize) = if VIEW_TRANSPOSE {
        (PLANE_H, PLANE_W)
    } else {
        (PLANE_W, PLANE_H)
    };
    let w = (pw * VIEW_SCALE)
        .min(usize::from(area.width))
        .min(board::LCD_W as usize);
    let h = (ph * VIEW_SCALE).min(usize::from(area.height));
    let x0 = area.x + ((usize::from(area.width) - w) / 2) as u16;
    let y0 = area.y + ((usize::from(area.height) - h) / 2) as u16;
    let sx_off = (pw - w / VIEW_SCALE) / 2;
    let sy_off = (ph - h / VIEW_SCALE) / 2;
    // The frame is whole lines, the plane's every pixel inside it.
    let green = |gx: usize, gy: usize| -> u16 {
        let v = u16::from(frame[gy * 2 * stride + gx * 2 + 1]);
        ((v >> 3) << 11) | ((v >> 2) << 5) | (v >> 3)
    };
    let mut line = [0u16; board::LCD_W as usize];
    for py in 0..h {
        let sy = sy_off
            + if VIEW_FLIP_Y {
                (h - 1 - py) / VIEW_SCALE
            } else {
                py / VIEW_SCALE
            };
        for (px, out) in line[..w].iter_mut().enumerate() {
            let sx = sx_off
                + if VIEW_FLIP_X {
                    (w - 1 - px) / VIEW_SCALE
                } else {
                    px / VIEW_SCALE
                };
            *out = if VIEW_TRANSPOSE {
                green(sy, sx)
            } else {
                green(sx, sy)
            };
        }
        let _ = lcd.blit(Rect::new(x0, y0 + py as u16, w as u16, 1), &line[..w]);
    }
    Rect::new(x0, y0, w as u16, h as u16)
}

/// For measurement: the plane column with a sharp step on the most rows,
/// where a roll would show, and that count. A whole frame has none.
pub fn seam_column(frame: &[u8]) -> (usize, u32) {
    const SHARP: u8 = 12;
    let stride = crate::camera::ov5647::WIDTH as usize;
    let mut best = (0usize, 0u32);
    for gx in 1..PLANE_W {
        let mut rows = 0u32;
        for gy in 0..PLANE_H {
            let row = gy * 2 * stride;
            let a = frame[row + gx * 2 + 1];
            let b = frame[row + (gx - 1) * 2 + 1];
            if a.abs_diff(b) > SHARP {
                rows += 1;
            }
        }
        if rows > best.1 {
            best = (gx, rows);
        }
    }
    best
}

/// For measurement: one past the last plane column carrying picture, the
/// furthest over three rows (a quarter, half, three quarters down). Fill
/// past the sensor's line is flat, so each row is scanned from the right
/// for the first column differing from the last column by more than `tol`.
pub fn content_edge(frame: &[u8], tol: u8) -> usize {
    let stride = crate::camera::ov5647::WIDTH as usize;
    let mut edge = 0;
    for gy in [PLANE_H / 4, PLANE_H / 2, PLANE_H * 3 / 4] {
        let row = gy * 2 * stride;
        let last = frame[row + (PLANE_W - 1) * 2 + 1];
        for gx in (0..PLANE_W).rev() {
            let v = frame[row + gx * 2 + 1];
            if v.abs_diff(last) > tol {
                edge = edge.max(gx + 1);
                break;
            }
        }
    }
    edge
}
