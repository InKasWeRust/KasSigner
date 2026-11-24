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

//! The OV5647 over MIPI-CSI behind `kassigner-hal`'s `Camera`: one 480 by
//! 480 raw Bayer frame in PSRAM (`FB` says why there), handed over past its
//! lead lines, 480 by [`LINES`], one byte a pixel. The decoder (through
//! [`crate::camera::bayer`]) and the viewfinder (`unit`) read its green
//! plane.

use esp_hal::delay::Delay;
use kassigner_hal::camera::{Camera, Error, Format, Power};
use kassigner_hal::timer::Deadline;
use kassigner_hal::tune::{Knob, Tune};

use core::cell::RefCell;

use crate::board::i2c::{self, Bus};
use crate::camera::ov5647::{reg, ADDR};
use crate::camera::{self as pipe, FrameBuffer, FRAME_BYTES};
use crate::systimer::SysTimer;

/// The unit's shared bus: sensor, touch controller and PMU.
pub type SharedBus = RefCell<Bus<'static>>;

/// Bytes the stored frame runs ahead of the sensor's lines, with the
/// capture aligned in vertical blanking. It moves with the line width (488
/// at 800 pixels, 8 at 640, measured), so it is not a FIFO depth;
/// `unit::seam_column` (`p4_unit`) checks it when the mode changes.
pub const LINE_PHASE: usize = 8;

/// Raw lines at the start of each stored frame that repeat the previous
/// frame's last ones: 13 to 16, measured on the unit.
pub const LEAD_LINES: usize = 16;

/// Raw lines handed over: the capture's, less the lead lines and the last,
/// which the line phase pushes [`LINE_PHASE`] bytes past the buffer.
pub const LINES: usize = pipe::CAPTURE_LINES as usize - LEAD_LINES - 1;

/// Where the handed-over frame starts: past the line phase and lead lines.
pub const START: usize = LINE_PHASE + LEAD_LINES * pipe::ov5647::WIDTH as usize;

/// The handed-over frame: 480 by `LINES`, one byte a pixel.
pub const FORMAT: Format = Format::new(pipe::ov5647::WIDTH as u16, LINES as u16, 1);

// The frame handed over is inside the buffer the capture fills.
const _: () = assert!(START + FORMAT.frame_bytes() <= FRAME_BYTES);

/// The frame buffer, 230,400 bytes of PSRAM, allocated at bring-up and
/// never freed. In L2MEM it left signing about 40 KB of main stack; PSRAM
/// at 125 MHz costs no capture, viewfinder or decode time (measured). The
/// capture's invalidate covers the L2 cache, which fronts PSRAM
/// (`soc::cache`); wipes go through the uncached window.
static mut FB: *mut FrameBuffer = core::ptr::null_mut();

/// Where the frame buffer is, in PSRAM's cached window.
fn fb() -> *mut FrameBuffer {
    // SAFETY: written once in `allocate`, before anything reads it, and
    // only read after.
    unsafe { *core::ptr::addr_of!(FB) }
}

/// Take the frame buffer from the heap, 128-byte aligned so a cache sync
/// over it never reaches a neighbour's line, and zero it: PSRAM keeps the
/// last boot's frame, perhaps a SeedQR's, through a reset.
fn allocate() -> Result<(), PipeError> {
    let layout = core::alloc::Layout::from_size_align(FRAME_BYTES, 128)
        .map_err(|_| PipeError::NoFrameBuffer)?;
    // SAFETY: a layout of nonzero size; the block is never freed.
    let p = unsafe { alloc::alloc::alloc(layout) }.cast::<FrameBuffer>();
    if p.is_null() || !crate::psram::CACHED.contains(&(p as usize)) {
        return Err(PipeError::NoFrameBuffer);
    }
    // SAFETY: written once, at bring-up, before anything reads it.
    unsafe { *core::ptr::addr_of_mut!(FB) = p };
    zero();
    Ok(())
}

/// Zero the frame in PSRAM through the uncached window, so the zeros are in
/// PSRAM on return whatever the caches hold, then drop its cached lines,
/// clean since only the DMA and this write it, so no read sees the old
/// bytes.
fn zero() {
    let direct = (fb() as usize + crate::psram::UNCACHED_OFFSET) as *mut u32;
    for i in 0..FRAME_BYTES / 4 {
        // SAFETY: the frame's words through the uncached window; the DMA
        // writes the frame only during a capture, not now.
        unsafe { core::ptr::write_volatile(direct.add(i), 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    crate::soc::cache::invalidate(fb() as u32, FRAME_BYTES as u32);
}

/// Stop the transfer and zero the frame, for a panic; the unit's `quiesce`
/// runs it with the other core parked. Otherwise that core's capture keeps
/// filling the frame, and the last picture, perhaps a SeedQR, stays until
/// the reset after the halt. The DMA is stopped only if its controller
/// answers.
pub fn clear_for_panic() {
    if fb().is_null() {
        return;
    }
    if pipe::dma::alive() {
        let _ = pipe::dma::stop();
    }
    zero();
}

/// The frame's place and length, for the panic probe; zero before bring-up.
#[cfg(feature = "panic-probe")]
pub(crate) fn probe_span() -> (usize, usize) {
    (fb() as usize, FRAME_BYTES)
}

/// The camera as the flow sees it.
pub struct P4Camera {
    pipe: pipe::Camera<'static>,
    bus: &'static SharedBus,
    delay: Delay,
    power: Power,
}

/// Why the camera did not come up.
pub type PipeError = pipe::Error;

impl P4Camera {
    /// Take the frame buffer and bring the pipeline up, the sensor over the
    /// shared bus.
    ///
    /// # Errors
    ///
    /// The pipeline's own, naming the block that refused.
    pub fn bring_up(bus: &'static SharedBus, delay: Delay) -> Result<Self, PipeError> {
        allocate()?;
        // The pipeline captures into the frame from here; the unit is brought
        // up once.
        // SAFETY: `allocate` took the frame from the heap and never frees it,
        // so it outlives the `'static` pipeline, and only raw pointers reach
        // it. `zero`, `raw` and `frame_buffer` touch it between captures, and
        // `clear_for_panic` stops the transfer before it wipes.
        let pipe = unsafe { pipe::Camera::new(fb()) };
        pipe.power_up(&delay)?;
        {
            let mut b = bus.borrow_mut();
            pipe.configure_sensor(&mut b, &delay)?;
            pipe.start(&mut b, &delay)?;
        }
        Ok(Self {
            pipe,
            bus,
            delay,
            power: Power::On,
        })
    }

    /// The raw frame as bytes.
    fn raw() -> &'static [u8] {
        // SAFETY: the frame buffer, which `frame` reads only after its
        // capture's DMA has finished.
        unsafe { core::slice::from_raw_parts(fb().cast::<u8>().cast_const(), FRAME_BYTES) }
    }
}

/// The whole frame buffer, read-only, for the unit test to check the wipe.
///
/// # Safety
///
/// Used only between two captures, and gone before the next capture or
/// `clear`, which write it. A frame [`Camera::frame`] lent may coexist:
/// both only read.
pub unsafe fn frame_buffer() -> &'static [u8] {
    // SAFETY: the DMA writes the buffer only during a capture, and the
    // caller reads it only between captures.
    unsafe { core::slice::from_raw_parts(fb().cast::<u8>().cast_const(), FRAME_BYTES) }
}

impl Camera for P4Camera {
    /// Zero the frame in PSRAM itself (`zero`): PSRAM keeps its contents
    /// through a reset, and download mode is one reset away. Checked on the
    /// unit: every byte zero when read back uncached.
    fn clear(&mut self) {
        zero();
    }

    fn format(&self) -> Format {
        FORMAT
    }

    fn frame(&mut self, deadline: Deadline) -> Result<&[u8], Error> {
        self.frame_idle(deadline, &mut || {})
    }

    /// `idle` runs in both of the pipeline's waits. No capture starts past
    /// `deadline`, and either wait gives up at it with `Timeout`.
    fn frame_idle(&mut self, deadline: Deadline, idle: &mut dyn FnMut()) -> Result<&[u8], Error> {
        if self.power != Power::On {
            return Err(Error::PoweredDown);
        }
        if deadline.expired(&SysTimer) {
            return Err(Error::Timeout);
        }
        // The pipeline's own budgets apply too (FRAME_HEADER_TIMEOUT_MS,
        // TRANSFER_TIMEOUT_MS).
        match self
            .pipe
            .capture_until(idle, &|| deadline.expired(&SysTimer))
        {
            Ok(_) => Ok(&Self::raw()[START..START + FORMAT.frame_bytes()]),
            Err(pipe::Error::NoFrameHeader) | Err(pipe::Error::TransferTimeout) => {
                Err(Error::Timeout)
            }
            Err(_) => Err(Error::Io),
        }
    }

    fn set_power(&mut self, power: Power) -> Result<(), Error> {
        if power == self.power {
            return Ok(());
        }
        match power {
            Power::Off => {
                let standby = self.pipe.stop(&mut self.bus.borrow_mut());
                // Off whatever the sensor answered: the DMA and the bridge
                // are stopped, so nothing it sends reaches memory.
                self.power = power;
                standby.map_err(|_| Error::Io)
            }
            Power::On => {
                // The CSI host, bridge and ISP from reset: restarted from
                // the last stream's state, the bridge came back empty or
                // stalled in three restarts of ten; from reset, fifty of
                // fifty worked.
                crate::soc::clocks::reset_csi_isp(&self.delay);
                self.pipe
                    .start(&mut self.bus.borrow_mut(), &self.delay)
                    .map_err(|_| Error::Io)?;
                self.power = power;
                Ok(())
            }
        }
    }

    fn power(&self) -> Power {
        self.power
    }
}

// ── Tuning ──────────────────────────────────────────────────────────────────

/// What Settings' Camera moves here, in screen order after the exposure
/// switch (OV5647 datasheet v1.0, sections 4.5 to 4.6, tables 7-4 and
/// 7-6): the loop's gain ceiling (`0xF8` in the mode table), stable window
/// edges (`0x58`, `0x50`), flicker bands and centre weight, acting only
/// while the loop runs; then gain and exposure, only while it is off. Raw
/// output has no contrast or sharpness.
///
/// A value wider than a byte is counted in fours; the ceiling steps by 2,
/// so the table's 248 (62) is on its grid. Only a boot restores them; a
/// camera restart keeps them. The screen opens on AGC.
static KNOBS: [Knob; 7] = [
    Knob::new("AGC", 0xFF, 2).in_auto().lead(),
    Knob::new("AEC-H", 0xFF, 4).in_auto(),
    Knob::new("AEC-L", 0xFF, 4).in_auto(),
    Knob::count("BANDS", 4).in_auto(),
    Knob::count("CENTER", 15).in_auto(),
    Knob::new("GAIN", 0xFF, 4).in_manual(),
    Knob::new("EXPO", EXPO_MAX, 4).in_manual(),
];

/// The stable window's edges, each an enter and a leave register written
/// alike.
const AEC_HIGH: [u16; 2] = [0x3A0F, 0x3A1B];
const AEC_LOW: [u16; 2] = [0x3A10, 0x3A1E];
/// The gain ceiling, ten bits: `0x3A18[1:0]` and `0x3A19`.
const GAIN_CEILING: u16 = 0x3A18;
/// The loop's exposure ceiling in flicker bands, `B60 MAX` and `B50 MAX`
/// (table 7-6), both written alike, at least 1. With banding on, as the
/// mode table leaves it, exposure moves in bands of 246 lines
/// (`0x3A0A`/`0x3A0B`) or 295 (`0x3A08`/`0x3A09`); four of 246 fill the
/// frame, the loop's limit with night mode off (AUTO settled at 980 lines,
/// measured), so the knob stops at 4. One band to two doubles the
/// exposure, so with a window narrower than that step the picture pumps:
/// widen AEC-H to AEC-L, or lean on gain. `MAX EXPO 60`/`50` (`0x3A02`,
/// `0x3A14`) do not bound the loop with night mode off.
const MAX_BANDS: [u16; 2] = [0x3A0D, 0x3A0E];
/// Metering weights, two zones of the 4 by 4 to a register (table 4-7):
/// the middle four are the high nibbles of `0x568A`/`0x568C` and the low of
/// `0x568B`/`0x568D`. The rest stay at 1, the default.
const WEIGHTS_MIDDLE: [u16; 4] = [0x568A, 0x568B, 0x568C, 0x568D];
/// This mode's frame length in lines (`0x380E`/`0x380F`); a longer
/// exposure buys nothing.
const VTS: u32 = 984;
/// The exposure knobs' top: four lines a count, four lines under the frame.
const EXPO_MAX: u8 = ((VTS - 4) / 4) as u8;
/// Both of `0x3503`'s manual bits: exposure and gain held.
const MANUAL: u8 = 0x03;

/// The sensor as Settings' Camera moves it, over the shared bus.
pub struct Tuner {
    bus: &'static SharedBus,
}

impl Tuner {
    /// Over the unit's shared bus.
    pub fn new(bus: &'static SharedBus) -> Self {
        Self { bus }
    }

    fn get(&self, r: u16) -> Result<u8, Error> {
        i2c::read16(&mut self.bus.borrow_mut(), ADDR, r).ok_or(Error::Io)
    }

    fn set(&self, regs: &[u16], value: u8) -> Result<(), Error> {
        let mut b = self.bus.borrow_mut();
        for &r in regs {
            if !i2c::write16(&mut b, ADDR, r, value) {
                return Err(Error::Io);
            }
        }
        Ok(())
    }

    /// A register pair, high byte first.
    fn get16(&self, r: u16) -> Result<u32, Error> {
        Ok((u32::from(self.get(r)?) << 8) | u32::from(self.get(r + 1)?))
    }

    /// The exposure in lines: 0x3500's low four bits, then 0x3501 and
    /// 0x3502, in sixteenths of a line.
    fn lines(&self) -> Result<u32, Error> {
        let e2 = u32::from(self.get(reg::EXPOSURE_HI)?);
        let e1 = u32::from(self.get(reg::EXPOSURE_HI + 1)?);
        let e0 = u32::from(self.get(reg::EXPOSURE_HI + 2)?);
        Ok(((e2 & 0x0F) << 12) | (e1 << 4) | (e0 >> 4))
    }

    /// A ten-bit value from a register pair, as a knob: a quarter of it.
    fn quarter10(&self, r: u16) -> Result<u8, Error> {
        Ok(((self.get16(r)? & 0x3FF) / 4) as u8)
    }

    /// A ten-bit value into a register pair, from a knob: four times it.
    fn set10(&self, r: u16, value: u8) -> Result<(), Error> {
        let v = u32::from(value) * 4;
        self.set(&[r], ((v >> 8) & 0x03) as u8)?;
        self.set(&[r + 1], (v & 0xFF) as u8)
    }
}

impl Tune for Tuner {
    fn knobs(&self) -> &'static [Knob] {
        &KNOBS
    }

    fn read(&mut self, out: &mut [u8]) -> Result<(), Error> {
        let top = u32::from(EXPO_MAX);
        // In `KNOBS`' order.
        let values = [
            self.quarter10(GAIN_CEILING)?,
            self.get(AEC_HIGH[0])?,
            self.get(AEC_LOW[0])?,
            self.get(MAX_BANDS[0])? & 0x3F,
            self.get(WEIGHTS_MIDDLE[0])? >> 4,
            self.quarter10(reg::GAIN_HI)?,
            (self.lines()? / 4).min(top) as u8,
        ];
        for (o, v) in out.iter_mut().zip(values) {
            *o = v;
        }
        Ok(())
    }

    /// The window's low edge is held at or under its high one, as on the
    /// Waveshare: the loop converges only while high is at least low.
    fn write(&mut self, knob: usize, value: u8) -> Result<(), Error> {
        match knob {
            1 => {
                self.set(&AEC_HIGH, value)?;
                if self.get(AEC_LOW[0])? > value {
                    self.set(&AEC_LOW, value)?;
                }
                Ok(())
            }
            2 => {
                let high = self.get(AEC_HIGH[0])?;
                self.set(&AEC_LOW, value.min(high))
            }
            0 => self.set10(GAIN_CEILING, value),
            3 => self.set(&MAX_BANDS, value.clamp(1, 0x3F)),
            6 => {
                // Sixteenths of a line, the unit of the sensor's exposure
                // registers.
                let e = (u32::from(value.min(EXPO_MAX)) * 4) << 4;
                self.set(&[reg::EXPOSURE_HI], ((e >> 16) & 0x0F) as u8)?;
                self.set(&[reg::EXPOSURE_HI + 1], ((e >> 8) & 0xFF) as u8)?;
                self.set(&[reg::EXPOSURE_HI + 2], (e & 0xFF) as u8)
            }
            5 => self.set10(reg::GAIN_HI, value),
            4 => {
                let w = value & 0x0F;
                self.set(&[WEIGHTS_MIDDLE[0], WEIGHTS_MIDDLE[2]], (w << 4) | 1)?;
                self.set(&[WEIGHTS_MIDDLE[1], WEIGHTS_MIDDLE[3]], 0x10 | w)
            }
            _ => Err(Error::Io),
        }
    }

    fn auto(&mut self) -> Option<bool> {
        self.get(reg::AEC_MANUAL).ok().map(|v| v & MANUAL == 0)
    }

    fn set_auto(&mut self, on: bool) -> Result<(), Error> {
        self.set(&[reg::AEC_MANUAL], if on { 0x00 } else { MANUAL })
    }
}
