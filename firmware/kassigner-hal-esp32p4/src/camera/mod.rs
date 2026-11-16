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

//! MIPI-CSI camera stack.
//!
//! ```text
//!   OV5647 --D-PHY--> CSI host --> ISP --> CSI bridge --> dw_gdma --> RAM
//! ```
//!
//! Order of calls, which the API does not check ([`Camera::new`] →
//! [`Camera::power_up`] → [`Camera::configure_sensor`] → [`Camera::start`]
//! → [`Camera::capture`]):
//! the MIPI LDO after any esp-hal PSRAM init, which `.write()`s over it;
//! the sensor configured before the D-PHY leaves reset, since a D-PHY that
//! does not see LP-11 then can latch a bad state for good; streaming last.

pub mod bayer;
pub mod ov5647;
pub mod sensor;

// Register-level blocks, public only with `unstable`, for the self-tests.
#[cfg(feature = "unstable")]
pub mod bridge;
#[cfg(not(feature = "unstable"))]
pub(crate) mod bridge;

#[cfg(feature = "unstable")]
pub mod csi_host;
#[cfg(not(feature = "unstable"))]
pub(crate) mod csi_host;

#[cfg(feature = "unstable")]
pub mod dma;
#[cfg(not(feature = "unstable"))]
pub(crate) mod dma;

#[cfg(feature = "unstable")]
pub mod dphy;
#[cfg(not(feature = "unstable"))]
pub(crate) mod dphy;

#[cfg(feature = "unstable")]
pub mod isp;
#[cfg(not(feature = "unstable"))]
pub(crate) mod isp;

#[cfg(feature = "unstable")]
pub mod mipi_ldo;
#[cfg(not(feature = "unstable"))]
pub(crate) mod mipi_ldo;

pub use isp::RawDepth;
pub use sensor::Ov5647;

use crate::{
    board::i2c::Bus,
    soc::{cache, clocks},
};
use bayer::Raw;
use core::marker::PhantomData;
use esp_hal::{
    delay::Delay,
    time::{Duration, Instant},
};

/// What went wrong, in the order the pipeline would hit it.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// `mipi_ldo::is_enabled()` false after enable.
    LdoNotEnabled,
    /// CSI-2 host version register did not read back.
    CsiHostDead,
    /// ISP version register did not read back.
    IspDead,
    /// dw_gdma component version did not read back.
    DmaDead,
    /// No sensor answered with the OV5647 chip ID.
    SensorNotFound,
    /// Sensor ACKed but the mode table did not fully write.
    SensorModeTable(sensor::Error),
    /// D-PHY test-interface readback returned zero.
    PhyNotResponding,
    /// ISP never saw a frame header.
    NoFrameHeader,
    /// DMA did not complete in time.
    TransferTimeout,
    /// The DMA channel would not stop, even aborted and reset.
    DmaStuck,
    /// The heap gave no room for the frame buffer in PSRAM.
    NoFrameBuffer,
}

/// Capture geometry.
pub struct Config {
    /// Raw frame width in pixels.
    pub width: u32,
    /// Raw frame height in pixels, the sensor mode's.
    pub height: u32,
    /// MIPI data lanes, 1 or 2.
    pub lanes: u32,
    /// Per-lane bit rate.
    pub lane_rate_mbps: u32,
    /// Raw bit depth.
    pub depth: RawDepth,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            width: ov5647::WIDTH,
            height: ov5647::HEIGHT,
            lanes: 2,
            lane_rate_mbps: ov5647::LANE_RATE_MBPS,
            depth: RawDepth::Raw8,
        }
    }
}

/// Lines captured per frame: all 480 of the square mode. A static frame in
/// L2MEM leaves 114 KB for the main stack: ECO2's RAM is
/// 0x4FF40000..0x4FFA0000 (memory.x in `esp-hal-fork/eco2-fix.patch`).
pub const CAPTURE_LINES: u32 = 480;
/// Bytes in one captured frame.
pub const FRAME_BYTES: usize = (ov5647::WIDTH * CAPTURE_LINES) as usize;
/// 64-bit words in one captured frame.
pub const FRAME_WORDS: u32 = (FRAME_BYTES / 8) as u32;

/// Time budgets in milliseconds of real time (see `soc::settle`).
const FRAME_HEADER_TIMEOUT_MS: u64 = 500;
const TRANSFER_TIMEOUT_MS: u64 = 200;
/// Let the AEC converge, about 30 frames: an OV5647's first frames are dark.
const AEC_SETTLE_MS: u32 = 600;

/// DMA destination. 64-byte aligned for the cache-line invalidate.
#[repr(C, align(64))]
pub struct FrameBuffer(pub [u8; FRAME_BYTES]);

impl FrameBuffer {
    /// A buffer filled with a recognisable pattern, for `static` init.
    pub const fn new() -> Self {
        Self([0xA5; FRAME_BYTES])
    }
}

impl Default for FrameBuffer {
    fn default() -> Self {
        Self::new()
    }
}

/// One captured frame, borrowing the camera so it cannot outlive the next
/// capture. `data` is a raw region, not a slice (see `bayer`).
pub struct Frame<'a> {
    /// Raw width in pixels.
    pub width: u32,
    /// Captured height in lines.
    pub height: u32,
    /// Raw Bayer bytes, `width * height` long.
    pub data: Raw,
    /// True if the DMA channel was still enabled at block end, and would
    /// have overrun the buffer without `stop()`. Expected `false` on this
    /// silicon; the hardware test checks it.
    pub dma_was_running: bool,
    _cam: PhantomData<&'a ()>,
}

impl Frame<'_> {
    /// Green plane (min, max, mean).
    pub fn green_stats(&self) -> (u8, u8, u32) {
        bayer::green_stats(self.data, self.width, self.height)
    }
    /// One green-plane pixel.
    pub fn green_at(&self, gx: u32, gy: u32) -> u8 {
        bayer::green_at(self.data, self.width, gx, gy)
    }
    /// Green-plane dimensions.
    pub fn green_dims(&self) -> (u32, u32) {
        bayer::green_dims(self.width, self.height)
    }
}

/// The camera: owns the frame buffer and sequences bring-up. The buffer is
/// a raw pointer, since a `&mut` would tell the compiler nothing else
/// writes it, and the DMA does.
///
/// ```ignore
/// static mut FB: camera::FrameBuffer = camera::FrameBuffer::new();
/// let mut cam = Camera::new(core::ptr::addr_of_mut!(FB));
/// cam.power_up(&delay)?;                     // AFTER psram init, if any
/// cam.configure_sensor(&mut bus, &delay)?;
/// cam.start(&mut bus, &delay)?;
/// let frame = cam.capture()?;
/// ```
pub struct Camera<'fb> {
    fb: *mut FrameBuffer,
    cfg: Config,
    _fb: PhantomData<&'fb mut FrameBuffer>,
}

impl<'fb> Camera<'fb> {
    /// Take the frame buffer for the camera's life. `fb` must outlive
    /// `'fb`, be touched by no Rust code but this `Camera`, and never come
    /// from a `&mut` (`addr_of_mut!` on a `static mut`, or a heap block).
    pub fn new(fb: *mut FrameBuffer) -> Self {
        Self {
            fb,
            cfg: Config::default(),
            _fb: PhantomData,
        }
    }

    fn dst(&self) -> u32 {
        self.fb as u32
    }

    /// Power, clock and check every block, after any PSRAM init; the first
    /// dead one is the error.
    pub fn power_up(&self, delay: &Delay) -> Result<(), Error> {
        mipi_ldo::enable(delay);
        clocks::enable_ref_20m();
        clocks::enable_csi();
        clocks::enable_dphy_cfg(delay);
        clocks::enable_isp(delay);
        clocks::enable_dw_gdma(delay);
        clocks::release_csi_isp_reset(delay);

        // Each block reports an identity constant; zero means unclocked or
        // held in reset.
        if !mipi_ldo::is_enabled() {
            return Err(Error::LdoNotEnabled);
        }
        if !csi_host::alive() {
            return Err(Error::CsiHostDead);
        }
        if !isp::alive() {
            return Err(Error::IspDead);
        }
        if !dma::alive() {
            return Err(Error::DmaDead);
        }
        Ok(())
    }

    /// Reset and load the sensor mode, before `start()`: the D-PHY needs the
    /// sensor driving LP-11 as it leaves reset.
    pub fn configure_sensor(&self, bus: &mut Bus<'_>, delay: &Delay) -> Result<(), Error> {
        if !Ov5647::present(bus) {
            return Err(Error::SensorNotFound);
        }
        Ov5647::configure(bus, delay).map_err(Error::SensorModeTable)
    }

    /// Bring up the receive path and start the sensor streaming.
    pub fn start(&self, bus: &mut Bus<'_>, delay: &Delay) -> Result<(), Error> {
        isp::init_passthrough(self.cfg.width, self.cfg.height, self.cfg.depth);
        dphy::init(self.cfg.lanes, self.cfg.lane_rate_mbps);
        bridge::configure(self.cfg.width, self.cfg.height, delay);
        dma::configure(bridge::MEM_BASE, self.dst(), FRAME_WORDS).map_err(|_| Error::DmaStuck)?;
        isp::clear_status();

        if dphy::phy_read(0x44) == 0 {
            return Err(Error::PhyNotResponding);
        }
        Ov5647::stream_on(bus);
        bridge::enable();
        delay.delay_millis(AEC_SETTLE_MS);
        Ok(())
    }

    /// Capture one frame, blocking until the DMA completes. The buffer is
    /// invalidated before the transfer, during which the CPU does not touch
    /// it, so every read after fills from memory.
    pub fn capture(&mut self) -> Result<Frame<'_>, Error> {
        self.capture_with(&mut || {})
    }

    /// [`Camera::capture`], calling `idle` on each turn of both waits (frame
    /// end, then transfer). The DMA must be armed in the vertical blanking
    /// before line zero: this mode's frame is 984 lines (`0x380E`/`0x380F`),
    /// 480 of picture (`0x380A`/`0x380B`), so an `idle` well under a
    /// millisecond leaves time.
    pub fn capture_with(&mut self, idle: &mut dyn FnMut()) -> Result<Frame<'_>, Error> {
        self.capture_until(idle, &|| false)
    }

    /// [`Camera::capture_with`], also given up once `expired` returns true,
    /// as [`Error::NoFrameHeader`] or [`Error::TransferTimeout`]: for a
    /// caller with its own deadline.
    pub fn capture_until(
        &mut self,
        idle: &mut dyn FnMut(),
        expired: &dyn Fn() -> bool,
    ) -> Result<Frame<'_>, Error> {
        isp::clear_status();
        cache::invalidate(self.dst(), FRAME_BYTES as u32);
        dma::configure(bridge::MEM_BASE, self.dst(), FRAME_WORDS).map_err(|_| Error::DmaStuck)?;

        // Wait for the frame in progress to end, empty the bridge in
        // vertical blanking, and have the DMA waiting for line zero: started
        // mid-line on stale FIFO bytes, every stored line would be shifted.
        let t0 = Instant::now();
        let budget = Duration::from_millis(FRAME_HEADER_TIMEOUT_MS);
        while !isp::frame_received() {
            if t0.elapsed() > budget || expired() {
                return Err(Error::NoFrameHeader);
            }
            idle();
        }
        bridge::flush();
        isp::clear_status();
        dma::start();

        let t0 = Instant::now();
        let budget = Duration::from_millis(TRANSFER_TIMEOUT_MS);
        while !dma::complete() {
            if t0.elapsed() > budget || expired() {
                let _ = dma::stop();
                return Err(Error::TransferTimeout);
            }
            idle();
        }

        // On this silicon the channel stops itself at block end; stopped
        // anyway.
        let dma_was_running = dma::running();
        let _ = dma::stop();

        // SAFETY: `fb` points at FRAME_BYTES valid for `'fb` (`new`'s
        // contract), which the DMA has finished writing; no cache line of it
        // survived the invalidate.
        let data = unsafe { Raw::new(self.fb as *const u8, FRAME_BYTES) };
        Ok(Frame {
            width: self.cfg.width,
            height: CAPTURE_LINES,
            data,
            dma_was_running,
            _cam: PhantomData,
        })
    }

    /// Stop the DMA, the bridge, and put the sensor to sleep.
    pub fn stop(&self, bus: &mut Bus<'_>) {
        let _ = dma::stop();
        bridge::disable();
        Ov5647::stream_off(bus);
    }
}
