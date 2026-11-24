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

//! esp-hal's DVP driver behind [`Capture`], built by the unit's bring-up.
//! Device only: it names esp-hal's types.
//!
//! The driver moves the camera and its buffer into a transfer and gives them
//! back when it ends, so this holds one or the other.
//!
//! With a second buffer it captures ping-pong: when a frame lands, the next
//! capture starts at once into the other buffer while the landed one is
//! handed out. With one, each capture waits for the sensor's next frame,
//! rounding every scan pass up to whole frame times of about 66 ms. The
//! frame handed out is not written until the next one is asked for.

use core::sync::atomic::{AtomicUsize, Ordering};

use esp_hal::dma::DmaRxBuf;
use esp_hal::lcd_cam::cam::{Camera as DvpCamera, CameraTransfer};

use super::camera::{Capture, LCD_CAM_CAM_CTRL1};

/// The capture's two buffers, by place and length, as [`EspDvp::new`] and
/// [`EspDvp::with_spare`] were given them, for a panic to clear: a panic
/// cannot reach the driver that holds them. Zero for a buffer not given.
static HELD_AT: [AtomicUsize; 2] = [AtomicUsize::new(0), AtomicUsize::new(0)];
static HELD_LEN: [AtomicUsize; 2] = [AtomicUsize::new(0), AtomicUsize::new(0)];

/// Note where `buf` is, in `slot`.
fn hold(slot: usize, buf: &mut DmaRxBuf) {
    let bytes = buf.as_mut_slice();
    HELD_LEN[slot].store(bytes.len(), Ordering::Release);
    HELD_AT[slot].store(bytes.as_mut_ptr().expose_provenance(), Ordering::Release);
}

/// The two buffers, by place and length, for the panic probe to look in;
/// a buffer not given is at zero.
#[cfg(feature = "panic-probe")]
pub(crate) fn probe_spans() -> [(usize, usize); 2] {
    [0, 1].map(|i| {
        (
            HELD_AT[i].load(Ordering::Acquire),
            HELD_LEN[i].load(Ordering::Acquire),
        )
    })
}

/// `LCD_CAM_CAM_START`, bit 29 of `CAM_CTRL1`: the capture runs while set.
const CAM_START: u32 = 1 << 29;
/// `GDMA_IN_LINK_CH0_REG`: the receive channel the unit gives the camera,
/// `DMA_CH0`, which the Waveshare's `cam_dma` stops the same way.
const GDMA_IN_LINK_CH0: u32 = 0x6003_F020;
/// `GDMA_INLINK_STOP_CH0`, bit 21: stop the channel's descriptor engine.
const INLINK_STOP: u32 = 1 << 21;
/// `GDMA_INLINK_PARK_CH0`, bit 24: the engine is idle.
const INLINK_PARK: u32 = 1 << 24;
/// Reads of `IN_LINK` the panic's clear makes at most, waiting for the
/// engine to park: the Waveshare's bound.
const PARK_READS: u32 = 10_000;

/// [`Capture::clear`] for a panic, which cannot reach the driver: through
/// the registers, stop the capture and zero both buffers, writing the PSRAM
/// one's zeros back. Run by the unit's `quiesce` with the other core parked.
///
/// The ping-pong capture keeps a frame in flight while the camera is on, so
/// at a panic the engine may still be writing and both buffers hold the
/// last frames, perhaps a SeedQR's picture. The engine is stopped first,
/// with a bounded wait to park; the buffers are zeroed after, parked or
/// not, so a late burst lands among zeros.
///
/// Does nothing until [`EspDvp::new`] has noted a buffer: before that the
/// camera is not set up, and its peripheral may not be clocked.
pub fn clear_for_panic() {
    let held = [0, 1].map(|i| {
        (
            HELD_AT[i].load(Ordering::Acquire),
            HELD_LEN[i].load(Ordering::Acquire),
        )
    });
    if held.iter().all(|&(at, _)| at == 0) {
        return;
    }
    // SAFETY: read-modify-writes of `CAM_CTRL1` and `IN_LINK` at the
    // manual's addresses, clearing `CAM_START` and setting `INLINK_STOP`.
    // Their peripherals are clocked: the camera was set up before a buffer
    // was noted. The driver that owns them never runs again: the unit is
    // halting.
    unsafe {
        let ctrl1 = core::ptr::read_volatile(LCD_CAM_CAM_CTRL1 as *const u32);
        core::ptr::write_volatile(LCD_CAM_CAM_CTRL1 as *mut u32, ctrl1 & !CAM_START);
        let link = core::ptr::read_volatile(GDMA_IN_LINK_CH0 as *const u32);
        core::ptr::write_volatile(GDMA_IN_LINK_CH0 as *mut u32, link | INLINK_STOP);
    }
    for _ in 0..PARK_READS {
        // SAFETY: a read of `IN_LINK`, which has no side effect.
        let link = unsafe { core::ptr::read_volatile(GDMA_IN_LINK_CH0 as *const u32) };
        if link & INLINK_PARK != 0 {
            break;
        }
    }
    for (at, len) in held {
        if at == 0 || len == 0 {
            continue;
        }
        let p = core::ptr::with_exposed_provenance_mut::<u8>(at);
        // SAFETY: `len` bytes at `p`, a buffer given to `EspDvp` for the
        // program's life, the engine stopped above. Whoever held it never
        // runs again: the other core is parked and this one is halting.
        unsafe { crate::stack::clear(p, len) };
        if crate::cache::is_external(p) {
            // SAFETY: the same buffer, in PSRAM by the check above.
            unsafe { crate::cache::write_back(p, len) };
        }
    }
}

/// The camera and its buffer, idle or mid-transfer.
pub struct EspDvp {
    idle: Option<(DvpCamera<'static>, DmaRxBuf)>,
    busy: Option<CameraTransfer<'static, DmaRxBuf>>,
    /// The other buffer, outside any transfer: free, or holding the frame
    /// last handed out while the next one is captured into its partner.
    spare: Option<DmaRxBuf>,
    /// Frames whose DMA reported an error, none of them lent.
    dma_errors: u32,
}

impl EspDvp {
    /// A capture over a configured camera and its receive buffer.
    pub fn new(camera: DvpCamera<'static>, mut buffer: DmaRxBuf) -> Self {
        hold(0, &mut buffer);
        Self {
            idle: Some((camera, buffer)),
            busy: None,
            spare: None,
            dma_errors: 0,
        }
    }

    /// Capture ping-pong, with `spare` as the second buffer.
    pub fn with_spare(mut self, mut spare: DmaRxBuf) -> Self {
        hold(1, &mut spare);
        self.spare = Some(spare);
        self
    }

    /// Frames whose DMA reported an error so far.
    pub const fn dma_errors(&self) -> u32 {
        self.dma_errors
    }
}

impl Capture for EspDvp {
    fn start(&mut self) -> bool {
        if self.busy.is_some() {
            return true;
        }
        let Some((cam, buf)) = self.idle.take() else {
            return false;
        };
        match cam.receive(buf) {
            Ok(transfer) => {
                self.busy = Some(transfer);
                true
            }
            Err((_, cam, buf)) => {
                self.idle = Some((cam, buf));
                false
            }
        }
    }

    fn is_done(&self) -> bool {
        self.busy.as_ref().is_some_and(|t| t.is_done())
    }

    fn abort(&mut self) {
        if let Some(transfer) = self.busy.take() {
            self.idle = Some(transfer.stop());
        }
    }

    fn clear(&mut self) {
        // A frame in flight is stopped first, as `abort` stops it: the DMA
        // owns the buffer until the transfer gives it back, and a write
        // meanwhile races the engine. `stop` clears the start bit and stops
        // the DMA channel before it hands the buffer back; `wait` would spin
        // until the sensor finished its frame, forever if it stopped clocking.
        self.abort();
        // Both buffers: either may hold the last frame of a SeedQR.
        let held = self.idle.as_mut().map(|(_, buf)| buf);
        for buf in held.into_iter().chain(self.spare.as_mut()) {
            let bytes = buf.as_mut_slice();
            for b in bytes.iter_mut() {
                // SAFETY: a valid reference to a byte this owns, and the
                // transfer is stopped, so the DMA is not writing it.
                unsafe { core::ptr::write_volatile(b, 0) };
            }
            // The second buffer is in PSRAM, and the two trade places as
            // frames land, so either may be the PSRAM one: its zeros sit in
            // the data cache until written back, and a reset before that
            // leaves the frame in PSRAM.
            if crate::cache::is_external(bytes.as_ptr()) {
                // SAFETY: the buffer's own whole slice, in PSRAM by the check
                // above; the transfer is stopped, so nothing else writes it.
                unsafe { crate::cache::write_back(bytes.as_mut_ptr(), bytes.len()) };
            }
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }

    fn finish(&mut self) -> Option<&[u8]> {
        if let Some(transfer) = self.busy.take() {
            let (result, cam, landed) = transfer.wait();
            if result.is_err() {
                // The engine stopped at a bad descriptor: the buffer may be
                // only partly written, the rest still the frame it held
                // before. It is not lent, as the Waveshare keeps no frame
                // that came up short. The next frame goes into it at once;
                // the spare keeps the frame last lent, which is not lent
                // again.
                self.dma_errors += 1;
                match cam.receive(landed) {
                    Ok(transfer) => self.busy = Some(transfer),
                    Err((_, cam, landed)) => self.idle = Some((cam, landed)),
                }
                return None;
            }
            // The next frame into the other buffer at once, and this one
            // handed out from `spare`. Without a second buffer, or if the
            // start fails, the landed frame stays with the camera.
            match self.spare.take() {
                Some(next) => match cam.receive(next) {
                    Ok(transfer) => {
                        self.busy = Some(transfer);
                        self.spare = Some(landed);
                    }
                    Err((_, cam, next)) => {
                        self.idle = Some((cam, landed));
                        self.spare = Some(next);
                    }
                },
                None => self.idle = Some((cam, landed)),
            }
        }
        if self.busy.is_some() {
            self.spare.as_ref().map(DmaRxBuf::as_slice)
        } else {
            self.idle.as_ref().map(|(_, buf)| buf.as_slice())
        }
    }
}
