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

//! A DMA buffer the I2S plays round and round for as long as the unit runs,
//! built on esp-hal's public buffer trait.
//!
//! esp-hal's `DmaLoopBuf` holds one descriptor, 4,092 bytes or 21 ms: a
//! 30 ms click plays round it more than once, and a stream started and
//! stopped per sound pops. So four descriptors of 4,092 bytes are chained
//! in a ring, 85 ms, never stopped, and [`super::speaker::M5Speaker`] writes
//! each note into it in place.

use esp_hal::dma::aligned::DmaAlignedMut;
use esp_hal::dma::{BurstConfig, DmaBufError, DmaDescriptor, DmaTxBuffer, Owner, Preparation};

/// The ring: 16,368 bytes, 85 ms of 48 kHz stereo.
pub const RING_BYTES: usize = 4 * RING_CHUNK;
/// One descriptor's share, the most a descriptor can hold rounded to whole
/// frames.
pub const RING_CHUNK: usize = 4092;

/// The buffer and its descriptors, each pointing at the next and the last
/// at the first.
pub struct DmaRing {
    descriptors: DmaAlignedMut<'static, [DmaDescriptor]>,
    buffer: DmaAlignedMut<'static, [u8]>,
}

impl DmaRing {
    /// Chain `descriptors` round `buffer`, an equal share each.
    ///
    /// # Errors
    ///
    /// `InsufficientDescriptors` if there are none, the buffer does not split
    /// equally among them, or a share is over [`RING_CHUNK`].
    pub fn new(
        mut descriptors: DmaAlignedMut<'static, [DmaDescriptor]>,
        mut buffer: DmaAlignedMut<'static, [u8]>,
    ) -> Result<Self, DmaBufError> {
        let n = descriptors.len();
        if n == 0 || !buffer.len().is_multiple_of(n) || buffer.len() / n > RING_CHUNK {
            return Err(DmaBufError::InsufficientDescriptors);
        }
        let chunk = buffer.len() / n;
        let base = descriptors.as_mut_ptr();
        let data = buffer.as_mut_ptr();
        for (i, d) in descriptors.iter_mut().enumerate() {
            d.set_owner(Owner::Dma);
            d.set_suc_eof(false);
            d.set_size(chunk);
            d.set_length(chunk);
            // SAFETY: `i * chunk` is inside the buffer, and `(i + 1) % n` is
            // inside the descriptors: both are offsets into what this owns.
            unsafe {
                d.buffer = data.add(i * chunk);
                d.next = base.add((i + 1) % n);
            }
        }
        Ok(Self {
            descriptors,
            buffer,
        })
    }

    /// The buffer, for the speaker to write into as the DMA reads it.
    pub fn as_mut_ptr(&mut self) -> (*mut u8, usize) {
        (self.buffer.as_mut_ptr(), self.buffer.len())
    }
}

// SAFETY: as esp-hal's own `DmaLoopBuf`: the descriptors and buffer are
// `'static` and owned here, and the chain never ends, so the DMA never
// checks an owner bit or writes a descriptor back.
unsafe impl DmaTxBuffer for DmaRing {
    type View = DmaRing;
    type Final = DmaRing;

    fn prepare(&mut self) -> Preparation {
        Preparation {
            start: self.descriptors.as_mut_ptr(),
            // `dma_buffers_impl!` places the ring in internal RAM.
            accesses_psram: false,
            burst_transfer: BurstConfig::default(),
            // Never set, so never checked: the ring is always the DMA's.
            check_owner: Some(false),
            auto_write_back: false,
        }
    }

    fn into_view(self) -> Self::View {
        self
    }

    fn from_view(view: Self::View) -> Self::Final {
        view
    }
}
