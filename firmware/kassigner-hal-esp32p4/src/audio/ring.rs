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

//! A DMA buffer the I2S plays round and round: the tick's. Other sounds are
//! streams that stop with the sound, so nothing would sound while the
//! processor is busy, as inside Argon2id; the ring, a click and silence
//! written once, plays by itself until stopped. Four descriptors of 4,092
//! bytes in a circle, 85 ms at 48 kHz: about twelve clicks a second.
//!
//! The same type as the M5's `ring.rs` in `kassigner-hal-esp32s3`, written
//! in each board crate since `kassigner-hal` cannot use esp-hal.

use esp_hal::dma::aligned::DmaAlignedMut;
use esp_hal::dma::{BurstConfig, DmaBufError, DmaDescriptor, DmaTxBuffer, Owner, Preparation};

/// The ring: four descriptors, 85 ms at 48 kHz.
pub const RING_BYTES: usize = 4 * RING_CHUNK;
/// One descriptor's share: the most it can hold, in whole frames.
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
    /// into equal shares, or a share is larger than [`RING_CHUNK`].
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

    /// The buffer, to write the tick into while the ring is not playing.
    pub fn buffer_mut(&mut self) -> &mut [u8] {
        &mut self.buffer
    }
}

// SAFETY: as esp-hal's `DmaLoopBuf`: descriptors and buffer are `'static`
// and owned here, and the chain never ends, so the DMA never checks an owner
// bit or writes a descriptor back.
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
