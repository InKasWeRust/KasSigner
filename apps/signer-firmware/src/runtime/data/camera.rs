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

// runtime/data/camera.rs — CameraState


pub struct CameraState {
    #[cfg(feature = "waveshare")]
    pub cam_tune_active: bool,
    #[cfg(feature = "waveshare")]
    pub cam_tune_dirty: bool,    // true = values changed, need I2C apply
    #[cfg(feature = "waveshare")]
    pub cam_tune_param: u8,      // 0=AEC_H, 1=AEC_L, 2=contrast, 3=brightness, 4=AGC_ceil, 5=sharpness
    #[cfg(feature = "waveshare")]
    pub cam_tune_vals: [u8; 6],  // current values for each parameter
}

impl CameraState {
    pub(super) fn new() -> Self {
        Self {
            #[cfg(feature = "waveshare")]
            cam_tune_active: false,
            #[cfg(feature = "waveshare")]
            cam_tune_dirty: true,
            #[cfg(feature = "waveshare")]
            cam_tune_param: 0,
            #[cfg(feature = "waveshare")]
            cam_tune_vals: [0x1A, 0x00, 0x3E, 0x00, 0xB8, 0x50],
        }
    }
}
