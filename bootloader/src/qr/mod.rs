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

// qr/mod.rs — QR code module (encoder + platform-gated decoder)
// qr/ — QR code encoding and decoding

pub mod encoder;

#[cfg(feature = "waveshare")]
#[path = "decoder_ws.rs"]
pub mod decoder;

#[cfg(feature = "m5stack")]
#[path = "decoder_m5.rs"]
pub mod decoder;
