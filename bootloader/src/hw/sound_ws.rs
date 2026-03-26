// KasSigner — Air-gapped hardware wallet for Kaspa
// Copyright (C) 2025 KasSigner Project (kassigner@proton.me)
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

// hw/sound.rs — Audio stubs for Waveshare ESP32-S3-Touch-LCD-2
//
// No speaker hardware on this board. All functions are no-ops
// to maintain API compatibility with handlers and UI code.

#![allow(dead_code)]
use esp_hal::delay::Delay;

pub fn set_volume(_vol: u8) {}
pub fn click(_delay: &mut Delay) {}
pub fn beep_error(_delay: &mut Delay) {}
pub fn success(_delay: &mut Delay) {}
pub fn warning(_delay: &mut Delay) {}
pub fn task_done(_delay: &mut Delay) {}
pub fn qr_found(_delay: &mut Delay) {}
pub fn qr_decoded(_delay: &mut Delay) {}
pub fn start_ticking() {}
pub fn stop_ticking() {}
