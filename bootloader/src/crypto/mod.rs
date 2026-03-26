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

// crypto/mod.rs — Security cryptographic primitives
//
// This module provides security primitives for the entire project:
//   - Constant-time comparison (constant_time)
//   - Secure memory zeroization (secure_zeroize)
//   - XOR-masked secret containers (secret_box)
//   - Flow integrity counters (flow)

#![allow(unused_imports)]
pub mod constant_time;
pub mod secure_zeroize;
pub mod secret_box;
pub mod flow;
