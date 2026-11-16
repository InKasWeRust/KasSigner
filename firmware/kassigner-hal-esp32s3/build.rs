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

// The capture examples read `KS_SHOW_BRIGHT` and `KS_READ_BRIGHT` with
// `option_env!` at compile time: without these lines cargo would not rebuild
// when one changes, and a new value would be ignored.

fn main() {
    for var in ["KS_SHOW_BRIGHT", "KS_READ_BRIGHT"] {
        println!("cargo:rerun-if-env-changed={var}");
    }
}
