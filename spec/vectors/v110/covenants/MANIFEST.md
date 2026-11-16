<!--
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
-->

# The covenant vectors

What `kassigner-kaspa`'s `kcc` module is checked against, one folder per
source, each file unchanged from its source.

## kcc1/

`conformance.json`: KCC-1's conformance vectors, "Covenant Concepts, Byte
Layouts, and ABI", Final. From `kaspanet/kccs` at
`1ed87aef59faff8354061aee30f734a3b8b2c3d2`,
`kcc-0001/vectors/conformance.json`; CC0 1.0, like every document there.

Read by `crates/kassigner-kaspa/tests/kcc1.rs`.

## kcc2/

`authority-schemes.json`: KCC-2's conformance vectors, "Authority Schemes",
Final. From the same commit, `kcc-0002/vectors/authority-schemes.json`; CC0
1.0.

Read by `crates/kassigner-kaspa/tests/kcc2.rs`.
