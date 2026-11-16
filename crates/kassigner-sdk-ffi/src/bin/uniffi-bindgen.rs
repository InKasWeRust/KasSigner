// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! UniFFI's command, built here so it is the version the library links:
//! `cargo run -p kassigner-sdk-ffi --bin uniffi-bindgen -- generate ...`,
//! as the crate's `build.sh` runs it.

fn main() {
    uniffi::uniffi_bindgen_main()
}
