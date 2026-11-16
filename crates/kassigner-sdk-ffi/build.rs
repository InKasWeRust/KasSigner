// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! On Apple's systems a dynamic library carries its own name, which an app
//! linking it copies and looks it up by at launch. Left to the linker, that
//! name is the full path of the file it wrote, in the `target/` folder of
//! the machine that built it. It is set here to `@rpath/` and the file's
//! name, which an app resolves against its own bundle.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var("CARGO_CFG_TARGET_VENDOR").as_deref() == Ok("apple") {
        println!("cargo:rustc-cdylib-link-arg=-Wl,-install_name,@rpath/libkassigner_sdk_ffi.dylib");
    }
}
