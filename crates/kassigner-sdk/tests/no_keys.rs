// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The property the level model exists to make checkable.

use std::process::Command;

/// No key material in the SDK's tree: `cargo tree -p kassigner-sdk` lists
/// neither `kassigner-crypto`, the one crate holding a seed, nor the firmware.
#[test]
fn the_sdk_reaches_no_key_material() {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let out = Command::new(cargo)
        .args([
            "tree",
            "-p",
            "kassigner-sdk",
            "--edges",
            "normal",
            "--prefix",
            "none",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("cargo tree runs");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let tree = String::from_utf8(out.stdout).unwrap();
    assert!(tree.contains("kassigner-protocol"), "{tree}");
    for absent in [
        "kassigner-crypto",
        "kassigner-fw",
        "kassigner-hal",
        "kassigner-signer",
    ] {
        assert!(
            !tree.contains(absent),
            "{absent} is in the SDK's tree:\n{tree}"
        );
    }
}

/// No GPL crate is in the trees of the SDK and its two bindings, which would
/// make an app shipping them GPL; every crate of this project there is MPL-2.0.
#[test]
fn what_an_app_links_carries_no_gpl() {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    for package in ["kassigner-sdk", "kassigner-sdk-wasm", "kassigner-sdk-ffi"] {
        let out = Command::new(&cargo)
            .args([
                "tree", "--color", "never", "-p", package, "--edges", "normal", "--prefix", "none",
                "--format", "{p}|{l}",
            ])
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .output()
            .expect("cargo tree runs");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let tree = String::from_utf8(out.stdout).unwrap();
        let mut ours = 0;
        for line in tree.lines() {
            let (name, license) = line.split_once('|').expect("{p}|{l}");
            assert!(
                !license.contains("GPL"),
                "{name} is {license}, in {package}'s tree"
            );
            if name.starts_with("kassigner-") {
                assert_eq!(
                    license.trim_end_matches(" (*)"),
                    "MPL-2.0",
                    "{name} in {package}'s tree"
                );
                ours += 1;
            }
        }
        assert!(ours > 0, "{package}: {tree}");
    }
}
