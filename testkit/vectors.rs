// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The recorded vectors in `spec/vectors/`, read as fuzz seeds. Included by
//! path, like `mutate.rs`, by the tests of crates two folders below the
//! root: the path to `spec/vectors/` counts from there.

/// The files in `spec/vectors/<dir>` that `names` selects, sorted by name.
/// An entry starting with a dot matches an ending (`.bin`), an empty one
/// every file, any other a whole name (`multisig.request` does not match
/// `pskb_multisig.request`).
pub fn files(dir: &str, names: &[&str]) -> Vec<Vec<u8>> {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../spec/vectors")
        .join(dir);
    let mut names: Vec<_> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .map(|e| e.unwrap().path())
        .filter(|p| {
            let name = p.file_name().unwrap().to_string_lossy().into_owned();
            names.iter().any(|n| match n.starts_with('.') {
                true => name.ends_with(n),
                false => n.is_empty() || name == *n,
            })
        })
        .collect();
    names.sort();
    names
        .into_iter()
        .map(|p| std::fs::read(p).unwrap())
        .collect()
}
