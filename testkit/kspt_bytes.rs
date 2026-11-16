// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! KSPT payloads for the tests, written byte by byte, so the readers are
//! checked against the format and not against the writer. Included by
//! path, like `hex.rs`, as a `pub mod`.

use kassigner_protocol::kspt::{write_script_len, Field, MAGIC, VERSION};

/// A script length, in the form the format writes it: one byte, or an
/// escape and two, never more.
pub fn spk_len(n: usize) -> Vec<u8> {
    let mut b = vec![0u8; 3];
    let w = write_script_len(Field::Script, n, &mut b).expect("len");
    b.truncate(w);
    b
}

/// A canonical `0x06` payload built by hand, every input and output paying
/// to `script`, covenant bindings as `0x43` records.
pub fn payload_bytes(
    script: &[u8],
    inputs: &[u64],
    outputs: &[(u64, Option<[u8; 32]>)],
) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&MAGIC);
    b.push(VERSION);
    b.push(0); // flags: reserved on the canonical version
    b.extend_from_slice(&1u16.to_le_bytes()); // tx_version
    b.push(inputs.len() as u8);
    b.push(outputs.len() as u8);
    b.extend_from_slice(&0u64.to_le_bytes()); // lock_time
    b.extend_from_slice(&[0u8; 20]); // subnetwork
    b.extend_from_slice(&0u64.to_le_bytes()); // gas
    b.extend_from_slice(&0u16.to_le_bytes()); // payload length

    for (i, amount) in inputs.iter().enumerate() {
        b.extend_from_slice(&[0x11u8; 32]); // prev_tx_id
        b.extend_from_slice(&(i as u32).to_le_bytes()); // prev_index
        b.extend_from_slice(&amount.to_le_bytes());
        b.extend_from_slice(&0u64.to_le_bytes()); // sequence
        b.push(1); // sig_op_count
        b.extend_from_slice(&0u16.to_le_bytes()); // spk_version
        b.extend_from_slice(&spk_len(script.len()));
        b.extend_from_slice(script);
        b.push(0); // signature count: unsigned
        b.extend_from_slice(&0u16.to_le_bytes()); // redeem length
    }

    for (value, _) in outputs {
        b.extend_from_slice(&value.to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes()); // spk_version
        b.extend_from_slice(&spk_len(script.len()));
        b.extend_from_slice(script);
    }

    // Covenant bindings arrive as 0x43 records after the outputs.
    for (i, (_, covenant)) in outputs.iter().enumerate() {
        if let Some(id) = covenant {
            b.push(0x43);
            b.push(i as u8);
            b.extend_from_slice(&0u16.to_le_bytes()); // authorizing input
            b.extend_from_slice(id);
        }
    }
    b
}
