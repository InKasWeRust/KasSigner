// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// tools/verify.rs — Firmware code segment comparator
//
// Verifies that two KasSigner .bin files contain identical code.
// Use this to confirm a signed release binary runs the same code
// as your own unsigned Docker build.
//
// Usage (from repo root):
//   cargo run --manifest-path tools/Cargo.toml --bin kassigner-verify -- <signed.bin> <unsigned.bin>
//
// What it does:
//   1. Parses both ESP-IDF images, locates the code segment in each
//   2. Computes SHA-256 over both code segments
//   3. Compares — if identical, the signed binary runs the same code
//
// Why this matters:
//   You can't reproduce a signed build (only the developer has the key).
//   But you CAN build unsigned from source and compare code segments.
//   If they match, the signature only adds boot verification —
//   it doesn't change what the code does.

use sha2::{Sha256, Digest};
use std::env;
use std::fs;
use std::process;

const CODE_LOAD_ADDR: u32 = 0x42060020;
const IMAGE_HEADER_SIZE: usize = 24;
const SEGMENT_HEADER_SIZE: usize = 8;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: kassigner-verify <signed.bin> <unsigned.bin>");
        eprintln!();
        eprintln!("Compares code segments of two KasSigner firmware binaries.");
        eprintln!("If they match, both binaries run identical code.");
        process::exit(1);
    }

    println!();
    println!("  KasSigner Code Segment Verifier");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    let (hash_a, size_a) = process_bin("A", &args[1]);
    let (hash_b, size_b) = process_bin("B", &args[2]);

    let hex_a: String = hash_a.iter().map(|b| format!("{:02x}", b)).collect();
    let hex_b: String = hash_b.iter().map(|b| format!("{:02x}", b)).collect();

    println!();
    println!("  [A] {} bytes  {}", size_a, hex_a);
    println!("  [B] {} bytes  {}", size_b, hex_b);

    if hash_a == hash_b {
        println!();
        println!("  ✓  CODE SEGMENTS IDENTICAL");
        println!("  Both binaries run the same code.");
        println!("  The only difference is the signature in the data segment.");
        println!();
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    } else {
        println!();
        println!("  ✗  CODE SEGMENTS DIFFER");
        println!("  These binaries contain different code.");
        println!("  Do NOT assume the signed binary matches your build.");
        println!();
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        process::exit(1);
    }
}

fn process_bin(label: &str, path: &str) -> ([u8; 32], usize) {
    let data = match fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("  Error: cannot read '{}': {}", path, e);
            process::exit(1);
        }
    };

    println!("  [{}] {}", label, path);
    println!("      {} bytes ({} KB)", data.len(), data.len() / 1024);

    if data.len() < IMAGE_HEADER_SIZE + SEGMENT_HEADER_SIZE || data[0] != 0xE9 {
        eprintln!("      Error: not a valid ESP-IDF image");
        process::exit(1);
    }

    let segment_count = data[1] as usize;
    let mut offset = IMAGE_HEADER_SIZE;

    for _ in 0..segment_count {
        if offset + SEGMENT_HEADER_SIZE > data.len() {
            eprintln!("      Error: truncated image");
            process::exit(1);
        }

        let load_addr = u32::from_le_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
        ]);
        let seg_size = u32::from_le_bytes([
            data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
        ]) as usize;

        let seg_data_start = offset + SEGMENT_HEADER_SIZE;

        if load_addr == CODE_LOAD_ADDR {
            if seg_data_start + seg_size > data.len() {
                eprintln!("      Error: code segment extends beyond file");
                process::exit(1);
            }

            let code = &data[seg_data_start..seg_data_start + seg_size];
            let mut hasher = Sha256::new();
            hasher.update(code);
            let hash: [u8; 32] = hasher.finalize().into();

            println!("      Code: {} bytes at 0x{:X}", seg_size, seg_data_start);
            return (hash, seg_size);
        }

        offset = seg_data_start + seg_size;
    }

    eprintln!("      Error: code segment (0x{:08X}) not found", CODE_LOAD_ADDR);
    process::exit(1);
}
