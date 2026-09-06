// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! Volatile SRAM and mapped-flash checks shared by every ESP32-S3 platform.

use core::sync::atomic::{compiler_fence, Ordering};
use shared_signer::bytes::zeroize_bytes;

const DATA_SEGMENT_BASE: u32 = 0x3C00_0020;
const FLASH_TEST_READ_SIZE: usize = 256;
const SRAM_TEST_SIZE: usize = 2048;

pub(crate) fn test_sram() -> bool {
    let mut buffer = [0u8; SRAM_TEST_SIZE];
    if !write_and_verify(&mut buffer, |_, _| 0xAA) {
        return false;
    }
    if !write_and_verify(&mut buffer, |_, _| 0x55) {
        return false;
    }
    if !write_and_verify(&mut buffer, |index, _| 1u8 << (index % 8)) {
        return false;
    }
    if !write_and_verify(&mut buffer, |index, _| ((index ^ 0xA5) & 0xFF) as u8) {
        return false;
    }
    zeroize_bytes(&mut buffer);
    true
}

fn write_and_verify<F>(buffer: &mut [u8], pattern: F) -> bool
where
    F: Fn(usize, u8) -> u8,
{
    for (index, byte) in buffer.iter_mut().enumerate() {
        *byte = pattern(index, *byte);
    }
    compiler_fence(Ordering::SeqCst);
    for (index, byte) in buffer.iter().enumerate() {
        let observed = unsafe { core::ptr::read_volatile(byte as *const u8) };
        if observed != pattern(index, observed) {
            return false;
        }
    }
    true
}

pub(crate) fn test_mapped_flash() -> bool {
    let data = unsafe {
        core::slice::from_raw_parts(
            DATA_SEGMENT_BASE as *const u8,
            FLASH_TEST_READ_SIZE,
        )
    };
    let mut all_ff = true;
    let mut all_zero = true;
    let mut seen = [false; 256];
    let mut unique_count = 0u32;

    for byte in data {
        let value = unsafe { core::ptr::read_volatile(byte as *const u8) };
        all_ff &= value == 0xFF;
        all_zero &= value == 0x00;
        if !seen[value as usize] {
            seen[value as usize] = true;
            unique_count += 1;
        }
    }

    !all_ff && !all_zero && unique_count >= 8
}
