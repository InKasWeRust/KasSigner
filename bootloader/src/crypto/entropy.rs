// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//! Central cryptographic random-number generator.
//!
//! At startup, `initialize` temporarily enables the ESP32-S3 primary
//! hardware entropy source, collects a master seed, and releases ADC1.
//! All later random requests are served by an HMAC-DRBG. There is no
//! fallback: callers receive an error until initialization succeeds.

use core::cell::RefCell;

use critical_section::Mutex;
use esp_hal::{
    peripherals::{ADC1, RNG},
    rng::{Trng, TrngSource},
};

use crate::wallet::hmac::{hmac_sha512, zeroize_buf};

const SEED_LEN: usize = 96;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntropyError {
    AlreadyInitialized,
    TrngUnavailable,
    HardwareHealthTestFailed,
    NotInitialized,
    GeneratorBusy,
    RequestCounterExhausted,
}

struct HmacDrbg {
    key: [u8; 64],
    value: [u8; 64],
    requests: u64,
}

impl HmacDrbg {
    fn new(seed: &[u8]) -> Self {
        let mut drbg = Self {
            key: [0u8; 64],
            value: [1u8; 64],
            requests: 0,
        };
        drbg.update(seed);
        drbg
    }

    fn update(&mut self, data: &[u8]) {
        let mut material = [0u8; 64 + 1 + SEED_LEN];
        material[..64].copy_from_slice(&self.value);
        material[64] = 0;
        material[65..65 + data.len()].copy_from_slice(data);

        self.key = hmac_sha512(&self.key, &material[..65 + data.len()]);
        self.value = hmac_sha512(&self.key, &self.value);

        if !data.is_empty() {
            material[..64].copy_from_slice(&self.value);
            material[64] = 1;
            material[65..65 + data.len()].copy_from_slice(data);
            self.key = hmac_sha512(&self.key, &material[..65 + data.len()]);
            self.value = hmac_sha512(&self.key, &self.value);
        }

        zeroize_buf(&mut material);
    }

    fn generate(&mut self, out: &mut [u8]) -> Result<(), EntropyError> {
        self.requests = self
            .requests
            .checked_add(1)
            .ok_or(EntropyError::RequestCounterExhausted)?;

        for chunk in out.chunks_mut(64) {
            self.value = hmac_sha512(&self.key, &self.value);
            chunk.copy_from_slice(&self.value[..chunk.len()]);
        }

        self.update(&[]);
        Ok(())
    }
}

impl Drop for HmacDrbg {
    fn drop(&mut self) {
        zeroize_buf(&mut self.key);
        zeroize_buf(&mut self.value);
        self.requests = 0;
    }
}

static GENERATOR: Mutex<RefCell<Option<HmacDrbg>>> = Mutex::new(RefCell::new(None));

fn hardware_health_check(seed: &[u8; SEED_LEN]) -> bool {
    if seed.iter().all(|byte| *byte == seed[0]) {
        return false;
    }

    if seed[..32] == seed[32..64] || seed[32..64] == seed[64..96] {
        return false;
    }

    for words in seed
        .chunks_exact(4)
        .collect::<heapless::Vec<_, 24>>()
        .windows(3)
    {
        if words[0] == words[1] && words[1] == words[2] {
            return false;
        }
    }

    true
}

/// Initialize the central generator from the ESP32-S3 primary entropy source.
///
/// `TrngSource` owns ADC1 while active. Both it and `Trng` are dropped before
/// this function returns, allowing battery ADC initialization to happen next.
pub fn initialize<'d>(rng: RNG<'d>, adc1: ADC1<'d>) -> Result<(), EntropyError> {
    if is_initialized() {
        return Err(EntropyError::AlreadyInitialized);
    }

    let source = TrngSource::new(rng, adc1);
    let trng = Trng::try_new().map_err(|_| EntropyError::TrngUnavailable)?;
    let mut seed = [0u8; SEED_LEN];
    trng.read(&mut seed);
    drop(trng);
    drop(source);

    if !hardware_health_check(&seed) {
        zeroize_buf(&mut seed);
        return Err(EntropyError::HardwareHealthTestFailed);
    }

    let generator = HmacDrbg::new(&seed);
    zeroize_buf(&mut seed);

    critical_section::with(|cs| {
        let mut slot = GENERATOR.borrow(cs).borrow_mut();
        if slot.is_some() {
            return Err(EntropyError::AlreadyInitialized);
        }
        *slot = Some(generator);
        Ok(())
    })
}

pub fn is_initialized() -> bool {
    critical_section::with(|cs| GENERATOR.borrow(cs).borrow().is_some())
}

/// Fill `out` with cryptographic random bytes.
///
/// On every failure, the destination is cleared and an explicit error is
/// returned. There is deliberately no weak or silent fallback.
pub fn fill(out: &mut [u8]) -> Result<(), EntropyError> {
    let result = critical_section::with(|cs| {
        let mut slot = GENERATOR
            .borrow(cs)
            .try_borrow_mut()
            .map_err(|_| EntropyError::GeneratorBusy)?;
        let generator = slot.as_mut().ok_or(EntropyError::NotInitialized)?;
        generator.generate(out)
    });

    if result.is_err() {
        out.fill(0);
    }
    result
}

/// Deterministic boot-time tests for the DRBG and startup health checks.
/// These use local state and never consume bytes from the live generator.
pub fn run_self_tests() -> (u32, u32) {
    const EXPECTED_FIRST: [u8; 64] = [
        0x4c, 0xdf, 0xc1, 0x62, 0xb7, 0x4c, 0xc2, 0xd7, 0xb6, 0x23, 0x6a, 0xff, 0x3c, 0x8c, 0x62, 0x68,
        0xed, 0xf8, 0xf8, 0xe2, 0x83, 0xdb, 0xda, 0x4b, 0x01, 0x4a, 0x50, 0x39, 0x03, 0x29, 0x16, 0x63,
        0x49, 0x6f, 0x86, 0xce, 0xd5, 0xb9, 0x1a, 0x7e, 0xd6, 0x1b, 0xbd, 0x24, 0x3d, 0x56, 0x8d, 0x19,
        0x49, 0xe3, 0x52, 0x04, 0x02, 0x6a, 0x9b, 0x36, 0x56, 0xb7, 0x18, 0x25, 0xf9, 0x8f, 0x05, 0x96,
    ];
    const EXPECTED_SECOND: [u8; 64] = [
        0xff, 0x16, 0xb2, 0x4d, 0x2a, 0xa4, 0x0a, 0xfc, 0x29, 0x1f, 0xb9, 0x9b, 0x79, 0x14, 0xfe, 0x7c,
        0x2b, 0x93, 0x7d, 0x2e, 0x9a, 0x7f, 0x02, 0x2b, 0x41, 0xf8, 0x14, 0x7f, 0x8d, 0x8e, 0x31, 0x58,
        0xb8, 0x74, 0x19, 0x58, 0xf1, 0x4e, 0x3b, 0x40, 0x15, 0xf9, 0x3b, 0xb5, 0x2a, 0xb2, 0x1c, 0xd7,
        0x77, 0x25, 0x82, 0x66, 0x59, 0x57, 0xe0, 0xd6, 0x98, 0x54, 0x0b, 0xb6, 0x5d, 0xe4, 0x22, 0x19,
    ];

    let mut passed = 0u32;
    let total = 6u32;

    let mut seed = [0u8; SEED_LEN];
    for (index, byte) in seed.iter_mut().enumerate() {
        *byte = index as u8;
    }
    let mut drbg = HmacDrbg::new(&seed);
    let mut first = [0u8; 64];
    let mut second = [0u8; 64];
    if drbg.generate(&mut first).is_ok() && first == EXPECTED_FIRST {
        passed += 1;
    }
    if drbg.generate(&mut second).is_ok()
        && second == EXPECTED_SECOND
        && second != first
    {
        passed += 1;
    }
    if hardware_health_check(&seed) {
        passed += 1;
    }

    let constant = [0x55u8; SEED_LEN];
    if !hardware_health_check(&constant) {
        passed += 1;
    }

    let mut repeated_blocks = seed;
    repeated_blocks[32..64].copy_from_slice(&seed[..32]);
    if !hardware_health_check(&repeated_blocks) {
        passed += 1;
    }

    let mut repeated_words = seed;
    repeated_words[..12].copy_from_slice(&[1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4]);
    if !hardware_health_check(&repeated_words) {
        passed += 1;
    }

    zeroize_buf(&mut seed);
    zeroize_buf(&mut first);
    zeroize_buf(&mut second);
    zeroize_buf(&mut repeated_blocks);
    zeroize_buf(&mut repeated_words);

    (passed, total)
}
