// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! ESP32-S3 resources exercised by Espressif QEMU.

use super::report::Report;
use crate::self_test::{
    crypto::test_sha256,
    memory::{test_mapped_flash, test_sram},
};
use esp_hal::{
    delay::Delay,
    rng::Rng,
    time::{Duration, Instant},
};
use core::sync::atomic::{AtomicU32, Ordering};

pub(crate) fn run(report: &mut Report, delay: &mut Delay) {
    report.check("Xtensa arithmetic and bit operations", test_cpu());
    report.check("atomic compare/exchange", test_atomics());
    report.check("internal SRAM volatile patterns", test_sram());
    report.check("internal heap allocation", crate::qemu::allocator::probe());
    report.check("mapped SPI flash segment", test_mapped_flash());
    report.check("SHA-256 known-answer vectors", test_sha256());
    report.check("system timer and blocking delay", test_timer(delay));
    report.check("RNG register stream sanity", test_rng());
}

fn test_cpu() -> bool {
    let product = 0x1357_9BDFu32.wrapping_mul(0x1020_3041);
    let rotated = product.rotate_left(13).rotate_right(13);
    let endian = u32::from_be_bytes([0x12, 0x34, 0x56, 0x78]);
    rotated == product && endian == 0x1234_5678
}

fn test_atomics() -> bool {
    let value = AtomicU32::new(7);
    if value.compare_exchange(7, 11, Ordering::SeqCst, Ordering::SeqCst).is_err() {
        return false;
    }
    value.fetch_add(5, Ordering::SeqCst) == 11
        && value.load(Ordering::SeqCst) == 16
}

fn test_timer(delay: &mut Delay) -> bool {
    let started = Instant::now();
    delay.delay_millis(5);
    started.elapsed() >= Duration::from_millis(1)
}

fn test_rng() -> bool {
    let rng = Rng::new();
    let first = rng.random();
    let mut any_nonzero = first != 0;
    let mut any_different = false;
    for _ in 0..15 {
        let value = rng.random();
        any_nonzero |= value != 0;
        any_different |= value != first;
    }
    any_nonzero && any_different
}
