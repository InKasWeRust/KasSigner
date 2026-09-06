// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! Physical-board hardware self-test facade.

use crate::self_test::{
    crypto::test_sha256,
    memory::{test_mapped_flash, test_sram},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HardwareTest {
    Sram,
    Psram,
    Flash,
    Sha256,
    Display,
    Argon2Psram,
}

impl HardwareTest {
    const COUNT: usize = 6;

    const fn index(self) -> usize {
        self as usize
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelfTestResult {
    passed: [bool; HardwareTest::COUNT],
}

impl SelfTestResult {
    pub const fn new() -> Self {
        Self {
            passed: [false; HardwareTest::COUNT],
        }
    }

    fn record(&mut self, test: HardwareTest, passed: bool) {
        self.passed[test.index()] = passed;
    }

    pub const fn passed(&self, test: HardwareTest) -> bool {
        self.passed[test.index()]
    }

    pub fn all_passed(&self) -> bool {
        self.passed.iter().all(|passed| *passed)
    }
}

pub fn run_all_tests() -> SelfTestResult {
    let mut result = SelfTestResult::new();
    log!("   Running self-tests...");
    log!();

    record(&mut result, HardwareTest::Sram, "Internal SRAM", test_sram());

    #[cfg(feature = "test-psram")]
    record(&mut result, HardwareTest::Psram, "PSRAM", test_psram());
    #[cfg(not(feature = "test-psram"))]
    {
        log!("[2/6] PSRAM: not enabled (use --features test-psram)");
        result.record(HardwareTest::Psram, true);
    }

    #[cfg(all(feature = "hardware-tests", feature = "argon2-bench"))]
    record(
        &mut result,
        HardwareTest::Argon2Psram,
        "Argon2/PSRAM benchmark",
        crate::diagnostics::argon2_bench::run(&mut || {}),
    );
    #[cfg(not(all(feature = "hardware-tests", feature = "argon2-bench")))]
    result.record(HardwareTest::Argon2Psram, true);

    record(
        &mut result,
        HardwareTest::Flash,
        "Flash mapped segment",
        test_mapped_flash(),
    );
    record(&mut result, HardwareTest::Sha256, "SHA256", test_sha256());

    log!("[6/6] Display: deferred until board initialization");
    result.record(HardwareTest::Display, true);
    log!();
    log!(
        "   {}",
        if result.all_passed() {
            "All tests passed"
        } else {
            "FAIL: Some tests failed"
        }
    );
    result
}

fn record(
    result: &mut SelfTestResult,
    test: HardwareTest,
    name: &str,
    passed: bool,
) {
    result.record(test, passed);
    log!("   {}: {}", name, if passed { "OK" } else { "FAIL" });
}

#[cfg(feature = "test-psram")]
fn test_psram() -> bool {
    const PROBE_BYTES: usize = 64 * 1024;
    let Ok(region) = crate::services::memory::psram::region() else {
        log!("   PSRAM mapping unavailable");
        return false;
    };
    let Ok(mut allocation) = crate::services::memory::psram::PsramAllocation::allocate(PROBE_BYTES, 8) else {
        log!("   PSRAM probe allocation failed");
        return false;
    };
    if !region.contains(allocation.start(), allocation.len()) {
        log!("   PSRAM probe provenance failed");
        return false;
    }
    for (index, byte) in allocation.as_mut_bytes().iter_mut().enumerate() {
        *byte = psram_probe_pattern(index);
    }
    let valid = allocation
        .as_bytes()
        .iter()
        .enumerate()
        .all(|(index, byte)| *byte == psram_probe_pattern(index));
    log!(
        "   PSRAM mapped probe: {} bytes at 0x{:08x} — {}",
        allocation.len(),
        allocation.start(),
        if valid { "OK" } else { "FAIL" },
    );
    valid
}

#[cfg(feature = "test-psram")]
fn psram_probe_pattern(index: usize) -> u8 {
    (index as u8).wrapping_mul(0x63) ^ ((index >> 8) as u8).wrapping_add(0x5a)
}
