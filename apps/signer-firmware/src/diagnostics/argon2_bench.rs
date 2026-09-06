//! Developer-only Argon2id calibration using the production PSRAM workspace path.
//!
//! Inputs are fixed, public test material. Never use wallet credentials or seed data here.

use offline_signer::crypto::password_kdf::{
    PasswordKdfError, PasswordKdfParams, PasswordKdfPurpose,
    ARGON2_VERSION_13, PROFILE_VERSION_1, SALT_SIZE,
};
use shared_signer::bytes::zeroize_bytes;

const TEST_PASSWORD: &[u8] = b"KasSigner Argon2 benchmark v1";
const TEST_SALT: [u8; SALT_SIZE] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];
const T_COST: u32 = 3;
const P_COST: u32 = 1;
const CPU_CYCLES_PER_MS: u64 = 240_000;
const WATCHDOG_BUDGET_MS: u64 = 25_000;
const PROBE_GRANULARITY: usize = 64 * 1024;
const PROBE_CAP: usize = 8 * 1024 * 1024;

struct Candidate {
    memory_kib: u32,
    expected: [u8; 32],
}

const CANDIDATES: [Candidate; 5] = [
    Candidate { memory_kib: 2_048, expected: [
        0x36, 0xa7, 0xdc, 0x90, 0x63, 0x15, 0x7f, 0x9a, 0x42, 0x46, 0xed, 0x0a, 0x3a, 0x3b, 0xd1, 0xf3,
        0x56, 0x6d, 0x56, 0xc1, 0x41, 0x76, 0xc7, 0x37, 0x82, 0x2e, 0x0b, 0x46, 0xbb, 0xc7, 0x0f, 0x53,
    ] },
    Candidate { memory_kib: 3_072, expected: [
        0x99, 0x2d, 0xfb, 0x18, 0x30, 0x30, 0x13, 0x22, 0x8d, 0x18, 0x24, 0x0c, 0xd7, 0x4f, 0xf9, 0xb8,
        0x37, 0x56, 0xa3, 0x37, 0x00, 0x0f, 0x88, 0x02, 0xc6, 0xf6, 0x64, 0x42, 0x83, 0xac, 0xec, 0xcb,
    ] },
    Candidate { memory_kib: 4_096, expected: [
        0x58, 0xac, 0x55, 0x29, 0x09, 0xad, 0x4f, 0xe9, 0x4b, 0xb0, 0xaa, 0x38, 0xe4, 0xe3, 0x27, 0x7a,
        0xf5, 0x21, 0x2d, 0x7e, 0x16, 0x4d, 0x45, 0xdb, 0x74, 0x77, 0x9a, 0xef, 0x3c, 0x18, 0xdc, 0x01,
    ] },
    Candidate { memory_kib: 5_120, expected: [
        0x45, 0xba, 0xf8, 0x55, 0xfd, 0x4a, 0x9d, 0x00, 0x1d, 0xa7, 0x03, 0x6d, 0x86, 0x04, 0x05, 0xf6,
        0xef, 0xd5, 0x7f, 0x01, 0x4f, 0x05, 0x5e, 0xdc, 0xac, 0xa2, 0x0d, 0xa8, 0x15, 0x8a, 0x84, 0x79,
    ] },
    Candidate { memory_kib: 6_144, expected: [
        0x57, 0xbe, 0x86, 0xa2, 0xf1, 0x9e, 0xc8, 0x2b, 0xee, 0xc2, 0xe9, 0xff, 0x57, 0x16, 0x18, 0x6e,
        0xba, 0x17, 0x40, 0x6d, 0x45, 0x81, 0x22, 0xeb, 0xe2, 0xd4, 0x65, 0xdb, 0xac, 0xc7, 0xd2, 0x8c,
    ] },
];

#[inline(never)]
pub(crate) fn run(watchdog_feed: &mut impl FnMut()) -> bool {
    crate::log!("[argon2-bench] fixed non-secret calibration inputs only");
    crate::log!("[argon2-bench] variant=Argon2id version=19 t={} p={}", T_COST, P_COST);
    match crate::services::memory::psram::region() {
        Ok(region) => crate::log!(
            "[argon2-bench] runtime_psram=0x{:08x}..0x{:08x} bytes={}",
            region.start, region.end().unwrap_or(region.start), region.len,
        ),
        Err(_) => {
            crate::log!("[argon2-bench] runtime_psram=UNAVAILABLE FAIL");
            return false;
        }
    }
    for candidate in &CANDIDATES {
        watchdog_feed();
        if !run_candidate(candidate) {
            crate::log!("[argon2-bench] stopping: candidate was not safe/successful");
            return false;
        }
        watchdog_feed();
    }
    crate::log!("[argon2-bench] complete; all fixed Argon2/PSRAM candidates passed");
    true
}

#[inline(never)]
fn run_candidate(candidate: &Candidate) -> bool {
    let free_before = crate::services::memory::psram::free_bytes();
    let largest_before = crate::services::memory::psram::probe_largest_allocatable(PROBE_CAP, PROBE_GRANULARITY);
    let parameters = PasswordKdfParams {
        profile_version: PROFILE_VERSION_1,
        argon_version: ARGON2_VERSION_13,
        m_cost_kib: candidate.memory_kib,
        t_cost: T_COST,
        p_cost: P_COST,
    };
    let started = esp_hal::xtensa_lx::timer::get_cycle_count();
    let result = crate::services::memory::password_kdf::derive_benchmark_key_32(
        PasswordKdfPurpose::PortableBackup,
        TEST_PASSWORD,
        &TEST_SALT,
        parameters,
    );
    let cycles = esp_hal::xtensa_lx::timer::get_cycle_count().wrapping_sub(started);
    let elapsed_ms = u64::from(cycles) / CPU_CYCLES_PER_MS;
    let free_after = crate::services::memory::psram::free_bytes();
    let largest_after = crate::services::memory::psram::probe_largest_allocatable(PROBE_CAP, PROBE_GRANULARITY);
    let liveness_ok = elapsed_ms <= WATCHDOG_BUDGET_MS;
    let status = classify_result(result, &candidate.expected);
    crate::log!(
        "[argon2-bench] m={}KiB t={} p={} alloc={} provenance={} integrity={} vector={} cycles={} ms={} psram=0x{:08x}..0x{:08x} workspace=0x{:08x}..0x{:08x} workspace_bytes={} free_before={} free_after={} largest_before={} largest_after={} watchdog_ok={} result={}",
        candidate.memory_kib, T_COST, P_COST, status.allocation_ok, status.checks.provenance_ok,
        status.checks.integrity_ok, status.checks.vector_ok, cycles, elapsed_ms, status.psram_start,
        status.psram_end, status.workspace_start, status.workspace_end, status.workspace_len,
        free_before, free_after, largest_before, largest_after, liveness_ok,
        status.is_safe(liveness_ok),
    );
    status.is_safe(liveness_ok)
}

#[derive(Clone, Copy)]
struct CandidateChecks {
    provenance_ok: bool,
    integrity_ok: bool,
    vector_ok: bool,
}

impl CandidateChecks {
    fn all_ok(self) -> bool {
        self.provenance_ok && self.integrity_ok && self.vector_ok
    }
}

struct CandidateStatus {
    allocation_ok: bool,
    checks: CandidateChecks,
    psram_start: usize,
    psram_end: usize,
    workspace_start: usize,
    workspace_end: usize,
    workspace_len: usize,
}

impl CandidateStatus {
    fn is_safe(&self, liveness_ok: bool) -> bool {
        self.allocation_ok && self.checks.all_ok() && liveness_ok
    }
}

fn classify_result(
    result: Result<crate::services::memory::password_kdf::BenchmarkResult, PasswordKdfError>,
    expected: &[u8; 32],
) -> CandidateStatus {
    match result {
        Ok(mut result) => {
            let vector_ok = result.key.as_ref().is_ok_and(|key| key == expected);
            if let Ok(key) = result.key.as_mut() { zeroize_bytes(key); }
            let psram_end = result.info.psram.end().unwrap_or(result.info.psram.start);
            let workspace_end = result.info.workspace_start.checked_add(result.info.workspace_len).unwrap_or(0);
            let provenance_ok = result.info.psram.contains(result.info.workspace_start, result.info.workspace_len);
            CandidateStatus {
                allocation_ok: true,
                checks: CandidateChecks { provenance_ok, integrity_ok: result.integrity_ok, vector_ok },
                psram_start: result.info.psram.start,
                psram_end,
                workspace_start: result.info.workspace_start,
                workspace_end,
                workspace_len: result.info.workspace_len,
            }
        }
        Err(_) => CandidateStatus {
            allocation_ok: false,
            checks: CandidateChecks { provenance_ok: false, integrity_ok: false, vector_ok: false },
            psram_start: 0,
            psram_end: 0,
            workspace_start: 0,
            workspace_end: 0,
            workspace_len: 0,
        },
    }
}
