import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(errors="strict")


class CredentialKdfHardwareMemoryTests(unittest.TestCase):

    def test_psram_region_comes_from_initialized_esp_hal_and_external_allocator(self) -> None:
        psram = read("apps/signer-firmware/src/services/memory/psram.rs")
        main = read("apps/signer-firmware/src/main.rs")
        for token in (
            "esp_hal::psram::psram_raw_parts(peripheral)",
            "MemoryCapability::External.into()",
            "HEAP.alloc_caps",
            "HEAP.add_region",
            "has_valid_provenance",
            "initialize_or_halt(&peripherals.PSRAM)",
        ):
            self.assertIn(token, psram + main)
        combined = (psram + main).lower()
        self.assertNotIn("0x3c", combined)
        self.assertNotIn("0x3d", combined)
        self.assertNotIn("psram_allocator!", combined)

    def test_production_argon2_uses_exact_psram_workspace_and_zeroizes_it(self) -> None:
        core = read("crates/offline-signer/src/crypto/password_kdf.rs")
        firmware = read("apps/signer-firmware/src/services/memory/password_kdf.rs")
        for token in (
            "workspace_block_count",
            "WORKSPACE_BLOCK_BYTES",
            "checked_mul(WORKSPACE_BLOCK_BYTES)",
            "Argon2Workspace::allocate(parameters)",
            "workspace.validate_provenance()?",
            "derive_key_32_with_workspace",
            "request.workspace.len() != params.block_count()",
            "zeroize_workspace(request.workspace)",
            "shared_signer::bytes::zeroize_bytes(self.as_mut_bytes())",
        ):
            self.assertIn(token, core + firmware + read("apps/signer-firmware/src/services/memory/psram.rs"))
        self.assertNotIn("Vec::<PasswordKdfBlock>", firmware)
        self.assertNotRegex(firmware, re.compile(r"m_cost_kib\s*[-/]"))

    def test_current_firmware_kdf_calls_cannot_bypass_psram_adapter(self) -> None:
        memory_adapter = ROOT / "apps/signer-firmware/src/services/memory/password_kdf.rs"
        offenders = []
        for path in (ROOT / "apps/signer-firmware/src").rglob("*.rs"):
            if path == memory_adapter:
                continue
            for line in path.read_text(errors="ignore").splitlines():
                if "password_kdf::derive_key_32" not in line:
                    continue
                if "crate::services::memory::password_kdf::derive_key_32" in line:
                    continue
                offenders.append(path.relative_to(ROOT).as_posix())
                break
        self.assertEqual(offenders, [])

    def test_diagnostic_integrity_and_kat_use_same_provenance_checked_workspace(self) -> None:
        firmware = read("apps/signer-firmware/src/services/memory/password_kdf.rs")
        bench = read("apps/signer-firmware/src/diagnostics/argon2_bench.rs")
        for token in (
            "full_buffer_integrity_test",
            "write_volatile",
            "read_volatile",
            "derive_benchmark_key_32_with_workspace",
            "runtime_psram=0x",
            "workspace=0x",
            "workspace_bytes={}",
            "provenance={}",
            "integrity={}",
            "vector={}",
            "watchdog_ok={}",
            "probe_largest_allocatable",
        ):
            self.assertIn(token, firmware + bench)

    def test_both_hardware_families_keep_argon2_diagnostic_builds(self) -> None:
        matrix = read("tools/build/firmware/build_matrix.py")
        self.assertIn('FirmwareBuild("waveshare,argon2-bench", PSRAM_OCTAL)', matrix)
        self.assertIn('FirmwareBuild("m5stack,argon2-bench")', matrix)


if __name__ == "__main__":
    unittest.main()
