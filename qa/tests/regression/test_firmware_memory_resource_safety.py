from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[3]
FIRMWARE_CHECKS = ROOT / "qa/checks/firmware"
sys.path.insert(0, str(FIRMWARE_CHECKS))
from stack_budget_contract import check_stack_budget_contract  # noqa: E402


class FirmwareMemoryResourceSafetyTests(unittest.TestCase):
    def read(self, relative: str) -> str:
        return (ROOT / relative).read_text(errors="ignore")

    def test_transaction_inputs_have_product_cap_everywhere(self):
        constants = self.read("crates/offline-signer/src/transaction/model/constants.rs")
        model = self.read("crates/offline-signer/src/transaction/model/transaction.rs")
        compact = self.read("crates/offline-signer/src/transaction/kspt/wire_adapter.rs")
        validation = self.read("crates/offline-signer/src/transaction/kspt/validation.rs")
        standard = self.read("crates/offline-signer/src/transaction/std_pskt/parser/global.rs")
        serializer = self.read("crates/offline-signer/src/transaction/std_pskt/serializer/mod.rs")
        self.assertIn("SIGNER_CAPABILITIES.max_inputs as usize", constants)
        for source in (model, compact, validation, standard, serializer):
            self.assertIn("MAX_INPUTS", source)
        self.assertIn("count > MAX_INPUTS", model)
        self.assertIn("PsktError::TooManyInputs", validation)
        self.assertIn("PskError::TooManyInputs", serializer)


    def test_stego_allocations_have_psram_headroom_and_cpu_ceiling(self):
        carrier = self.read("apps/signer-firmware/src/runtime/interactions/stego/export_confirm/carrier.rs")
        importer = self.read("apps/signer-firmware/src/runtime/interactions/stego/import_decrypt.rs")
        psram = self.read("apps/signer-firmware/src/services/memory/psram.rs")
        picture = self.read("crates/signer-firmware-core/src/backup/stego_picture/mod.rs")
        codec = self.read("crates/signer-firmware-core/src/backup/stego_picture/codec.rs")
        self.assertIn("STEGO_WORK_HEADROOM", carrier)
        self.assertIn("free_bytes() < planned", carrier)
        self.assertGreaterEqual(carrier.count("allocate_with_reserve"), 3)
        self.assertIn("IMPORT_HEADROOM", importer)
        self.assertIn("allocate_with_reserve", importer)
        self.assertIn("size.checked_add(reserve)", psram)
        self.assertIn("PictureError::AllocationFailed", picture)
        self.assertIn("const MAX_DECODE_BLOCKS", codec)
        self.assertIn("PictureError::WorkLimitExceeded", codec)

    def test_sd_kib_buffers_are_heap_backed_and_not_returned_by_value(self):
        loader = self.read("apps/signer-firmware/src/runtime/interactions/sd/imports/payload_detection.rs")
        selected = self.read("apps/signer-firmware/src/runtime/interactions/sd/imports/selected_file/mod.rs")
        kpub = self.read("apps/signer-firmware/src/runtime/interactions/sd/exports/kpub.rs")
        self.assertNotIn("Result<([u8; 1024], usize)", loader)
        self.assertIn("buffer: &mut [u8]", loader)
        self.assertIn("memory::zeroed_bytes(1024)", selected)
        self.assertIn("memory::zeroed_bytes(1024)", kpub)

    def test_production_infallible_allocation_and_stack_pressure_gate_is_green(self):
        errors = []
        check_stack_budget_contract(errors)
        self.assertEqual(errors, [])
        orchestrator = self.read("qa/checks/firmware/check_firmware_source_contracts.py")
        self.assertIn("check_stack_budget_contract(errors)", orchestrator)

    def test_compiler_emitted_whole_image_stack_budget_is_mandatory(self):
        checker = self.read("qa/checks/firmware/compiled_stack_budget.py")
        linux = self.read("tools/build/firmware/build_with_hash.sh")
        windows = self.read("tools/build/firmware/build_with_hash.ps1")
        self.assertIn('MAX_FIRST_PARTY_FRAME = 8 * 1024', checker)
        self.assertIn('MAX_ANY_FRAME = 16 * 1024', checker)
        self.assertIn('.stack_sizes', checker)
        for source in (linux, windows):
            self.assertIn('emit-stack-sizes', source)
            self.assertIn('compiled_stack_budget.py', source)


if __name__ == "__main__":
    unittest.main()
