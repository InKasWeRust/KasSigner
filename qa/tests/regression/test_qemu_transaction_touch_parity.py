from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]
QEMU_TARGET = ROOT / "apps/signer-firmware/src/qemu/validation/target.rs"
REDUCER = ROOT / "crates/signer-firmware-core/src/presentation/transaction.rs"
CORE_TESTS = ROOT / "crates/signer-firmware-core/src/unit_tests/firmware_flow_tests.rs"
MENUS = ROOT / "apps/signer-firmware/src/runtime/navigation/ui_graph/menus.rs"


class QemuTransactionTouchParityTests(unittest.TestCase):
    def test_qemu_confirm_vectors_match_production_reducer_and_menu_order(self) -> None:
        qemu = QEMU_TARGET.read_text(errors="strict")
        reducer = REDUCER.read_text(errors="strict")
        core_tests = CORE_TESTS.read_text(errors="strict")
        menus = MENUS.read_text(errors="strict")

        self.assertIn("(15..=105).contains(&x)", reducer)
        self.assertIn("TransactionEffect::ConfirmChoice(0)", reducer)
        self.assertIn("(215..=305).contains(&x)", reducer)
        self.assertIn("TransactionEffect::ConfirmChoice(1)", reducer)
        self.assertIn("(115..=205).contains(&x)", reducer)
        self.assertIn("TransactionEffect::ConfirmChoice(2)", reducer)

        self.assertIn('ui_menu!(ConfirmTx, 0, "Confirm"', menus)
        self.assertIn('ui_menu!(ConfirmTx, 1, "Cancel"', menus)
        self.assertIn('ui_menu!(ConfirmTx, 2, "Inspect"', menus)

        for source in (qemu, core_tests):
            self.assertIn("TransactionScreen::Confirm, 60, 208, false", source)
            self.assertIn("TransactionEffect::ConfirmChoice(0)", source)
            self.assertIn("TransactionScreen::Confirm, 260, 208, false", source)
            self.assertIn("TransactionEffect::ConfirmChoice(1)", source)
            self.assertIn("TransactionScreen::Confirm, 160, 208, false", source)
            self.assertIn("TransactionEffect::ConfirmChoice(2)", source)
            self.assertIn("TransactionScreen::Confirm, 0, 0, true", source)
            self.assertIn("TransactionEffect::ConfirmBack", source)

        self.assertNotIn("TransactionScreen::Confirm, 100, 200, false", qemu)

    def test_qemu_reducer_failure_is_actionable(self) -> None:
        qemu = QEMU_TARGET.read_text(errors="strict")
        self.assertIn("[QEMU TEST] DETAIL: transaction touch reducer", qemu)
        self.assertIn("expected={}", qemu)
        self.assertIn("actual={}", qemu)
        for label in (
            "guide-derive",
            "confirm-left",
            "confirm-right",
            "confirm-center",
            "confirm-back",
            "review-back",
        ):
            self.assertIn(f'"{label}"', qemu)


if __name__ == "__main__":
    unittest.main()
