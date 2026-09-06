from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[3]
FIRMWARE = ROOT / "apps/signer-firmware/src"


class FirmwareErrorUtf8SafetyTests(unittest.TestCase):
    def read(self, relative: str) -> str:
        return (ROOT / relative).read_text(encoding="utf-8", errors="strict")

    def test_all_error_variants_delegate_to_one_shared_surface(self):
        errors = self.read("apps/signer-firmware/src/ui/screens/signing/errors.rs")
        self.assertEqual(errors.count("fn draw_error_surface("), 1)
        for method in ("draw_rejected_screen", "draw_error_back_screen", "draw_transient_error_screen", "draw_entropy_error_screen", "draw_tx_error_screen", "draw_recoverable_error_screen_with_action", "draw_fatal_error_screen"):
            body = errors[errors.index(f"pub fn {method}"):]
            body = body[:body.index("\n    }") + 6]
            self.assertIn("draw_error_surface", body, method)
        recoverable = errors[errors.index("pub fn draw_recoverable_error_screen("):]
        recoverable = recoverable[:recoverable.index("\n    }") + 6]
        self.assertIn("draw_recoverable_error_screen_with_action", recoverable)
        self.assertEqual(errors.count('measure_header("ERROR")'), 1)

    def test_visible_error_actions_match_real_input_semantics(self):
        errors = self.read("apps/signer-firmware/src/ui/screens/signing/errors.rs")
        feedback = self.read("apps/signer-firmware/src/runtime/interactions/support/feedback.rs")
        navigation = self.read("apps/signer-firmware/src/ui/redraw/navigation.rs")
        presentation = self.read("apps/signer-firmware/src/runtime/presentation/mod.rs")
        self.assertIn('ErrorAction::Acknowledge { ready: true, label: "OK" }', errors)
        self.assertIn("ERROR_OK_ZONE.contains(x, y)", presentation)
        self.assertIn('AppState::Rejected => boot_display.draw_rejected_screen("TX Cancelled")', navigation)
        self.assertIn("display.draw_transient_error_screen(message);", feedback)
        self.assertNotIn("display.draw_rejected_screen(message);", feedback)
        self.assertIn("ErrorAction::Back", errors)
        self.assertIn("ErrorAction::None", errors)

    def test_operation_order_violation_is_restart_required_and_non_dismissible(self):
        presentation = self.read("apps/signer-firmware/src/runtime/presentation/mod.rs")
        errors = self.read("apps/signer-firmware/src/ui/screens/signing/errors.rs")
        violation = presentation[presentation.index("fn operation_order_violation"):presentation.index("fn now_millis", presentation.index("fn operation_order_violation"))]
        fatal_renderer = errors[errors.index("pub fn draw_fatal_error_screen"): ]
        fatal_renderer = fatal_renderer[:fatal_renderer.index("\n    }") + 6]
        self.assertIn('message: "Operation lifecycle ordering failure. Restart required."', violation)
        self.assertIn('code: "OP-ORDER-01"', violation)
        self.assertIn("ModalState::FatalError { .. } => true", presentation)
        self.assertIn("ErrorAction::None", fatal_renderer)
        self.assertNotIn("Acknowledge", fatal_renderer)

    def test_rejected_renderer_is_reserved_for_rejected_state(self):
        callers = []
        for path in FIRMWARE.rglob("*.rs"):
            text = path.read_text(encoding="utf-8", errors="ignore")
            if "draw_rejected_screen(" not in text:
                continue
            relative = path.relative_to(ROOT).as_posix()
            if relative.endswith("ui/screens/signing/errors.rs"):
                continue
            callers.append(relative)
        self.assertEqual(callers, ["apps/signer-firmware/src/ui/redraw/navigation.rs"])

    def test_stable_and_fatal_errors_do_not_advertise_fake_ok(self):
        export = self.read("apps/signer-firmware/src/ui/redraw/export.rs")
        qr = self.read("apps/signer-firmware/src/ui/redraw/signing/qr.rs")
        device = self.read("apps/signer-firmware/src/ui/redraw/device.rs")
        destructive = self.read("apps/signer-firmware/src/runtime/destructive/mod.rs")
        self.assertIn("draw_error_back_screen", export)
        self.assertIn("draw_error_back_screen", qr)
        self.assertIn("draw_fatal_error_screen", device)
        self.assertIn("draw_transient_error_screen", destructive)

    def test_utf8_clipping_uses_character_boundaries(self):
        typography = self.read("apps/signer-firmware/src/ui/display/typography.rs")
        self.assertIn("pub(crate) fn truncate_chars", typography)
        self.assertIn("text.char_indices()", typography)
        self.assertIn("nth(max_chars)", typography)
        for relative in (
            "apps/signer-firmware/src/ui/display/boot.rs",
            "apps/signer-firmware/src/ui/screens/device/pop_it.rs",
            "apps/signer-firmware/src/runtime/signing/verification.rs",
        ):
            source = self.read(relative)
            self.assertIn("truncate_chars", source, relative)
        errors = self.read("apps/signer-firmware/src/ui/screens/signing/errors.rs")
        self.assertIn("fn wrap_error_text", errors)
        self.assertIn("text.char_indices()", errors)
        self.assertNotIn("truncate_chars", errors)

    def test_no_arbitrary_str_byte_prefix_truncation_remains(self):
        unsafe = re.compile(r"&(?:message|reason|commit)\[\.\.[0-9]+\]")
        hits = []
        for path in FIRMWARE.rglob("*.rs"):
            source = path.read_text(encoding="utf-8", errors="ignore")
            if unsafe.search(source):
                hits.append(path.relative_to(ROOT).as_posix())
        self.assertEqual(hits, [])


if __name__ == "__main__":
    unittest.main()
