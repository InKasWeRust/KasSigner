from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[3]
FW = ROOT / "apps/signer-firmware"


class WorkflowUiTouchParityTests(unittest.TestCase):
    def source(self, relative: str) -> str:
        return (ROOT / relative).read_text(encoding="utf-8")


    def test_production_and_workflow_share_physical_back_classification(self):
        dispatch = self.source("apps/signer-firmware/src/runtime/event_loop/dispatch.rs")
        touch = self.source("apps/signer-firmware/src/runtime/touch_dispatch.rs")
        receive = self.source("apps/signer-firmware/src/runtime/workflow_tests/connected/receive.rs")
        self.assertIn("physical_touch_input(x, y)", dispatch)
        self.assertIn("is_back_tap(x, y)", touch)
        self.assertIn("workflow_touch_input", touch)
        self.assertIn("TOUCH PARITY FAIL", touch)
        self.assertNotIn("TouchInput::new(160, 110, true)", receive)
        self.assertIn("zone_center(crate::ui::layout::BACK_ZONE)", receive)

    def test_address_renderer_hit_testing_and_e2e_share_zones(self):
        layout = self.source("apps/signer-firmware/src/ui/layout.rs")
        renderer = self.source("apps/signer-firmware/src/ui/screens/wallet/address/receive.rs")
        handler = self.source("apps/signer-firmware/src/runtime/interactions/export/address.rs")
        e2e = self.source("apps/signer-firmware/src/runtime/workflow_tests/connected/receive.rs")
        for name in (
            "ADDRESS_CHAIN_ZONE", "ADDRESS_QR_ZONE", "ADDRESS_PREV_ZONE",
            "ADDRESS_INDEX_ZONE", "ADDRESS_NEXT_ZONE",
        ):
            self.assertIn(name, layout)
            self.assertIn(name, renderer)
            self.assertIn(name, handler)
        self.assertIn("ADDRESS_CHAIN_ZONE", e2e)
        self.assertIn("ADDRESS_QR_ZONE", e2e)
        self.assertNotIn("ctx.touch(160, 185)", e2e)

    def test_error_ok_renderer_handler_and_e2e_share_zone(self):
        layout = self.source("apps/signer-firmware/src/ui/layout.rs")
        errors = self.source("apps/signer-firmware/src/ui/screens/signing/errors.rs")
        presentation = self.source("apps/signer-firmware/src/runtime/presentation/mod.rs")
        rejected = self.source("apps/signer-firmware/src/runtime/interactions/menu/qr/presentation.rs")
        signing = self.source("apps/signer-firmware/src/runtime/workflow_tests/connected/signing/mod.rs")
        self.assertIn("ERROR_OK_ZONE: TouchZone = TouchZone::new(72, 178, 176, 42)", layout)
        self.assertIn("ERROR_OK_ZONE", errors)
        self.assertIn("ERROR_OK_ZONE.contains(x, y)", presentation)
        self.assertIn("ERROR_OK_ZONE.contains(x, y)", rejected)
        self.assertIn("zone_center(crate::ui::layout::ERROR_OK_ZONE)", signing)

    def test_workflow_ui_cannot_override_production_layout(self):
        allowed = {
            "runtime_evidence.rs",
            "redraw/navigation/developer.rs",
            "layout.rs",  # workflow menu visibility only; production geometry is unconditional
        }
        forbidden_features = ("workflow-runtime-auto", "workflow-test-auto", "workflow-hil-auto")
        offenders = []
        for path in (FW / "src/ui").rglob("*.rs"):
            rel = path.relative_to(FW / "src/ui").as_posix()
            text = path.read_text(encoding="utf-8")
            if any(feature in text for feature in forbidden_features) and rel not in allowed:
                offenders.append(rel)
        self.assertEqual(offenders, [], f"workflow-only UI layout branches: {offenders}")

    def test_literal_workflow_back_flags_match_production_back_zone(self):
        pattern = re.compile(r"TouchInput::new\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(true|false)\s*\)")
        mismatches = []
        for path in (FW / "src/runtime/workflow_tests/connected").rglob("*.rs"):
            text = path.read_text(encoding="utf-8")
            for match in pattern.finditer(text):
                x, y = int(match.group(1)), int(match.group(2))
                claimed = match.group(3) == "true"
                actual = x < 49 and y < 49
                if claimed != actual:
                    line = text[:match.start()].count("\n") + 1
                    mismatches.append(f"{path.relative_to(FW)}:{line}: ({x},{y}) claimed_back={claimed}")
        self.assertEqual(mismatches, [], "workflow forged physical Back events:\n" + "\n".join(mismatches))

    def test_qr_back_chrome_uses_shared_top_left_back_origin(self):
        layout = self.source("apps/signer-firmware/src/ui/layout.rs")
        boot = self.source("apps/signer-firmware/src/ui/display/boot.rs")
        chrome = self.source("apps/signer-firmware/src/ui/screens/components/qr_brightness.rs")
        self.assertIn("BACK_ZONE: TouchZone = TouchZone::new(0, 0, 49, 49)", layout)
        self.assertIn("Image::new(&back, Point::new(0, 0))", boot)
        self.assertIn("self.draw_back_button();", chrome)


if __name__ == "__main__":
    unittest.main()
