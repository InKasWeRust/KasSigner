#!/usr/bin/env python3
"""release-qualification, normal-flash, and security-evidence regressions."""
from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
COVERAGE_PATH = ROOT / "qa/checks/firmware/production_e2e_coverage.py"


def load_coverage():
    spec = importlib.util.spec_from_file_location("production_e2e_coverage_v612", COVERAGE_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ReleaseFlashSecurityTests(unittest.TestCase):
    def test_release_inventory_is_closed_without_lowering_connected_threshold(self) -> None:
        coverage = load_coverage()
        manifest, errors = coverage.build_manifest(ROOT)
        self.assertEqual(errors, [])
        self.assertEqual(coverage.LEVELS["connected"], 2)
        self.assertEqual(manifest["item_coverage_summary"]["total"], 504)
        self.assertEqual(manifest["item_coverage_summary"]["backlog"], 0)
        self.assertGreaterEqual(manifest["coverage_summary"]["states"]["total"], 176)
        self.assertGreaterEqual(manifest["coverage_summary"]["menu_items"]["total"], 73)
        self.assertGreaterEqual(manifest["coverage_summary"]["actions"]["total"], 198)
        self.assertEqual(manifest["release_qualification"]["incomplete_item_count"], 0)
        self.assertTrue(manifest["release_qualification"]["ready"])
        self.assertEqual(coverage.release_qualification_errors(manifest), [])

    def test_workflow_test_controller_is_not_production_surface(self) -> None:
        coverage = load_coverage()
        actions = set(coverage.production_actions(ROOT))
        self.assertFalse(any("controllers/workflow_tests.rs::" in action for action in actions))
        self.assertEqual(len(coverage.EXCLUDED_BASELINE_ACTIONS), 4)
        self.assertTrue(coverage.EXCLUDED_BASELINE_ACTIONS.isdisjoint(actions))

    def test_firmware_update_action_remains_explicitly_owned(self) -> None:
        coverage = load_coverage()
        manifest, errors = coverage.build_manifest(ROOT)
        self.assertEqual(errors, [])
        retired = "apps/signer-firmware/src/runtime/interactions/stego/mode.rs::handle_firmware_update"
        self.assertNotIn(retired, manifest["surface"]["actions"])
        action = "apps/signer-firmware/src/runtime/interactions/settings/mod.rs::handle_advanced_navigation"
        entry = manifest["surface"]["actions"][action]
        self.assertIn("connected-firmware-update-usb-guidance", entry["implemented_scenarios"])
        self.assertGreaterEqual(coverage.LEVELS[entry["highest_level"]], coverage.LEVELS["connected"])

    def test_normal_flash_build_does_not_import_workflow_auto_only_rejection(self) -> None:
        nav = (ROOT / "apps/signer-firmware/src/runtime/navigation/mod.rs").read_text()
        tx = (ROOT / "apps/signer-firmware/src/runtime/navigation/transaction.rs").read_text()
        self.assertIn('#[cfg(feature = "workflow-test-auto")]\npub(crate) use transaction::reject_active_signing;', nav)
        self.assertIn('#[cfg(feature = "workflow-test-auto")]\npub(crate) fn reject_active_signing', tx)
        ordinary_reexport = nav.split("mod transaction;", 1)[1].split('#[cfg(feature = "workflow-test-auto")]', 1)[0]
        self.assertNotIn("reject_active_signing", ordinary_reexport)

    def test_firmware_update_workflow_helpers_do_not_warn_in_normal_flash_build(self) -> None:
        facade = (ROOT / "apps/signer-firmware/src/services/fw_update/mod.rs").read_text()
        self.assertNotIn("verify_image", facade)
        self.assertFalse((ROOT / "apps/signer-firmware/src/services/fw_update/verification.rs").exists())
        self.assertFalse((ROOT / "apps/signer-firmware/src/services/fw_update/layout.rs").exists())

    def test_transaction_confirmation_has_no_unreviewed_impossible_panic(self) -> None:
        source = (ROOT / "apps/signer-firmware/src/runtime/navigation/transaction.rs").read_text()
        block = source.split("pub(crate) fn confirm_transaction", 1)[1].split("fn authorize_signing", 1)[0]
        self.assertNotIn("unreachable!", block)
        self.assertIn("if !matches!(cursor, 0 | 1 | 2)", block)
        self.assertIn("match cursor", block)
        self.assertIn("0 => authorize_signing(ad)", block)
        self.assertIn("1 => reject_signing(ad)", block)

    def test_qa_exhaustiveness_scenario_owns_every_current_production_surface(self) -> None:
        coverage = load_coverage()
        surface = coverage.discover_surface(ROOT)
        scenarios = json.loads((ROOT / coverage.SCENARIOS).read_text())["scenarios"]
        scenario = next(item for item in scenarios if item["id"] == "qa-production-exhaustiveness-gate")
        self.assertEqual(set(scenario["states"]), set(surface["states"]))
        self.assertEqual(set(scenario["menu_items"]), set(surface["menu_items"]))
        self.assertEqual(set(scenario["actions"]), set(surface["actions"]))
        self.assertEqual(set(scenario["items"]), {f"E2E-099-{index:02d}" for index in range(1, 6)})

    def test_entropy_and_export_sections_have_explicit_qa_owners(self) -> None:
        scenarios = {
            item["id"]: item
            for item in json.loads((ROOT / "qa/config/workflow/production_e2e_scenarios.json").read_text())["scenarios"]
        }
        entropy = scenarios["qa-mandatory-entropy-matrix"]
        export = scenarios["qa-export-menu-routing-matrix"]
        self.assertEqual(entropy["level"], "qa")
        self.assertEqual(len(entropy["items"]), 15)
        self.assertIn("SeedEntropyUnavailable", entropy["states"])
        self.assertEqual(export["level"], "qa")
        self.assertEqual(len(export["items"]), 5)
        self.assertIn("ExportChoice", export["states"])
        export_source = (ROOT / "apps/signer-firmware/src/runtime/interactions/export/menus/root.rs").read_text()
        graph = (ROOT / "apps/signer-firmware/src/runtime/navigation/ui_graph/menus.rs").read_text()
        for state in ("SeedBackupMenu", "WatchOnlyMenu", "SigningKeysMenu", "StegoModeSelect"):
            self.assertIn(state, graph)
        self.assertIn("effects::menu_select(ad, item)", export_source)
        self.assertIn("route!(SeedList)", export_source)


if __name__ == "__main__":
    unittest.main()
