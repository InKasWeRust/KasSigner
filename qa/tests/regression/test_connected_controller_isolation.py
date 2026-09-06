#!/usr/bin/env python3
"""keeps controller E2E media-independent and isolates internal setup resets."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]


class ConnectedControllerIsolationTests(unittest.TestCase):
    def test_controller_catalog_never_consumes_real_sd_outside_hil(self) -> None:
        text = (ROOT / "apps/signer-firmware/src/runtime/workflow_tests/connected/mod.rs").read_text()
        self.assertIn('let no_controller_sd = None;', text)
        self.assertIn('let controller_sd = &no_controller_sd;', text)
        self.assertIn('run_all_connected_tranches(ad, boot_display, i2c, controller_sd, delay)', text)
        self.assertIn('let controller_sd = sd_card_type;', text)
        self.assertIn('CONTROLLER SD VIEW FORCED UNAVAILABLE; PHYSICAL SD REMAINS HIL-ONLY', text)
        # Real media is still inspected before the synthetic controller view is selected.
        self.assertLess(text.index('sd_media::prepare_controller_e2e(sd_card_type)'), text.index('let no_controller_sd = None;'))

    def test_internal_setup_uses_authoritative_reset_not_user_home(self) -> None:
        onboarding = (ROOT / "apps/signer-firmware/src/runtime/workflow_tests/connected/onboarding/mod.rs").read_text()
        reset = onboarding.split('pub(super) fn reset_to_storage_choice', 1)[1].split('pub(super) fn exercise', 1)[0]
        self.assertIn('super::reset_tranche_to_home(ad)', reset)
        self.assertNotIn('effects::home(ad)', reset)

        wallet = (ROOT / "apps/signer-firmware/src/runtime/workflow_tests/connected/wallet.rs").read_text()
        entry = wallet.split('pub(super) fn exercise', 1)[1].split('fn wallet_menu_integrity', 1)[0]
        self.assertIn('super::reset_tranche_to_home(ad)', entry)
        self.assertNotIn('effects::home(ad)', entry)

        backup = (ROOT / "apps/signer-firmware/src/runtime/workflow_tests/connected/backup.rs").read_text()
        entry = backup.split('pub(super) fn exercise', 1)[1].split('fn run_stage', 1)[0]
        self.assertIn('super::reset_tranche_to_home(ad)', entry)
        self.assertNotIn('effects::home(ad)', entry)

        root = (ROOT / "apps/signer-firmware/src/runtime/workflow_tests/connected/root.rs").read_text()
        isolation = root.split('fn wallet_and_backup', 1)[1].split('fn return_home', 1)[0]
        self.assertIn('super::reset_tranche_to_home(ad)', isolation)
        self.assertNotIn('effects::home(ad)', isolation)

    def test_actual_home_route_and_connect_cancellation_stay_production_driven(self) -> None:
        root = (ROOT / "apps/signer-firmware/src/runtime/workflow_tests/connected/root.rs").read_text()
        return_home = root.split('fn return_home', 1)[1].split('pub(super) fn home_ok', 1)[0]
        connect = root.split('fn connect_kassee_from_home', 1)[1]
        self.assertIn('crate::runtime::effects::home(ad)', return_home)
        self.assertIn('crate::runtime::effects::home(ad)', connect)
        self.assertIn('OperationKind::ConnectKasSee', connect)

    def test_hil_still_requires_real_sd_media(self) -> None:
        media = (ROOT / "apps/signer-firmware/src/runtime/workflow_tests/connected/sd_media.rs").read_text()
        browser = (ROOT / "apps/signer-firmware/src/runtime/workflow_tests/connected/sd_workflows/browser.rs").read_text()
        self.assertIn('#[cfg(feature = "workflow-hil-auto")]', media)
        self.assertIn('let Some(card_type) = *sd else', media)
        self.assertIn('#[cfg(feature = "workflow-hil-auto")]', browser)
        self.assertIn('if ctx.sd.is_none()', browser)


if __name__ == "__main__":
    unittest.main()
