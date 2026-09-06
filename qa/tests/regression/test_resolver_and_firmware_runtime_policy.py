from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


class ResolverAndFirmwareRuntimePolicyTests(unittest.TestCase):
    def test_public_resolver_matches_rusty_kaspa_browser_security_policy(self):
        resolver = read("apps/kassee-web/web/js/core/node/resolver.js")
        config = read("apps/kassee-web/web/js/core/config/network.js")
        self.assertIn("globalThis.location?.protocol === 'https:' ? 'tls' : 'any'", resolver)
        self.assertIn("/${security}/wrpc/borsh", resolver)
        self.assertIn("if (security === 'tls') return url.startsWith('wss://')", resolver)
        self.assertIn("url.startsWith('ws://') || url.startsWith('wss://')", resolver)
        self.assertIn("All resolvers failed for ${networkState.network} (${security})", resolver)
        for host in (
            "maxim.kaspa.stream", "troy.kaspa.stream", "sean.kaspa.stream", "eric.kaspa.stream",
            "jake.kaspa.green", "mark.kaspa.green", "adam.kaspa.green", "liam.kaspa.green",
            "noah.kaspa.blue", "ryan.kaspa.blue", "jack.kaspa.blue", "luke.kaspa.blue",
            "john.kaspa.red", "mike.kaspa.red", "paul.kaspa.red", "alex.kaspa.red",
        ):
            self.assertIn(host, config)

    def test_runtime_hil_uses_usb_guidance_and_a_real_signing_scanner(self):
        runtime = read("apps/signer-firmware/src/runtime/workflow_tests/connected/runtime_gui.rs")
        firmware_runtime = read("apps/signer-firmware/src/runtime/workflow_tests/connected/runtime_gui/firmware.rs")
        runtime_contract = runtime + "\n" + firmware_runtime
        host = read("qa/checks/firmware/run_workflow_tests.py")
        self.assertIn('const NAME: &str = "firmware-update-guidance-render";', runtime_contract)
        self.assertIn("ad.navigation.app.state != AppState::FirmwareUpdateReady", runtime_contract)
        self.assertIn("NavigationOwner::Settings", runtime_contract)
        self.assertNotIn("Firmware Update scanner did not retain Settings ownership", runtime_contract)
        self.assertIn('const NAME: &str = "scan-qr-camera";', runtime_contract)
        self.assertIn("open_root(ad, 1, AppState::ScanQR)", runtime_contract)
        self.assertIn("NavigationOwner::Signing", runtime_contract)
        self.assertIn("run_camera_cycle", runtime_contract)
        self.assertIn('"firmware-update-guidance-render"', host)
        self.assertIn('"scan-qr-camera"', host)
        self.assertNotIn('"firmware-update-camera"', host)

    def test_firmware_update_production_route_remains_usb_guidance(self):
        menus = read("apps/signer-firmware/src/runtime/navigation/ui_graph/menus.rs")
        routes = read("apps/signer-firmware/src/runtime/navigation/menu_reducer/routes.rs")
        self.assertIn('"settings.advanced.firmware_update", FirmwareUpdateReady', menus)
        self.assertIn('(AdvancedMenu, 0) => FirmwareUpdateReady', routes)
        self.assertNotIn('"settings.advanced.firmware_update", ScanQR', menus)


if __name__ == "__main__":
    unittest.main()
