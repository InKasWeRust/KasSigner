import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = ROOT / "qa/checks/security/watcher_only_apps.py"
SPEC = importlib.util.spec_from_file_location("watcher_only_apps", MODULE_PATH)
watcher_only_apps = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(watcher_only_apps)


class WatcherOnlyAppsGateTests(unittest.TestCase):
    def test_current_repository_satisfies_watch_only_boundary(self):
        self.assertEqual(watcher_only_apps.audit(), [])

    def test_detectors_reject_wallet_private_key_identifiers(self):
        for sample in (
            "const privateKey = generate();",
            "state.mySecretKey = value;",
            "let xprv = imported;",
            "const sk = wallet.secret;",
        ):
            with self.subTest(sample=sample):
                self.assertIsNotNone(watcher_only_apps.BROWSER_PRIVATE_IDENTIFIERS.search(sample))
        for sample in (
            "let private_key = bytes;",
            "let signer_secret = scalar;",
            "use k256::SecretKey;",
        ):
            with self.subTest(sample=sample):
                self.assertIsNotNone(watcher_only_apps.RUST_PRIVATE_IDENTIFIERS.search(sample))

    def test_retired_hot_api_names_are_explicitly_denied(self):
        self.assertIn("adaptor_generate_keypair", watcher_only_apps.RETIRED_HOT_APIS)
        self.assertIn("tagged_vault_keygen", watcher_only_apps.RETIRED_HOT_APIS)
        self.assertIn("tagged_vault_spend(", watcher_only_apps.RETIRED_DIRECT_VAULT_CALLS)


if __name__ == "__main__":
    unittest.main()
