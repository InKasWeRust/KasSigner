from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[3]


class FundedWasmMergeExportBoundaryTests(unittest.TestCase):
    def test_funded_broadcast_uses_supported_sdk_completion_boundary(self):
        funded = (ROOT / "qa/checks/integration/funded_testnet_e2e_case.mjs").read_text()
        api = (ROOT / "apps/kassee-web/web/js/wasm/api.js").read_text()
        shell = (ROOT / "apps/kassee-web/src/lib.rs").read_text()

        self.assertIn("wasm.kassigner_sdk_complete(", funded)
        self.assertIn("const merged = signed.psktHex", funded)
        self.assertNotIn("wasm.pskt_merge_signed_kspt", funded)
        self.assertIn("'kassigner_sdk_complete'", api)
        self.assertIn(
            "export function kassigner_sdk_complete(...args) { return invoke('kassigner_sdk_complete', args); }",
            api,
        )
        self.assertIn("pub fn kassigner_sdk_complete(", shell)

    def test_sdk_signed_pskt_json_field_matches_authored_and_funded_consumers(self):
        sdk = (ROOT / "crates/kassigner-sdk/src/lib.rs").read_text()
        broadcast = (ROOT / "apps/kassee-web/web/js/features/transactions/send/broadcast.js").read_text()
        funded = (ROOT / "qa/checks/integration/funded_testnet_e2e_case.mjs").read_text()

        self.assertIn("#[serde(rename_all = \"camelCase\")]", sdk)
        self.assertIn("pub pskt_hex: String", sdk)
        self.assertIn("openPsktReview(signed.psktHex)", broadcast)
        self.assertNotIn("signed.pskbHex", broadcast)
        self.assertIn("const merged = signed.psktHex", funded)

    def test_funded_wasm_calls_are_owned_by_stable_facade(self):
        api = (ROOT / "apps/kassee-web/web/js/wasm/api.js").read_text()
        funded = (ROOT / "qa/checks/integration/funded_testnet_e2e_case.mjs").read_text()
        inventory_match = re.search(
            r"const\s+GENERATED_WASM_EXPORTS\s*=\s*Object\.freeze\(\[([\s\S]*?)\]\);",
            api,
        )
        self.assertIsNotNone(inventory_match)
        inventory = set(re.findall(r"['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]", inventory_match.group(1)))
        calls = set(re.findall(r"\bwasm\.([A-Za-z_][A-Za-z0-9_]*)\s*\(", funded))
        calls.discard("init")
        self.assertFalse(
            calls - inventory,
            f"funded E2E calls missing from stable WASM facade: {sorted(calls - inventory)}",
        )


if __name__ == "__main__":
    unittest.main()
