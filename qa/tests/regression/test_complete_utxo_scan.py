from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[3]


class KasSeeCompleteUtxoScanTests(unittest.TestCase):
    def test_coin_control_uses_complete_batched_outpoint_union(self):
        query = (ROOT / "crates/online-watcher/src/network/queries/utxos.rs").read_text()
        self.assertIn("COMPLETE_SCAN_BATCH_ADDRESSES: usize = 8", query)
        self.assertIn("pub async fn fetch_all_complete", query)
        self.assertIn("addresses.chunks(COMPLETE_SCAN_BATCH_ADDRESSES)", query)
        self.assertIn("let key = (entry.tx_id.clone(), entry.index);", query)
        self.assertIn("if seen.insert(key)", query)
        self.assertIn("let entries = fetch_for_addresses(websocket_url, batch).await?;", query)

        facade = (ROOT / "crates/online-watcher/src/facade.rs").read_text()
        wasm = (ROOT / "crates/online-watcher/src/wasm_api/wallet/account.rs").read_text()
        api = (ROOT / "apps/kassee-web/web/js/wasm/api.js").read_text()
        self.assertIn("synchronize_utxos_complete", facade)
        self.assertIn("pub async fn fetch_utxos_complete", wasm)
        self.assertIn("'fetch_utxos_complete'", api)
        self.assertIn("export function fetch_utxos_complete", api)

        coin_control = (ROOT / "apps/kassee-web/web/js/features/wallet/core/coin_control_utxos.js").read_text()
        self.assertIn("fetch_utxos_complete", coin_control)
        self.assertIn("export async function fetchCoinControlUtxos", coin_control)
        for relative in (
            "apps/kassee-web/web/js/features/wallet/tools/address_views.js",
            "apps/kassee-web/web/js/features/transactions/send/compose/send_form.js",
        ):
            source = (ROOT / relative).read_text()
            self.assertIn("fetchCoinControlUtxos", source, relative)

    def test_coin_control_reports_scan_scope_and_keeps_32_input_ceiling(self):
        view = (ROOT / "apps/kassee-web/web/js/features/wallet/tools/address_views.js").read_text()
        self.assertIn("current UTXO", view)
        self.assertIn("addresses scanned", view)
        self.assertIn("signerMaxInputs()", view)

        deep = (ROOT / "qa/checks/web/web_wallet_deep_paths.test.mjs").read_text()
        self.assertIn("Array.from({length:33}", deep)
        self.assertIn("consolidateSelection.size,32", deep)
        self.assertIn("at most 32 selected inputs", deep)
        self.assertNotIn("Max 8", deep)

    def test_multi_entry_wrpc_reply_is_regressed(self):
        response_tests = (ROOT / "crates/online-watcher/src/network/unit_tests/utxo_response.rs").read_text()
        self.assertIn("utxo_response_preserves_every_entry_in_multi_entry_reply", response_tests)
        self.assertRegex(response_tests, r"repeated_entry_response\([^\n]+, 5\)")
        self.assertIn("assert_eq!(entries.len(), 5);", response_tests)


if __name__ == "__main__":
    unittest.main()
