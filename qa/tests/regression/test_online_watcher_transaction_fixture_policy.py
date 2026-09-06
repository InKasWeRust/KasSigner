from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[3]
WATCHER = ROOT / "crates/online-watcher/src"


class OnlineWatcherTransactionFixturePolicyTests(unittest.TestCase):
    def test_standard_send_fixture_preserves_non_dust_change(self) -> None:
        source = (WATCHER / "transaction_builder/unit_tests/mod.rs").read_text()
        test = source.split(
            "fn standard_send_preparation_and_utxo_paths_are_host_testable()", 1
        )[1].split("\n#[test]", 1)[0]
        self.assertIn("utxo(0xb2, 1, 40_000_000)", test)
        self.assertNotIn("utxo(0xb2, 1, 30_000_000)", test)

    def test_contract_success_fixtures_use_economic_sompi_amounts(self) -> None:
        shipping = (
            WATCHER
            / "wasm_api/contracts/covenant/families/escrow/shipping/unit_tests/mod.rs"
        ).read_text()
        self.assertIn("utxo(1, 200_000_000)", shipping)
        self.assertIn("build_deposit(&plan, 50_000_000, 10_000_000)", shipping)

        allowance = (
            WATCHER / "wasm_api/contracts/covenant/families/unit_tests/mod.rs"
        ).read_text()
        self.assertIn("40_000_000,\n        1_000_000,\n        &utxos", allowance)
        self.assertNotIn("100_000_000,\n        1_000_000,\n        &utxos", allowance)

    def test_global_thread_fixtures_use_global_scripts_and_valid_continuations(self) -> None:
        source = (
            WATCHER
            / "wasm_api/contracts/covenant/global_thread/unit_tests/mod.rs"
        ).read_text()
        self.assertIn("build_global_allowance_script", source)
        self.assertIn("build_global_spending_limit_script", source)
        self.assertIn('"amount": 100_000_000', source)
        self.assertIn("withdrawal: 40_000_000", source)
        self.assertIn("fee: 1_000_000", source)



if __name__ == "__main__":
    unittest.main()
