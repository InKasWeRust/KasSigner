from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[3]
CRAP_CHECK_DIR = ROOT / "qa/checks/quality/crap"
sys.path.insert(0, str(CRAP_CHECK_DIR))

from source_complexity import function_decisions  # noqa: E402


REPORTED_FUNCTIONS = {
    "crates/online-watcher/src/transaction_builder/pskb/application.rs": {
        "prepare_from_utxos",
    },
    "crates/online-watcher/src/transaction_builder/zk/merkle.rs": {
        "build_merkle_whitelist_spend",
    },
    "crates/online-watcher/src/transaction_builder/covenant/allowance.rs": {
        "build_allowance_withdrawal",
    },
    "crates/online-watcher/src/transaction_builder/oracle_publish/request.rs": {
        "parse_string",
    },
    "crates/online-watcher/src/wasm_api/contracts/oracle/genesis.rs": {
        "build_oracle_genesis_json",
    },
    "crates/online-watcher/src/wasm_api/contracts/covenant/families/escrow/shipping/address.rs": {
        "build_shipping_escrow_json",
    },
    "crates/online-watcher/src/wasm_api/contracts/oracle/publish.rs": {
        "parse_publish_request",
    },
    "crates/online-watcher/src/transaction_builder/covenant/shipping/plan.rs": {
        "parse_plan_request",
    },
    "crates/online-watcher/src/transaction_builder/covenant/global_thread.rs": {
        "build_withdrawal",
    },
    "crates/online-watcher/src/transaction_builder/covenant/vault/genesis.rs": {
        "prepare_vault_genesis",
        "build_vault_genesis_pskb",
        "build_vault_genesis_wire",
    },
    "crates/online-watcher/src/transaction_builder/covenant/vault/spend.rs": {
        "build_vault_spend_pskb",
        "build_vault_spend_with_material",
        "prepare",
        "fetch_and_prepare",
        "finalize_vault_spend",
    },
}


LATEST_CRAP_REFACTOR_LIMITS = {
    "crates/online-watcher/src/protocol/pskt/consensus/finalizer.rs": {
        "finalize_to_consensus": 6,
        "parse": 6,
    },
    "crates/online-watcher/src/protocol/pskt/review/parser.rs": {
        "parse_pskt_object": 8,
    },
    "crates/online-watcher/src/transaction_builder/planning/amounts.rs": {
        "storage_mass_estimate": 7,
    },
    "crates/online-watcher/src/transaction_builder/covenant/builder.rs": {
        "adjusted_send": 4,
    },
    "crates/online-watcher/src/transaction_builder/covenant/allowance.rs": {
        "build_remote_result": 2,
        "prepare_material": 10,
        "require_utxos": 3,
        "required_amount": 2,
        "ensure_funded": 3,
        "checked_return_amount": 3,
        "decode_allowance_scripts": 2,
    },
    "crates/online-watcher/src/transaction_builder/pskb/thread_request.rs": {
        "build_withdrawal": 2,
        "prepare_withdrawal_material": 8,
        "finalize_withdrawal": 3,
        "prepare_topup_material": 6,
        "build_topup": 3,
    },
    "crates/online-watcher/src/protocol/pskt/anti_klepto.rs": {
        "same_transaction_body": 4,
    },
    "crates/online-watcher/src/protocol/pskt/kspt_bridge/merger.rs": {
        "merge_signed_kspt_into_pskb": 2,
        "signed_network": 8,
        "find_network_trailer": 2,
    },
}

CHECKED_ARITHMETIC_ERROR_PATHS = (
    "crates/online-watcher/src/account/balance.rs",
    "crates/online-watcher/src/transaction_builder/covenant/fee.rs",
    "crates/online-watcher/src/transaction_builder/covenant/builder.rs",
    "crates/online-watcher/src/transaction_builder/planning/amounts.rs",
    "crates/online-watcher/src/transaction_builder/covenant/vault/spend.rs",
    "crates/online-watcher/src/wasm_api/contracts/vault/split.rs",
    "crates/online-watcher/src/transaction_builder/covenant/payjoin.rs",
    "crates/online-watcher/src/transaction_builder/covenant/shipping/withdraw.rs",
    "crates/online-watcher/src/contracts/shipping_escrow/construction.rs",
    "crates/online-watcher/src/protocol/pskt/review/parser.rs",
    "crates/online-watcher/src/contracts/shipping_escrow/script.rs",
)

REMOVED_COMBINED_FETCHERS = {
    "crates/online-watcher/src/wasm_api/contracts/oracle/publish/context.rs": "fetch_sources",
    "crates/online-watcher/src/wasm_api/contracts/covenant/families/escrow/shipping/plan.rs": "fetch_plan_sources",
    "crates/online-watcher/src/wasm_api/contracts/covenant/families/payjoin/claim.rs": "fetch_sources",
}


class OnlineWatcherCrapRegressionFixTests(unittest.TestCase):


    def test_allowance_prepare_material_keeps_validation_branches_in_small_helpers(self) -> None:
        source = (
            ROOT
            / "crates/online-watcher/src/transaction_builder/covenant/allowance.rs"
        ).read_text()
        body = source.split("pub(super) fn prepare_material(", 1)[1].split(
            "\n}\n\nfn require_utxos", 1
        )[0]
        self.assertNotIn("if ", body)
        for helper in ("require_utxos", "ensure_funded", "checked_return_amount"):
            self.assertIn(f"fn {helper}", source)

    def test_latest_checked_arithmetic_refactors_stay_below_reported_complexity(self) -> None:
        for relative, limits in LATEST_CRAP_REFACTOR_LIMITS.items():
            source = (ROOT / relative).read_text()
            records = {record.name: record for record in function_decisions(source, relative)}
            for name, maximum in limits.items():
                self.assertIn(name, records, f"missing {relative}::{name}")
                self.assertLessEqual(
                    records[name].decisions,
                    maximum,
                    f"{relative}::{name} reintroduced the known CRAP regression",
                )

    def test_checked_arithmetic_static_errors_do_not_create_coverage_only_closures(self) -> None:
        for relative in CHECKED_ARITHMETIC_ERROR_PATHS:
            source = (ROOT / relative).read_text()
            self.assertNotIn(
                '.ok_or_else(|| "',
                source,
                f"{relative} reintroduced a static error closure counted as a host function",
            )

    def test_zero_coverage_combined_network_fetchers_were_removed(self) -> None:
        for relative, name in REMOVED_COMBINED_FETCHERS.items():
            source = (ROOT / relative).read_text()
            names = {record.name for record in function_decisions(source, relative)}
            self.assertNotIn(name, names, f"{relative}::{name} reintroduced")

    def test_merkle_result_has_no_test_only_production_diagnostics(self) -> None:
        source = (
            ROOT
            / "crates/online-watcher/src/transaction_builder/zk/merkle.rs"
        ).read_text()
        result = source.split("pub(crate) struct PreparedMerkleSpend", 1)[1].split("}", 1)[0]
        signature = source.split("fn encode_merkle_spend(", 1)[1].split(") ->", 1)[0]
        self.assertNotIn("total:", result)
        self.assertNotIn("fee:", result)
        self.assertNotIn("input_count:", result)
        self.assertNotIn("_total:", signature)
        self.assertNotIn("_fee:", signature)

    def test_native_string_boundaries_exist_for_wasm_error_paths(self) -> None:
        required = {
            "crates/online-watcher/src/wasm_api/protocol/pskb_planning.rs":
                "prepare_sweep_from_utxos_string",
            "crates/online-watcher/src/wasm_api/contracts/oracle/publish.rs":
                "parse_publish_request_string",
        }
        for relative, symbol in required.items():
            self.assertIn(symbol, (ROOT / relative).read_text())


if __name__ == "__main__":
    unittest.main()
