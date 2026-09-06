from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[3]
ONLINE = ROOT / "crates/online-watcher/src"
WASM = ONLINE / "wasm_api"


def read(relative: str) -> str:
    return (ROOT / relative).read_text()


class WasmBusinessBoundaryTests(unittest.TestCase):

    def test_wasm_contracts_do_not_own_transaction_or_covenant_business(self) -> None:
        forbidden_literals = (
            "network::submission",
            "transaction_builder::selection",
            "PskbPlan {",
            "PskbInputPlan::",
            "PskbOutputPlan::",
            "PskbGlobalPlan::",
            "SweepInputPolicy::",
            "encode_pskt_value",
            '"previousOutpoint"',
            '"partialSigs"',
            '"covenantBinding"',
            "getrandom::getrandom",
            "script_to_address(",
            "address_to_script_pubkey(",
        )
        checked = re.compile(r"\.checked_(?:add|sub|mul)\s*\(")
        script_builder = re.compile(r"(?:build|create)_[A-Za-z0-9_]*(?:script|redeem)\s*\(")
        roots = (
            WASM / "contracts/covenant",
            WASM / "contracts/vault",
            WASM / "contracts/oracle",
            WASM / "contracts/zk",
        )
        for root in roots:
            for path in root.rglob("*.rs"):
                if "unit_tests" in path.parts:
                    continue
                source = path.read_text(errors="replace")
                code = "\n".join(
                    line for line in source.splitlines()
                    if not line.lstrip().startswith("//")
                )
                self.assertFalse(checked.search(code), path.as_posix())
                self.assertFalse(script_builder.search(code), path.as_posix())
                for token in forbidden_literals:
                    self.assertNotIn(token, code, path.as_posix())

    def test_network_backed_planning_is_outside_wasm(self) -> None:
        for path in WASM.rglob("*.rs"):
            if "unit_tests" in path.parts:
                continue
            relative = path.relative_to(WASM).as_posix()
            source = path.read_text(errors="replace")
            if relative == "wallet/watcher.rs":
                self.assertIn("network::queries", source)
            else:
                self.assertNotIn("network::queries", source, relative)

    def test_extracted_domain_and_application_owners_are_browser_neutral(self) -> None:
        owners = (
            "crates/online-watcher/src/contracts/covenant/construction/mod.rs",
            "crates/online-watcher/src/contracts/oracle/genesis.rs",
            "crates/online-watcher/src/contracts/shipping_escrow/construction.rs",
            "crates/online-watcher/src/transaction_builder/pskb/application.rs",
            "crates/online-watcher/src/transaction_builder/covenant/sweep.rs",
            "crates/online-watcher/src/transaction_builder/covenant/vault/spend.rs",
            "crates/online-watcher/src/transaction_builder/covenant/global_thread.rs",
            "crates/online-watcher/src/transaction_builder/oracle_publish/plan.rs",
            "crates/online-watcher/src/transaction_builder/zk/crowdfund.rs",
            "crates/online-watcher/src/transaction_builder/zk/merkle.rs",
        )
        for relative in owners:
            source = read(relative)
            self.assertNotIn("JsValue", source, relative)
            self.assertNotIn("wasm_bindgen", source, relative)
            self.assertNotIn("web_sys", source, relative)
            self.assertNotIn("js_sys", source, relative)

    def test_representative_wasm_exports_are_thin_delegates(self) -> None:
        delegates = {
            "crates/online-watcher/src/wasm_api/contracts/vault/spend.rs":
                "crate::transaction_builder::covenant::vault::spend",
            "crates/online-watcher/src/wasm_api/contracts/covenant/families/payjoin.rs":
                "crate::contracts::covenant::construction::payjoin::build_json",
            "crates/online-watcher/src/wasm_api/contracts/covenant/families/escrow/timelocked.rs":
                "crate::contracts::covenant::construction::escrow::build_timelocked_json",
            "crates/online-watcher/src/wasm_api/contracts/oracle/genesis.rs":
                "crate::contracts::oracle::genesis",
            "crates/online-watcher/src/wasm_api/contracts/oracle/publish.rs":
                "crate::transaction_builder::oracle_publish",
            "crates/online-watcher/src/wasm_api/contracts/zk/crowdfund/sweep.rs":
                "crate::transaction_builder::zk::crowdfund",
        }
        for relative, owner in delegates.items():
            self.assertIn(owner, read(relative), relative)


if __name__ == "__main__":
    unittest.main()
