#!/usr/bin/env python3
"""KasSee sealed-state contracts, including multisig branch discovery."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[3]
WEB_JS = ROOT / "apps/kassee-web/web/js"
STATE_ROOT = WEB_JS / "app/state"


class KasSeeMultisigDiscoveryStateTests(unittest.TestCase):
    def test_sealed_state_declares_multisig_discovery_fields(self) -> None:
        network = (STATE_ROOT / "core/network_state.js").read_text()
        transaction = (STATE_ROOT / "core/transaction_state.js").read_text()
        multisig = (WEB_JS / "features/transactions/pskt_multisig/multisig.js").read_text()
        self.assertIn("export const networkState = Object.seal({", network)
        self.assertIn("'msBranchScan': null", network)
        self.assertIn("export const transactionState = Object.seal({", transaction)
        self.assertIn("'msBranchSelectedUtxos': []", transaction)
        self.assertIn("networkState.msBranchScan = result", multisig)
        self.assertIn("transactionState.msBranchSelectedUtxos = []", multisig)

    def test_discovery_renders_addresses_and_never_succeeds_silently(self) -> None:
        multisig = (WEB_JS / "features/transactions/pskt_multisig/multisig.js").read_text()
        branch = (ROOT / "crates/online-watcher/src/transaction_builder/multisig/branch.rs").read_text()
        self.assertIn("setDiscoveryStatus(`Scanning 45' cosigner branch S${cosigner}…`, 'loading')", multisig)
        self.assertIn("next_receive_address", multisig)
        self.assertIn("next_change_address", multisig)
        self.assertIn("result.utxos?.[0]?.address || result.next_receive_address || ''", multisig)
        self.assertIn("addressPrefix(networkState.network).replace(/:$/, '')", multisig)
        self.assertIn("regular wallet balance is separate", multisig)
        self.assertIn("syncCosignerBranch(descriptor)", multisig)
        self.assertIn("\"next_receive_address\": next_receive_address", branch)
        self.assertIn("\"next_change_address\": next_change_address", branch)

    def test_every_direct_assignment_to_a_sealed_state_has_a_declared_field(self) -> None:
        sealed: dict[str, tuple[Path, set[str]]] = {}
        pattern = re.compile(r"export const (\w+) = Object\.seal\(\{([\s\S]*?)\}\);")
        key_pattern = re.compile(r"['\"]([A-Za-z_$][\w$]*)['\"]\s*:")
        for path in STATE_ROOT.rglob("*.js"):
            match = pattern.search(path.read_text())
            if match:
                name, body = match.groups()
                sealed[name] = (path, set(key_pattern.findall(body)))

        errors: list[str] = []
        sources = [(path, path.read_text(errors="ignore")) for path in WEB_JS.rglob("*.js")]
        for name, (state_path, declared) in sealed.items():
            assignment = re.compile(rf"\b{re.escape(name)}\.([A-Za-z_$][\w$]*)\s*=")
            for source_path, source in sources:
                for field in assignment.findall(source):
                    if field not in declared:
                        errors.append(
                            f"{source_path.relative_to(ROOT)} assigns undeclared sealed field "
                            f"{name}.{field}; declare it in {state_path.relative_to(ROOT)}"
                        )
        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
