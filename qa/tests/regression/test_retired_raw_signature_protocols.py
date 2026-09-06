from pathlib import Path
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[3]


class RetiredRawSignatureProtocolTests(unittest.TestCase):
    RETIRED_PATHS = (
        "crates/online-watcher/src/contracts/zk/rng.rs",
        "crates/online-watcher/src/contracts/covenant/script/oracle.rs",
        "crates/online-watcher/src/wasm_api/contracts/covenant/families/oracle.rs",
        "apps/kassee-web/web/js/features/covenants/payload_and_swaps/crowdfund_watcher.js",
        "apps/kassee-web/web/js/features/covenants/recovery/scanner/extended/crowdfund.js",
        "apps/kassee-web/web/html/screens/covenant/create/form/advanced/oracle.html",
        "apps/kassee-web/web/html/screens/covenant/oracle",
    )
    RETIRED_TERMS = (
        "create_covenant_oracle_claim", "create_oracle_heartbeat",
        "oracleSig", "oracleMsgHash", "oracleAttestations",
        "cov-oracle-claim", "cov-oracle-pk",
        "schnorr_sign_ephemeral", "schnorr_sign_with_key",
    )


    def test_retired_protocol_files_are_physically_absent(self) -> None:
        for relative in self.RETIRED_PATHS:
            self.assertFalse((ROOT / relative).exists(), relative)

    def test_retired_protocol_identifiers_are_absent_from_production_surfaces(self) -> None:
        roots = (
            ROOT / "crates/online-watcher/src",
            ROOT / "apps/kassee-web/web/js",
            ROOT / "apps/kassee-web/web/html",
        )
        source = "\n".join(
            path.read_text(errors="ignore")
            for root in roots
            for path in root.rglob("*")
            if path.is_file() and path.suffix in {".rs", ".js", ".html"}
        )
        for term in self.RETIRED_TERMS:
            self.assertNotIn(term, source, term)



    def test_current_crowdfunding_is_restored_without_wallet_raw_hash_signing(self) -> None:
        api = (ROOT / "apps/kassee-web/web/js/wasm/api.js").read_text()
        script = (ROOT / "crates/online-watcher/src/contracts/crowdfund/script.rs").read_text()
        sweep = (ROOT / "crates/online-watcher/src/wasm_api/contracts/zk/crowdfund/sweep.rs").read_text()
        sweep_core = (ROOT / "crates/online-watcher/src/transaction_builder/zk/crowdfund.rs").read_text()
        web = "\n".join(path.read_text(errors="ignore") for path in (ROOT / "apps/kassee-web/web/js").rglob("*.js"))
        for export in ("crowdfund_campaign_id", "covenant_crowdfund", "zk_crowdfund_setup", "zk_crowdfund_prove", "inspect_crowdfund_contributions", "create_crowdfund_sweep"):
            self.assertIn(export, api)
        for term in ("OP_ZK_PRECOMPILE", "OP_TX_INPUT_AMOUNT", "OP_TX_OUTPUT_SPK", "OP_TX_INPUT_SCRIPT_SIG_SUBSTR", "append_campaign_isolation", "CROWDFUND_MAX_SWEEP_FEE_SOMPI"):
            self.assertIn(term, script)
        self.assertNotIn("OP_CHECKSIGFROMSTACK", script)
        self.assertIn("proof::serialize_total(total)? != public_input", sweep_core)
        self.assertIn("crate::transaction_builder::zk::crowdfund::create_crowdfund_sweep_string", sweep)
        self.assertNotIn("proof::serialize_total(total)? != public_input", sweep)
        self.assertNotIn("window._crowdfund", web)
        self.assertNotIn("SIGN HASH", web)

    def test_retired_oracle_v1_rust_symbols_do_not_survive_in_tests_or_production(self) -> None:
        retired_symbols = (
            "build_oracle_json",
            "build_p2sh_oracle_claim_sig_script",
            "build_p2sh_oracle_heartbeat_sig_script",
            "oracle_heartbeat: bool",
            "oracle_heartbeat: false",
        )
        rust_source = "\n".join(
            path.read_text(errors="ignore")
            for path in (ROOT / "crates/online-watcher/src").rglob("*.rs")
        )
        for symbol in retired_symbols:
            self.assertNotIn(symbol, rust_source, symbol)

    def test_live_online_watcher_rng_is_a_declared_wasm_dependency(self) -> None:
        manifest = tomllib.loads((ROOT / "crates/online-watcher/Cargo.toml").read_text())
        dependency = manifest["dependencies"].get("getrandom")
        self.assertIsInstance(dependency, dict)
        self.assertEqual(dependency.get("version"), "0.2")
        self.assertIn("js", dependency.get("features", []))

        for relative in ("Cargo.lock", "apps/kassee-web/Cargo.lock"):
            lock = tomllib.loads((ROOT / relative).read_text())
            package = next(
                item for item in lock["package"]
                if item["name"] == "online-watcher" and item["version"] == "2.0.0"
            )
            dependency_refs = [
                dependency
                for dependency in package.get("dependencies", [])
                if dependency.split()[0] == "getrandom"
            ]
            self.assertEqual(len(dependency_refs), 1, relative)

            locked_getrandom = [
                item for item in lock["package"]
                if item["name"] == "getrandom"
            ]
            self.assertIn("0.2.17", [item["version"] for item in locked_getrandom], relative)

            dependency_ref = dependency_refs[0].split()
            if len(dependency_ref) == 1:
                self.assertEqual(len(locked_getrandom), 1, relative)
                self.assertEqual(locked_getrandom[0]["version"], "0.2.17", relative)
            else:
                self.assertEqual(dependency_ref[1], "0.2.17", relative)

    def test_current_oracle_v1_is_attestation_bound_while_legacy_raw_hash_api_stays_absent(self) -> None:
        api = (ROOT / "apps/kassee-web/web/js/wasm/api.js").read_text()
        family = (ROOT / "crates/online-watcher/src/wasm_api/contracts/covenant/families/oracle_v1.rs").read_text()
        oracle_core = (ROOT / "crates/online-watcher/src/contracts/covenant/oracle_v1.rs").read_text()
        script = (ROOT / "crates/online-watcher/src/contracts/covenant/script/oracle_v1.rs").read_text()
        self.assertIn("covenant_oracle_mb", api)
        self.assertIn("create_oracle_mb_publish", api)
        self.assertIn("covenant_oracle_v1", api)
        self.assertIn("verify_oracle_v1_attestation", api)
        self.assertIn("KasSigner Oracle v1", oracle_core)
        self.assertIn("oracle_covenant_key_id_hex", family)
        self.assertIn("Sha256::digest(statement.as_bytes())", oracle_core)
        self.assertIn("[0u8; 16]", oracle_core)
        self.assertIn("must be distinct", oracle_core)
        self.assertIn("crate::contracts::covenant::oracle_v1::build_json", family)
        self.assertNotIn("Sha256::digest(statement.as_bytes())", family)
        self.assertIn("expected_message_commitment", script)
        self.assertIn("OP_CHECKSIGFROMSTACK", script)
        self.assertNotIn("create_covenant_oracle_claim", api)
        self.assertNotIn("create_oracle_heartbeat", api)


if __name__ == "__main__":
    unittest.main()
