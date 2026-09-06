from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[3]


class CriticalDomainCoveragePolicyTests(unittest.TestCase):
    def assert_contains(self, relative_path: str, fragments: tuple[str, ...]) -> None:
        text = (ROOT / relative_path).read_text(encoding="utf-8")
        for fragment in fragments:
            self.assertIn(fragment, text, f"{relative_path} must retain {fragment}")

    def test_transaction_construction_has_native_model_and_contract_tests(self) -> None:
        self.assert_contains(
            "crates/offline-signer/src/transaction/model/unit_tests/mod.rs",
            (
                "transaction_model_constructors_totals_and_reset_are_covered",
                "redeem_storage_covers_empty_inline_pool_and_capacity_errors",
                "multisig_labels_slots_and_store_capacity_are_covered",
            ),
        )
        self.assert_contains(
            "crates/online-watcher/src/contracts/unit_tests/construction.rs",
            (
                "critical_contract_script_builders_and_costs_are_covered",
                "savings_scripts_cover_unconditional_goal_deadline_and_recovery_layouts",
            ),
        )
        self.assert_contains(
            "crates/online-watcher/src/wasm_api/contracts/vault/unit_tests/mod.rs",
            (
                "vault_genesis_material_and_identifiers_are_public_network_bound_data",
                "vault_pskb_plans_require_hardware_signing_and_preserve_covenant_binding",
                "vault_watch_only_request_and_response_boundaries_are_exact",
                "watcher must not synthesize a wallet signature",
            ),
        )

    def test_signing_has_entry_point_sighash_and_anti_klepto_tests(self) -> None:
        self.assert_contains(
            "crates/offline-signer/src/transaction/kspt/signing/unit_tests/mod.rs",
            (
                "single_key_public_entry_points_cover_response_and_in_place_signing",
                "raw_account_context_and_public_multisig_wrappers_are_covered",
            ),
        )
        self.assert_contains(
            "crates/offline-signer/src/transaction/unit_tests/sighash_tests.rs",
            ("component_hashes_cover_all_sighash_and_covenant_payload_branches",),
        )
        self.assert_contains(
            "crates/offline-signer/src/crypto/unit_tests/anti_klepto_tests.rs",
            (
                "anti_klepto_rejects_invalid_key_points_and_scalar_boundaries",
                "host_scalar_material",
            ),
        )
        self.assert_contains(
            "crates/online-watcher/src/protocol/pskt/anti_klepto.rs",
            ("verify_host_transcript_wire", "schnorr::bip340_verify"),
        )

    def test_key_handling_has_raw_roundtrip_recovery_and_validation_tests(self) -> None:
        self.assert_contains(
            "crates/offline-signer/src/derivation/unit_tests/bip32_tests.rs",
            ("extended_private_raw_roundtrip_and_raw_pubkey_helpers_are_covered",),
        )
        self.assert_contains(
            "crates/offline-signer/src/derivation/unit_tests/xpub_tests.rs",
            (
                "canonical_kpub_wrappers_and_binary_qr_import_are_covered",
                "account_xprv_public_wrappers_and_invalid_import_are_covered",
            ),
        )
        self.assert_contains(
            "crates/online-watcher/src/privacy/stealth/unit_tests/mod.rs",
            ("stealth_key_and_tweak_helpers_cover_roundtrip_and_validation",),
        )


    def test_browser_recovery_has_persisted_coverage_and_health_integration(self) -> None:
        self.assert_contains(
            "qa/checks/web/run_web_recovery_coverage.py",
            (
                "NODE_V8_COVERAGE",
                "web_recovery_coverage.test.mjs",
                "minimum-function",
                "v8-coverage.json",
            ),
        )
        self.assert_contains(
            "qa/checks/quality/crap/policy.json",
            (
                '"supplemental_coverage": "browser_recovery"',
                '"label": "wallet recovery"',
            ),
        )
        self.assert_contains(
            "scripts/linux/quality/crap.sh",
            (
                "generate_browser_recovery_coverage",
                "--browser-recovery-coverage",
            ),
        )
        self.assert_contains(
            "qa/checks/web/web_recovery_coverage.test.mjs",
            (
                "rebuildCrowdfund",
                "rebuildOracleV1",
                "rebuildPrivateSwap",
                "campaign identity",
                "forbidden transient or secret material",
            ),
        )

    def test_global_thread_types_stay_in_their_owned_submodules(self) -> None:
        self.assert_contains(
            "crates/online-watcher/src/transaction_builder/pskb/mod.rs",
            (
                "pub(crate) mod global_thread;",
                "mod thread_policy;",
                "pub use thread_policy::GlobalThreadPolicy;",
            ),
        )
        self.assert_contains(
            "crates/online-watcher/src/transaction_builder/pskb/thread_policy.rs",
            (
                "pub struct GlobalThreadPolicy",
                "pub(crate) enum GlobalThreadFamily",
            ),
        )
        self.assert_contains(
            "crates/online-watcher/src/transaction_builder/unit_tests/mod.rs",
            (
                "global_thread::{",
                "plan_global_thread_topup, plan_global_thread_withdrawal, GlobalThreadPlanError,",
                "GlobalThreadTopupRequest, GlobalThreadWithdrawalRequest,",
                "GlobalThreadPolicy,",
            ),
        )
        planner = (
            ROOT / "crates/online-watcher/src/transaction_builder/pskb/global_thread.rs"
        ).read_text(encoding="utf-8")
        self.assertNotIn("pub struct GlobalThreadPolicy", planner)
        self.assertNotIn("enum GlobalThreadFamily", planner)

    def test_no_std_error_string_assertions_import_to_string(self) -> None:
        self.assert_contains(
            "crates/offline-signer/src/crypto/unit_tests/schnorr_tests.rs",
            (
                "#[cfg(test)]\nuse alloc::string::ToString;",
                "SchnorrError::InvalidPrivateKey.to_string()",
            ),
        )

    def test_message_digest_known_answer_uses_declared_first_party_hex_encoder(self) -> None:
        path = ROOT / "crates/offline-signer/src/crypto/unit_tests/message_tests.rs"
        text = path.read_text(encoding="utf-8")
        self.assertIn("shared_signer::bytes::encode_lower_hex", text)
        self.assertIn("8801296b169c712eab1cfeb5f0710e361c130de7195adc1a1f7ce7d380cd0ebd", text)
        self.assertNotIn("hex::", text)


if __name__ == "__main__":
    unittest.main()
