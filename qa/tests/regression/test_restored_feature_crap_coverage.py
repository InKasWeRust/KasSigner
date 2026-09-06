from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(errors="replace")


class RestoredFeatureCrapCoverageTests(unittest.TestCase):
    def test_backup_header_and_private_swap_claim_are_decomposed_without_policy_changes(self):
        backup = read("apps/signer-firmware/src/services/backup/container.rs")
        framing = read("crates/offline-signer/src/crypto/container_framing.rs")
        claim = read("crates/offline-signer/src/transaction/private_swap.rs")
        self.assertIn("container_framing::parse_backup_header", backup)
        self.assertIn("fn derive_reader_key", backup)
        for helper in (
            "parse_current_backup_header", "parse_legacy_backup_header",
            "parse_backup_kind", "parse_backup_len", "copy_nonzero",
        ):
            self.assertIn(f"fn {helper}", framing)
        for helper in (
            "validate_claim_transaction_shape", "validate_claim_policy", "validate_claim_output",
        ):
            self.assertIn(f"fn {helper}", claim)

    def test_restored_crypto_paths_have_native_unit_coverage_outside_production_watcher_files(self):
        required = {
            "crates/shared-signer/src/covenant_sign/private_swap/unit_tests/mod.rs": (
                "every_private_swap_request_kind_roundtrips", "every_private_swap_response_kind_roundtrips",
            ),
            "crates/offline-signer/src/transaction/private_swap/unit_tests/mod.rs": (
                "canonical_private_swap_script_roundtrips", "claim_sighash_enforces_transaction",
            ),
            "crates/online-watcher/src/protocol/private_swap/adaptor/unit_tests/mod.rs": (
                "public_adaptor_math_verifies_completes_extracts", "adaptor_verifiers_fail_closed",
            ),
            "crates/online-watcher/src/wasm_api/contracts/covenant/families/oracle_v1/unit_tests/mod.rs": (
                "oracle_attestation_decode_and_redeem_binding", "oracle_builder_rejects",
            ),
            "crates/online-watcher/src/transaction_builder/zk/unit_tests/mod.rs": (
                "crowdfund_helpers_have_host_native_coverage", "fetch_contributions(&[], \"unused\")",
            ),
            "crates/online-watcher/src/transaction_builder/covenant/unit_tests/mod.rs": (
                "allowance_prepare_material_has_host_native_coverage", "prepare_material(",
            ),
            "crates/online-watcher/src/wasm_api/protocol/covenant_sign/unit_tests/mod.rs": (
                "covenant_anti_klepto_host_verifier", "verify_covenant_anti_klepto_string",
            ),
        }
        for relative, terms in required.items():
            source = read(relative)
            for term in terms:
                self.assertIn(term, source, f"{relative}: {term}")

    def test_private_swap_script_int_vectors_distinguish_op_zero_from_pushed_zero(self):
        tests = read("crates/offline-signer/src/transaction/private_swap/unit_tests/mod.rs")
        self.assertIn("assert_eq!(read_script_int(&[OP_0], &mut pos), Ok(0));", tests)
        self.assertIn("&[1, 0][..]", tests)
        self.assertNotIn("&[0u8][..]", tests)

    def test_residual_restoration_crap_warnings_are_decomposed_or_directly_covered(self):
        oracle = read("crates/online-watcher/src/contracts/covenant/oracle_v1.rs")
        oracle_wasm = read("crates/online-watcher/src/wasm_api/contracts/covenant/families/oracle_v1.rs")
        private_wire = read("crates/shared-signer/src/covenant_sign/private_swap.rs")
        private_validation = read("crates/shared-signer/src/covenant_sign/private_swap/validation.rs")
        covenant = read("crates/shared-signer/src/covenant_sign/script_int.rs")
        claim = read("crates/offline-signer/src/transaction/private_swap.rs")
        scripts = read("crates/online-watcher/src/protocol/pskt/scripts/unit_tests/mod.rs")
        for term in ("fn checked_inputs", "fn bound_statement"):
            self.assertIn(term, oracle)
        self.assertIn("crate::contracts::covenant::oracle_v1::build_json", oracle_wasm)
        self.assertNotIn("fn checked_inputs", oracle_wasm)
        self.assertNotIn("fn bound_statement", oracle_wasm)
        for term in ("fn validate_request_prefix", "fn validate_request_payload_length", "fn parse_bool"):
            self.assertIn(term, private_validation)
        for term in ("fn canonical_u64_push_data", "fn canonical_positive_u64_bytes", "fn decode_script_u64"):
            self.assertIn(term, covenant)
        for term in ("fn parse_claim_salt", "fn parse_claim_pubkey", "fn parse_claim_destination", "fn parse_claim_fee_policy"):
            self.assertIn(term, claim)
        self.assertIn("private_swap_claim_sigscript_requires_one_canonical_schnorr_signature", scripts)
        self.assertIn("assert_eq!(script[0], 65)", scripts)
        self.assertIn("assert_eq!(script[65], 0x01)", scripts)
        self.assertIn("assert_eq!(script[66], 0x51)", scripts)


if __name__ == "__main__":
    unittest.main()
