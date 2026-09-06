import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]


class CryptoMutationAndHostCoverageHardeningTests(unittest.TestCase):
    def test_covenant_derivation_removes_equivalent_operator_mutants_and_pins_vectors(self):
        source = (ROOT / "crates/offline-signer/src/derivation/covenant.rs").read_text()
        tests = (ROOT / "crates/offline-signer/src/derivation/covenant/unit_tests/mod.rs").read_text()

        for literal in (
            "const COVENANT_PURPOSE: u32 = 0x8000_2720;",
            "const KASPA_COIN_TYPE: u32 = 0x8001_b207;",
            "const COVENANT_BINDING_ACCOUNT: u32 = 0x8000_0001;",
            "const PRIVATE_SWAP_CLAIM_ACCOUNT: u32 = 0x8000_0003;",
            "const PRIVATE_SWAP_BINDING_ACCOUNT: u32 = 0x8000_0004;",
            "const PRIVATE_SWAP_ADAPTOR_ACCOUNT: u32 = 0x8000_0005;",
        ):
            self.assertIn(literal, source)
        self.assertIn("derive_child(&current, HARDENED + index)?", source)
        self.assertNotIn("derive_child(&current, HARDENED | index)?", source)
        self.assertIn("covenant_derivation_and_binding_match_exact_independent_vectors", tests)
        self.assertIn("0xe3, 0xfa, 0x23, 0x5d", tests)
        self.assertIn("0x88, 0x53, 0x22, 0xf5", tests)
        self.assertIn("cancellation_probe[0] ^= 1;", tests)
        self.assertIn("cancellation_probe[1] ^= 1;", tests)

    def test_remaining_crypto_mutation_relations_have_exact_or_directional_tests(self):
        stealth = (ROOT / "crates/online-watcher/src/privacy/stealth/unit_tests/mod.rs").read_text()
        adaptor = (ROOT / "crates/offline-signer/src/crypto/unit_tests/adaptor_tests.rs").read_text()
        kspt = (ROOT / "crates/offline-signer/src/transaction/kspt/signing/covenant.rs").read_text()

        self.assertIn("stealth_tweak_masks_the_high_index_bit_against_an_exact_vector", stealth)
        self.assertIn("assert_eq!(index, 0x5f00_ed1a);", stealth)
        self.assertIn("host_nonce_relation_requires_addition_of_the_committed_host_scalar", adaptor)
        self.assertIn("assert!(!points_equal(&added, &subtracted));", adaptor)
        self.assertNotIn("0x20 => checked_advance(offset, 33, script.len())", kspt)
        self.assertIn("0x01..=0x4b => checked_advance(offset, 1 + opcode as usize, script.len())", kspt)

    def test_canonical_kspt_relay_and_live_kassee_adapters_keep_direct_host_coverage(self):
        protocol_relay = (ROOT / "crates/kassigner-protocol/src/pskt/relay.rs").read_text()
        protocol_fields = (ROOT / "crates/kassigner-protocol/src/pskt/relay_fields.rs").read_text()
        protocol_tests = (ROOT / "crates/kassigner-protocol/src/unit_tests/mod.rs").read_text()
        kassee_tests = (ROOT / "crates/online-watcher/src/protocol/pskt/unit_tests/kspt_bridge.rs").read_text()
        bridge_root = ROOT / "crates/online-watcher/src/protocol/pskt/kspt_bridge"

        self.assertFalse((bridge_root / "encoder.rs").exists())
        self.assertFalse((bridge_root / "merger/unit_tests").exists())
        self.assertFalse((bridge_root / "relay/unit_tests").exists())
        for needle in ("InputFields::parse", "collect_signatures", "apply_ms45", "apply_derivations", "apply_covenants"):
            self.assertIn(needle, protocol_relay)
        for needle in ("parse_utxo_fields", "parse_outpoint", "collect_signatures", "parse_ms45"):
            self.assertIn(needle, protocol_fields)
        self.assertIn("derivation_helpers_own_kassigner_proprietary_encoding", protocol_tests)
        for name in (
            "relay_v4_encodes_explicit_networks_and_derivation_hints",
            "hd45_relay_and_signature_merge_preserve_derivation_metadata_end_to_end",
        ):
            self.assertIn(name, kassee_tests)
        self.assertIn("merge_signed_kspt_into_pskb", kassee_tests)

    def test_shared_covenant_and_policy_branch_vectors_cover_boolean_boundaries(self):
        covenant = (ROOT / "crates/shared-signer/src/covenant_sign/unit_tests/mod.rs").read_text()
        advanced = (ROOT / "crates/signer-firmware-core/src/unit_tests/advanced_policy_tests.rs").read_text()
        for name in (
            "request_length_enum_and_review_helpers_cover_all_boundaries",
            "response_shape_helpers_cover_true_and_false_sides_directly",
            "message_and_known_binding_helpers_cover_registered_and_unregistered_shapes",
            "envelope_wire_failures_cover_short_circuit_sides_without_relaxing_types",
            "oracle_v1_binding_rejects_every_layout_and_commitment_boundary",
        ):
            self.assertIn(name, covenant)
        self.assertIn("REQUEST_MAGIC.to_vec()", covenant)
        self.assertIn("REVEAL_MAGIC.to_vec()", covenant)
        self.assertIn("assert!(!is_message(&response_prefix));", covenant)
        for name in (
            "signing_window_boundaries_and_policy_clock_errors_cover_short_circuits",
            "weekly_parser_covers_case_whitespace_delimiters_and_adjacent_nonoverlap",
            "datetime_day_month_and_leap_boundaries_are_exact",
            "requires_clock_and_unsorted_window_short_circuits_are_explicit",
        ):
            self.assertIn(name, advanced)

        private_swap = (ROOT / "crates/shared-signer/src/covenant_sign/private_swap/unit_tests/mod.rs").read_text()
        parsing = (ROOT / "crates/signer-firmware-core/src/unit_tests/firmware_decisions/parsing.rs").read_text()
        self.assertIn("private_swap_wire_short_circuits_cover_each_parse_boundary", private_swap)
        self.assertIn("covenant_prefix_classifiers_cover_short_circuit_and_covi_sides", parsing)


if __name__ == "__main__":
    unittest.main()
