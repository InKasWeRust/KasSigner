from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(errors="replace")


class UniversalCovenantSigningTests(unittest.TestCase):
    def test_covenant_derivation_path_is_rustdoc_text_not_a_doctest(self) -> None:
        derivation = read("crates/offline-signer/src/derivation/covenant.rs")
        self.assertIn("//! ```text\n//! m/10016'/111111'/0'/i0'/i1'/i2'/i3'/i4'\n//! ```", derivation)
        self.assertNotIn("//!     m/10016'/111111'/0'/i0'/i1'/i2'/i3'/i4'", derivation)

    def test_no_std_unit_tests_import_vec_explicitly(self) -> None:
        unit_tests = read("crates/shared-signer/src/covenant_sign/unit_tests/mod.rs")
        self.assertIn("use std::vec::Vec;", unit_tests)

    def test_wallet_raw_hash_signing_stays_absent_and_covenant_path_is_isolated(self) -> None:
        firmware = "\n".join(path.read_text(errors="replace") for path in (ROOT / "apps/signer-firmware/src").rglob("*.rs"))
        derivation = read("crates/offline-signer/src/derivation/covenant.rs")
        service = read("apps/signer-firmware/src/services/covenant_sign.rs")
        self.assertNotIn("SIGN HASH", firmware.upper().replace("COVENANT SIGN", ""))
        self.assertIn("COVENANT_PURPOSE", derivation)
        self.assertIn("COVENANT_ACCOUNT", derivation)
        self.assertIn("COVENANT_BINDING_ACCOUNT", derivation)
        self.assertIn("HARDENED + index", derivation)
        self.assertNotIn("HARDENED | index", derivation)
        self.assertIn("[u32; 5]", derivation)
        self.assertIn("derive_active_seed", service)
        self.assertNotIn("derive_active_private_key", service)
        self.assertNotIn("derive_active_account_key", service)
        self.assertIn("provisional_covenant_signature", service)
        self.assertIn("finalize_covenant_signature", service)
        self.assertIn("verify_host_secret", service)
        self.assertIn("verify_nonce_relation", service)
        self.assertNotIn("pub fn sign_covenant_commitment", derivation)

    def test_request_kind_wire_decoder_is_present_and_fail_closed(self) -> None:
        protocol = read("crates/shared-signer/src/covenant_sign/mod.rs")
        unit_tests = read("crates/shared-signer/src/covenant_sign/unit_tests/mod.rs")
        self.assertIn("fn parse_kind(value: u8) -> Result<RequestKind, ProtocolError>", protocol)
        for mapping in (
            "0 => Ok(RequestKind::KeyInfo)",
            "1 => Ok(RequestKind::Known)",
            "2 => Ok(RequestKind::Opaque)",
            "3 => Ok(RequestKind::Bind)",
        ):
            self.assertIn(mapping, protocol)
        self.assertIn("_ => Err(ProtocolError::InvalidKind)", protocol)
        self.assertIn("request_kind_decoder_rejects_unknown_wire_values", unit_tests)

    def test_envelope_keeps_transport_metadata_separate_from_exact_commitment(self) -> None:
        protocol = read("crates/shared-signer/src/covenant_sign/mod.rs")
        js = read("apps/kassee-web/web/js/features/covenants/signing/protocol.js")
        derivation = read("crates/offline-signer/src/derivation/covenant.rs")
        self.assertIn('*b"CVSG"', protocol)
        self.assertIn('*b"CVSR"', protocol)
        self.assertIn('*b"CVRV"', protocol)
        self.assertIn("pub commitment: [u8; 32]", protocol)
        self.assertIn("exact third-party commitment is consumed as-is", derivation)
        self.assertIn("without changing the covenant message", derivation)
        self.assertIn("bindingTokenHex", js)
        self.assertIn("covenantOpaqueRequestHex", js)
        self.assertIn("covenantKnownRequestHex", js)
        self.assertIn("covenantBindRequestHex", js)
        self.assertIn("createCovenantSigningChallenge", js)
        self.assertIn("covenantRevealHex", js)

    def test_known_review_retains_full_protocol_context_without_preview_truncation(self) -> None:
        protocol = read("crates/shared-signer/src/covenant_sign/mod.rs")
        state = read("apps/signer-firmware/src/runtime/data/signing/covenant.rs")
        service = read("apps/signer-firmware/src/services/covenant_sign.rs")
        ui = read("apps/signer-firmware/src/ui/screens/signing/covenant.rs")
        self.assertIn("pub const MAX_CONTEXT_LEN: usize = 1_024", protocol)
        self.assertIn("context: [u8; shared_signer::covenant_sign::MAX_CONTEXT_LEN]", state)
        self.assertIn("if input.len() > ad.signing.covenant.context.len()", service)
        self.assertIn("copy_review_context", service)
        self.assertNotIn("copy_preview", service)
        self.assertNotIn(".min(ad.signing.covenant.context.len())", service)
        self.assertIn("context_page_count", state)
        self.assertIn("context_page_text", state)
        self.assertIn("if page < pages", ui)

    def test_known_and_opaque_modes_have_distinct_verification_and_confirmation(self) -> None:
        protocol = read("crates/shared-signer/src/covenant_sign/mod.rs")
        validation = read("crates/shared-signer/src/covenant_sign/validation.rs")
        service = read("apps/signer-firmware/src/services/covenant_sign.rs")
        ui = read("apps/signer-firmware/src/ui/screens/signing/covenant.rs")
        controller = read("apps/signer-firmware/src/runtime/interactions/tx/covenant_signing.rs")
        self.assertIn("recompute_known_commitment", service)
        self.assertIn("known_script_binds", service)
        self.assertIn("BindingHint::None | BindingHint::KeyPresent", validation)
        self.assertIn("KasSigner cannot verify", ui)
        self.assertIn("UNVERIFIED AUTHORIZATION", ui)
        self.assertIn("COMMITMENT (FULL)", ui)
        self.assertIn("KEY INSTANCE", ui)
        self.assertIn("CovenantSignOpaqueWarning", controller)
        self.assertIn("CovenantSignOpaqueConfirm", controller)
        self.assertIn("oracle_v1_script_binds", protocol)
        self.assertIn("script == pattern.as_slice()", protocol)

    def test_device_allocates_instance_id_and_binding_record_prevents_rebinding(self) -> None:
        protocol_js = read("apps/kassee-web/web/js/features/covenants/signing/protocol.js")
        service = read("apps/signer-firmware/src/services/covenant_sign.rs")
        state = read("apps/signer-firmware/src/runtime/data/signing/covenant.rs")
        derivation = read("crates/offline-signer/src/derivation/covenant.rs")
        self.assertIn("Device allocates the covenant key ID", protocol_js)
        self.assertNotIn("randomCovenantKeyId", protocol_js)
        self.assertIn("crypto::entropy::fill(&mut key_id)", service)
        self.assertIn("replace_pending_allocation", service)
        self.assertIn("request.key_id != ad.signing.covenant.pending_key_id", service)
        self.assertIn("clear_pending_allocation", service)
        self.assertIn("covenant_binding_token", derivation)
        self.assertIn("covenant_binding_matches", service)
        self.assertIn("script_hash", derivation)
        self.assertIn("COVENANT_BINDING_ACCOUNT", derivation)
        self.assertIn("pending_key_id", state)
        self.assertIn("if *instance_id == [0u8; 32]", derivation)
        self.assertIn("m/10016'/111111'/0'/i0'/i1'/i2'/i3'/i4'", derivation)
        seed_manager = read("apps/signer-firmware/src/wallet/seed_manager/manager.rs")
        self.assertNotIn("CovenantBindingRegistry", seed_manager)
        self.assertNotIn("covenant_bindings", seed_manager)
        self.assertNotIn("BindingRegistryFull", service)
        self.assertNotIn("CovenantKeyRebound", service)

    def test_binding_record_is_recoverable_with_covenant_and_funding_is_gated(self) -> None:
        oracle = read("apps/kassee-web/web/js/features/oracle/v1/controller.js")
        invite_share = read("apps/kassee-web/web/js/app/events/contracts/covenant_creation/invite_sharing.js")
        invite_import = read("apps/kassee-web/web/js/features/covenants/recovery/import/invite.js")
        beneficiary = read("apps/kassee-web/web/js/features/covenants/recovery/export/beneficiary_payload.js")
        repository = read("apps/kassee-web/web/js/features/covenants/recovery/active/repository.js")
        params = read("apps/kassee-web/web/js/features/covenants/payload_and_swaps/params/advanced.js")
        scanner = read("apps/kassee-web/web/js/features/covenants/recovery/scanner/primary/oracle.js")
        fund = read("apps/kassee-web/web/js/features/covenants/generation/fund.js")
        self.assertIn("scanOracleV1BindingResponse", oracle)
        self.assertIn("covenantScriptFingerprint", oracle)
        self.assertIn("oracle_covenant_binding_token_hex", oracle)
        self.assertIn("invite.obt", invite_share)
        self.assertIn("invite.obt", invite_import)
        self.assertIn("invite.obt", beneficiary)
        self.assertIn("oracle_covenant_binding_token_hex", repository)
        self.assertIn("oracle_covenant_binding_token_hex", params)
        self.assertIn("oracle_covenant_binding_token_hex", scanner)
        self.assertIn("Bind the isolated Oracle covenant key", fund)

    def test_host_transcript_verification_and_session_wipe_are_mandatory(self) -> None:
        oracle = read("apps/kassee-web/web/js/features/oracle/v1/controller.js")
        wasm = read("crates/online-watcher/src/wasm_api/protocol/covenant_sign.rs")
        camera_back = read("apps/signer-firmware/src/runtime/interactions/camera_loop/touch_input.rs")
        navigation = read("apps/signer-firmware/src/runtime/navigation/kernel.rs")
        self.assertIn("verify_covenant_anti_klepto", oracle)
        self.assertIn("verify_nonce_relation", wasm)
        self.assertIn("zeroize_bytes(&mut host_secret)", wasm)
        self.assertIn("CovenantSigningPhase::AwaitingReveal", camera_back)
        self.assertIn("ad.signing.covenant.reset()", camera_back)
        self.assertIn("ad.signing.covenant.reset()", navigation)

    def test_oracle_v1_uses_exact_sha256_commitment_and_bound_universal_covenant_signing(self) -> None:
        family = read("crates/online-watcher/src/contracts/covenant/oracle_v1.rs")
        controller = read("apps/kassee-web/web/js/features/oracle/v1/controller.js")
        attestation = read("apps/kassee-web/web/js/features/oracle/v1/attestation.js")
        self.assertIn("Sha256::digest(statement.as_bytes())", family)
        self.assertNotIn("message_digest(statement.as_bytes())", family)
        self.assertIn("covenantKnownRequestHex", controller)
        self.assertIn("covenantBindRequestHex", controller)
        self.assertIn("bindingTokenHex: result.oracle_covenant_binding_token_hex", controller)
        self.assertIn("CovenantKnownScheme.ORACLE_V1", controller)
        self.assertIn("sha256Commitment", attestation)
        self.assertIn("bindingToken: parsed.bindingToken", attestation)

    def test_host_label_state_is_absent_from_covenant_authorization(self) -> None:
        shared = read("crates/shared-signer/src/covenant_sign/mod.rs")
        state = read("apps/signer-firmware/src/runtime/data/signing/covenant.rs")
        protocol_js = read("apps/kassee-web/web/js/features/covenants/signing/protocol.js")
        self.assertNotIn("MAX_LABEL_LEN", shared)
        self.assertNotIn("pub label", shared)
        self.assertNotIn("label_len", state)
        self.assertNotIn("request.label", read("apps/signer-firmware/src/services/covenant_sign.rs"))
        self.assertNotIn("label:", protocol_js)


if __name__ == "__main__":
    unittest.main()
