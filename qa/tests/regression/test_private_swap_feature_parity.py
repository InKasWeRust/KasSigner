from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(errors='replace')


class PrivateSwapFeatureParityTests(unittest.TestCase):
    def test_private_swap_wire_error_tests_do_not_require_request_debug_or_equality(self):
        tests = read('crates/shared-signer/src/covenant_sign/private_swap/unit_tests/mod.rs')
        compact_tests = "".join(tests.split())
        self.assertIn('matches!(parse_request(&bad),Err(ProtocolError::InvalidMagic))', compact_tests)
        self.assertIn('matches!(parse_request(&bad),Err(ProtocolError::UnsupportedVersion))', compact_tests)
        self.assertIn('matches!(parse_request(&bad),Err(ProtocolError::InvalidKind))', compact_tests)
        self.assertIn('matches!(parse_request(&bad),Err(ProtocolError::InvalidFields))', compact_tests)
        self.assertIn('matches!(parse_request(&bad),Err(ProtocolError::InvalidLength))', compact_tests)
        self.assertNotIn('assert_eq!(parse_request(&bad)', compact_tests)
        protocol = read('crates/shared-signer/src/covenant_sign/private_swap.rs')
        request_line = next(i for i, line in enumerate(protocol.splitlines()) if line.startswith('pub struct PrivateSwapRequest'))
        previous = protocol.splitlines()[request_line - 1].strip()
        self.assertEqual(previous, '')

    def test_private_swap_unit_test_uses_local_wire_module(self):
        tests = read('crates/shared-signer/src/covenant_sign/private_swap/unit_tests/mod.rs')
        self.assertIn('use super::session_id;', tests)
        self.assertNotIn('use super::super::session_id;', tests)

    def test_offline_private_swap_unit_test_imports_immediate_parent_module(self):
        tests = read('crates/offline-signer/src/transaction/private_swap/unit_tests/mod.rs')
        self.assertIn('use super::{parse_private_swap_script, PrivateSwapError};', tests)
        self.assertNotIn('use super::super::{parse_private_swap_script, PrivateSwapError};', tests)

    def test_private_swap_replaces_htlc_in_the_live_ui(self):
        menu = read('apps/kassee-web/web/html/screens/covenant/create/menu.html')
        panel = read('apps/kassee-web/web/html/screens/covenant/create/private_swap.html')
        authored = menu + '\n' + panel
        self.assertIn('Private Swap', authored)
        self.assertIn('No preimage', authored)
        self.assertNotIn('HTLC', authored)
        self.assertNotIn('Atomic Swap', authored)
        for retired in (
            'apps/kassee-web/web/html/screens/covenant/create/form/advanced/atomic_swap.html',
            'apps/kassee-web/web/html/screens/covenant/spend/atomic_claim.html',
            'crates/online-watcher/src/contracts/covenant/script/atomic_swap.rs',
            'crates/online-watcher/src/wasm_api/contracts/covenant/families/atomic_swap.rs',
        ):
            self.assertFalse((ROOT / retired).exists(), retired)

    def test_claim_is_transaction_sighash_bound_and_has_no_hashlock(self):
        script = read('crates/online-watcher/src/contracts/covenant/script/private_swap.rs')
        production_script = script.split('#[cfg(test)]', 1)[0]
        device = read('crates/offline-signer/src/transaction/private_swap.rs')
        service = read('apps/signer-firmware/src/services/private_swap.rs')
        self.assertIn('OP_CHECKSIGVERIFY', script)
        self.assertIn('OP_TX_INPUT_COUNT', script)
        self.assertIn('OP_TX_OUTPUT_COUNT', script)
        self.assertIn('OP_TX_OUTPUT_SPK', script)
        self.assertIn('PRIVATE_SWAP_MAX_FEE_SOMPI', script)
        self.assertNotIn('OP_CHECKSIGFROMSTACK', production_script)
        self.assertNotIn('OP_SHA256', production_script)
        self.assertNotIn('OP_BLAKE2B', production_script)
        self.assertIn('calculate_sighash(tx, 0, sighash_type)', device)
        self.assertIn('SigHashType::All', device)
        self.assertIn('private_swap_claim_sighash', service)
        self.assertIn('parse_compact_kspt', service)
        self.assertNotIn('private_swap_binding(', production_script)
        self.assertNotIn('parse_private_swap_header', production_script)
        self.assertNotIn('parse_private_swap_destination', production_script)
        self.assertNotIn('parse_private_swap_owner', production_script)

    def test_private_swap_keys_are_separate_from_generic_covenant_sign(self):
        derivation = read('crates/offline-signer/src/derivation/covenant.rs')
        firmware = read('apps/signer-firmware/src/services/private_swap.rs')
        self.assertIn('PRIVATE_SWAP_CLAIM_ACCOUNT', derivation)
        self.assertIn('PRIVATE_SWAP_BINDING_ACCOUNT', derivation)
        self.assertIn('PRIVATE_SWAP_ADAPTOR_ACCOUNT', derivation)
        self.assertIn('private_swap_public_key', firmware)
        self.assertIn('private_swap_binding_matches', firmware)
        self.assertNotIn('covenant_public_key(&seed.bytes', firmware)
        self.assertNotIn('covenant_binding_matches(&seed.bytes', firmware)

    def test_adaptor_exchange_is_two_round_and_exact_transaction_bound(self):
        wire = read('crates/shared-signer/src/covenant_sign/private_swap.rs')
        device = read('apps/kassee-web/web/js/features/covenants/private_swap/device_flow.js')
        controller = read('apps/kassee-web/web/js/features/covenants/private_swap/controller.js')
        self.assertIn('PSWG', wire)
        self.assertIn('PSWR', wire)
        self.assertIn('PSWS', wire)
        self.assertIn('host_commitment', wire)
        self.assertIn('private_swap_claim_sighash', controller)
        self.assertIn('private_swap_verify_presignature', controller)
        self.assertIn('verify_host_secret', read('apps/signer-firmware/src/services/private_swap.rs'))
        self.assertIn('private_swap_extract_secret', controller)
        self.assertIn('private_swap_complete_public', controller)
        self.assertIn('readyAckHash', controller)
        self.assertIn('Bob readiness verified cryptographically', controller)
        self.assertIn('myPreSignature', device)

    def test_recovery_keeps_public_transcript_but_rejects_secrets_and_transient_transactions(self):
        controller = read('apps/kassee-web/web/js/features/covenants/private_swap/controller.js')
        scanner = read('apps/kassee-web/web/js/features/covenants/recovery/scanner/primary/private_swap.js')
        self.assertIn("private_swap_recovery_json", controller)
        self.assertIn("key.toLowerCase().includes('secret')", controller)
        self.assertIn('MAX_RECOVERY_JSON_BYTES', scanner)
        self.assertIn('assertRecoveryObjectSafe', scanner)
        for field in ('myClaimPskb', 'myClaimKspt', 'counterClaimKspt', 'counterCompletedSignature'):
            self.assertIn(field, scanner)

    def test_watcher_accepts_only_the_claim_branch_signature(self):
        watcher = read('apps/kassee-web/web/js/features/covenants/private_swap/watcher.js')
        self.assertIn("script[0] !== 65", watcher)
        self.assertIn("script[66] !== 0x51", watcher)
        self.assertIn("owner refund branch", watcher)

    def test_recovered_swap_rebuilds_the_exact_reviewed_claim_before_completion(self):
        controller = read('apps/kassee-web/web/js/features/covenants/private_swap/controller.js')
        self.assertIn('ensureMyClaimTransaction()', controller)
        self.assertIn("exactUnsigned(privateSwapState.myClaimFeeSompi", controller)
        self.assertIn("if (sighash !== privateSwapState.myClaimSighash)", controller)
        complete_body = controller.split('export async function completeAlicePrivateSwap()', 1)[1].split('export async function bobClaimPrivateSwap()', 1)[0]
        bob_body = controller.split('export async function bobClaimPrivateSwap()', 1)[1].split('export function openPrivateSwapRefund()', 1)[0]
        self.assertIn('await ensureMyClaimTransaction();', complete_body)
        self.assertIn('await ensureMyClaimTransaction();', bob_body)

    def test_firmware_review_displays_transaction_values_before_presign_or_complete(self):
        ui = read('apps/signer-firmware/src/ui/screens/signing/covenant.rs')
        self.assertIn('private_swap_kas_line("OUTPUT"', ui)
        self.assertIn('private_swap_kas_line("FEE"', ui)
        self.assertIn('REFUND DAA', ui)
        self.assertIn('DEST SCRIPT SHA-256', ui)
        self.assertIn('TX SIGHASH', ui)


if __name__ == '__main__':
    unittest.main()
