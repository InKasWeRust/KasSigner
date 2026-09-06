import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[3]


class SigningBoundary(unittest.TestCase):
    def test_raw_hash_and_retired_protocol_authorization_are_absent(self):
        firmware = '\n'.join(
            path.read_text(errors='replace')
            for path in (ROOT / 'apps/signer-firmware/src').rglob('*.rs')
        )
        for token in ('SignMsgHashPreview', 'AdaptorSignRequest', 'scan_hash', 'KADS1:'):
            self.assertNotIn(token, firmware)
        facade = (ROOT / 'crates/offline-signer/src/facade.rs').read_text()
        self.assertNotIn('pub fn sign_message(', facade)
        self.assertNotIn('pub fn sign_message_with_entropy(', facade)

    def test_reviewed_message_is_domain_separated_on_device(self):
        crypto = (ROOT / 'crates/offline-signer/src/crypto/message.rs').read_text()
        service = (ROOT / 'apps/signer-firmware/src/runtime/interactions/tx/message_signing/service.rs').read_text()
        self.assertIn('KasSigner Signed Message v1', crypto)
        self.assertIn('message_digest(message)', crypto)
        self.assertIn('crypto::message::message_digest', service)
        self.assertIn('sign_user_message_with_entropy', service)

    def test_historical_adaptor_v1_surface_stays_absent_while_private_swap_v2_is_present(self):
        retired_paths = (
            'crates/online-watcher/src/privacy/adaptor',
            'crates/online-watcher/src/wasm_api/privacy/adaptor',
            'apps/kassee-web/web/js/app/events/contracts/adaptor_swap.js',
            'apps/kassee-web/web/js/app/state/covenants/adaptor_state.js',
            'apps/kassee-web/web/js/features/covenants/payload_and_swaps/adaptor_policy.js',
            'apps/kassee-web/web/js/features/covenants/recovery/scanner/historical_payload.js',
            'apps/kassee-web/web/html/screens/covenant/create/adaptor_swap.html',
        )
        for relative in retired_paths:
            self.assertFalse((ROOT / relative).exists(), relative)

        required_v2 = (
            'crates/offline-signer/src/crypto/adaptor.rs',
            'crates/online-watcher/src/protocol/private_swap/adaptor.rs',
            'crates/shared-signer/src/covenant_sign/private_swap.rs',
            'apps/signer-firmware/src/services/private_swap.rs',
            'apps/kassee-web/web/js/features/covenants/private_swap/controller.js',
            'apps/kassee-web/web/html/screens/covenant/create/private_swap.html',
        )
        for relative in required_v2:
            self.assertTrue((ROOT / relative).is_file(), relative)

        production = '\n'.join(
            path.read_text(errors='replace')
            for root in (
                ROOT / 'apps/signer-firmware/src', ROOT / 'apps/kassee-web/web/js',
                ROOT / 'crates/online-watcher/src', ROOT / 'crates/offline-signer/src',
            )
            for path in root.rglob('*') if path.is_file() and path.suffix in {'.rs', '.js'}
        )
        for retired_token in ('KasSigner-AdaptorSwap-v1', 'adaptor_generate_keypair', 'adaptor_create_sig'):
            self.assertNotIn(retired_token, production)

    def test_active_bip340_verifier_is_neutral_anti_klepto_support(self):
        schnorr = (ROOT / 'crates/online-watcher/src/protocol/schnorr.rs').read_text()
        anti_klepto = (ROOT / 'crates/online-watcher/src/protocol/pskt/anti_klepto.rs').read_text()
        self.assertIn('pub(crate) fn bip340_verify', schnorr)
        self.assertIn('schnorr::bip340_verify', anti_klepto)
        self.assertNotIn('adaptor', schnorr.lower())


if __name__ == '__main__':
    unittest.main()
