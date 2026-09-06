from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]
WEB_JS = ROOT / "apps/kassee-web/web/js"
BALANCE = WEB_JS / "features/wallet/core/balance.js"
BROADCAST = WEB_JS / "features/transactions/send/broadcast.js"
SIGNED_IMAGE = WEB_JS / "features/transactions/send/signed_qr_image_import.js"
TRANSACTION_EVENTS = WEB_JS / "app/events/transactions/transactions.js"
BROADCAST_HTML = ROOT / "apps/kassee-web/web/html/screens/transactions/broadcast.html"
BROWSER_WEBSOCKET = ROOT / "crates/online-watcher/src/infrastructure/browser_websocket.rs"
BIP32 = ROOT / "crates/online-watcher/src/account/bip32.rs"


class KasSeeConnectionAndQrImportPolicyTests(unittest.TestCase):
    def test_balance_reconnect_is_background_and_bounded(self) -> None:
        source = BALANCE.read_text()
        self.assertNotIn("showLoading('Connecting...')", source)
        self.assertNotIn("console.error('Balance fetch failed:'", source)
        self.assertIn("const BALANCE_RECONNECT_ATTEMPTS = 3", source)
        self.assertIn("isRetryableNodeError", source)
        self.assertIn("'timeout'", source)
        self.assertIn("noteReconnectAttempt", source)
        self.assertIn("showNodeFailureAfterRetries", source)
        self.assertIn("Last known balance shown", source)

    def test_supplemental_utxo_timeout_does_not_replace_balance(self) -> None:
        source = BALANCE.read_text()
        self.assertIn("History tracking is supplemental", source)
        self.assertIn("setStatus('online', 'Connected');", source)
        self.assertNotIn("UTXO history track:", source)

    def test_websocket_error_handler_does_not_read_optional_message(self) -> None:
        source = BROWSER_WEBSOCKET.read_text()
        self.assertIn("type ErrorHandler = Closure<dyn FnMut(Event)>;", source)
        self.assertNotIn("ErrorEvent", source)
        self.assertNotIn("event.message()", source)
        self.assertIn('ConnectionFailed("WebSocket error".into())', source)

    def test_wallet_derivation_diagnostics_are_removed(self) -> None:
        source = BIP32.read_text()
        self.assertNotIn("Parsed kpub at depth", source)
        self.assertNotIn("Derived {} receive + {} change addresses", source)

    def test_broadcast_screen_supports_signed_qr_image_files(self) -> None:
        html = BROADCAST_HTML.read_text()
        events = TRANSACTION_EVENTS.read_text()
        importer = SIGNED_IMAGE.read_text()
        broadcast = BROADCAST.read_text()

        self.assertIn('id="btn-load-signed-qr-image"', html)
        self.assertIn('id="input-signed-qr-image"', html)
        self.assertIn('id="broadcast-image-status"', html)
        self.assertIn("importSignedQrImage(file)", events)
        self.assertIn("decodeQrImageFile(file)", importer)
        self.assertIn("stopCamera: false", importer)
        self.assertIn("progressTargetId: 'broadcast-image-status'", importer)
        self.assertIn("options.stopCamera !== false", broadcast)


if __name__ == "__main__":
    unittest.main()
