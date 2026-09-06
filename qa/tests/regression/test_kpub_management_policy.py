from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]
WEB = ROOT / "apps/kassee-web/web"
OPEN_HTML = WEB / "html/document/open.html"
MANAGER_HTML = WEB / "html/screens/wallet/kpub_manager.html"
WELCOME_HTML = WEB / "html/screens/system/welcome.html"
SCANNER_HTML = WEB / "html/screens/system/scanner.html"
MANAGER = WEB / "js/features/wallet/kpub_manager/controller.js"
REPOSITORY = WEB / "js/features/wallet/kpub_manager/repository.js"
NAVIGATION = WEB / "js/app/navigation.js"
WALLET_SESSION = WEB / "js/app/state/core/wallet_session.js"
SETTINGS_EVENTS = WEB / "js/app/events/wallet/settings_and_wallet.js"
SYSTEM_EVENTS = WEB / "js/app/events/system/core.js"
SYSTEM_CSS = WEB / "css/app/screens/system.css"
STATE_RESET = WEB / "js/features/wallet/state_reset.js"
RESET = WEB / "js/features/wallet/reset.js"


class KpubManagementPolicyTests(unittest.TestCase):
    def test_settings_cog_exposes_centralized_kpub_management(self) -> None:
        shell = OPEN_HTML.read_text()
        screen = MANAGER_HTML.read_text()
        welcome = WELCOME_HTML.read_text()
        scanner = SCANNER_HTML.read_text()
        settings_events = SETTINGS_EVENTS.read_text()
        system_events = SYSTEM_EVENTS.read_text()

        self.assertIn('id="gear-tab-kpub-manager"', shell)
        self.assertIn('data-target="kpub-manager"', shell)
        self.assertIn('id="screen-kpub-manager"', screen)
        self.assertIn('id="kpub-saved-list"', screen)
        self.assertIn('id="btn-open-kpub-import"', screen)
        self.assertIn('id="btn-scan-managed-kpub"', screen)
        self.assertIn('id="btn-upload-managed-kpub"', screen)
        self.assertIn('id="input-managed-kpub-image"', screen)
        self.assertIn('id="input-managed-kpub"', screen)
        self.assertIn('id="input-kpub-friendly-name"', screen)
        self.assertIn('id="chk-new-kpub-auto-load"', screen)
        self.assertIn('id="btn-save-managed-kpub"', screen)
        self.assertIn('>Use kpub once</button>', screen)
        self.assertIn('It is not saved and will not load on startup.', screen)
        self.assertIn('id="welcome-saved-kpubs"', welcome)
        self.assertIn('id="welcome-kpub-list"', welcome)
        self.assertIn('Friendly name (optional)', screen)
        self.assertNotIn('input-managed-kpub', scanner)
        self.assertIn("showKpubManager(returnScreen)", settings_events)
        self.assertIn("showKpubManager('welcome', { openImport: true })", system_events)

    def test_saved_kpub_list_is_bounded_and_scrollable(self) -> None:
        source = SYSTEM_CSS.read_text()
        rule = source[source.index('.kpub-saved-list {'):source.index('}', source.index('.kpub-saved-list {'))]
        self.assertIn('max-height:', rule)
        self.assertIn('overflow-y: auto', rule)
        welcome_rule = source[source.index('.welcome-kpub-list {'):source.index('}', source.index('.welcome-kpub-list {'))]
        self.assertIn('max-height:', welcome_rule)
        self.assertIn('overflow-y: auto', welcome_rule)

    def test_import_form_heading_keeps_normal_readable_width(self) -> None:
        source = SYSTEM_CSS.read_text()
        rule = source[source.index('.kpub-manager-form-heading {'):source.index('}', source.index('.kpub-manager-form-heading {'))]
        self.assertIn('grid-template-columns: minmax(0, 1fr) auto', rule)
        cancel_rule = source[
            source.index('.kpub-manager-form-heading .btn-link {'):
            source.index('}', source.index('.kpub-manager-form-heading .btn-link {'))
        ]
        self.assertIn('width: auto', cancel_rule)

    def test_repository_persists_named_entries_and_one_startup_selection(self) -> None:
        source = REPOSITORY.read_text()
        self.assertIn("const STORAGE_KEY = 'kassee-kpub-manager-v1'", source)
        self.assertIn("function save({ name, kpub, network })", source)
        self.assertIn("function rename(id, name)", source)
        self.assertIn("function remove(id)", source)
        self.assertIn("function setAutoLoad(id)", source)
        self.assertIn("function autoLoadEntry()", source)
        self.assertIn("function nextDefaultName(entries)", source)
        self.assertIn("return `Wallet ${index}`", source)
        self.assertIn("store.autoLoadId = id", source)
        self.assertIn("if (store.autoLoadId === id) store.autoLoadId = null", source)

    def test_manager_supports_all_import_methods_and_safe_switching(self) -> None:
        source = MANAGER.read_text()
        self.assertIn("deriveKpubQrWallet(data, networkState.network)", source)
        self.assertIn("decodeKpubQrImage(file)", source)
        self.assertIn("deriveKpubWallet(kpubInput.value, networkState.network)", source)
        self.assertIn("loadSavedKpub(entry.id)", source)
        self.assertIn("Any in-progress unsigned transaction will be discarded", source)
        self.assertIn("export function useKpubOnce()", source)
        self.assertIn("profile: null", source)
        self.assertIn("hardenedWalletCleanup()", source)
        self.assertIn("clearForWalletSwitch()", source)
        self.assertLess(
            source.index("deriveKpubWallet(entry.kpub, entry.network)"),
            source.index("clearForWalletSwitch()", source.index("export function loadSavedKpub")),
            "a saved kpub must validate before hardened cleanup clears the current wallet",
        )
        self.assertIn("kpubRepository.remove(entry.id)", source)
        self.assertIn("This only removes the public watch-only key", source)
        self.assertNotIn("xprv", source.lower())
        self.assertNotIn("mnemonic", source.lower())

    def test_reset_and_one_time_unload_share_hardened_cleanup(self) -> None:
        reset = RESET.read_text()
        cleanup = STATE_RESET.read_text()
        manager = MANAGER.read_text()

        self.assertIn("oneTime ? 'Unload one-time kpub' : 'Reset Wallet'", reset)
        self.assertIn("hardenedWalletCleanup();", reset)
        self.assertIn("requestWalletRuntimeReset();", reset)
        self.assertIn("export function hardenedWalletCleanup()", cleanup)
        self.assertIn("clearAntiKleptoSession();", cleanup)
        self.assertIn("resetSignedQrImageImportSession();", cleanup)
        self.assertIn("stopQrCycle();", cleanup)
        self.assertIn("stopAutoRefresh();", cleanup)
        self.assertIn("sessionStorage.clear()", cleanup)
        self.assertIn("kassee:request-runtime-reset", cleanup)
        self.assertIn("consumeSkipAutoLoadOnce()", manager)

    def test_startup_routes_after_wasm_to_wallet_or_saved_selection(self) -> None:
        source = NAVIGATION.read_text()
        ready_offset = source.index("markWasmReady();")
        route_offset = source.index("routeStartupKpub")
        self.assertGreater(route_offset, ready_offset)
        self.assertIn("if (wasmStarted)", source)
        self.assertIn("startupRoute.state === 'loaded'", source)
        self.assertIn("startupRoute.state === 'failed'", source)
        self.assertIn("startupRoute.state === 'selection'", source)

        manager = MANAGER.read_text()
        self.assertIn("export function routeStartupKpub()", manager)
        self.assertIn("renderWelcomeKpubs()", manager)
        self.assertIn("showScreen('welcome')", manager)
        self.assertIn("state: entries.length > 0 ? 'selection' : 'empty'", manager)
        self.assertIn("loadSavedKpub(startupEntry.id, { startup: true })", manager)

    def test_wallet_session_tracks_active_saved_profile(self) -> None:
        source = WALLET_SESSION.read_text()
        self.assertIn("let walletProfile = null", source)
        self.assertIn("profile()", source)
        self.assertIn("setProfile(profile)", source)
        self.assertGreaterEqual(source.count("walletProfile = null"), 3)


if __name__ == "__main__":
    unittest.main()
