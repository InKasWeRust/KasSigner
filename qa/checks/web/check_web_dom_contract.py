#!/usr/bin/env python3
"""Validate required KasSee wallet-import and covenant DOM contracts."""

from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[3]
HTML_ROOT = ROOT / "apps/kassee-web/web/html"
JS_ROOT = ROOT / "apps/kassee-web/web/js"

REQUIRED_PRIVATE_SWAP_IDS = {
    "cov-private-swap-panel", "private-swap-hub", "private-swap-create",
    "private-swap-join", "private-swap-dashboard", "btn-private-swap-create",
    "btn-private-swap-join", "btn-private-swap-create-key", "btn-private-swap-join-key",
    "btn-private-swap-bind", "btn-private-swap-fund", "btn-private-swap-presign",
    "btn-private-swap-share-presig", "btn-private-swap-scan-presig",
    "btn-private-swap-share-ready", "btn-private-swap-scan-ready",
    "btn-private-swap-complete", "btn-private-swap-bob-claim", "btn-private-swap-refund",
}
REQUIRED_KPUB_IMPORT_IDS = {
    "btn-scan-kpub", "kassee-startup-status", "screen-kpub-manager",
    "kpub-saved-list", "btn-open-kpub-import", "kpub-import-form",
    "btn-scan-managed-kpub", "btn-upload-managed-kpub",
    "input-managed-kpub-image", "input-managed-kpub",
    "input-kpub-friendly-name", "chk-new-kpub-auto-load",
    "btn-save-managed-kpub",
}
REQUIRED_WELCOME_KPUB_IDS = {
    "btn-scan-kpub", "kassee-startup-status",
    "welcome-saved-kpubs", "welcome-kpub-list",
}
RETIRED_KPUB_IMPORT_IDS = {
    "btn-load-kpub-image", "input-kpub-image", "input-kpub", "btn-import-kpub",
}
RETIRED_CREATION_TOKENS = {
    "buildTreasury", "cov-fields-treasury", "buildTimelockedEscrow",
    "cov-fields-tl-escrow", "deprecated.js",
}


def main() -> int:
    html = "\n".join(path.read_text(encoding="utf-8") for path in HTML_ROOT.rglob("*.html"))
    js = "\n".join(path.read_text(encoding="utf-8") for path in JS_ROOT.rglob("*.js"))
    ids = set(re.findall(r'\bid=["\']([^"\']+)["\']', html))
    errors: list[str] = []

    missing_kpub = sorted(REQUIRED_KPUB_IMPORT_IDS - ids)
    if missing_kpub:
        errors.append(f"kpub management/import DOM is incomplete: {missing_kpub}")
    retired_kpub = sorted(RETIRED_KPUB_IMPORT_IDS & ids)
    if retired_kpub:
        errors.append(f"retired standalone kpub-import controls remain: {retired_kpub}")
    missing_welcome_kpub = sorted(REQUIRED_WELCOME_KPUB_IDS - ids)
    if missing_welcome_kpub:
        errors.append(f"welcome saved-kpub selection DOM is incomplete: {missing_welcome_kpub}")

    welcome = (HTML_ROOT / 'screens/system/welcome.html').read_text(encoding="utf-8")
    scanner = (HTML_ROOT / 'screens/system/scanner.html').read_text(encoding="utf-8")
    manager = (HTML_ROOT / 'screens/wallet/kpub_manager.html').read_text(encoding="utf-8")
    donate = (HTML_ROOT / 'screens/system/donate.html').read_text(encoding="utf-8")
    if '>Load kpub<' not in welcome:
        errors.append('welcome screen must expose one Load kpub entry point')
    for control in REQUIRED_KPUB_IMPORT_IDS - {"btn-scan-kpub", "kassee-startup-status"}:
        if control in welcome:
            errors.append(f'welcome screen must not duplicate managed kpub control: {control}')
    for control in (
        'btn-open-kpub-import', 'btn-scan-managed-kpub', 'btn-upload-managed-kpub',
        'input-managed-kpub-image', 'input-managed-kpub', 'input-kpub-friendly-name',
        'btn-save-managed-kpub', 'kpub-saved-list',
    ):
        if control not in manager:
            errors.append(f'kpub management must own import control: {control}')
        if control in scanner:
            errors.append(f'camera scanner must not duplicate managed kpub control: {control}')
    if 'Scan kpub QR with camera' not in js or 'decodeKpubQrImage' not in js:
        errors.append('kpub management must support camera scanning and QR image upload')
    if "showKpubManager('welcome', { openImport: true })" not in js:
        errors.append('the welcome Load kpub button must open the centralized kpub manager')

    kpub_css = (ROOT / 'apps/kassee-web/web/css/app/screens/system.css').read_text(encoding="utf-8")
    saved_list_rule = re.search(r'\.kpub-saved-list\s*\{([^}]*)\}', kpub_css, re.S)
    if not saved_list_rule or 'max-height:' not in saved_list_rule.group(1) or 'overflow-y: auto' not in saved_list_rule.group(1):
        errors.append('saved kpubs must render in a bounded scrollable list')

    if '>Close</button>' not in donate or '>Skip</button>' in donate:
        errors.append('donation page must use Close rather than Skip')
    if 'img/kassigner-donation-qr.png' not in donate:
        errors.append('donation page must include the static donation QR asset')
    if donate.count('title="Copy donation address"') < 2:
        errors.append('donation address and QR must both be clickable copy targets')
    donation_js = (JS_ROOT / 'features/donations/screen.js').read_text(encoding="utf-8")
    if 'donationIsVisible()' not in donation_js or "classList.contains('active')" not in donation_js:
        errors.append('donation logo toggle must derive state from the visible donation screen')
    qr_asset = ROOT / 'apps/kassee-web/web/img/kassigner-donation-qr.png'
    if not qr_asset.is_file() or qr_asset.stat().st_size < 1000:
        errors.append('static donation QR PNG asset is missing or empty')
    donation_css = (ROOT / 'apps/kassee-web/web/css/app/screens/donation_and_safe_area.css').read_text(encoding="utf-8")
    if '#btn-donate-skip:hover' not in donation_css or 'filter: brightness(1.1)' not in donation_css:
        errors.append('donation Close hover must remain opaque and visibly interactive')
    if 'background: rgba(229, 83, 75, 0.08)' in donation_css:
        errors.append('donation Close hover must not become transparent')
    mobile_donation = re.search(r'@media\s*\(max-width:\s*420px\)\s*\{(.*)\}\s*$', donation_css, re.S)
    if not mobile_donation or not re.search(r'\.donate-header\s*\{[^}]*flex-direction:\s*column', mobile_donation.group(1), re.S):
        errors.append('narrow donation layout must stack the QR below the KasSigner brand')

    settings_events = (JS_ROOT / 'app/events/wallet/settings_and_wallet.js').read_text(encoding="utf-8")
    if "['addresses', 'utxos', 'tokens', 'history'].includes(target)" not in settings_events:
        errors.append('gear wallet-tool tabs must share immediate navigation handling')
    if "showScreen(target);" not in settings_events or "if (!walletSession.hasWallet())" not in settings_events:
        errors.append('gear wallet-tool tabs must leave the current screen immediately, even without a loaded wallet')


    back_buttons = re.findall(
        r'<button\b[^>]*\bclass=["\']([^"\']*)["\'][^>]*\bid=["\']([^"\']*(?:-back(?:-[^"\']*)?|btn-scanner-cancel))["\']',
        html,
    )
    unstyled_back = sorted(button_id for classes, button_id in back_buttons if 'btn-back' not in classes.split())
    if unstyled_back:
        errors.append(f'back controls must use the shared btn-back style: {unstyled_back}')
    buttons_css = (ROOT / 'apps/kassee-web/web/css/app/components/buttons.css').read_text(encoding="utf-8")
    if '.btn-back {' not in buttons_css or "content: '←'" not in buttons_css:
        errors.append('shared back controls must be prominent and visually identifiable')
    if '.back-home-row {' not in buttons_css or '.btn-home-nav {' not in buttons_css:
        errors.append('every shared Back control must split its row with a Home control')
    navigation_controls = (JS_ROOT / 'core/ui/navigation_controls.js').read_text(encoding="utf-8")
    if "document.querySelectorAll('.btn-back')" not in navigation_controls or "homeButton.textContent = 'Home'" not in navigation_controls:
        errors.append('shared navigation controls must attach Home beside every Back button')
    navigation_js = (JS_ROOT / 'app/navigation.js').read_text(encoding="utf-8")
    if 'screenHistory' not in navigation_js or 'export function navigateBack' not in navigation_js:
        errors.append('shared navigation must maintain bounded screen history for Back')
    shell_js = (JS_ROOT / 'app/shell_controls.js').read_text(encoding="utf-8")
    settings_js = (JS_ROOT / 'features/settings/screen.js').read_text(encoding="utf-8")
    if "setScreenReturn('settings', visibleScreenName())" not in shell_js:
        errors.append('shell settings navigation must remember the visible return screen')
    if 'takeScreenReturn(' not in settings_js or "'settings'" not in settings_js:
        errors.append('settings Back must consume the remembered return screen')

    missing = sorted(REQUIRED_PRIVATE_SWAP_IDS - ids)
    if missing:
        errors.append(f"Private Swap v2 DOM is incomplete: {missing}")
    if 'data-cov-panel="private-swap"' not in html or 'id="cov-private-swap-panel"' not in html:
        errors.append("Private Swap must be selectable from the covenant card UI")
    for token in ("openPrivateSwap", "preparePrivateSwapPreSignature", "completeAlicePrivateSwap"):
        if token not in js:
            errors.append(f"Private Swap controller is missing {token}")
    for retired in ('data-cov-type="atomic-swap"', "buildAtomicSwap", "case 'atomic-swap'", 'HTLC'):
        if retired in html or retired in js:
            errors.append(f"retired HTLC Atomic Swap surface remains: {retired}")

    if "context.covSelectType" in js:
        errors.append("covenant type selection must use the direct module function")
    if js.count("export function covSelectType") != 1:
        errors.append("covenant type selection must have one direct exported implementation")

    for token in sorted(RETIRED_CREATION_TOKENS):
        if token in html or token in js:
            errors.append(f"retired covenant creation surface remains: {token}")

    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1
    print(f"PASS: centralized kpub management and covenant DOM contract ({len(ids)} authored ids, Private Swap v2 coherent)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
