"""KasSee static HTML composition and compatibility contracts."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
import hashlib
import re

from tools.build.web.build_web_index import (
    MANIFEST,
    OUTPUT,
    SOURCE_ROOT,
    manifest_entries,
    render,
)

EXPECTED_SCREEN_IDS = {
    "screen-welcome",
    "screen-dashboard",
    "screen-addresses",
    "screen-verify",
    "screen-utxos",
    "screen-history",
    "screen-portfolio",
    "screen-tokens",
    "screen-settings",
    "screen-kpub-manager",
    "screen-send",
    "screen-qr-display",
    "screen-scanner",
    "screen-receive",
    "screen-multisig",
    "screen-covenant",
    "screen-stealth",
    "screen-broadcast",
    "screen-pskt-review",
    "screen-donate",
}
EXPECTED_ID_DIGEST = "7de6cd456152341235ceebf92a801af023370cc57976810f3d2cfc66d466f347"
EXPECTED_ID_TAG_DIGEST = "e0d01d6aace2bea5798594c56a95eddeb6d428be48911ca5088ab03f7eb2e613"
EXPECTED_FRAGMENTS = (
    "document/open.html",
    "screens/system/welcome.html",
    "screens/system/dashboard.html",
    "screens/wallet/addresses.html",
    "screens/system/verify.html",
    "screens/wallet/utxos.html",
    "screens/wallet/history.html",
    "screens/wallet/portfolio.html",
    "screens/wallet/tokens.html",
    "screens/system/settings.html",
    "screens/wallet/kpub_manager.html",
    "screens/transactions/send.html",
    "screens/system/qr_display.html",
    "screens/system/scanner.html",
    "screens/wallet/receive.html",
    "screens/wallet/multisig.html",
    "screens/covenant/create/menu.html",
    "screens/covenant/create/kasfreeze.html",
    "screens/covenant/create/tagged_vault.html",
    "screens/covenant/create/form/open.html",
    "screens/covenant/create/form/basic/simple.html",
    "screens/covenant/create/form/savings/piggy.html",
    "screens/covenant/create/form/escrow/basic.html",
    "screens/covenant/create/form/escrow/shipment.html",
    "screens/covenant/create/form/savings/timelocked.html",
    "screens/covenant/create/form/automation/dead_mans_switch.html",
    "screens/covenant/create/form/limits/spending_limit.html",
    "screens/covenant/create/form/limits/allowance.html",
    "screens/covenant/create/form/advanced/payjoin.html",
    "screens/covenant/create/form/advanced/oracle_v1.html",
    "screens/covenant/create/form/advanced/crowdfund.html",
    "screens/covenant/create/form/advanced/commit_reveal.html",
    "screens/covenant/create/form/advanced/merkle_whitelist.html",
    "screens/covenant/create/private_swap.html",
    "screens/covenant/create/form/close.html",
    "screens/covenant/create/result.html",
    "screens/covenant/spend/owner_spend.html",
    "screens/covenant/spend/consolidate.html",
    "screens/covenant/spend/borrower_spend.html",
    "screens/covenant/spend/beneficiary_spend.html",
    "screens/covenant/recovery/timeout_refund.html",
    "screens/covenant/spend/payjoin_claim.html",
    "screens/covenant/spend/oracle_v1_claim.html",
    "screens/covenant/proofs/advanced_proofs.html",
    "screens/covenant/proofs/oracle_v1_attest.html",
    "screens/covenant/create/shipment.html",
    "screens/covenant/proofs/commit_reveal_spend.html",
    "screens/covenant/proofs/commit_reveal_verify.html",
    "screens/covenant/proofs/merkle_whitelist.html",
    "screens/covenant/proofs/rollup_and_balance.html",
    "screens/covenant/recovery/load_existing.html",
    "screens/privacy/stealth.html",
    "screens/transactions/broadcast.html",
    "screens/transactions/pskt_review.html",
    "screens/system/donate.html",
    "document/close.html",
)


def check_composition(root: Path) -> tuple[list[str], str | None]:
    errors: list[str] = []
    screens_root = SOURCE_ROOT / "screens"
    expected_screen_groups = {"system", "wallet", "transactions", "privacy", "covenant"}
    actual_screen_groups = {
        path.name for path in screens_root.iterdir() if path.is_dir()
    } if screens_root.exists() else set()
    if actual_screen_groups != expected_screen_groups:
        errors.append(
            f"web HTML screen groups changed: expected {sorted(expected_screen_groups)}, "
            f"got {sorted(actual_screen_groups)}"
        )
    direct_screen_fragments = sorted(path.name for path in screens_root.glob("*.html"))
    if direct_screen_fragments:
        errors.append(
            f"web HTML screen fragments must be grouped by domain: {direct_screen_fragments}"
        )
    covenant_root = screens_root / "covenant"
    expected_covenant_groups = {"create", "spend", "recovery", "proofs"}
    actual_covenant_groups = {
        path.name for path in covenant_root.iterdir() if path.is_dir()
    } if covenant_root.exists() else set()
    if actual_covenant_groups != expected_covenant_groups:
        errors.append(
            f"covenant HTML groups changed: expected {sorted(expected_covenant_groups)}, "
            f"got {sorted(actual_covenant_groups)}"
        )
    direct_covenant_fragments = sorted(path.name for path in covenant_root.glob("*.html"))
    if direct_covenant_fragments:
        errors.append(
            f"covenant HTML fragments must be grouped by workflow: {direct_covenant_fragments}"
        )
    create_root = covenant_root / "create"
    form_root = create_root / "form"
    expected_form_groups = {"advanced", "automation", "basic", "escrow", "limits", "savings"}
    actual_form_groups = {
        path.name for path in form_root.iterdir() if path.is_dir()
    } if form_root.exists() else set()
    if actual_form_groups != expected_form_groups:
        errors.append(
            f"covenant creation form groups changed: expected {sorted(expected_form_groups)}, "
            f"got {sorted(actual_form_groups)}"
        )
    expected_form_root_files = {"open.html", "close.html"}
    actual_form_root_files = {
        path.name for path in form_root.glob("*.html")
    } if form_root.exists() else set()
    if actual_form_root_files != expected_form_root_files:
        errors.append(
            f"covenant creation form shell changed: expected {sorted(expected_form_root_files)}, "
            f"got {sorted(actual_form_root_files)}"
        )
    if (create_root / "create.html").exists():
        errors.append("monolithic covenant creation HTML must not return")
    try:
        entries = manifest_entries()
    except ValueError as error:
        return [str(error)], None

    if tuple(entries) != EXPECTED_FRAGMENTS:
        errors.append(
            "web HTML fragment inventory/order changed: expected "
            f"{list(EXPECTED_FRAGMENTS)}, got {entries}"
        )

    actual_fragments = {
        path.relative_to(SOURCE_ROOT).as_posix()
        for path in SOURCE_ROOT.rglob("*.html")
    }
    if actual_fragments != set(entries):
        errors.append(
            "web HTML source fragments differ from the manifest: "
            f"unlisted={sorted(actual_fragments - set(entries))}, "
            f"missing={sorted(set(entries) - actual_fragments)}"
        )

    for entry in entries:
        source = SOURCE_ROOT / entry
        fragment_source = source.read_text(errors="ignore")
        line_count = len(fragment_source.splitlines())
        if line_count > 600:
            errors.append(
                f"web HTML source fragment exceeds 600 lines: {entry} ({line_count})"
            )
        if re.search(r"\sstyle=[\"']", fragment_source):
            errors.append(f"authored HTML contains inline styling: {entry}")
        if re.search(r"<style\b", fragment_source, re.I):
            errors.append(f"authored HTML contains an inline style block: {entry}")
        if "data:image" in fragment_source:
            errors.append(f"authored HTML contains an embedded image asset: {entry}")

    generated = render(entries)
    if not OUTPUT.is_file() or OUTPUT.read_text() != generated:
        errors.append(
            "web/index.html is stale; run tools/build/web/build_web_index.py"
        )
    return errors, generated


def check(root: Path) -> list[str]:
    errors, generated = check_composition(root)
    build_script = root / "tools/build/web/build_kassee_runtime.py"
    if not build_script.is_file():
        errors.append("Canonical KasSee runtime builder is missing: tools/build/web/build_kassee_runtime.py")
    else:
        build_source = build_script.read_text(errors="ignore")
        wasm_offset = build_source.find('"build",')
        for builder in (
            "tools/build/web/build_web_index.py",
            "tools/build/web/build_app_css.py",
            "tools/build/web/build_constellation_assets.py",
        ):
            offset = build_source.find(builder)
            if offset < 0 or wasm_offset < 0 or offset > wasm_offset:
                errors.append(f"Canonical KasSee runtime builder must run {builder} before the WASM cargo build")
    index_path = root / "apps/kassee-web/web/index.html"
    if not index_path.is_file():
        return [*errors, "KasSee web/index.html is missing"]

    source = index_path.read_text(errors="ignore")
    if generated is not None and source != generated:
        return errors

    id_tags = [
        (match.group(3), match.group(1).lower())
        for match in re.finditer(
            r'<([A-Za-z][A-Za-z0-9:-]*)\b([^>]*?\bid=["\']([^"\']+)["\'][^>]*)>',
            source,
            re.S,
        )
    ]
    ids = [name for name, _ in id_tags]
    duplicate_ids = sorted(name for name, count in Counter(ids).items() if count > 1)
    if duplicate_ids:
        errors.append(f"web/index.html contains duplicate DOM IDs: {duplicate_ids}")

    id_digest = hashlib.sha256("\n".join(sorted(ids)).encode()).hexdigest()
    # The UTXO-explorer includes the 'Send with Selected' coin-control action.
    if len(ids) != 624 or id_digest != EXPECTED_ID_DIGEST:
        errors.append(
            f"web shell DOM ID contract changed: {len(ids)} IDs / {id_digest}"
        )

    id_tag_digest = hashlib.sha256(
        "\n".join(f"{name}:{tag}" for name, tag in sorted(id_tags)).encode()
    ).hexdigest()
    if id_tag_digest != EXPECTED_ID_TAG_DIGEST:
        errors.append(f"web shell DOM element-type contract changed: {id_tag_digest}")

    screen_ids = set(re.findall(
        r'<section\b[^>]*\bid=["\']([^"\']+)["\'][^>]*'
        r'\bclass=["\'][^"\']*\bscreen\b',
        source,
        re.I,
    ))
    if screen_ids != EXPECTED_SCREEN_IDS:
        errors.append(
            f"web screen inventory changed: expected {sorted(EXPECTED_SCREEN_IDS)}, "
            f"got {sorted(screen_ids)}"
        )

    if len(re.findall(r'href=["\']css/app\.css(?:\?[^"\']*)?["\']', source)) != 1:
        errors.append("web/index.html must load css/app.css exactly once")
    if len(re.findall(
        r'<script\b[^>]*\btype=["\']module["\'][^>]*'
        r'\bsrc=["\']js/main\.js["\'][^>]*></script>',
        source,
        re.I | re.S,
    )) != 1:
        errors.append("web/index.html must load js/main.js once as a module")
    if len(re.findall(
        r'<script\b[^>]*\bsrc=["\']lib/jsQR\.js["\'][^>]*></script>',
        source,
        re.I | re.S,
    )) != 1:
        errors.append("web/index.html must load the local jsQR compatibility library once")
    inline_handlers = sorted(set(re.findall(r"\s(on[A-Za-z]+)\s*=", source)))
    if inline_handlers:
        errors.append(f"web/index.html contains inline event handlers: {inline_handlers}")

    return errors
