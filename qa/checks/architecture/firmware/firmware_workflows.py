"""Hard boundaries for split firmware settings and SD import workflows."""

from __future__ import annotations

from pathlib import Path


def _check_settings(root: Path) -> list[str]:
    errors: list[str] = []
    legacy = root / "apps/signer-firmware/src/runtime/interactions/settings.rs"
    directory = root / "apps/signer-firmware/src/runtime/interactions/settings"
    expected = {"mod.rs", "audio.rs", "camera.rs", "display.rs", "menu.rs", "scalar.rs", "storage.rs"}
    actual = {path.name for path in directory.glob("*.rs")} if directory.exists() else set()
    if legacy.exists():
        errors.append("monolithic controllers/settings.rs must not return")
    if actual != expected:
        errors.append(f"settings controller inventory changed: expected {sorted(expected)}, got {sorted(actual)}")
    facade = directory / "mod.rs"
    if facade.exists() and "pub fn handle_settings_touch" not in facade.read_text(errors="ignore"):
        errors.append("settings façade lost handle_settings_touch")
    for path in directory.glob("*.rs") if directory.exists() else ():
        lines = len(path.read_text(errors="ignore").splitlines())
        if lines > 220:
            errors.append(f"settings module exceeds 220-line SRP limit: {path.relative_to(root)} ({lines})")
    return errors


def _check_sd_imports(root: Path) -> list[str]:
    errors: list[str] = []
    directory = root / "apps/signer-firmware/src/runtime/interactions/sd/imports"
    required = {"mod.rs", "payload_detection.rs", "file_browser.rs", "import_menu.rs", "kspt_import.rs"}
    actual = {path.name for path in directory.glob("*.rs")} if directory.exists() else set()
    missing = required - actual
    if missing:
        errors.append(f"SD import workflow modules are missing: {sorted(missing)}")
    browser = (directory / "file_browser.rs").read_text(errors="ignore")
    selected = (directory / "selected_file/mod.rs").read_text(errors="ignore")
    detection = (directory / "payload_detection.rs").read_text(errors="ignore")
    if "selected_file::import_selected_file" not in browser:
        errors.append("SD file browser must delegate payload execution to selected_file")
    if "detect_payload(" not in selected or not any(marker in detection for marker in ("enum DetectedSdPayload", "DetectedPayload as DetectedSdPayload")):
        errors.append("SD selected-file workflow must use typed payload detection")
    selected_children = directory / "selected_file"
    expected_children = {"mod.rs", "covenant_backup.rs", "private_key.rs", "xprv.rs"}
    actual_children = {path.name for path in selected_children.glob("*.rs")} if selected_children.exists() else set()
    if actual_children != expected_children:
        errors.append(f"selected-file importer inventory changed: expected {sorted(expected_children)}, got {sorted(actual_children)}")
    if len(selected.splitlines()) > 100:
        errors.append("SD selected-file façade exceeds 100 lines")
    for forbidden in ("Legacy fallback", "ends_with(b\".KPB\")", "ends_with(b\".KPS\")"):
        if forbidden in browser:
            errors.append(f"SD browser retains filename-based legacy routing: {forbidden}")
    return errors



def _check_signing_and_bip85(root: Path) -> list[str]:
    errors: list[str] = []
    firmware = root / "apps/signer-firmware/src/runtime/interactions"

    signing_facade = firmware / "menu/signing.rs"
    signing_root = firmware / "menu/signing"
    expected_signing = {"common.rs", "single_sig.rs", "multisig.rs"}
    actual_signing = {path.name for path in signing_root.glob("*.rs")} if signing_root.exists() else set()
    if actual_signing != expected_signing:
        errors.append(
            f"signing-menu module inventory changed: expected {sorted(expected_signing)}, got {sorted(actual_signing)}"
        )
    signing_source = "\n".join(
        path.read_text(errors="ignore") for path in [signing_facade, *sorted(signing_root.glob("*.rs"))]
        if path.exists()
    )
    if len(signing_facade.read_text(errors="ignore").splitlines()) > 80:
        errors.append("signing-menu façade exceeds 80 lines")
    if signing_source.count('"No seed loaded"') != 1:
        errors.append("signing-menu seed-required feedback must have one shared implementation")
    if 'draw_saving_screen("Deriving addresses...")' not in signing_source:
        errors.append("signing-menu address preparation must use the shared progress screen")

    bip85_facade = firmware / "seed/bip85.rs"
    bip85_root = firmware / "seed/bip85"
    expected_bip85 = {"derivation.rs", "navigation.rs"}
    actual_bip85 = {path.name for path in bip85_root.glob("*.rs")} if bip85_root.exists() else set()
    if actual_bip85 != expected_bip85:
        errors.append(
            f"BIP85 module inventory changed: expected {sorted(expected_bip85)}, got {sorted(actual_bip85)}"
        )
    derivation = (bip85_root / "derivation.rs").read_text(errors="ignore")
    combined = "\n".join(
        path.read_text(errors="ignore") for path in [bip85_facade, *sorted(bip85_root.glob("*.rs"))]
        if path.exists()
    )
    for symbol in ("derive_mnemonic_12", "derive_mnemonic_24"):
        if combined.count(symbol) != 1 or symbol not in derivation:
            errors.append(f"BIP85 {symbol} must have one derivation owner")
    if "zeroize_bytes(&mut seed.bytes)" not in derivation:
        errors.append("BIP85 derivation must zeroize the parent seed")
    return errors



def _function_body(source: str, name: str) -> str:
    import re
    match = re.search(rf"\bfn\s+{re.escape(name)}\s*\(", source)
    if match is None:
        return ""
    opening = source.find("{", match.end())
    if opening < 0:
        return ""
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[opening + 1:index]
    return ""


def _state_targets(body: str) -> set[str]:
    import re
    return set(re.findall(r"\bAppState::([A-Z][A-Za-z0-9_]*)", body))


def _reachable(graph: dict[str, set[str]], target: str) -> bool:
    frontier = ["MainMenu"]
    seen = {"MainMenu"}
    while frontier:
        state = frontier.pop()
        if state == target:
            return True
        for next_state in graph.get(state, set()):
            if next_state not in seen:
                seen.add(next_state)
                frontier.append(next_state)
    return False


def _check_production_root_reachability(root: Path) -> list[str]:
    """Validate consumer routes from the authoritative Stage-1 production UI graph."""
    import json

    errors: list[str] = []
    graph_path = root / "qa/config/workflow/production_ui_graph.json"
    if not graph_path.is_file():
        return ["generated production UI graph is missing"]
    document = json.loads(graph_path.read_text(encoding="utf-8"))
    menus = document.get("menus", [])
    states = document.get("states", [])

    action_rows = {
        item["action"]: (menu["state"], item["destination"], item["guard"])
        for menu in menus for item in menu.get("items", [])
    }
    required_actions = {
        "home.connect_kassee": "SeedsMenu",
        "wallet.backup": "WalletBackupMethodsMenu",
        "wallet.recovery": "SdImportMenu",
        "wallet.details": "WalletDetails",
        "wallet.switch_add": "SeedList",
        "wallet.multisig": "MultisigMenu",
        "multisig.kpub": "MultisigMenu",
        "wallet.advanced": "WalletAdvancedMenu",
        "wallet.backup.view_words": "SeedBackup",
        "wallet.backup.seedqr": "ExportSeedQR",
        "wallet.backup.sd": "SdBackupWarning",
        "wallet.backup.advanced": "BackupRecoveryMenu",
        "wallet.advanced.bip85": "ChooseWordCount",
        "wallet.advanced.last_word": "ChooseWordCount",
        "wallet.backup.advanced.xprv": "XprvExportMenu",
        "wallet.backup.advanced.export_key": "ExportPrivKeyIndex",
        "recovery.import_raw_key": "ImportPrivKey",
        "wallet.advanced.sign_message": "SignMsgChoice",
        "wallet.advanced.commit_secret": "CommitRevealType",
        "wallet.advanced.decrypt_secret": "DecryptSecretScan",
        "wallet.backup.advanced.compact_seedqr": "ExportCompactSeedQR",
        "wallet.backup.advanced.plain_seedqr": "ExportPlainWordsQR",
        "wallet.backup.advanced.stego": "StegoModeSelect",
        "settings.advanced.firmware_update": "FirmwareUpdateReady",
        "settings.advanced.pop_it": "PopItPrompt",
    }
    for action, expected_destination in required_actions.items():
        row = action_rows.get(action)
        if row is None:
            errors.append(f"production UI graph missing consumer action: {action}")
        elif row[1] != expected_destination:
            errors.append(
                f"production UI graph consumer action {action} routes to {row[1]}, "
                f"expected {expected_destination}"
            )

    # Canonical-entry edges plus menu edges form the source-of-truth route graph.
    route_graph: dict[str, set[str]] = {}
    for menu in menus:
        route_graph.setdefault(menu["state"], set()).update(
            item["destination"] for item in menu.get("items", [])
        )
    known_states = {row["state"] for row in states}
    for row in states:
        entry = row.get("entry", "")
        if entry in known_states:
            route_graph.setdefault(entry, set()).add(row["state"])

    required_targets = set(required_actions.values()) | {
        "SettingsMenu", "SeedsMenu", "AdvancedMenu", "AdvancedFeatures",
        "DisplaySettings", "SdCardSettings", "About", "AddWalletChoice",
        "MultisigChooseMN", "SeedList",
    }
    for target in sorted(required_targets):
        if not _reachable(route_graph, target):
            errors.append(
                f"consumer capability is not graph-reachable from MainMenu: AppState::{target}"
            )

    firmware = root / "apps/signer-firmware/src"
    settings = (firmware / "runtime/interactions/settings/menu.rs").read_text(errors="ignore")
    if "cam_tune_active = true" not in settings or "cam_tune_dirty = true" not in settings:
        errors.append("waveshare Camera Settings route must retain camera-tuning activation")
    if "route!(CameraSettings)" not in settings:
        errors.append("waveshare Camera Settings route missing typed navigation target")

    pop_it = (firmware / "runtime/interactions/settings/advanced/workflow.rs").read_text(errors="ignore")
    if "route!(PopItPrompt)" not in pop_it:
        errors.append("m5stack production route missing typed Pop It! transition")
    return errors

def check(root: Path) -> list[str]:
    return [
        *_check_settings(root),
        *_check_sd_imports(root),
        *_check_signing_and_bip85(root),
        *_check_production_root_reachability(root),
    ]
