from __future__ import annotations

from pathlib import Path
import hashlib
import re

def _check_screen_modules(root: Path) -> list[str]:
    ROOT = root
    errors: list[str] = []
    # Firmware screen rendering is grouped by user-facing responsibility while
    # preserving the ui::screens module and BootDisplay method contract.
    screens_facade = ROOT / "apps/signer-firmware/src/ui/screens.rs"
    screens_root = ROOT / "apps/signer-firmware/src/ui/screens"
    required_screen_modules = (
        screens_root / "components/mod.rs",
        screens_root / "components/qr_renderer.rs",
        screens_root / "navigation/mod.rs",
        screens_root / "dialogs/mod.rs",
        screens_root / "dialogs/choices.rs",
        screens_root / "dialogs/destructive.rs",
        screens_root / "dialogs/firmware_update.rs",
        screens_root / "dialogs/popups.rs",
        screens_root / "dialogs/status.rs",
        screens_root / "security.rs",
        screens_root / "device/mod.rs",
        screens_root / "device/camera.rs",
        screens_root / "device/settings.rs",
        screens_root / "signing/mod.rs",
        screens_root / "signing/confirmation.rs",
        screens_root / "signing/errors.rs",
        screens_root / "signing/message_preview.rs",
        screens_root / "signing/message_result.rs",
        screens_root / "signing/message_source.rs",
        screens_root / "signing/transaction_guide.rs",
        screens_root / "signing/progress.rs",
        screens_root / "signing/qr.rs",
        screens_root / "signing/transaction_review/mod.rs",
        screens_root / "storage/mod.rs",
        screens_root / "storage/sd/mod.rs",
        screens_root / "storage/steganography/mod.rs",
        screens_root / "storage/steganography/jpeg.rs",
        screens_root / "storage/steganography/text.rs",
        screens_root / "storage/steganography/prompts.rs",
        screens_root / "wallet/mod.rs",
        screens_root / "wallet/address/mod.rs",
        screens_root / "wallet/keyboard.rs",
        screens_root / "wallet/multisig/mod.rs",
        screens_root / "wallet/multisig/setup.rs",
        screens_root / "wallet/multisig/result.rs",
        screens_root / "wallet/qr_export/mod.rs",
        screens_root / "wallet/seed_generation.rs",
        screens_root / "wallet/seed_management.rs",
        screens_root / "wallet/seed_slots.rs",
    )
    for required in required_screen_modules:
        if not required.exists():
            errors.append(f"required firmware screen module is missing: {required.relative_to(ROOT)}")
    if screens_facade.exists():
        screens_facade_source = screens_facade.read_text(errors="ignore")
        if len(screens_facade_source.splitlines()) > 80:
            errors.append("ui/screens.rs must remain a small stable module root")
        if re.search(r"\bimpl(?:<[^>]+>)?\s+BootDisplay", screens_facade_source):
            errors.append("ui/screens.rs must not contain screen implementations")
    screen_production_files = list(screens_root.rglob("*.rs")) if screens_root.exists() else []
    for path in screen_production_files:
        line_count = len(path.read_text(errors="ignore").splitlines())
        if line_count > 600:
            errors.append(
                f"firmware screen module exceeds 600-line SRP limit: "
                f"{path.relative_to(ROOT)} ({line_count} lines)"
            )
    components_root = screens_root / "components"
    components_source = "\n".join(
        path.read_text(errors="ignore") for path in components_root.rglob("*.rs")
    ) if components_root.exists() else ""
    for helper in ("draw_level_settings", "update_level_bar", "draw_send_confirmation_layout", "draw_seed_qr_payload"):
        if helper not in components_source:
            errors.append(f"firmware shared screen component missing: {helper}")
    delegated_screen_methods = {
        screens_root / "device/settings.rs": ("draw_level_settings(", "update_level_bar("),
        screens_root / "signing/confirmation.rs": ("draw_send_confirmation_layout(",),
        screens_root / "wallet/qr_export/seed.rs": ("draw_seed_qr_payload(",),
    }
    for path, required_calls in delegated_screen_methods.items():
        source = path.read_text(errors="ignore")
        for call in required_calls:
            if call not in source:
                errors.append(f"firmware screen bypasses shared rendering component: {path.relative_to(ROOT)} -> {call}")

    screen_source = "\n".join(path.read_text(errors="ignore") for path in screen_production_files)
    screen_signature_pattern = re.compile(
        r"(?ms)^\s*pub\s+fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*(.*?)\{"
    )
    screen_methods = [name for name, _ in screen_signature_pattern.findall(screen_source)]
    duplicates = sorted({name for name in screen_methods if screen_methods.count(name) > 1})
    if duplicates:
        errors.append(f"firmware screen methods have duplicate owners: {duplicates}")
    firmware_source = "\n".join(
        path.read_text(errors="ignore")
        for path in (ROOT / "apps/signer-firmware/src").rglob("*.rs")
    )
    unused_methods = sorted(
        name for name in screen_methods
        if re.search(rf"\.{re.escape(name)}\s*\(", firmware_source) is None
    )
    if unused_methods:
        errors.append(f"firmware screen methods have no consumer: {unused_methods}")



    return errors


def _check_redraw_state_coverage(root: Path, redraw_source: str) -> list[str]:
    errors: list[str] = []
    redraw_states = set(re.findall(
        r"(?:crate::runtime::input::)?AppState::([A-Za-z0-9_]+)",
        redraw_source,
    ))
    state_source = (root / "apps/signer-firmware/src/runtime/input/state.rs").read_text(
        errors="ignore"
    )
    state_match = re.search(r"(?ms)pub enum AppState\s*\{(?P<body>.*?)^\}", state_source)
    declared_states = set() if state_match is None else set(re.findall(
        r"(?m)^    ([A-Z][A-Za-z0-9_]*)\b", state_match.group("body")
    ))
    missing_states = declared_states - redraw_states
    unknown_states = redraw_states - declared_states
    if missing_states:
        errors.append(f"firmware redraw is missing AppState variants: {sorted(missing_states)}")
    if unknown_states:
        errors.append(f"firmware redraw references unknown AppState variants: {sorted(unknown_states)}")
    return errors


def _check_mnemonic_and_seed_ui(root: Path) -> list[str]:
    ROOT = root
    errors: list[str] = []
    ui_root = ROOT / "apps/signer-firmware/src/ui"
    pin_ui = ui_root / "pin_ui.rs"
    pin_ui_tests = ui_root / "unit_tests/pin_ui_tests.rs"
    if pin_ui.exists() or pin_ui_tests.exists():
        errors.append("dormant PIN UI implementation or tests must not return")

    legacy_mnemonic_module = ui_root / "setup_wizard.rs"
    mnemonic_root = ROOT / "apps/signer-firmware/src/wallet/mnemonic"
    mnemonic_limits = {
        "mod.rs": 80,
        "generation.rs": 120,
        "dice.rs": 180,
        "touch.rs": 100,
        "checksum.rs": 180,
        "word_input.rs": 160,
        "validation.rs": 100,
    }
    if legacy_mnemonic_module.exists():
        errors.append("legacy monolithic mnemonic-setup module must not exist")
    actual_mnemonic = {path.name for path in mnemonic_root.glob("*.rs")}
    if actual_mnemonic != set(mnemonic_limits):
        errors.append(
            f"wallet mnemonic module inventory changed: expected {sorted(mnemonic_limits)}, "
            f"got {sorted(actual_mnemonic)}"
        )
    mnemonic_source = ""
    for name, limit in mnemonic_limits.items():
        path = mnemonic_root / name
        if not path.exists():
            errors.append(f"required wallet mnemonic module is missing: {path.relative_to(ROOT)}")
            continue
        source = path.read_text(errors="ignore")
        mnemonic_source += "\n" + source
        if len(source.splitlines()) > limit:
            errors.append(
                f"wallet mnemonic module exceeds SRP limit: {path.relative_to(ROOT)} "
                f"({len(source.splitlines())} > {limit})"
            )
    mnemonic_facade = (mnemonic_root / "mod.rs").read_text(errors="ignore") if mnemonic_root.exists() else ""
    for symbol in ("DiceCollector", "TouchEntropyCollector", "calc_last_word_12", "calc_last_word_24", "generate_from_entropy", "generate_from_dice", "WordInput", "validate", "complete_last_word"):
        if symbol not in mnemonic_facade:
            errors.append(f"wallet mnemonic façade is missing export: {symbol}")
    if "TOUCH_ENTROPY_TARGET" in mnemonic_facade:
        errors.append("wallet mnemonic façade must keep TOUCH_ENTROPY_TARGET private to touch.rs")
    if "pub const fn target(&self) -> usize" not in mnemonic_source:
        errors.append("wallet touch-entropy collector must expose its target through target()")
    for obsolete_mnemonic_symbol in (
        "SetupState", "SetupWizard", "SetPin", "ConfirmPin",
        "serialize_mnemonic", "deserialize_mnemonic",
    ):
        if re.search(rf"\b{obsolete_mnemonic_symbol}\b", mnemonic_source):
            errors.append(
                f"wallet mnemonic domain retains dormant PIN/NVS surface: {obsolete_mnemonic_symbol}"
            )

    seed_legacy = ui_root / "seed_manager.rs"
    seed_root = ROOT / "apps/signer-firmware/src/wallet/seed_manager"
    seed_limits = {
        "mod.rs": 80,
        "slot.rs": 180,
        "source.rs": 100,
        "manager.rs": 220,
        "mnemonic_store.rs": 100,
        "matching.rs": 100,
        "network.rs": 120,
        "seedqr.rs": 180,
        "passphrase.rs": 160,
        "protection.rs": 180,
    }
    if seed_legacy.exists():
        errors.append("legacy monolithic seed-manager module must not exist")
    actual_seed = {path.name for path in seed_root.glob("*.rs")}
    if actual_seed != set(seed_limits):
        errors.append(
            f"seed-manager module inventory changed: expected {sorted(seed_limits)}, "
            f"got {sorted(actual_seed)}"
        )
    for name, limit in seed_limits.items():
        path = seed_root / name
        if not path.exists():
            errors.append(f"required seed-manager module is missing: {path.relative_to(ROOT)}")
            continue
        line_count = len(path.read_text(errors="ignore").splitlines())
        if line_count > limit:
            errors.append(
                f"seed-manager module exceeds SRP limit: {path.relative_to(ROOT)} "
                f"({line_count} > {limit})"
            )
    seed_facade = (seed_root / "mod.rs").read_text(errors="ignore") if seed_root.exists() else ""
    for symbol in ("SeedSlot", "SeedManager", "MAX_SLOTS", "encode_seedqr", "decode_seedqr", "encode_compact_seedqr", "decode_compact_seedqr", "PassphraseInput"):
        if symbol not in seed_facade:
            errors.append(f"wallet seed-manager façade is missing export: {symbol}")
    firmware_source = "\n".join(
        path.read_text(errors="ignore")
        for path in (ROOT / "apps/signer-firmware/src").rglob("*.rs")
    )
    if re.search(r"\bNVS\b", firmware_source, re.I):
        errors.append("stateless firmware retains dormant NVS references")

    icon_browser = ROOT / "apps/signer-firmware/src/ui/icon_browser.rs"
    if icon_browser.exists() and re.search(r"\bstruct\s+IconEntry\b", icon_browser.read_text(errors="ignore")):
        errors.append("unused IconEntry catalog type must not return")
    return errors


def _check_redraw_modules(root: Path) -> list[str]:
    ROOT = root
    errors: list[str] = []
    # Redraw routing is grouped by screen family while preserving ui::redraw::redraw_screen.
    redraw_facade = ROOT / "apps/signer-firmware/src/ui/redraw.rs"
    redraw_root = ROOT / "apps/signer-firmware/src/ui/redraw"
    required_redraw_modules = {
        redraw_root / name for name in (
            "covenant.rs", "device.rs", "export.rs", "messages.rs", "multisig.rs", "navigation.rs",
            "settings.rs", "signing.rs", "stego.rs", "storage.rs", "system.rs", "wallet.rs",
        )
    }
    actual_redraw_modules = set(redraw_root.glob("*.rs")) if redraw_root.exists() else set()
    if required_redraw_modules - actual_redraw_modules:
        errors.append(
            "required firmware redraw modules are missing: "
            f"{sorted(path.name for path in required_redraw_modules - actual_redraw_modules)}"
        )
    if actual_redraw_modules - required_redraw_modules:
        errors.append(
            "unregistered firmware redraw modules found: "
            f"{sorted(path.name for path in actual_redraw_modules - required_redraw_modules)}"
        )
    if redraw_facade.exists():
        redraw_facade_source = redraw_facade.read_text(errors="ignore")
        if len(redraw_facade_source.splitlines()) > 80:
            errors.append("ui/redraw.rs must remain a small stable façade")
        if "match ad.navigation.app.state" in redraw_facade_source:
            errors.append("ui/redraw.rs must delegate screen-family redraw implementations")
        api_match = re.search(r"(?ms)^pub fn redraw_screen\s*(.*?)\{", redraw_facade_source)
        api_signatures = [] if api_match is None else [
            " ".join(f"pub fn redraw_screen {api_match.group(1)}".split())
        ]
        api_digest = hashlib.sha256("\n".join(api_signatures).encode()).hexdigest()
        if len(api_signatures) != 1 or api_digest != "e0ebf2afa44b0343240f40f2be30ecba661624211c4b8a434d0faf2a773e11b2":
            errors.append(f"firmware redraw API changed: {len(api_signatures)} signatures / {api_digest}")
    redraw_implementation_files = sorted(redraw_root.rglob("*.rs"))
    for module in redraw_implementation_files:
        line_count = len(module.read_text(errors="ignore").splitlines())
        if line_count > 600:
            errors.append(
                f"firmware redraw module exceeds 600-line SRP limit: "
                f"{module.relative_to(ROOT)} ({line_count} lines)"
            )
    redraw_source = "\n".join(path.read_text(errors="ignore") for path in redraw_implementation_files)
    errors.extend(_check_redraw_state_coverage(ROOT, redraw_source))
    for module in redraw_implementation_files:
        dispatchers = module.read_text(errors="ignore").count("match ad.navigation.app.state")
        if dispatchers > 1:
            errors.append(
                f"firmware redraw module owns multiple state dispatchers: {module.relative_to(ROOT)}"
            )
    for module in actual_redraw_modules:
        source = module.read_text(errors="ignore")
        delegates_state = (
            "match ad.navigation.app.state" in source
            or "redraw_state(ad.navigation.app.state" in source
            or "mod " in source
        )
        if not delegates_state:
            errors.append(
                f"firmware redraw module neither dispatches nor delegates: {module.relative_to(ROOT)}"
            )

    errors.extend(_check_mnemonic_and_seed_ui(ROOT))

    return errors


def check(root: Path) -> list[str]:
    return [
        *_check_screen_modules(root),
        *_check_redraw_modules(root),
    ]
