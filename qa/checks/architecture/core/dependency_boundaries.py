"""Cross-crate dependency and platform-boundary rules."""

from __future__ import annotations

from pathlib import Path
import re
import tomllib


def _check_explicit_parent_imports(root: Path) -> list[str]:
    errors: list[str] = []
    source_roots = (
        root / "apps/signer-firmware/src",
        root / "crates/offline-signer/src",
        root / "crates/online-watcher/src",
        root / "crates/shared-signer/src",
        root / "crates/signer-firmware-core/src",
    )
    wildcard = re.compile(r"(?m)^\s*use\s+super(?:::\s*super)*::\*\s*;")
    for source_root in source_roots:
        for path in source_root.rglob("*.rs"):
            if "unit_tests" in path.parts or "tests" in path.parts:
                continue
            match = wildcard.search(path.read_text(errors="ignore"))
            if match:
                line = path.read_text(errors="ignore").count("\n", 0, match.start()) + 1
                errors.append(
                    "production modules must use explicit named dependencies: "
                    f"{path.relative_to(root)}:{line}"
                )
    child_prelude = re.compile(r"\bchild_prelude\b")
    for source_root in source_roots:
        for path in source_root.rglob("*.rs"):
            if "unit_tests" in path.parts or "tests" in path.parts:
                continue
            match = child_prelude.search(path.read_text(errors="ignore"))
            if match:
                line = path.read_text(errors="ignore").count("\n", 0, match.start()) + 1
                errors.append(
                    "synthetic child preludes are forbidden; import from the owning module: "
                    f"{path.relative_to(root)}:{line}"
                )
    return errors


def _check_browser_direct_utilities(root: Path) -> list[str]:
    errors: list[str] = []
    web_root = root / "apps/kassee-web/web/js"
    all_source = "\n".join(
        path.read_text(errors="ignore")
        for path in web_root.rglob("*.js")
        if "pkg" not in path.parts and "lib" not in path.parts
    )
    for forbidden in (
        "createFeatureContext", "installFeatureCapability", "storeForCapability",
        "DomainStore", "readApplicationCapability", "writeApplicationCapability",
    ):
        if forbidden in all_source:
            errors.append(f"generic browser capability routing must not return: {forbidden}")
    if re.search(r"\bcontext\.[A-Za-z_$]", all_source):
        errors.append("browser utilities and state must use direct imports, not feature context")
    context_path = web_root / "app/context.js"
    if context_path.exists():
        errors.append("browser context service locator must not return")
    return errors



def _check_standard_rust_module_layout(root: Path) -> list[str]:
    """Reject ordinary production #[path] wiring outside platform/test adapters."""
    errors: list[str] = []
    roots = (
        root / "apps/signer-firmware/src",
        root / "crates/offline-signer/src",
        root / "crates/online-watcher/src",
        root / "crates/shared-signer/src",
        root / "crates/signer-firmware-core/src",
    )
    allowed = {
        "apps/signer-firmware/src/hw/mod.rs",
        "apps/signer-firmware/src/services/verify/mod.rs",
    }
    path_attribute = re.compile(r'(?m)^\s*#\[path\s*=\s*"([^"]+)"\]')
    for source_root in roots:
        for path in source_root.rglob("*.rs"):
            relative = path.relative_to(root).as_posix()
            source = path.read_text(errors="ignore")
            for match in path_attribute.finditer(source):
                target = match.group(1)
                if relative in allowed or "unit_tests" in target or "/tests/" in target:
                    continue
                line = source.count("\n", 0, match.start()) + 1
                errors.append(
                    "ordinary production modules must use the standard Rust module hierarchy: "
                    f"{relative}:{line} -> {target}"
                )
    return errors


def _check_browser_state_boundaries(root: Path) -> list[str]:
    errors: list[str] = []
    web_root = root / "apps/kassee-web/web/js"
    required = (
        "core/state/session.js",
        "core/ui/toast.js",
        "core/node/resolver.js",
        "core/node/daa.js",
        "core/config/network.js",
        "core/config/services.js",
        "features/covenants/payload_and_swaps/types.js",
        "features/stealth/index/config.js",
        "features/assets/client.js",
        "features/assets/render.js",
        "features/settings/screen.js",
        "features/donations/screen.js",
        "features/oracle/model_b/controller/proving/client.js",
        "features/oracle/model_b/controller/proving/validation.js",
        "features/oracle/model_b/controller/proving/skeleton.js",
        "features/covenants/payload_and_swaps/params/standard.js",
        "features/covenants/payload_and_swaps/params/advanced.js",
    )
    for relative in required:
        if not (web_root / relative).is_file():
            errors.append(f"required focused browser module is missing: {relative}")
    if (web_root / "core/application_state.js").exists():
        errors.append("mixed-responsibility core/application_state.js must not return")
    if (web_root / "features/settings_and_tokens.js").exists():
        errors.append("mixed settings-and-assets façade must not return")

    all_source = "\n".join(path.read_text(errors="ignore") for path in web_root.rglob("*.js"))
    for capability in (
        "BROADCAST_ENABLED", "COV_TYPE", "COV_TYPE_REV", "KSTL_SUBNET_HEX",
        "STEALTH_LOOKBACK_BS", "STEALTH_MAX_R", "STEALTH_MAX_WINDOWS",
        "AUTO_REFRESH_INTERVAL", "DONATE_ADDRESS", "KASPLEX_API", "KNS_LOOKUP",
        "KRC721_API", "RESOLVERS", "GAP_EXPAND_RECEIVE", "GAP_EXPAND_CHANGE",
        "ORACLE_MB", "ORACLE_MB_DEPLOY",
    ):
        if re.search(rf"\bcontext\.{re.escape(capability)}\b", all_source):
            errors.append(f"immutable browser configuration must be a direct import: {capability}")

    thin_wrapper = re.compile(
        r"export\s+(?:async\s+)?function\s+\w+\([^)]*\)\s*\{\s*"
        r"return\s+\w+Impl\(context(?:,|\))",
        re.S,
    )
    for path in web_root.rglob("*.js"):
        source = path.read_text(errors="ignore")
        if thin_wrapper.search(source):
            errors.append(
                "browser façade only injects global context instead of exposing a direct module: "
                f"{path.relative_to(root)}"
            )
    return errors


def _check_shared_workflow_ownership(root: Path) -> list[str]:
    errors: list[str] = []
    checks = {
        "crates/offline-signer/src/derivation/bip39/seed.rs": (
            "fn seed_from_indices(",
        ),
        "crates/offline-signer/src/transaction/std_pskt/parser/helpers.rs": (
            "fn capture_nonempty_object(",
        ),
        "apps/kassee-web/web/js/core/forms/duration.js": (
            "export function bindDurationInputs(",
        ),
        "apps/signer-firmware/src/runtime/interactions/sd/imports/import_menu.rs": (
            "const IMPORT_RULES:",
        ),
        "apps/signer-firmware/src/ui/screens/components/qr_renderer.rs": (
            "pub(in crate::ui::screens) fn draw_encoded_qr(",
        ),
    }
    for relative, markers in checks.items():
        path = root / relative
        source = path.read_text(errors="ignore") if path.is_file() else ""
        for marker in markers:
            if marker not in source:
                errors.append(f"shared workflow primitive is missing from {relative}: {marker}")

    production = "\n".join(
        path.read_text(errors="ignore")
        for source_root in (
            root / "apps/signer-firmware/src",
            root / "crates/offline-signer/src",
            root / "crates/online-watcher/src",
        )
        for path in source_root.rglob("*.rs")
        if "unit_tests" not in path.parts and "tests" not in path.parts
    )
    expected_single = {
        "fn seed_from_indices(": 1,
        "fn capture_nonempty_object(": 1,
    }
    for marker, expected in expected_single.items():
        count = production.count(marker)
        if count != expected:
            errors.append(f"shared primitive {marker} must have one implementation, found {count}")

    qr_callers = (
        root / "apps/signer-firmware/src/ui/screens/signing/qr.rs",
        root / "apps/signer-firmware/src/ui/screens/wallet/qr_export/fullscreen.rs",
    )
    for path in qr_callers:
        if "draw_qr_screen_with_options(" not in path.read_text(errors="ignore"):
            errors.append(f"QR screen bypasses shared renderer: {path.relative_to(root)}")
    return errors

def check(root: Path) -> list[str]:
    errors: list[str] = []
    checks = {
        root / "crates/offline-signer/Cargo.toml": (
            "online-watcher",
            "web-sys",
            "wasm-bindgen",
        ),
        root / "crates/online-watcher/Cargo.toml": (
            "offline-signer",
            "esp-hal",
            "esp32s3",
        ),
        root / "crates/shared-signer/Cargo.toml": (
            "offline-signer",
            "online-watcher",
            "esp-hal",
            "web-sys",
            "wasm-bindgen",
        ),
        root / "crates/signer-firmware-core/Cargo.toml": (
            "offline-signer",
            "online-watcher",
            "esp-hal",
            "web-sys",
            "wasm-bindgen",
        ),
    }
    for manifest, forbidden_names in checks.items():
        data = tomllib.loads(manifest.read_text())
        dependencies = set(data.get("dependencies", {}))
        for name in forbidden_names:
            if name in dependencies:
                errors.append(f"{manifest.relative_to(root)} must not depend on {name}")

    shared_source = "\n".join(
        path.read_text(errors="ignore")
        for path in (root / "crates/shared-signer/src").rglob("*.rs")
    )
    for forbidden in ("esp_hal", "web_sys", "wasm_bindgen", "WebSocket", "SdCard"):
        if forbidden in shared_source:
            errors.append(f"shared code contains platform concern: {forbidden}")

    firmware_core_source = "\n".join(
        path.read_text(errors="ignore")
        for path in (root / "crates/signer-firmware-core/src").rglob("*.rs")
        if "unit_tests" not in path.parts
    )
    for forbidden in ("esp_hal", "web_sys", "wasm_bindgen", "WebSocket"):
        if forbidden in firmware_core_source:
            errors.append(f"firmware core contains platform adapter concern: {forbidden}")

    online_source = "\n".join(
        path.read_text(errors="ignore")
        for path in (root / "crates/online-watcher/src").rglob("*.rs")
    )
    for forbidden in ("Mnemonic", "ExtendedPrivateKey", "RawPrivateKey", "SecretMaterial"):
        if forbidden in online_source:
            errors.append(f"online core contains offline secret type: {forbidden}")

    errors.extend(_check_explicit_parent_imports(root))
    errors.extend(_check_standard_rust_module_layout(root))
    errors.extend(_check_browser_direct_utilities(root))
    errors.extend(_check_browser_state_boundaries(root))
    errors.extend(_check_shared_workflow_ownership(root))
    return errors
