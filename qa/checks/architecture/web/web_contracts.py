"""Browser state ownership checks for focused, sealed domain state objects."""

from __future__ import annotations

from pathlib import Path
import re

_STATE_DECLARATION = re.compile(
    r"export\s+const\s+(?P<name>[A-Za-z_$][\w$]*)\s*=\s*Object\.seal\(\{(?P<body>.*?)\}\);",
    re.S,
)
_STATE_PROPERTY = re.compile(r"['\"]([A-Za-z_$][\w$]*)['\"]\s*:")
_STATE_EXPORT = re.compile(
    r"export\s*\{\s*([A-Za-z_$][\w$]*)\s*\}\s*from\s*['\"]\./([^'\"]+)['\"]"
)

_REQUIRED_STATES = {
    "commitRevealState",
    "covenantRecoveryState",
    "covenantState",
    "covenantWatcherState",
    "crowdfundState",
    "navigationState",
    "networkState",
    "oracleState",
    "scannerState",
    "stealthState",
    "transactionState",
    "uiState",
    "walletState",
}


def _state_modules(state_root: Path, errors: list[str]) -> dict[str, tuple[Path, set[str]]]:
    modules: dict[str, tuple[Path, set[str]]] = {}
    for path in sorted(state_root.rglob("*_state.js")):
        source = path.read_text(errors="ignore")
        declarations = list(_STATE_DECLARATION.finditer(source))
        if len(declarations) != 1:
            errors.append(
                f"browser state module must export one sealed object: {path.relative_to(state_root)}"
            )
            continue
        match = declarations[0]
        name = match.group("name")
        properties = set(_STATE_PROPERTY.findall(match.group("body")))
        if not properties:
            errors.append(f"browser state module is empty: {path.relative_to(state_root)}")
        if name in modules:
            errors.append(f"duplicate browser state object: {name}")
        modules[name] = (path, properties)
    return modules


def _check_state_exports(
    state_root: Path,
    modules: dict[str, tuple[Path, set[str]]],
    errors: list[str],
) -> None:
    index = state_root / "index.js"
    if not index.is_file():
        errors.append("browser state facade is missing: app/state/index.js")
        return
    exports = {name: module for name, module in _STATE_EXPORT.findall(index.read_text(errors="ignore"))}
    expected = {
        name: path.relative_to(state_root).as_posix()
        for name, (path, _properties) in modules.items()
    }
    actual_states = {name: exports.get(name) for name in modules}
    if actual_states != expected:
        errors.append(
            f"browser state facade exports changed: expected {sorted(expected.items())}, "
            f"got {sorted(actual_states.items())}"
        )
    if exports.get("walletSession") != "core/wallet_session.js":
        errors.append("browser wallet session facade export is missing or misplaced")
    unexpected = set(exports) - set(modules) - {"walletSession"}
    if unexpected:
        errors.append(f"browser state facade has unexpected exports: {sorted(unexpected)}")


def _check_property_ownership(
    web_js_root: Path,
    modules: dict[str, tuple[Path, set[str]]],
    errors: list[str],
) -> None:
    property_owners: dict[str, str] = {}
    for state_name, (_path, properties) in modules.items():
        for property_name in properties:
            previous = property_owners.get(property_name)
            if previous is not None:
                errors.append(
                    f"browser state property has multiple owners: {property_name} ({previous}, {state_name})"
                )
            property_owners[property_name] = state_name

    application_sources = {
        path: path.read_text(errors="ignore")
        for path in web_js_root.rglob("*.js")
        if "app/state" not in path.as_posix() and "pkg" not in path.parts and "lib" not in path.parts
    }
    combined = "\n".join(application_sources.values())
    for state_name, (_path, properties) in modules.items():
        for property_name in properties:
            if not re.search(rf"\b{re.escape(state_name)}\.{re.escape(property_name)}\b", combined):
                errors.append(f"browser state property has no authored consumer: {state_name}.{property_name}")

    dynamic_access = re.compile(r"\b(?:" + "|".join(map(re.escape, modules)) + r")\s*\[")
    for path, source in application_sources.items():
        if dynamic_access.search(source):
            errors.append(
                f"dynamic browser state property access is forbidden: {path.relative_to(web_js_root)}"
            )


def _check_wallet_boundary(web_js_root: Path, errors: list[str]) -> None:
    session = web_js_root / "app/state/core/wallet_session.js"
    source = session.read_text(errors="ignore") if session.exists() else ""
    for method in ("hasWallet", "current", "json", "replace", "clear", "primaryReceiveAddress"):
        if not re.search(rf"\b{method}\s*\(", source):
            errors.append(f"wallet session facade is missing method: {method}")
    combined = "\n".join(
        path.read_text(errors="ignore")
        for path in web_js_root.rglob("*.js")
        if "app/state" not in path.as_posix() and "pkg" not in path.parts and "lib" not in path.parts
    )
    for forbidden in (
        "walletState.walletData",
        "JSON.parse(walletSession.json())",
        "JSON.parse(walletState",
    ):
        if forbidden in combined:
            errors.append(f"wallet payload boundary bypass must not return: {forbidden}")


def check_feature_contracts(root: Path, wasm_import_names: list[str]) -> list[str]:
    del wasm_import_names
    errors: list[str] = []
    web_js_root = root / "apps/kassee-web/web/js"
    state_root = web_js_root / "app/state"
    modules = _state_modules(state_root, errors)
    if set(modules) != _REQUIRED_STATES:
        errors.append(
            f"browser domain state inventory changed: expected {sorted(_REQUIRED_STATES)}, "
            f"got {sorted(modules)}"
        )
    _check_state_exports(state_root, modules, errors)
    _check_property_ownership(web_js_root, modules, errors)
    _check_wallet_boundary(web_js_root, errors)

    combined = "\n".join(
        path.read_text(errors="ignore")
        for path in web_js_root.rglob("*.js")
        if "pkg" not in path.parts and "lib" not in path.parts
    )
    forbidden = (
        "createFeatureContext",
        "installFeatureCapability",
        "storeForCapability",
        "DomainStore",
        "readApplicationCapability",
        "writeApplicationCapability",
    )
    for token in forbidden:
        if token in combined:
            errors.append(f"generic browser capability registry must not return: {token}")
    if re.search(r"\bcontext\.[A-Za-z_$]", combined):
        errors.append("browser feature context property access must not return")

    removed_paths = (
        web_js_root / "app/context.js",
        web_js_root / "app/contracts.js",
        web_js_root / "app/contracts",
        web_js_root / "app/stores",
    )
    for path in removed_paths:
        if path.exists():
            errors.append(
                f"legacy browser capability infrastructure must not return: {path.relative_to(web_js_root)}"
            )
    return errors
