from __future__ import annotations

from pathlib import Path
import hashlib
import re

from architecture.core.common import relative_posix
from .web_contracts import check_feature_contracts
from .web_infrastructure import check_scoped_context, check_shared_browser_infrastructure

def _check_wasm_consumption(
    root: Path,
    web_js_root: Path,
    wasm_api_path: Path,
    wasm_import_names: list[str],
) -> list[str]:
    del root
    errors: list[str] = []
    consumed_names: set[str] = set()
    named_import = re.compile(
        r"""import\s*\{(?P<names>.*?)\}\s*from\s*['"](?P<source>[^'"]+)['"]""",
        re.S,
    )
    for path in sorted(web_js_root.rglob("*.js")):
        if path == wasm_api_path or "pkg" in path.parts or "lib" in path.parts:
            continue
        source = path.read_text(errors="ignore")
        for match in named_import.finditer(source):
            import_path = (path.parent / match.group("source")).resolve()
            if import_path != wasm_api_path.resolve():
                continue
            for raw_name in match.group("names").split(","):
                name = raw_name.split("//", 1)[0].strip()
                if not name:
                    continue
                consumed_names.add(name.split(" as ", 1)[0].strip())
    for name in wasm_import_names:
        if name not in consumed_names:
            errors.append(f"browser WASM import has no authored import consumer: {name}")
    return errors

def _rust_wasm_export_source(root: Path) -> str:
    roots = (root / "crates/online-watcher/src/wasm_api", root / "apps/kassee-web/src")
    return "\n".join(path.read_text(errors="ignore") for base in roots for path in base.rglob("*.rs"))


def _check_module_layout(root: Path) -> tuple[list[str], list[str], str]:
    ROOT = root
    errors: list[str] = []
    # Enforce scoped browser feature ownership without freezing implementation files.
    web_js_root = ROOT / "apps/kassee-web/web/js"
    required_web_js_files = {
        "main.js",
        "app/bootstrap.js",
        "app/shell_controls.js",
        "app/state/index.js",
        "app/state/core/wallet_state.js",
        "app/state/core/wallet_session.js",
        "app/state/core/network_state.js",
        "app/state/core/navigation_state.js",
        "app/state/core/transaction_state.js",
        "app/state/core/ui_state.js",
        "app/state/covenants/covenant_state.js",
        "app/state/covenants/commit_reveal_state.js",
        "app/state/covenants/covenant_recovery_state.js",
        "app/state/covenants/covenant_watcher_state.js",
        "app/state/features/scanner_state.js",
        "app/state/features/oracle_state.js",
        "app/state/features/stealth_state.js",
        "app/events/index.js",
        "core/script_pushes.js",
        "wasm/api.js",
    }
    actual_web_js_modules = {
        relative_posix(path, web_js_root)
        for path in web_js_root.rglob("*.js")
    } if web_js_root.exists() else set()
    missing_web_js_files = required_web_js_files - actual_web_js_modules
    if missing_web_js_files:
        errors.append(f"required browser modules missing: {sorted(missing_web_js_files)}")
    if "app/initializers.js" in actual_web_js_modules:
        errors.append("legacy app/initializers.js must not return")
    if "app/browser_contract.js" in actual_web_js_modules:
        errors.append("legacy window compatibility module must not return")
    web_main = web_js_root / "main.js"
    if web_main.exists():
        main_lines = len(web_main.read_text().splitlines())
        if main_lines > 20:
            errors.append(f"web/js/main.js exceeds entry-point limit: {main_lines} lines")
        main_source = web_main.read_text(errors="ignore")
        if main_source.count("await import('./app/bootstrap.js')") != 1 or main_source.count("await startApplication()") != 1:
            errors.append("web/js/main.js must dynamically load and start the application exactly once")
        if "pkg/kassee_web.js" in main_source:
            errors.append("web/js/main.js must not import the generated WASM package directly")
        if "bindShellControls" not in main_source or "./app/shell_controls.js" not in main_source:
            errors.append("web/js/main.js must bind dependency-free shell controls before application startup")
    errors.extend(check_scoped_context(web_js_root))
    for module_path in sorted(web_js_root.rglob("*.js")) if web_js_root.exists() else []:
        relative = module_path.relative_to(web_js_root)
        module_source = module_path.read_text(errors="ignore")
        line_count = len(module_source.splitlines())
        if relative != Path("wasm/api.js") and line_count > 600:
            errors.append(f"web module exceeds SRP size limit: {relative} ({line_count} lines)")
        if re.search(r"\sstyle=[\"']", module_source):
            errors.append(f"static inline JavaScript styling is forbidden: {relative}")
        if ".style.cssText" in module_source:
            errors.append(f"JavaScript cssText styling is forbidden: {relative}")
    errors.extend(check_shared_browser_infrastructure(web_js_root))
    wasm_api_path = web_js_root / "wasm/api.js"
    if wasm_api_path.exists():
        wasm_api_source = wasm_api_path.read_text(errors="ignore")
        export_match = re.search(
            r"const\s+GENERATED_WASM_EXPORTS\s*=\s*Object\.freeze\(\[(.*?)\]\);",
            wasm_api_source,
            re.S,
        )
        if not export_match:
            errors.append("web WASM API module must declare generated export inventory")
            wasm_import_names: list[str] = []
        else:
            wasm_import_names = [
                "init",
                *re.findall(r"['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]", export_match.group(1)),
            ]
            if len(wasm_import_names) != len(set(wasm_import_names)):
                errors.append("browser WASM API contains duplicate export names")
            if "await import('../../pkg/kassee_web.js')" not in wasm_api_source:
                errors.append("web WASM API must load the generated package lazily")
            if re.search(r"\}\s*from\s*['\"]\.\./\.\./pkg/kassee_web\.js['\"]", wasm_api_source):
                errors.append("web WASM API must not statically re-export the generated package")
            for name in wasm_import_names:
                declaration = rf"export\s+(?:async\s+)?function\s+{re.escape(name)}\s*\("
                if not re.search(declaration, wasm_api_source):
                    errors.append(f"browser WASM API wrapper missing: {name}")
            rust_wasm_source = _rust_wasm_export_source(ROOT)
            rust_exports = set(re.findall(
                r"#\[wasm_bindgen(?:\([^]]*\))?\](?:\s*#\[[^]]+\])*\s*pub(?:\s+async)?\s+fn\s+([A-Za-z_][A-Za-z0-9_]*)",
                rust_wasm_source,
            ))
            imported = {name for name in wasm_import_names if name != "init"}
            missing = sorted(imported - rust_exports)
            if missing:
                errors.append(f"browser imports missing Rust WASM exports: {missing}")
            errors.extend(_check_wasm_consumption(ROOT, web_js_root, wasm_api_path, wasm_import_names))
    else:
        wasm_import_names = []
    all_web_js_source = "\n".join(
        path.read_text(errors="ignore")
        for path in sorted(web_js_root.rglob("*.js"))
    ) if web_js_root.exists() else ""
    for path in sorted(web_js_root.rglob("*.js")) if web_js_root.exists() else []:
        if path != wasm_api_path and "pkg/kassee_web.js" in path.read_text(errors="ignore"):
            errors.append(f"direct WASM package import outside wasm/api.js: {path.relative_to(ROOT)}")
    if "create_oracle_mb_heartbeat_roll" in all_web_js_source:
        errors.append("obsolete standalone Oracle heartbeat-roll browser surface must not return")
    script_walker = web_js_root / "core/script_pushes.js"
    script_walker_source = script_walker.read_text(errors="ignore") if script_walker.exists() else ""
    for required in ("walkScriptPushes", "opcode === 0x4c"):
        if required not in script_walker_source:
            errors.append(f"shared JavaScript script walker missing behavior: {required}")
    script_parser_paths = (
        web_js_root / "features/wallet/core.js",
        web_js_root / "features/covenants/watchers_and_ui/ui/script_metadata.js",
    )
    script_parser_source = "\n".join(path.read_text(errors="ignore") for path in script_parser_paths)
    for required_call in ("walkScriptPushes(",):
        if required_call not in script_parser_source:
            errors.append(f"browser script parsers bypass shared walker: {required_call}")
    if "let lastPush" in script_parser_source or "op >= 0x01 && op <= 0x4b" in script_parser_source:
        errors.append("duplicated browser script-push walker must not return")
    broadcast_source = (
        web_js_root / "features/transactions/send/broadcast.js"
    ).read_text(errors="ignore")
    if "Preimage QR share (commented out" in broadcast_source or "generate_qr_svg_text(preimageJson)" in broadcast_source:
        errors.append("disabled preimage-QR broadcast implementation must not return")
    obsolete_commit_hash_patterns = {
        "handleCrHash": r"\bhandleCrHash\b",
        "btn-cov-cr-hash": r"[\"']btn-cov-cr-hash[\"']",
        "cov-cr-preimage": r"[\"']cov-cr-preimage[\"']",
    }
    for name, pattern in obsolete_commit_hash_patterns.items():
        if re.search(pattern, all_web_js_source):
            errors.append(f"dead manual commit-hash browser surface must not return: {name}")
    web_html_source = "\n".join(
        path.read_text(errors="ignore")
        for path in (ROOT / "apps/kassee-web/web/html").rglob("*.html")
    )
    if 'id="cov-cr-preimage"' in web_html_source:
        errors.append("dead commit-reveal preimage fallback field must not return")
    return errors, wasm_import_names, all_web_js_source

def _check_browser_contracts(root: Path, all_web_js_source: str) -> list[str]:
    ROOT = root
    errors: list[str] = []
    web_js_root = ROOT / "apps/kassee-web/web/js"
    # Application code must not expose or consume a window.* compatibility API.
    for path in sorted(web_js_root.rglob("*.js")) if web_js_root.exists() else []:
        source = path.read_text(errors="ignore")
        if re.search(r"\bwindow\.[A-Za-z_$][A-Za-z0-9_$]*", source):
            errors.append(f"application-defined browser global access is forbidden: {path.relative_to(ROOT)}")
        if "Object.defineProperty(window" in source:
            errors.append(f"application-defined browser global proxy is forbidden: {path.relative_to(ROOT)}")
    if "readApplicationCapability" in all_web_js_source or "writeApplicationCapability" in all_web_js_source:
        errors.append("generic browser capability bypass functions must not return")
    storage_keys = set(
        f"{store}:{key}"
        for store, key in re.findall(
            r"\b(localStorage|sessionStorage)\.(?:getItem|setItem|removeItem)\(\s*['\"]([^'\"]+)['\"]",
            all_web_js_source,
        )
    )
    storage_digest = hashlib.sha256("\n".join(sorted(storage_keys)).encode()).hexdigest()
    if len(storage_keys) != 4 or storage_digest != "a3c14153e561016b2d5f49cca079687c748ecfe033f842ba9ec2f4fd9393b7ed":
        errors.append(f"browser storage contract changed: {len(storage_keys)} keys / {storage_digest}")
    required_web_checks = (
        ROOT / "qa/checks/web/check_web_dom_contract.py",
        ROOT / "qa/checks/web/check_web_covenant_interactions.mjs",
        ROOT / "qa/checks/web/check_web_javascript.py",
        ROOT / "qa/checks/web/check_web_critical_paths.mjs",
    )
    missing_web_checks = [path.name for path in required_web_checks if not path.exists()]
    if missing_web_checks:
        errors.append(f"required browser regression checks missing: {missing_web_checks}")
    expected_event_binders = {
        "bindCoreEvents", "bindOracleEvents", "bindStealthEvents",
        "bindCovenantCreationEvents", "bindCovenantActionsEvents",
        "bindCovenantSpecializedEvents", "bindTaggedVaultAndRecoveryEvents",
        "bindCovenantLoadingEvents", "bindTransactionsEvents",
        "bindSettingsAndWalletEvents", "bindPortfolioEvents",
    }
    event_root = web_js_root / "app/events"
    expected_event_groups = {"system", "wallet", "transactions", "contracts"}
    actual_event_groups = {
        path.name for path in event_root.iterdir() if path.is_dir()
    } if event_root.exists() else set()
    if actual_event_groups != expected_event_groups:
        errors.append(
            f"web event groups changed: expected {sorted(expected_event_groups)}, "
            f"got {sorted(actual_event_groups)}"
        )
    direct_event_modules = sorted(
        path.name for path in event_root.glob("*.js") if path.name != "index.js"
    ) if event_root.exists() else []
    if direct_event_modules:
        errors.append(
            f"web event handlers must be grouped by domain, found direct modules: {direct_event_modules}"
        )
    required_event_modules = {
        "index.js",
        "system/core.js",
        "wallet/settings_and_wallet.js",
        "transactions/transactions.js",
        "transactions/stealth.js",
        "contracts/oracle.js",
        "contracts/covenant_creation.js",
        "contracts/covenant_actions.js",
        "contracts/covenant_specialized.js",
        "contracts/tagged_vault_and_recovery.js",
        "contracts/covenant_loading.js",
    }
    actual_event_modules = {
        path.relative_to(event_root).as_posix() for path in event_root.rglob("*.js")
    } if event_root.exists() else set()
    missing_event_modules = required_event_modules - actual_event_modules
    if missing_event_modules:
        errors.append(f"required grouped web event modules missing: {sorted(missing_event_modules)}")
    event_index = event_root / "index.js"
    if event_index.exists():
        event_source = event_index.read_text(errors="ignore")
        actual_event_binders = set(re.findall(r"\b(bind[A-Za-z0-9]+Events)\(\);", event_source))
        if actual_event_binders != expected_event_binders:
            errors.append(
                f"web event binder inventory changed: expected {sorted(expected_event_binders)}, "
                f"got {sorted(actual_event_binders)}"
            )
        if "createFeatureContext" in event_source:
            errors.append("event composition must use direct imports rather than application capabilities")
    return errors

def _check_recovery_compatibility_exception(root: Path) -> list[str]:
    errors: list[str] = []
    web_root = root / "apps/kassee-web/web/js"
    historical_modules = sorted(
        path.relative_to(web_root).as_posix()
        for path in web_root.rglob("historical*.js")
    )
    if historical_modules:
        errors.append(
            "historical browser recovery modules must stay absent: "
            + ", ".join(historical_modules)
        )
    regression_test = root / "qa/checks/web/check_web_critical_paths.mjs"
    if not regression_test.exists():
        errors.append("current recovery regression test is missing")
    else:
        test_source = regression_test.read_text(errors="ignore")
        for symbol in ("readOptionalDate", "normalizeRecoveredInvite"):
            if symbol not in test_source:
                errors.append(f"current recovery regression lacks coverage for: {symbol}")
    return errors


def check(root: Path) -> list[str]:
    layout_errors, wasm_import_names, all_web_js_source = _check_module_layout(root)
    return [
        *layout_errors,
        *check_feature_contracts(root, wasm_import_names),
        *_check_browser_contracts(root, all_web_js_source),
        *_check_recovery_compatibility_exception(root),
    ]
