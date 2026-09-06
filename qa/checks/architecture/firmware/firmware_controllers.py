from __future__ import annotations
from pathlib import Path
import hashlib, re

from architecture.core.common import relative_posix

from .camera_contract import check_camera_controllers

EXPECTED_SD_HANDLERS = frozenset({
    "handle_sd_delete_confirm",
    "handle_sd_file_list",
    "handle_sd_import_menu",
    "handle_sd_kpub_encrypt_ask",
    "handle_sd_kpub_file_list",
    "handle_sd_kpub_filename",
    "handle_sd_kspt_encrypt_ask",
    "handle_sd_kspt_encrypt_pass",
    "handle_sd_kspt_file_list",
    "handle_sd_kspt_filename",
    "handle_sd_ms_addr_encrypt_ask",
    "handle_sd_ms_addr_filename",
    "handle_sd_ms_desc_encrypt_ask",
    "handle_sd_ms_desc_filename",
    "handle_sd_overwrite_warning",
    "handle_sd_sig_filename",
    "handle_sd_xprv_export_passphrase",
    "handle_sd_xprv_filename",
    "handle_seed_backup_warning",
    "handle_seed_backup_filename",
    "handle_seed_backup_export_passphrase",
    "handle_wallet_backup_file_list",
    "handle_wallet_backup_import_passphrase",
    "handle_show_qr_mode_choice",
    "handle_show_qr_popup",
})

def _check_export_controllers(root: Path) -> list[str]:
    ROOT = root
    errors: list[str] = []
    export_facade = ROOT / "apps/signer-firmware/src/runtime/interactions/export.rs"
    export_root = ROOT / "apps/signer-firmware/src/runtime/interactions/export"
    required_export_modules = (
        export_root / "address.rs",
        export_root / "derivation.rs",
        export_root / "kpub.rs",
        export_root / "menus/root.rs",
        export_root / "private_key.rs",
        export_root / "seed_backup.rs",
        export_root / "menus/seed.rs",
        export_root / "seed_qr.rs",
        export_root / "menus/signing_keys.rs",
        export_root / "watch_only.rs",
        export_root / "xprv.rs",
    )
    for required in required_export_modules:
        if not required.exists():
            errors.append(f"required firmware export module is missing: {required.relative_to(ROOT)}")
    if export_facade.exists():
        export_facade_source = export_facade.read_text(errors="ignore")
        if len(export_facade_source.splitlines()) > 120:
            errors.append("controllers/export.rs must remain a small stable façade")
        if "match ad.app.state" in export_facade_source:
            errors.append("controllers/export.rs must delegate workflow implementations")
    export_production_files = list(export_root.rglob("*.rs")) if export_root.exists() else []
    for path in export_production_files:
        line_count = len(path.read_text(errors="ignore").splitlines())
        if line_count > 300:
            errors.append(
                f"firmware export module exceeds 300-line SRP limit: "
                f"{path.relative_to(ROOT)} ({line_count} lines)"
            )
    export_source = "\n".join(
        path.read_text(errors="ignore") for path in [export_facade, *export_production_files]
        if path.exists()
    )
    export_signature_pattern = re.compile(
        r"(?ms)^\s*pub\s+fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*(.*?)\{"
    )
    export_functions = {
        name for name, _ in export_signature_pattern.findall(export_source)
    }
    if export_functions != {"handle_export_touch"}:
        errors.append(
            "firmware export façade must expose only handle_export_touch; "
            f"got {sorted(export_functions)}"
        )
    return errors
def _check_sd_controllers(root: Path) -> list[str]:
    ROOT = root
    errors: list[str] = []
    sd_facade = ROOT / "apps/signer-firmware/src/runtime/interactions/sd/mod.rs"
    sd_root = ROOT / "apps/signer-firmware/src/runtime/interactions/sd"
    required_sd_modules = (
        sd_root / "common/context.rs",
        sd_root / "common/filename.rs",
        sd_root / "common/list_navigation.rs",
        sd_root / "common/import_scan.rs",
        sd_root / "common/encryption_prompt.rs",
        sd_root / "common/overwrite.rs",
        sd_root / "common/passphrase.rs",
        sd_root / "common/shared.rs",
        sd_root / "imports/file_browser.rs",
        sd_root / "imports/payload_detection.rs",
        sd_root / "imports/selected_file/mod.rs",
        sd_root / "imports/selected_file/covenant_backup.rs",
        sd_root / "imports/selected_file/private_key.rs",
        sd_root / "imports/selected_file/xprv.rs",
        sd_root / "imports/import_menu.rs",
        sd_root / "imports/kspt_import.rs",
        sd_root / "exports/kpub.rs",
        sd_root / "exports/kspt_export/mod.rs",
        sd_root / "exports/multisig.rs",
        sd_root / "exports/qr.rs",
        sd_root / "exports/signature.rs",
        sd_root / "backup/mod.rs",
        sd_root / "backup/seed.rs",
        sd_root / "backup/import.rs",
        sd_root / "backup/xprv/mod.rs",
        sd_root / "backup/xprv/export.rs",
    )
    for required in required_sd_modules:
        if not required.exists():
            errors.append(f"required firmware SD module is missing: {required.relative_to(ROOT)}")
    retired_wallet_backup_paths = (
        sd_root / "backup/seed_backup.rs",
        sd_root / "backup/seed_restore.rs",
        ROOT / "apps/signer-firmware/src/ui/screens/storage/sd/warning.rs",
    )
    for retired in retired_wallet_backup_paths:
        if retired.exists():
            errors.append(f"retired password-only wallet-backup tombstone must stay deleted: {retired.relative_to(ROOT)}")
    if sd_facade.exists():
        sd_facade_source = sd_facade.read_text(errors="ignore")
        if len(sd_facade_source.splitlines()) > 140:
            errors.append("controllers/sd/mod.rs must remain a small stable façade")
        if "let mut needs_redraw" in sd_facade_source:
            errors.append("controllers/sd/mod.rs must delegate workflow implementations")
    expected_sd_groups = {"common", "imports", "exports", "backup"}
    actual_sd_groups = {path.name for path in sd_root.iterdir() if path.is_dir()} if sd_root.exists() else set()
    if actual_sd_groups != expected_sd_groups:
        errors.append(
            f"firmware SD groups changed: expected {sorted(expected_sd_groups)}, "
            f"got {sorted(actual_sd_groups)}"
        )
    direct_sd_modules = sorted(path.name for path in sd_root.glob("*.rs")) if sd_root.exists() else []
    if direct_sd_modules != ["mod.rs"]:
        errors.append(f"firmware SD root must contain only mod.rs, found: {direct_sd_modules}")
    sd_production_files = list(sd_root.rglob("*.rs")) if sd_root.exists() else []
    for path in sd_production_files:
        line_count = len(path.read_text(errors="ignore").splitlines())
        if line_count > 500:
            errors.append(
                f"firmware SD module exceeds 500-line SRP limit: "
                f"{path.relative_to(ROOT)} ({line_count} lines)"
            )
    sd_handler_source = "\n".join(
        path.read_text(errors="ignore") for path in sd_production_files
        if path.name not in {"context.rs", "shared.rs"}
    )
    sd_handlers = set(re.findall(
        r"(?m)^pub\((?:super|crate)\) fn (handle_[A-Za-z0-9_]+)\(", sd_handler_source
    ))
    sd_handlers.discard("handle_file_list_touch")
    expected_sd_handlers = EXPECTED_SD_HANDLERS
    if sd_handlers != expected_sd_handlers:
        errors.append(
            "firmware SD state handler inventory changed: "
            f"expected {sorted(expected_sd_handlers)}, got {sorted(sd_handlers)}"
        )
    filename_source = (sd_root / "common/filename.rs").read_text(errors="ignore") if (sd_root / "common/filename.rs").exists() else ""
    list_navigation_source = (sd_root / "common/list_navigation.rs").read_text(errors="ignore") if (sd_root / "common/list_navigation.rs").exists() else ""
    common_facade_source = (sd_root / "common/mod.rs").read_text(errors="ignore")
    if "run_filename_workflow(" not in filename_source or "struct FilenameWorkflow" not in filename_source:
        errors.append("firmware SD filename screens must share the configurable filename workflow")
    if "navigate_file_list(" not in list_navigation_source or "enum FileListAction" not in list_navigation_source:
        errors.append("firmware SD file lists must share pure paging and hit-testing")
    if "run_sd_file_list_context" not in common_facade_source or "run_sd_list_context" not in common_facade_source:
        errors.append("firmware SD list navigation must be re-exported through common/mod.rs")
    if "list_navigation::{FileListControllerOutcome" in sd_facade_source:
        errors.append("controllers/sd/mod.rs must consume list navigation through the common façade")
    filename_handlers = {
        "backup/xprv/export.rs": "handle_sd_xprv_filename",
        "exports/kpub.rs": "handle_sd_kpub_filename",
        "exports/kspt_export/filename.rs": "handle_sd_kspt_filename",
        "exports/multisig.rs": "handle_sd_ms_addr_filename",
    }
    for relative, handler in filename_handlers.items():
        source = (sd_root / relative).read_text(errors="ignore")
        if handler in source and "run_filename_workflow(" not in source:
            errors.append(f"firmware SD filename handler bypasses shared workflow: {relative}::{handler}")
    multisig_source = (sd_root / "exports/multisig.rs").read_text(errors="ignore")
    if "handle_sd_ms_desc_filename" in multisig_source and multisig_source.count("run_filename_workflow(") < 2:
        errors.append("multisig address and descriptor filenames must share the common workflow")
    list_handlers = (
        sd_root / "imports/file_browser.rs",
        sd_root / "imports/kspt_import.rs",
        sd_root / "exports/kpub.rs",
        sd_root / "backup/import.rs",
    )
    for path in list_handlers:
        source = path.read_text(errors="ignore")
        if "run_sd_file_list_context(" not in source and "run_sd_list_context(" not in source:
            errors.append(f"firmware SD list bypasses shared navigation: {path.relative_to(ROOT)}")
    duplicated_list_tokens = ("let max_vis: usize = 4", "let mut tapped: Option<usize>")
    for token in duplicated_list_tokens:
        offenders = [
            relative_posix(path, ROOT) for path in list_handlers
            if token in path.read_text(errors="ignore")
        ]
        if offenders:
            errors.append(f"duplicated SD list navigation returned ({token}): {offenders}")
    sd_api_paths = [sd_facade, sd_root / "common/routing.rs", sd_root / "common/shared.rs"]
    sd_api_source = "\n".join(
        path.read_text(errors="ignore") for path in sd_api_paths if path.exists()
    )
    sd_signature_pattern = re.compile(
        r"(?ms)^\s*(pub(?:\(crate\))?)\s+fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*(.*?)\{"
    )
    sd_signatures = sorted(
        " ".join(f"{visibility} fn {name} {tail}".split())
        for visibility, name, tail in sd_signature_pattern.findall(sd_api_source)
    )
    sd_signature_hash = hashlib.sha256("\n".join(sd_signatures).encode()).hexdigest()
    # Descriptor parsing stays private to the SD subtree; camera QR import
    # calls the shared-signer parser directly so there is still one parser owner.
    if len(sd_signatures) != 7 or sd_signature_hash != (
        "16c9a0da425f96313723f2f15824df34033a4968f5bea437db44e10995dbc0b7"
    ):
        errors.append(
            f"firmware SD API changed: expected 7 signatures with the locked digest, got "
            f"{len(sd_signatures)} signatures / {sd_signature_hash}"
        )
    return errors
def _check_state_controllers(root: Path) -> list[str]:
    ROOT = root
    errors: list[str] = []
    controller_contracts = {
        "seed": {
            "modules": ("bip85.rs", "delete_seed.rs", "import/mod.rs", "passphrase.rs", "passphrase_choice.rs", "seed_list.rs", "wallet_name.rs"),
            "api_count": 1,
            "api_digest": "74d02759a6b4b64b202d0525d8cca161abe1b4f02731019963c6100d103504b7",
            "state_count": 9,
            "state_digest": "1b8879554a027becb6085e7d16851f7971301c1d8a3617e3ec771c81ae4e83dc",
        },
        "tx": {
            "modules": ("commit_results.rs", "commit_reveal.rs", "covenant_signing.rs", "message_signing.rs", "message_source/mod.rs", "multisig_output.rs", "multisig_setup.rs", "private_swap.rs", "transaction.rs"),
            "api_count": 1,
            "api_digest": "83f6902fe557dee254dc4063b9c1e399d97b567c9a5c45192de1ee49774ea55a",
            "state_count": 26,
            "state_digest": "f1d679a363437d27b6f6b68bb842d2eb66c20ce27391d405a892994b3c618baf",
        },
        "stego": {
            "modules": ("context.rs", "export_confirm/mod.rs", "export_description.rs", "export_security.rs", "import_decrypt.rs", "import_finish.rs", "import_selection/mod.rs", "mode.rs"),
            "api_count": 1,
            "api_digest": "ceab23f1102d535acf13ec0f51232d882bc85dbdecdb5c33db0562ddaece2b0b",
            "state_count": 18,
            "state_digest": "76b3da3f2bd9b528ae979c8f315c677c605ce336446f212b65279c4c1dbf6e6c",
        },
        "menu": {
            "modules": ("import_export/mod.rs", "primary.rs", "qr.rs", "seed_generation.rs", "seed_tools.rs", "signing.rs"),
            "api_count": 1,
            "api_digest": "d7fb2213d77171c5030f2f9ca6c2c99b5d23089ebe1cf95844ac8b1676d378f4",
            "state_count": 15,
            "state_digest": "bf8760440963a66d8633f6978d5c0aa83b8a340f0f9a56218a689460429c1595",
        },
    }
    for controller_name, contract in controller_contracts.items():
        facade = ROOT / f"apps/signer-firmware/src/runtime/interactions/{controller_name}.rs"
        module_root = ROOT / f"apps/signer-firmware/src/runtime/interactions/{controller_name}"
        required = {module_root / name for name in contract["modules"]}
        actual = set(module_root.glob("*.rs")) if module_root.exists() else set()
        for nested_mod in module_root.glob("*/mod.rs") if module_root.exists() else []:
            actual.add(nested_mod)
        missing = required - actual
        extra = actual - required
        if missing:
            errors.append(
                f"required firmware {controller_name} modules are missing: "
                f"{sorted(path.name for path in missing)}"
            )
        if extra:
            errors.append(
                f"unregistered firmware {controller_name} modules found: "
                f"{sorted(path.name for path in extra)}"
            )
        if facade.exists():
            facade_source = facade.read_text(errors="ignore")
            if len(facade_source.splitlines()) > 100:
                errors.append(f"controllers/{controller_name}.rs must remain a small stable façade")
            if "match ad.navigation.app.state" in facade_source:
                errors.append(f"controllers/{controller_name}.rs must delegate state implementations")
            api_match = re.search(
                rf"(?ms)^pub fn handle_{controller_name}_touch\s*(.*?)\{{", facade_source
            )
            api_signatures = [] if api_match is None else [
                " ".join(
                    f"pub fn handle_{controller_name}_touch {api_match.group(1)}".split()
                )
            ]
            api_digest = hashlib.sha256("\n".join(api_signatures).encode()).hexdigest()
            if len(api_signatures) != contract["api_count"] or api_digest != contract["api_digest"]:
                errors.append(
                    f"firmware {controller_name} API changed: "
                    f"{len(api_signatures)} signatures / {api_digest}"
                )
        implementation_files = sorted(module_root.rglob("*.rs"))
        for module in implementation_files:
            line_count = len(module.read_text(errors="ignore").splitlines())
            if line_count > 600:
                errors.append(
                    f"firmware {controller_name} module exceeds 600-line SRP limit: "
                    f"{module.relative_to(ROOT)} ({line_count} lines)"
                )
        module_source = "\n".join(path.read_text(errors="ignore") for path in implementation_files)
        handled_states = set(re.findall(
            r"(?:crate::runtime::input::)?AppState::([A-Za-z0-9_]+)\s*=>",
            module_source,
        ))
        handled_states.update(re.findall(
            r"ad\.navigation\.app\.state\s*(?:==|!=)\s*(?:crate::runtime::input::)?AppState::([A-Za-z0-9_]+)",
            module_source,
        ))
        if not handled_states:
            errors.append(f"firmware {controller_name} modules do not handle any AppState")
        for module in implementation_files:
            source = module.read_text(errors="ignore")
            dispatcher_count = source.count("match ad.navigation.app.state") + len(re.findall(
                r"ad\.navigation\.app\.state\s*(?:==|!=)\s*(?:crate::runtime::input::)?AppState::",
                source,
            ))
            if dispatcher_count > 1:
                errors.append(
                    f"firmware {controller_name} module owns multiple state dispatchers: "
                    f"{module.relative_to(ROOT)}"
                )
        for module in actual:
            source = module.read_text(errors="ignore")
            has_dispatcher = (
                "match ad.navigation.app.state" in source
                or re.search(
                    r"ad\.navigation\.app\.state\s*(?:==|!=)\s*(?:crate::runtime::input::)?AppState::",
                    source,
                ) is not None
            )
            if (not has_dispatcher and "mod " not in source
                    and "pub(super) fn" not in source and module.name != "context.rs"):
                errors.append(
                    f"firmware {controller_name} module neither dispatches nor delegates: "
                    f"{module.relative_to(ROOT)}"
                )
    return errors

def _check_pure_controller_boundary(root: Path) -> list[str]:
    errors: list[str] = []
    source_root = root / "apps/signer-firmware/src"
    controller = source_root / "controllers.rs"
    legacy_tree = source_root / "controllers"
    interactions = source_root / "runtime/interactions"
    if legacy_tree.exists():
        errors.append("legacy effectful src/controllers/ tree must stay retired")
    if not controller.exists():
        return [*errors, "pure firmware controllers.rs boundary is missing"]
    source = controller.read_text(errors="ignore")
    if len(source.splitlines()) > 120:
        errors.append("pure controllers.rs boundary exceeds 120-line SRP limit")
    for required in ("struct TouchInput", "enum InteractionDomain", "fn classify(", "HandlerGroup"):
        if required not in source:
            errors.append(f"pure controller boundary lost {required}")
    forbidden = (
        "crate::hw", "esp_hal", "crate::services", "crate::ui", "PersistentWallet",
        "BootDisplay", "I2c", "Delay", "Flash", "HMAC", "save_with_credential", "unlock_saved",
    )
    for token in forbidden:
        if token in source:
            errors.append(f"pure controller boundary imports/owns effectful capability: {token}")
    if not interactions.is_dir():
        errors.append("effectful runtime/interactions adapter tree is missing")
    touch_routes = (source_root / "runtime/event_loop/touch_routes.rs").read_text(errors="ignore")
    if "controllers::classify" not in touch_routes or "InteractionDomain::" not in touch_routes:
        errors.append("event-loop input dispatch must enter effectful adapters through the pure controller classifier")
    return errors

def check(root: Path) -> list[str]:
    return [
        *_check_pure_controller_boundary(root),
        *_check_export_controllers(root),
        *_check_sd_controllers(root),
        *check_camera_controllers(root),
        *_check_state_controllers(root),
    ]
