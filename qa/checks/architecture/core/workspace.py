from __future__ import annotations

from pathlib import Path
import re
import tomllib

from firmware.firmware_lint_policy import check_policy as check_firmware_lint_policy
from .common import is_generated_tree
from architecture.web.generated_output import check_web_pkg_policy
from .quality_ownership import check_quality_ownership
from architecture.tooling.workspace_delivery import _check_firmware_delivery_paths, _check_master_test_runner
from .sdk.workspace import check as check_sdk_workspace




def _check_qa_test_layout(root: Path) -> list[str]:
    """Reject Rust integration-test roots that collide with sibling module directories."""
    errors: list[str] = []
    tests_root = root / "qa/tests"
    if not tests_root.is_dir():
        return errors

    for test_root in sorted(tests_root.glob("*.rs")):
        module_name = test_root.stem
        module_dir = tests_root / module_name
        module_mod = module_dir / "mod.rs"
        if not module_mod.is_file():
            continue

        source = test_root.read_text(errors="ignore")
        ambiguous = re.search(
            rf"(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+{re.escape(module_name)}\s*;",
            source,
        )
        if ambiguous:
            errors.append(
                f"ambiguous Rust integration-test module: {test_root.relative_to(root)} "
                f"declares `mod {module_name};` while "
                f"{module_mod.relative_to(root)} also exists; use an explicit #[path] alias"
            )
    return errors

def _check_repository_metadata(root: Path) -> list[str]:
    errors: list[str] = []
    attributes = (root / ".gitattributes").read_text(errors="ignore").splitlines()
    active = [line.strip() for line in attributes if line.strip() and not line.lstrip().startswith("#")]
    duplicates = sorted({line for line in active if active.count(line) > 1})
    if duplicates:
        errors.append(f".gitattributes contains duplicate rules: {duplicates}")
    for line in active:
        token = line.split(maxsplit=1)[0]
        if token.startswith("kassee/") or token.startswith("web/"):
            errors.append(f".gitattributes retains stale repository path: {token}")
    ignore = (root / ".gitignore").read_text(errors="ignore")
    for required in ("__pycache__/", "*.py[cod]"):
        if required not in ignore:
            errors.append(f".gitignore must exclude Python cache artifacts: {required}")
    return errors

def _check_root_manifest_and_lints(root: Path) -> list[str]:
    errors: list[str] = []
    root_manifest = tomllib.loads((root / "Cargo.toml").read_text())
    if "package" in root_manifest or "lib" in root_manifest:
        errors.append("root Cargo.toml must be a virtual workspace without a root package")
    errors.extend(check_firmware_lint_policy(root))
    return errors

def _check_business_facades(root: Path) -> list[str]:
    errors: list[str] = []
    business_facades = {
        root / "crates/offline-signer/src/facade.rs": "OfflineSigner",
        root / "crates/online-watcher/src/facade.rs": "WatchWallet",
    }
    for path, expected_struct in business_facades.items():
        if not path.is_file():
            errors.append(f"missing business facade module: {path.relative_to(root)}")
            continue
        source = path.read_text(errors="ignore")
        structs = re.findall(r"\bpub\s+struct\s+([A-Za-z_][A-Za-z0-9_]*)", source)
        if structs != [expected_struct]:
            errors.append(
                f"business facade {path.relative_to(root)} must expose only {expected_struct}, got {structs}"
            )
        line_count = len(source.splitlines())
        if line_count > 250:
            errors.append(
                f"business facade exceeds coordination limit: {path.relative_to(root)} ({line_count} lines)"
            )

    unexpected: list[str] = []
    facade_name = re.compile(r"\bpub\s+struct\s+([A-Za-z_][A-Za-z0-9_]*Facade)\b")
    for path in root.rglob("*.rs"):
        if path in business_facades or any(part in {"target", "external"} for part in path.parts):
            continue
        for name in facade_name.findall(path.read_text(errors="ignore")):
            unexpected.append(f"{path.relative_to(root)}::{name}")
    if unexpected:
        errors.append("unexpected broad business facade types: " + ", ".join(sorted(unexpected)))
    return errors

def _check_firmware_core_ownership(root: Path) -> list[str]:
    errors: list[str] = []
    core = root / "crates/signer-firmware-core/src"
    expected_groups = {
        "backup", "camera", "entropy", "input", "power", "presentation",
        "qr", "runtime", "security", "storage", "time", "update",
    }
    actual_groups = {
        path.name for path in core.iterdir()
        if path.is_dir() and path.name != "unit_tests"
    }
    if actual_groups != expected_groups:
        errors.append(
            "signer-firmware-core must group device decisions by backup, camera, entropy, "
            "input, power, presentation, qr, runtime, security, storage, time, and update"
        )
    for group in sorted(core.iterdir()):
        if not group.is_dir() or group.name == "unit_tests":
            continue
        direct_modules = [
            path for path in group.iterdir()
            if path.is_file() and path.name != "mod.rs"
        ]
        if len(direct_modules) > 6:
            errors.append(
                f"crowded signer-firmware-core group: {group.relative_to(root)} has "
                f"{len(direct_modules)} modules (maximum 6)"
            )

    shared_lib = (root / "crates/shared-signer/src/lib.rs").read_text(errors="ignore")
    for forbidden in ("firmware", "advanced_policy", "entropy", "release", "stego_picture"):
        if f"pub mod {forbidden};" in shared_lib:
            errors.append(f"shared-signer must not expose firmware-owned module: {forbidden}")
    if (root / "crates/shared-signer/src/firmware").exists():
        errors.append("shared-signer/src/firmware must not exist after firmware-core extraction")
    descriptor = root / "crates/kassigner-protocol/src/wire/multisig_descriptor.rs"
    if not descriptor.is_file():
        errors.append("canonical multisig descriptor parser must live in kassigner-protocol wire")
    return errors

def check(root: Path) -> list[str]:
    ROOT = root
    errors: list[str] = [
        *_check_firmware_delivery_paths(root),
        *_check_master_test_runner(root),
        *check_quality_ownership(root),
        *_check_qa_test_layout(root),
        *_check_repository_metadata(root),
        *check_web_pkg_policy(root),
    ]

    for obsolete in (
        "bootloader", "kassee", "rqrr_nostd", "platforms", "vendor", "hardware",
        "src", "tests", "benches", "fuzz",
    ):
        if (ROOT / obsolete).exists():
            errors.append(f"obsolete or misplaced top-level path exists: {obsolete}")


    errors.extend(check_sdk_workspace(ROOT))

    errors.extend(_check_business_facades(ROOT))

    # Independent deliverables use separate Cargo workspace roots and lockfiles.
    root_workspace = tomllib.loads((ROOT / "Cargo.toml").read_text()).get("workspace", {})
    expected_workspace_members = {
        "crates/kassigner-protocol",
        "crates/kassigner-sdk",
        "crates/offline-signer",
        "crates/online-watcher",
        "crates/shared-signer",
        "crates/signer-firmware-core",
    }
    expected_workspace_excludes = {
        "apps/signer-firmware",
        "apps/kassee-web",
        "tools",
        "qa",
        "qa/fuzz",
        "external/rqrr-nostd",
    }
    if set(root_workspace.get("members", [])) != expected_workspace_members:
        errors.append("root workspace must contain only reusable library crates")
    if set(root_workspace.get("exclude", [])) != expected_workspace_excludes:
        errors.append("independent applications, tools, and QA must be excluded from the root workspace")
    for relative in (
        "apps/signer-firmware/Cargo.toml",
        "apps/kassee-web/Cargo.toml",
        "tools/Cargo.toml",
        "qa/Cargo.toml",
        "qa/fuzz/Cargo.toml",
        "external/rqrr-nostd/Cargo.toml",
    ):
        manifest = tomllib.loads((ROOT / relative).read_text())
        if manifest.get("workspace", {}).get("resolver") != "2":
            errors.append(f"independent workspace marker is missing: {relative}")

    if (ROOT / "rust-toolchain.toml").exists():
        errors.append("the ESP toolchain pin must not apply to every workspace")
    firmware_toolchain = ROOT / "apps/signer-firmware/rust-toolchain.toml"
    if not firmware_toolchain.is_file() or 'channel = "esp"' not in firmware_toolchain.read_text():
        errors.append("firmware-local ESP toolchain pin is missing")

    organized_roots = {
        ROOT / "crates/kassigner-protocol/src": 1,
        ROOT / "crates/kassigner-sdk/src": 1,
        ROOT / "crates/offline-signer/src": 2,
        ROOT / "crates/online-watcher/src": 2,
        ROOT / "crates/signer-firmware-core/src": 3,
        ROOT / "apps/signer-firmware/src/hw": 1,
    }
    for directory, maximum_files in organized_roots.items():
        direct_files = [path for path in directory.iterdir() if path.is_file()]
        if len(direct_files) > maximum_files:
            errors.append(
                f"crowded source root: {directory.relative_to(ROOT)} has "
                f"{len(direct_files)} direct files (maximum {maximum_files})"
            )

    errors.extend(_check_firmware_core_ownership(ROOT))

    required_qa_paths = [
        ROOT / "qa/Cargo.toml",
        ROOT / "qa/tests/common",
        ROOT / "qa/tests/conformance",
        ROOT / "qa/tests/integration",
        ROOT / "qa/tests/fixtures",
        ROOT / "qa/benches",
        ROOT / "qa/fuzz/Cargo.toml",
        ROOT / "qa/fuzz/unwrap_qr_payload.rs",
    ]
    for required in required_qa_paths:
        if not required.exists():
            errors.append(f"required QA path is missing: {required.relative_to(ROOT)}")

    if (ROOT / "qa/src").exists():
        errors.append("qa must not contain an artificial src/ package target")
    if (ROOT / "qa/fuzz/fuzz_targets").exists():
        errors.append("qa/fuzz must be flat; fuzz_targets/ is not allowed")
    if (ROOT / "external/hardware/case-waveshare").exists():
        errors.append("external/hardware must be flat; case-waveshare/ is not allowed")

    for forbidden_name in ("boot_test.rs", "self_test.rs"):
        for path in ROOT.rglob(forbidden_name):
            if is_generated_tree(path, ROOT):
                continue
            errors.append(f"test implementation must live under unit_tests/: {path.relative_to(ROOT)}")

    for path in ROOT.rglob("*.rs"):
        relative = path.relative_to(ROOT)
        if (
            is_generated_tree(path, ROOT)
            or "unit_tests" in relative.parts
            or "tests" in relative.parts
            or relative.parts[0] == "qa"
        ):
            continue
        source = path.read_text(errors="ignore")
        if "#[test]" in source or re.search(r"\bmod\s+tests\b", source):
            errors.append(f"inline test implementation remains in production source: {relative}")

    for duplicate_root in ROOT.rglob("src/mod.rs"):
        if is_generated_tree(duplicate_root, ROOT):
            continue
        if (duplicate_root.parent / "lib.rs").exists():
            errors.append(f"duplicate crate root module exists: {duplicate_root.relative_to(ROOT)}")

    production_roots = (
        ROOT / "apps/signer-firmware/src",
        ROOT / "crates/offline-signer/src",
        ROOT / "crates/online-watcher/src",
        ROOT / "crates/shared-signer/src",
        ROOT / "crates/signer-firmware-core/src",
    )
    for source_root in production_roots:
        for path in source_root.rglob("*.rs"):
            source = path.read_text(errors="ignore")
            relative = path.relative_to(ROOT)
            if re.search(r"(?m)^#!\[allow\(", source):
                errors.append(f"crate/file-wide lint allowance is forbidden: {relative}")
            if "#[allow(deprecated)]" in source:
                errors.append(f"deprecated API suppression is forbidden: {relative}")
            if "#[allow(dead_code)]" in source:
                errors.append(f"retained dead-code suppression is forbidden: {relative}")

    errors.extend(_check_root_manifest_and_lints(ROOT))
    return errors
