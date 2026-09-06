"""Self-enforcement for the grouped architecture checker package."""

from __future__ import annotations

from pathlib import Path
import ast
import re

from .common import rust_function_lengths

CHECK_MODULES = {
    "core/checker_structure.py",
    "core/dependency_boundaries.py",
    "core/inventory/repository_inventory.py",
    "core/rust_syntax.py",
    "core/source_quality.py",
    "core/workspace.py",
    "tooling/native_entrypoints.py",
    "tooling/toolchain_policy.py",
    "firmware/subsystems/firmware_boot.py",
    "firmware/subsystems/firmware_backup.py",
    "firmware/firmware_controllers.py",
    "firmware/guards/account_key.py",
    "firmware/guards/source_integrity.py",
    "firmware/guards/wallet_session.py",
    "firmware/firmware_display.py",
    "firmware/firmware_navigation.py",
    "firmware/firmware_presentation.py",
    "firmware/subsystems/firmware_media.py",
    "firmware/firmware_runtime.py",
    "firmware/firmware_services.py",
    "firmware/firmware_screens.py",
    "firmware/firmware_state.py",
    "firmware/subsystems/firmware_storage.py",
    "firmware/firmware_workflows.py",
    "protocols/offline_portability.py",
    "protocols/offline_protocols.py",
    "protocols/online.py",
    "protocols/online_paths.py",
    "protocols/wasm_api.py",
    "web/web_constellation.py",
    "web/web_css.py",
    "web/web_html.py",
    "web/web_js.py",
}
WARNING_MODULES = {
    "core/comment_quality.py",
    "core/duplication.py",
    "core/function_duplication.py",
    "core/symbol_quality.py",
    "web/advisory_quality.py",
}
SUPPORT_MODULES = {
    "__init__.py",
    "core/__init__.py",
    "core/inventory/__init__.py",
    "core/common.py",
    "web/generated_output.py",
    "core/quality_ownership.py",
    "tooling/workspace_delivery.py",
    "core/sdk/__init__.py",
    "core/sdk/workspace.py",
    "firmware/__init__.py",
    "firmware/camera_contract.py",
    "firmware/firmware_settings_state.py",
    "firmware/guards/__init__.py",
    "firmware/subsystems/__init__.py",
    "protocols/__init__.py",
    "protocols/compact_protocols.py",
    "protocols/online_business.py",
    "tooling/__init__.py",
    "web/__init__.py",
    "web/web_contracts.py",
    "web/web_infrastructure.py",
}
EXPECTED_GROUPS = {"core", "firmware", "protocols", "tooling", "web"}
MAX_ARCHITECTURE_FUNCTION_LINES = 150


def registered_modules(entrypoint_source: str) -> tuple[set[str], set[str], set[str]]:
    tree = ast.parse(entrypoint_source)
    imported: set[str] = set()
    registered: dict[str, set[str]] = {"CHECKS": set(), "WARNING_CHECKS": set()}
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and (
            node.module == "architecture" or node.module.startswith("architecture.")
        ):
            imported.update(alias.name for alias in node.names)
        if not isinstance(node, ast.Assign):
            continue
        names = {
            target.id for target in node.targets
            if isinstance(target, ast.Name) and target.id in registered
        }
        if not names or not isinstance(node.value, ast.Tuple):
            continue
        members = {
            element.id for element in node.value.elts
            if isinstance(element, ast.Name)
        }
        for name in names:
            registered[name].update(members)
    return imported, registered["CHECKS"], registered["WARNING_CHECKS"]


def warning_exit_is_nonfatal(entrypoint_source: str) -> bool:
    """Require warnings to be printed while only hard errors control exit status."""
    tree = ast.parse(entrypoint_source)
    main = next(
        (
            node for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "main"
        ),
        None,
    )
    if main is None:
        return False
    final_return_zero = any(
        isinstance(node, ast.Return)
        and isinstance(node.value, ast.Constant)
        and node.value.value == 0
        for node in main.body
    )
    for node in ast.walk(main):
        if not isinstance(node, ast.If):
            continue
        names = {child.id for child in ast.walk(node.test) if isinstance(child, ast.Name)}
        if "warnings" in names and any(
            isinstance(child, ast.Return)
            and isinstance(child.value, ast.Constant)
            and child.value.value not in (None, 0)
            for child in ast.walk(node)
        ):
            return False
    return final_return_zero



def _orphaned_outer_attribute_lines(source: str) -> list[int]:
    """Return outer doc/attribute lines that end at a block close or EOF."""
    lines = source.splitlines()
    orphaned: list[int] = []
    for index, line in enumerate(lines):
        stripped = line.lstrip()
        is_doc = stripped.startswith("///")
        is_attribute = stripped.startswith("#[") and not stripped.startswith("#![")
        if not (is_doc or is_attribute):
            continue
        previous = lines[index - 1].lstrip() if index else ""
        if is_doc and previous.startswith("///"):
            continue
        if is_attribute and previous.startswith("#["):
            continue
        cursor = index
        while cursor < len(lines):
            candidate = lines[cursor].strip()
            if candidate.startswith("///") or candidate.startswith("#["):
                cursor += 1
                continue
            if not candidate or candidate.startswith("//"):
                cursor += 1
                continue
            break
        if cursor >= len(lines) or lines[cursor].strip().startswith("}"):
            orphaned.append(index + 1)
    return orphaned


def _orphaned_rust_doc_comments(root: Path) -> list[str]:
    """Reject outer Rust documentation or attributes with no following item."""
    errors: list[str] = []
    roots = (root / "apps", root / "crates", root / "tools")
    for source_root in roots:
        if not source_root.exists():
            continue
        for path in source_root.rglob("*.rs"):
            if any(part in {"target", "external", "vendor", "generated"} for part in path.parts):
                continue
            for line in _orphaned_outer_attribute_lines(path.read_text(errors="ignore")):
                errors.append(
                    "orphaned Rust documentation/outer attribute: "
                    f"{path.relative_to(root).as_posix()}:{line}"
                )
    return errors

def _warning_contract_errors(package_root: Path) -> list[str]:
    errors: list[str] = []
    warning_contracts = {
        "core/comment_quality.py": "ARCH-W006",
        "core/function_duplication.py": "ARCH-W008",
        "core/symbol_quality.py": "ARCH-W009",
        "web/advisory_quality.py": "ARCH-W011",
    }
    for module_name, code in warning_contracts.items():
        if code not in (package_root / module_name).read_text(errors="ignore"):
            errors.append(f"advisory warning contract missing {code}: {module_name}")
    function_duplication_source = (package_root / "core/function_duplication.py").read_text(errors="ignore")
    if "ARCH-W018" not in function_duplication_source:
        errors.append("advisory warning contract missing ARCH-W018: core/function_duplication.py")
    symbol_quality_source = (package_root / "core/symbol_quality.py").read_text(errors="ignore")
    for code in ("ARCH-W013", "ARCH-W014", "ARCH-W015", "ARCH-W016"):
        if code not in symbol_quality_source:
            errors.append(f"advisory warning contract missing {code}: core/symbol_quality.py")
    advisory_source = (package_root / "web/advisory_quality.py").read_text(errors="ignore")
    if "ARCH-W017" not in advisory_source:
        errors.append("advisory warning contract missing ARCH-W017: web/advisory_quality.py")
    dependency_source = (package_root / "core/dependency_boundaries.py").read_text(errors="ignore")
    if "synthetic child preludes are forbidden" not in dependency_source:
        errors.append("explicit production import-boundary enforcement is missing")
    return errors

def check(root: Path) -> list[str]:
    errors: list[str] = []
    entrypoint = root / "qa/checks/check_architecture.py"
    package_root = root / "qa/checks/architecture"
    entrypoint_source = entrypoint.read_text(errors="ignore")

    if len(entrypoint_source.splitlines()) > 80:
        errors.append("architecture checker entry point exceeds 80 lines")

    actual_groups = {
        path.name for path in package_root.iterdir()
        if path.is_dir() and path.name != "__pycache__"
    }
    if actual_groups != EXPECTED_GROUPS:
        errors.append(
            f"architecture checker groups changed: expected {sorted(EXPECTED_GROUPS)}, "
            f"got {sorted(actual_groups)}"
        )

    direct_python = {path.name for path in package_root.glob("*.py")}
    if direct_python != {"__init__.py"}:
        errors.append(
            f"architecture checks must be grouped; root Python files are {sorted(direct_python)}"
        )

    actual_modules = {
        path.relative_to(package_root).as_posix()
        for path in package_root.rglob("*.py")
        if "__pycache__" not in path.parts
    }
    expected_modules = CHECK_MODULES | WARNING_MODULES | SUPPORT_MODULES
    if actual_modules != expected_modules:
        errors.append(
            f"architecture checker module inventory changed: expected "
            f"{sorted(expected_modules)}, got {sorted(actual_modules)}"
        )

    expected_checks = {Path(name).stem for name in CHECK_MODULES}
    expected_warnings = {Path(name).stem for name in WARNING_MODULES}
    imported, registered_checks, registered_warnings = registered_modules(entrypoint_source)
    if imported != expected_checks | expected_warnings:
        errors.append(
            f"architecture checker imports changed: expected "
            f"{sorted(expected_checks | expected_warnings)}, got {sorted(imported)}"
        )
    if registered_checks != expected_checks:
        errors.append(
            f"hard architecture check registration changed: expected {sorted(expected_checks)}, "
            f"got {sorted(registered_checks)}"
        )
    if registered_warnings != expected_warnings:
        errors.append(
            f"advisory architecture check registration changed: expected "
            f"{sorted(expected_warnings)}, got {sorted(registered_warnings)}"
        )
    if registered_checks & registered_warnings:
        errors.append("architecture modules cannot be both hard checks and advisory warnings")
    if not warning_exit_is_nonfatal(entrypoint_source):
        errors.append("advisory architecture warnings must not control a nonzero exit status")

    source_quality = (package_root / "core/source_quality.py").read_text(errors="ignore")
    if "MAX_FUNCTION_LINES = 200" not in source_quality:
        errors.append("blocking production-function threshold must remain 200 lines")
    if "MAX_MODULE_LINES = 450" not in source_quality:
        errors.append("blocking executable-module threshold must remain 450 lines")
    errors.extend(_warning_contract_errors(package_root))

    rust_parser_probe = r"""
fn array_signature<'a, 'b>(zones: &'a [TouchZone; 4], nested: Option<Result<[u8; 8], &'b ()>>) {
    let raw = r#"} not the function end"#;
    let _ = (zones, nested, raw, '\u{7b}');
}
trait Probe {
    fn declaration(bytes: &[u8; 4]);
}
fn following() {
    let _x = [0u8; 4];
}
"""
    parsed_probe = rust_function_lengths(rust_parser_probe, include_indented=True)
    if [name for name, _ in parsed_probe] != ["array_signature", "following"]:
        errors.append(
            "Rust function-size parser must handle array-type semicolons and skip declarations"
        )
    attribute_probe = "struct Good {\n    /// attached\n    field: u8,\n}\nstruct Bad {\n    /// orphaned\n}\n#[derive(Clone)]\n"
    if _orphaned_outer_attribute_lines(attribute_probe) != [6, 8]:
        errors.append("Rust orphaned outer-attribute scanner regression")

    for module_name in CHECK_MODULES | WARNING_MODULES:
        source = (package_root / module_name).read_text(errors="ignore")
        line_count = len(source.splitlines())
        if line_count > 400:
            errors.append(
                f"architecture checker module exceeds 400 lines: "
                f"{module_name} ({line_count} lines)"
            )
        if "def check(root: Path) -> list[str]:" not in source:
            errors.append(f"architecture checker module lacks check() contract: {module_name}")
        tree = ast.parse(source)
        for function in (
            node for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        ):
            function_lines = function.end_lineno - function.lineno + 1
            if function_lines > MAX_ARCHITECTURE_FUNCTION_LINES:
                errors.append(
                    f"architecture checker function exceeds "
                    f"{MAX_ARCHITECTURE_FUNCTION_LINES} lines: "
                    f"{module_name}::{function.name} ({function_lines} lines)"
                )
        if module_name != "core/checker_structure.py" and (
            "sys.exit" in source or re.search(r"(?m)^\s*print\(", source)
        ):
            errors.append(
                f"architecture check module performs process I/O instead of returning findings: "
                f"{module_name}"
            )

    checker_sources = "\n".join(
        path.read_text(errors="ignore")
        for path in [entrypoint, *sorted(package_root.rglob("*.py"))]
        if path.name != "checker_structure.py" and "__pycache__" not in path.parts
    )
    forbidden_tokens = (
        "protected" + "_hashes",
        "protected downstream file " + "changed",
        "protected downstream file is " + "missing",
    )
    for forbidden in forbidden_tokens:
        if forbidden in checker_sources:
            errors.append(f"whole-file hash enforcement remains in architecture checker: {forbidden}")
    if re.search(r"sha256\s*\([^)]*\.read_bytes\s*\(", checker_sources, re.S):
        errors.append("architecture checker must not hash complete file bytes")

    errors.extend(_orphaned_rust_doc_comments(root))
    return errors
