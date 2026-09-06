"""Repository ownership and privileged-execution policy helpers."""

from __future__ import annotations

from pathlib import Path


REQUIRED_DIRS = (
    "tools/build/firmware",
    "tools/build/web",
    "tools/dev",
    "tools/firmware/qemu",
    "qa/linux/runner",
    "qa/windows/runner",
    "scripts/linux/quality",
    "scripts/windows/quality",
    "scripts/linux/build",
    "scripts/windows/build",
    "scripts/linux/install",
    "scripts/windows/install",
    "scripts/linux/lib",
    "scripts/windows/lib",
    "scripts/linux/qemu",
    "scripts/windows/qemu",
    "qa/checks/architecture",
    "qa/checks/firmware",
    "qa/checks/web",
    "qa/checks/workspace",
    "qa/checks/quality",
    "qa/checks/quality/crap",
    "qa/contracts/quality",
    "qa/tests/conformance",
    "qa/tests/integration",
    "qa/tests/regression",
    "qa/tests/tooling",
    "qa/tests/fixtures",
    "qa/benches",
    "qa/fuzz",
)

REQUIRED_FILES = (
    "tools/build/firmware/build_matrix.py",
    "tools/build/firmware/matrix_runner.py",
    "tools/build/web/build_app_css.py",
    "tools/build/web/build_constellation_assets.py",
    "tools/build/web/build_web_index.py",
    "tools/build/web/ordered_manifest.py",
    "tools/dev/firmware_mirror.rs",
    "tools/dev/setup_check.rs",
    "scripts/linux/lib/admin.sh",
    "scripts/linux/quality/crap.sh",
    "qa/linux/run-all.sh",
    "qa/linux/lib/terminal_pause.sh",
    "qa/linux/run-pinned-branch-coverage.sh",
    "qa/linux/run-all.desktop",
    "qa/checks/quality/crap/classify_report.py",
    "qa/checks/quality/crap/check.py",
    "qa/checks/quality/crap/policy.json",
    "qa/checks/quality/crap/source_complexity.py",
    "qa/checks/quality/crap/firmware_testability.py",
    "qa/contracts/quality/crap_ratchets.json",
    "qa/tests/tooling/test_crap_reporting.py",
    "qa/tests/tooling/test_crap_check.py",
    "crates/online-watcher/src/protocol/pskt/unit_tests/kspt_compact.rs",
)


def _check_verification_ownership(root: Path) -> list[str]:
    errors: list[str] = []
    for obsolete in ("scripts/tests", "tools/tests", "tools/development"):
        if (root / obsolete).exists():
            errors.append(f"obsolete test/development path exists: {obsolete}")

    for relative in REQUIRED_DIRS:
        if not (root / relative).is_dir():
            errors.append(f"required repository ownership directory is missing: {relative}")

    for relative in REQUIRED_FILES:
        if not (root / relative).is_file():
            errors.append(f"required repository ownership file is missing: {relative}")

    compact_tests = root / "crates/online-watcher/src/protocol/pskt/unit_tests/kspt_compact.rs"
    compact_mod = root / "crates/online-watcher/src/protocol/pskt/unit_tests/mod.rs"
    if compact_tests.is_file() and compact_mod.is_file():
        if "mod kspt_compact;" not in compact_mod.read_text(errors="ignore"):
            errors.append("compact KSPT parser characterization tests are not registered")
        source = compact_tests.read_text(errors="ignore")
        for case in (
            "compact_parser_rejects_every_truncated_required_prefix",
            "compact_parser_rejects_invalid_covenant_trailer_indexes",
            "xonly_position_honors_all_pushdata_lengths",
        ):
            if case not in source:
                errors.append(f"compact KSPT parser coverage is missing: {case}")

    for owner in (root / "scripts", root / "tools"):
        for directory in owner.rglob("tests"):
            if directory.is_dir():
                errors.append(f"tests must live under qa/: {directory.relative_to(root)}")
        for path in owner.rglob("test_*.py"):
            errors.append(f"Python tests must live under qa/: {path.relative_to(root)}")
    return errors


def _check_admin_access(root: Path) -> list[str]:
    errors: list[str] = []
    admin_helper = root / "scripts/linux/lib/admin.sh"
    if admin_helper.is_file():
        source = admin_helper.read_text(errors="ignore")
        for token in (
            "KasSigner needs administrator access",
            "Reason: %s",
            "The next prompt is from sudo",
            "sudo -v",
        ):
            if token not in source:
                errors.append(f"administrator-access helper is missing: {token}")
        for graphical_prompt in ("notify-send", "kdialog", "\033]9;"):
            if graphical_prompt in source:
                errors.append(
                    "administrator-access explanation must remain terminal-only"
                )

    for path in (root / "scripts").rglob("*.sh"):
        if path == admin_helper:
            continue
        if "sudo " in path.read_text(errors="ignore"):
            errors.append(
                "scripts must route sudo through the administrator-access "
                f"terminal explanation helper: {path.relative_to(root)}"
            )
    return errors


def check_quality_ownership(root: Path) -> list[str]:
    """Keep tools, verification, and privileged execution in their owners."""
    return [
        *_check_verification_ownership(root),
        *_check_admin_access(root),
    ]
