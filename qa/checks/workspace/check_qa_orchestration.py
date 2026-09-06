#!/usr/bin/env python3
"""Validate the public QA catalog and explicit test/check entrypoint ownership."""
from __future__ import annotations

import json
from pathlib import Path
import re
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[3]
CATALOG = ROOT / "qa/config/run_all_steps.tsv"
OWNERSHIP = ROOT / "qa/config/test_entrypoints.json"
TEST_PROFILE = ROOT / "qa/config/run_all_test_steps.txt"
ALLOWED_COMMANDS = {
    "make test",
    "make qa",
    "make test-hardware",
    "make workflow-e2e",
    "make workflow-hil",
    "make release",
    "make release-readiness",
}


def catalog_rows() -> list[tuple[str, str, str, str, str]]:
    rows: list[tuple[str, str, str, str, str]] = []
    for raw in CATALOG.read_text(encoding="utf-8").splitlines():
        if not raw or raw.startswith("#"):
            continue
        fields = raw.split("\t", 4)
        if len(fields) != 5:
            raise ValueError(f"invalid QA catalog row: {raw!r}")
        rows.append(tuple(fields))  # type: ignore[arg-type]
    return rows


def _has_main_guard(path: Path) -> bool:
    text = path.read_text(errors="replace")
    return bool(re.search(r"if\s+__name__\s*==\s*['\"]__main__['\"]", text))


def discover_entrypoints() -> set[str]:
    found: set[str] = set()
    for pattern in (
        "qa/linux/run-*.sh",
        "qa/windows/run-*.ps1",
        "qa/linux/release/*.sh",
        "qa/windows/release/*.ps1",
    ):
        found.update(path.relative_to(ROOT).as_posix() for path in ROOT.glob(pattern) if path.is_file())
    found.add("qa/windows/runner/run_all.py")

    for path in (ROOT / "qa/checks").rglob("*.py"):
        if _has_main_guard(path):
            found.add(path.relative_to(ROOT).as_posix())
    for path in (ROOT / "qa/checks").rglob("*.mjs"):
        name = path.name
        if name.endswith(".test.mjs") or name.startswith("check_"):
            found.add(path.relative_to(ROOT).as_posix())

    for path in (ROOT / "qa/tests/tooling").glob("test_*.py"):
        found.add(path.relative_to(ROOT).as_posix())
    for path in (ROOT / "qa/tests/regression").glob("test_*.py"):
        found.add(path.relative_to(ROOT).as_posix())

    qa_manifest = tomllib.loads((ROOT / "qa/Cargo.toml").read_text())
    for section in ("test", "bench"):
        for item in qa_manifest.get(section, []):
            relative = Path("qa") / str(item["path"])
            found.add(relative.as_posix())

    fuzz_manifest = tomllib.loads((ROOT / "qa/fuzz/Cargo.toml").read_text())
    for item in fuzz_manifest.get("bin", []):
        found.add((Path("qa/fuzz") / str(item["path"])).as_posix())

    for path in (ROOT / "apps/kassee-ios/Tests").rglob("*.swift"):
        found.add(path.relative_to(ROOT).as_posix())
    android_app = ROOT / "apps/kassee-android/app/src"
    for branch in ("test", "androidTest"):
        for path in (android_app / branch).rglob("*.kt"):
            found.add(path.relative_to(ROOT).as_posix())
    for path in (ROOT / "apps/kassee-android/portable-tests").rglob("*.kt"):
        found.add(path.relative_to(ROOT).as_posix())
    return found


def check(root: Path = ROOT) -> list[str]:
    del root  # paths are repository-global by design
    errors: list[str] = []
    try:
        rows = catalog_rows()
    except (OSError, ValueError) as error:
        return [str(error)]
    ids = [row[3] for row in rows]
    if len(ids) != len(set(ids)):
        errors.append("QA catalog step IDs must be unique")
    scopes = [row[0] for row in rows]
    if not rows or rows[0][3] != "preflight.crap-check" or rows[0][0] != "qa":
        errors.append("preflight.crap-check must be the first full make-qa gate")
    if len(rows) < 2 or rows[1][3] != "preflight.core-ci" or rows[1][0] != "qa":
        errors.append("preflight.core-ci must run immediately after preflight.crap-check")
    test_positions = [i for i, scope in enumerate(scopes) if scope == "test"]
    if test_positions:
        first_test, last_test = min(test_positions), max(test_positions)
        if test_positions != list(range(first_test, last_test + 1)):
            errors.append("make-test catalog rows must form one contiguous block in make-qa")
        if first_test != 2:
            errors.append("make-test catalog block must immediately follow preflight.core-ci")
    if any(scope not in {"test", "qa", "hardware"} for scope in scopes):
        errors.append("QA catalog contains an unknown scope")
    mobile_workspaces = {"kassee-ios", "kassee-android"}
    for scope, category, workspace, step_id, _description in rows:
        if scope in {"test", "qa"} and category == "hardware":
            errors.append(f"physical hardware step leaked into make qa: {step_id}")
        if scope == "hardware" and category != "hardware":
            errors.append(f"hardware-only step must use hardware category: {step_id}")
        if scope == "test" and workspace in mobile_workspaces:
            errors.append(f"mobile test leaked into fast make test: {step_id}")
    test_ids = [row[3] for row in rows if row[0] == "test"]
    configured_test = [
        line.strip() for line in TEST_PROFILE.read_text().splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if configured_test != test_ids:
        errors.append("run_all_test_steps.txt does not exactly match the catalog test block")

    required = {
        "integration.real-node",
        "integration.funded-testnet-e2e",
        "emulation.signer-firmware-qemu",
        "bench.shared-signer-protocol-throughput",
        "mutation.repository-security-fresh",
        "mutation.repository-crypto-certification",
        "fuzz.repository-security-targets",
    }
    missing_required = sorted(required - set(ids))
    if missing_required:
        errors.append("authoritative make-qa catalog is missing required steps: " + ", ".join(missing_required))
    if all(step in ids for step in required):
        position = {step: ids.index(step) for step in ids}
        test_end = max(ids.index(step) for step in test_ids)
        if min(position["integration.real-node"], position["integration.funded-testnet-e2e"]) <= test_end:
            errors.append("real-node/funded E2E must run after the complete make-test prefix")
        if position["integration.real-node"] > position["mutation.repository-security-fresh"] or position["integration.funded-testnet-e2e"] > position["mutation.repository-security-fresh"]:
            errors.append("interactive real-node/funded E2E must run before fresh mutation")
        if not (position["mutation.repository-security-fresh"] < position["mutation.repository-crypto-certification"] < position["fuzz.repository-security-targets"]):
            errors.append("fresh mutation, crypto certification, and final fuzz ordering is incorrect")

    document = json.loads(OWNERSHIP.read_text(encoding="utf-8"))
    entries = document.get("entrypoints", [])
    owned: dict[str, dict[str, object]] = {}
    for entry in entries:
        path = str(entry.get("path", ""))
        if not path or path in owned:
            errors.append(f"duplicate/empty entrypoint ownership record: {path!r}")
            continue
        owned[path] = entry
        commands = entry.get("commands")
        if not isinstance(commands, list) or not commands or any(command not in ALLOWED_COMMANDS for command in commands):
            errors.append(f"entrypoint {path} has invalid public command classification: {commands!r}")
            commands = []
        if "make test" in commands and "make qa" not in commands:
            errors.append(f"entrypoint {path} is in make test but missing from authoritative make qa")
        if "make test" in commands and (
            path.startswith("qa/checks/ios/")
            or path.startswith("qa/checks/android/")
            or path.startswith("apps/kassee-ios/")
            or path.startswith("apps/kassee-android/")
        ):
            errors.append(f"mobile entrypoint leaked into fast make test: {path}")
        hardware_commands = {"make test-hardware", "make workflow-e2e", "make workflow-hil"}
        if "make qa" in commands and hardware_commands.intersection(commands):
            errors.append(f"entrypoint {path} mixes non-hardware make qa with physical/HIL ownership")
        role = str(entry.get("role", ""))
        if role == "hardware-runner" and ({"make test", "make qa"} & set(commands)):
            errors.append(f"physical/HIL entrypoint leaked into non-hardware public QA: {path}")
        step = entry.get("step")
        if "make test" in commands or "make qa" in commands:
            role = str(entry.get("role", ""))
            if step == "catalog" and role in {"runner", "alias"}:
                pass
            elif not isinstance(step, str) or step not in ids:
                errors.append(f"entrypoint {path} is assigned to an unknown run-all step: {step!r}")
            elif "make test" in commands and dict((row[3], row[0]) for row in rows).get(step) != "test":
                errors.append(f"entrypoint {path} claims make test but step {step} is not in the test prefix")

    discovered = discover_entrypoints()
    missing = sorted(discovered - set(owned))
    stale = sorted(set(owned) - discovered)
    if missing:
        errors.append("orphaned registered test/check entrypoints: " + ", ".join(missing))
    if stale:
        errors.append("stale test/check ownership records: " + ", ".join(stale))
    return errors


def main() -> int:
    errors = check()
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1
    print(f"PASS: QA orchestration catalog owns {len(discover_entrypoints())} registered test/check entrypoints")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
