"""Support functions for the critical mutation-testing runner."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import tomllib
from typing import Any
import zipfile

ROOT = Path(__file__).resolve().parents[3]
CHECKS_DIR = ROOT / "qa/checks"
if str(CHECKS_DIR) not in sys.path:
    sys.path.insert(0, str(CHECKS_DIR))

from toolchains import load_toolchains  # noqa: E402

POLICY = ROOT / "qa/checks/security/policy.json"
RUN_SCOPE_FILE = "run-scope.json"


SUMMARY_FIELDS = {
    "CaughtMutant": "caught",
    "MissedMutant": "missed",
    "Timeout": "timeout",
    "Unviable": "unviable",
}


def outcome_name(outcome: dict[str, Any]) -> str | None:
    scenario = outcome.get("scenario")
    if not isinstance(scenario, dict):
        return None
    mutant = scenario.get("Mutant")
    if not isinstance(mutant, dict):
        return None
    name = mutant.get("name")
    return name if isinstance(name, str) and name else None


def merge_outcome_documents(
    previous: dict[str, Any], current: dict[str, Any]
) -> dict[str, Any]:
    """Merge an incremental cargo-mutants result with its prior full result."""
    previous_outcomes = previous.get("outcomes", [])
    current_outcomes = current.get("outcomes", [])
    if not isinstance(previous_outcomes, list) or not isinstance(current_outcomes, list):
        raise ValueError("cargo-mutants outcomes must be arrays")

    baseline = next(
        (outcome for outcome in current_outcomes if outcome_name(outcome) is None),
        next((outcome for outcome in previous_outcomes if outcome_name(outcome) is None), None),
    )
    merged: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for outcome in previous_outcomes:
        name = outcome_name(outcome)
        if name is None:
            continue
        if name not in merged:
            order.append(name)
        merged[name] = outcome
    for outcome in current_outcomes:
        name = outcome_name(outcome)
        if name is None:
            continue
        if name not in merged:
            order.append(name)
        merged[name] = outcome

    combined = ([baseline] if baseline is not None else []) + [merged[name] for name in order]
    counts = {field: 0 for field in SUMMARY_FIELDS.values()}
    for outcome in combined:
        field = SUMMARY_FIELDS.get(outcome.get("summary"))
        if field is not None:
            counts[field] += 1

    previous_version = previous.get("cargo_mutants_version") or previous.get("version")
    current_version = current.get("cargo_mutants_version") or current.get("version")
    if previous_version and current_version and previous_version != current_version:
        raise ValueError(
            f"cargo-mutants version changed across incremental run: "
            f"{previous_version!r} -> {current_version!r}"
        )

    return {
        "outcomes": combined,
        "total_mutants": sum(counts.values()),
        "missed": counts["missed"],
        "caught": counts["caught"],
        "timeout": counts["timeout"],
        "unviable": counts["unviable"],
        "success": counts["missed"] == 0 and counts["timeout"] == 0,
        "start_time": previous.get("start_time") or current.get("start_time"),
        "end_time": current.get("end_time") or previous.get("end_time"),
        "cargo_mutants_version": current_version or previous_version,
    }


def write_outcome_lists(results: Path, parsed: dict[str, Any]) -> None:
    buckets: dict[str, list[str]] = {field: [] for field in SUMMARY_FIELDS.values()}
    for outcome in parsed.get("outcomes", []):
        name = outcome_name(outcome)
        field = SUMMARY_FIELDS.get(outcome.get("summary"))
        if name is not None and field is not None:
            buckets[field].append(name)
    for field, names in buckets.items():
        text = "\n".join(sorted(names))
        (results / f"{field}.txt").write_text(text + ("\n" if text else ""))


def digest_files(paths: list[Path]) -> str:
    digest = hashlib.sha256()
    for path in sorted(set(paths)):
        relative = path.relative_to(ROOT).as_posix().encode()
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        content = path.read_bytes()
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def mutation_scope_sha256() -> str:
    """Hash the cargo-mutants profile and every selected production source file."""
    config_path = ROOT / ".cargo/mutants.toml"
    config = tomllib.loads(config_path.read_text())
    examine = config.get("examine_globs", [])
    exclude = config.get("exclude_globs", [])
    files: set[Path] = set()
    for pattern in examine:
        files.update(path for path in ROOT.glob(pattern) if path.is_file())
    selected = [
        path
        for path in files
        if not any(path.relative_to(ROOT).match(pattern) for pattern in exclude)
    ]
    # The profile itself is mutation provenance: changing examine/exclude rules,
    # timeout behavior, or cargo-mutants arguments must invalidate prior evidence
    # even when the currently selected source bytes happen to be unchanged.
    return digest_files([config_path, *selected])


def mutation_config_sha256() -> str:
    """Hash only the cargo-mutants profile that controls mutant discovery/execution."""
    return hashlib.sha256((ROOT / ".cargo/mutants.toml").read_bytes()).hexdigest()


def workspace_test_sha256() -> str:
    """Hash inputs capable of changing cargo-mutants workspace test outcomes."""
    paths: list[Path] = [ROOT / "Cargo.toml", ROOT / "Cargo.lock"]
    for crate in ("kassigner-protocol", "offline-signer", "online-watcher", "shared-signer", "signer-firmware-core"):
        crate_root = ROOT / "crates" / crate
        paths.append(crate_root / "Cargo.toml")
        paths.extend(path for path in (crate_root / "src").rglob("*.rs") if path.is_file())
    return digest_files([path for path in paths if path.is_file()])


def load_run_scope(results: Path) -> dict[str, Any] | None:
    """Read immutable provenance stamped by an actual or explicitly reused mutation run."""
    path = results / RUN_SCOPE_FILE
    if not path.is_file():
        return None
    try:
        document = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    schema = document.get("schema_version")
    source = document.get("mutation_scope_sha256")
    tests = document.get("workspace_test_sha256")
    version = document.get("cargo_mutants_version")
    if schema not in (1, 2):
        return None
    if not all(isinstance(value, str) for value in (source, tests, version)):
        return None
    if len(source) != 64 or len(tests) != 64:
        return None
    if schema == 1:
        return {
            "schema_version": 1,
            "mutation_scope_sha256": source,
            "workspace_test_sha256": tests,
            "cargo_mutants_version": version,
            "evidence_mode": "legacy",
            "candidate_certified": False,
            "mutation_config_sha256": None,
            "mutant_inventory_sha256": None,
            "carried_forward_caught": None,
            "carried_forward_unviable": None,
            "base_mutation_scope_sha256": None,
        }

    config = document.get("mutation_config_sha256")
    inventory = document.get("mutant_inventory_sha256")
    mode = document.get("evidence_mode")
    certified = document.get("candidate_certified")
    carried = document.get("carried_forward_caught")
    carried_unviable = document.get("carried_forward_unviable")
    base_scope = document.get("base_mutation_scope_sha256")
    if not (
        isinstance(config, str)
        and len(config) == 64
        and isinstance(inventory, str)
        and len(inventory) == 64
        and isinstance(mode, str)
        and isinstance(certified, bool)
        and isinstance(carried, int)
        and carried >= 0
        and isinstance(carried_unviable, int)
        and carried_unviable >= 0
        and (base_scope is None or (isinstance(base_scope, str) and len(base_scope) == 64))
    ):
        return None
    return {
        "schema_version": 2,
        "mutation_scope_sha256": source,
        "workspace_test_sha256": tests,
        "cargo_mutants_version": version,
        "evidence_mode": mode,
        "candidate_certified": certified,
        "mutation_config_sha256": config,
        "mutant_inventory_sha256": inventory,
        "carried_forward_caught": carried,
        "carried_forward_unviable": carried_unviable,
        "base_mutation_scope_sha256": base_scope,
    }


def write_run_scope(
    results: Path,
    *,
    source_digest: str,
    test_digest: str,
    tool_version: str,
    evidence_mode: str,
    candidate_certified: bool,
    config_digest: str,
    inventory_digest: str,
    carried_forward_caught: int = 0,
    carried_forward_unviable: int = 0,
    base_source_digest: str | None = None,
) -> None:
    """Stamp whether evidence is development-incremental or fresh certification."""
    if candidate_certified and evidence_mode != "certification-fresh":
        raise ValueError("only certification-fresh mutation evidence may be candidate-certified")
    if candidate_certified and (carried_forward_caught != 0 or carried_forward_unviable != 0):
        raise ValueError("candidate-certified mutation evidence cannot carry prior outcomes")
    document = {
        "schema_version": 2,
        "mutation_scope_sha256": source_digest,
        "workspace_test_sha256": test_digest,
        "cargo_mutants_version": tool_version,
        "evidence_mode": evidence_mode,
        "candidate_certified": candidate_certified,
        "mutation_config_sha256": config_digest,
        "mutant_inventory_sha256": inventory_digest,
        "carried_forward_caught": carried_forward_caught,
        "carried_forward_unviable": carried_forward_unviable,
        "base_mutation_scope_sha256": base_source_digest,
    }
    (results / RUN_SCOPE_FILE).write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n"
    )


def mutation_cache_action(
    *,
    use_iterate: bool,
    has_existing_outcomes: bool,
    run_scope: dict[str, Any] | None,
    current_scope: str,
    current_test_scope: str,
    reuse_unchanged: bool,
) -> str:
    """Choose exact reuse, context-aware iteration, or an unprovenanced reset."""
    if not use_iterate or not has_existing_outcomes:
        return "run"
    if run_scope is None:
        return "fresh-unprovenanced"
    source_matches = run_scope["mutation_scope_sha256"] == current_scope
    tests_match = run_scope["workspace_test_sha256"] == current_test_scope
    if reuse_unchanged and source_matches and tests_match:
        return "reuse"
    if source_matches:
        return "iterate-tests-changed"
    return "iterate-source-changed"


def load_policy(path: Path = POLICY) -> dict[str, Any]:
    document = json.loads(path.read_text())
    if document.get("schema_version") != 1:
        raise ValueError("unsupported security policy schema")
    policy = dict(document["mutation"])
    toolchains = load_toolchains()
    policy["toolchain"] = toolchains["KASSIGNER_STABLE_RUST"]
    policy["cargo_mutants_version"] = toolchains["KASSIGNER_CARGO_MUTANTS_VERSION"]
    return policy


def run(command: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    print("+", " ".join(command), flush=True)
    return subprocess.run(command, cwd=ROOT, text=True, check=check)


def captured(command: list[str]) -> str:
    result = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    return result.stdout.strip()


def ensure_rustup() -> int:
    """Ensure rustup is available without shadowing repository-local Cargo plugins.

    The Windows master runner prepends a version-qualified local tool directory
    before invoking mutation QA.  Preserve that ordering when rustup is already
    available; otherwise an older global cargo-mutants in CARGO_HOME/bin can
    shadow the freshly installed local candidate.
    """
    if shutil.which("rustup") is not None:
        return 0

    cargo_bin = Path(os.environ.get("CARGO_HOME", str(Path.home() / ".cargo"))) / "bin"
    current = os.environ.get("PATH", "")
    entries = current.split(os.pathsep) if current else []
    cargo_text = str(cargo_bin)
    compare = cargo_text.casefold() if os.name == "nt" else cargo_text
    normalized = {entry.casefold() if os.name == "nt" else entry for entry in entries}
    if compare not in normalized:
        os.environ["PATH"] = cargo_text + (os.pathsep + current if current else "")

    bootstrap = ROOT / "scripts/linux/lib/rustup_bootstrap.sh"
    completed = subprocess.run(
        ["bash", str(bootstrap), "--ensure-rustup"], cwd=ROOT, text=True, check=False
    )
    if completed.returncode != 0 or shutil.which("rustup") is None:
        print("ERROR: verified rustup bootstrap failed")
        return completed.returncode or 2
    return 0


def _cargo_metadata(toolchain: str, *arguments: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["CARGO_RESOLVER_INCOMPATIBLE_RUST_VERSIONS"] = "fallback"
    command = [
        "rustup",
        "run",
        toolchain,
        "cargo",
        "metadata",
        "--manifest-path",
        str(ROOT / "Cargo.toml"),
        "--format-version",
        "1",
        *arguments,
    ]
    print("+", " ".join(command), flush=True)
    return subprocess.run(
        command,
        cwd=ROOT,
        env=env,
        text=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        check=False,
    )


def reconcile_root_lock(toolchain: str) -> int:
    """Make the root lock graph reproducible under the pinned mutation Cargo."""
    locked = _cargo_metadata(toolchain, "--locked")
    if locked.returncode == 0:
        return 0

    lockfile = ROOT / "Cargo.lock"
    if not lockfile.is_file():
        print("ERROR: root Cargo.lock is missing")
        return 2

    original = lockfile.read_bytes()
    print(
        f"Root Cargo.lock is stale under pinned Cargo {toolchain}; "
        "reconciling transactionally."
    )

    refreshed = _cargo_metadata(toolchain, "--offline")
    if refreshed.returncode != 0:
        lockfile.write_bytes(original)
        print("Offline lock reconciliation was insufficient; retrying with registry access.")
        refreshed = _cargo_metadata(toolchain)

    if refreshed.returncode != 0:
        lockfile.write_bytes(original)
        detail = refreshed.stderr.strip()
        print("ERROR: Cargo could not reconcile the root Cargo.lock")
        if detail:
            print(detail)
        return 2

    verified = _cargo_metadata(toolchain, "--locked")
    if verified.returncode != 0:
        lockfile.write_bytes(original)
        detail = verified.stderr.strip()
        print("ERROR: reconciled root Cargo.lock still fails --locked verification")
        if detail:
            print(detail)
        return 2

    print("Root Cargo.lock reconciled and verified under --locked.")
    return 0


def setup(policy: dict[str, Any]) -> int:
    toolchain = policy["toolchain"]
    version = policy["cargo_mutants_version"]
    if ensure_rustup() != 0:
        return 2
    run(["rustup", "toolchain", "install", toolchain, "--profile", "minimal"])
    if reconcile_root_lock(toolchain) != 0:
        return 2
    actual = captured(["rustup", "run", toolchain, "cargo", "mutants", "--version"])
    expected = f"cargo-mutants {version}"
    if expected not in actual:
        install = [
            "rustup",
            "run",
            toolchain,
            "cargo",
            "install",
            "cargo-mutants",
            "--version",
            version,
            "--locked",
        ]
        install_root = os.environ.get("CARGO_INSTALL_ROOT", "").strip()
        if install_root:
            install.extend(["--root", install_root])
        install.append("--force")
        run(install)
        actual = captured(["rustup", "run", toolchain, "cargo", "mutants", "--version"])
    if expected not in actual:
        print(f"ERROR: expected {expected!r}, received {actual!r}")
        return 2
    print(actual)
    return 0


def count_lines(path: Path) -> int:
    if not path.is_file():
        return 0
    return sum(bool(line.strip()) for line in path.read_text(errors="replace").splitlines())


def locate_results(path: Path) -> Path:
    """Resolve either a mutants.out directory or its --output parent directory."""
    candidates = (path, path / "mutants.out")
    for candidate in candidates:
        if (candidate / "outcomes.json").is_file() or (candidate / "lock.json").is_file():
            return candidate
    return path


def read_outcomes(path: Path) -> tuple[dict[str, Any] | None, list[str]]:
    errors: list[str] = []
    outcomes = path / "outcomes.json"
    if not outcomes.is_file():
        return None, ["mutants outcomes.json is missing"]
    try:
        parsed = json.loads(outcomes.read_text())
    except json.JSONDecodeError:
        return None, ["mutants outcomes.json is invalid"]
    if not isinstance(parsed, dict):
        errors.append("mutants outcomes.json root must be an object")
        return None, errors
    return parsed, errors


def archive_results(results: Path, destination: Path) -> str | None:
    if not results.is_dir():
        return None
    files = sorted(path for path in results.rglob("*") if path.is_file())
    if not files:
        return None
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.unlink(missing_ok=True)
    with zipfile.ZipFile(
        destination, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as archive:
        for path in files:
            archive.write(path, Path("mutation/mutants.out") / path.relative_to(results))
    with zipfile.ZipFile(destination) as archive:
        corrupt = archive.testzip()
        if corrupt is not None:
            raise RuntimeError(f"corrupt mutation artifact member: {corrupt}")
    return hashlib.sha256(destination.read_bytes()).hexdigest()


def write_triage(parsed: dict[str, Any] | None, destination: Path) -> None:
    if parsed is None:
        return
    from collections import Counter

    missed_files: Counter[str] = Counter()
    missed_functions: Counter[str] = Counter()
    timeout_files: Counter[str] = Counter()
    timeout_functions: Counter[str] = Counter()
    for outcome in parsed.get("outcomes", []):
        summary = outcome.get("summary")
        scenario = outcome.get("scenario") or {}
        if not isinstance(scenario, dict):
            continue
        mutant = scenario.get("Mutant") or {}
        file_name = mutant.get("file") or "unknown"
        function = mutant.get("function") or {}
        function_name = function.get("function_name") or "<module>"
        key = f"{file_name}::{function_name}"
        if summary == "MissedMutant":
            missed_files[file_name] += 1
            missed_functions[key] += 1
        elif summary == "Timeout":
            timeout_files[file_name] += 1
            timeout_functions[key] += 1

    def ranked(counter: Counter[str], limit: int = 100) -> list[dict[str, Any]]:
        return [
            {"name": name, "count": count}
            for name, count in counter.most_common(limit)
        ]

    document = {
        "schema_version": 1,
        "healthy": not missed_files and not timeout_files,
        "missed_mutants": int(parsed.get("missed", 0)),
        "timeout_mutants": int(parsed.get("timeout", 0)),
        "highest_missed_files": ranked(missed_files),
        "highest_missed_functions": ranked(missed_functions),
        "timeout_files": ranked(timeout_files),
        "timeout_functions": ranked(timeout_functions),
        "recommended_order": [
            "Eliminate timeout-causing loop and parser mutations first",
            "Add public-behavior tests for the highest missed security-critical functions",
            "Review equivalent mutants before using a justified cargo-mutants exclusion",
            "Rerun `python3 qa/checks/security/mutation.py run` so context-proven development outcomes are reused",
        ],
    }
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")


def _restore_results_archive(archive_path: Path, output_parent: Path) -> bool:
    """Validate and atomically restore one persisted cargo-mutants archive."""
    destination = output_parent / "mutants.out"
    staging = output_parent / "mutants.out.restore"
    shutil.rmtree(staging, ignore_errors=True)
    staging.mkdir(parents=True, exist_ok=True)
    prefix = Path("mutation/mutants.out")
    try:
        with zipfile.ZipFile(archive_path) as archive:
            if archive.testzip() is not None:
                raise zipfile.BadZipFile("mutation checkpoint CRC validation failed")
            for member in archive.infolist():
                member_path = Path(member.filename)
                try:
                    relative = member_path.relative_to(prefix)
                except ValueError:
                    continue
                if (
                    not relative.parts
                    or member.is_dir()
                    or relative.is_absolute()
                    or ".." in relative.parts
                ):
                    if ".." in relative.parts or relative.is_absolute():
                        raise zipfile.BadZipFile("unsafe mutation checkpoint member path")
                    continue
                target = staging / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(archive.read(member))
    except (OSError, zipfile.BadZipFile):
        shutil.rmtree(staging, ignore_errors=True)
        return False

    required = ("outcomes.json", "mutants.json", RUN_SCOPE_FILE)
    if any(not (staging / name).is_file() for name in required):
        shutil.rmtree(staging, ignore_errors=True)
        return False
    try:
        outcomes = json.loads((staging / "outcomes.json").read_text())
        mutants = json.loads((staging / "mutants.json").read_text())
        run_scope = json.loads((staging / RUN_SCOPE_FILE).read_text())
    except (OSError, json.JSONDecodeError):
        shutil.rmtree(staging, ignore_errors=True)
        return False
    if (
        not isinstance(outcomes, dict)
        or not isinstance(mutants, list)
        or not isinstance(run_scope, dict)
    ):
        shutil.rmtree(staging, ignore_errors=True)
        return False

    shutil.rmtree(destination, ignore_errors=True)
    staging.replace(destination)
    return True


def restore_results(output_parent: Path) -> bool:
    """Restore the newest valid persisted raw mutation evidence into target/."""
    candidates = [ROOT / "target/qa/security/latest/mutation-results.zip"]
    pointer = ROOT / "target/qa/security/latest-run.json"
    if pointer.is_file():
        try:
            run_path = Path(json.loads(pointer.read_text())["run_directory"])
        except (KeyError, OSError, json.JSONDecodeError):
            run_path = Path()
        if run_path:
            if not run_path.is_absolute():
                run_path = ROOT / run_path
            candidates.append(run_path / "mutation-results.zip")
    for archive_path in candidates:
        if archive_path.is_file() and _restore_results_archive(archive_path, output_parent):
            return True
    return False
