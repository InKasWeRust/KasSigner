#!/usr/bin/env python3
"""Provision, run, summarize, persist, and gate critical mutation testing."""

from __future__ import annotations

import argparse
from fnmatch import fnmatchcase
import hashlib
import json
import os
from pathlib import Path
import sys
import tomllib
from typing import Any
import zipfile

_SECURITY_DIR = Path(__file__).resolve().parent
if str(_SECURITY_DIR) not in sys.path:
    sys.path.insert(0, str(_SECURITY_DIR))

from mutation_support import (  # noqa: E402
    POLICY, ROOT, RUN_SCOPE_FILE, archive_results, count_lines, load_policy,
    load_run_scope, locate_results, merge_outcome_documents, mutation_cache_action,
    mutation_config_sha256, mutation_scope_sha256, read_outcomes, setup,
    workspace_test_sha256, write_run_scope, write_triage,
)
from mutation_reuse import inventory_sha256, load_mutant_inventory  # noqa: E402


def _selected_files(include_globs: list[str], exclude_globs: list[str]) -> set[str]:
    selected: set[str] = set()
    for pattern in include_globs:
        for path in ROOT.glob(pattern):
            if not path.is_file():
                continue
            relative = path.relative_to(ROOT).as_posix()
            if any(fnmatchcase(relative, excluded) for excluded in exclude_globs):
                continue
            selected.add(relative)
    return selected


def _global_mutation_files() -> set[str]:
    config = tomllib.loads((ROOT / ".cargo/mutants.toml").read_text())
    return _selected_files(
        list(config.get("examine_globs", [])),
        list(config.get("exclude_globs", [])),
    )


def _global_mutation_profile_errors() -> list[str]:
    """Reject stale cargo-mutants globs before an expensive mutation run starts."""
    config = _mutation_config()
    exclude_globs = list(config.get("exclude_globs", []))
    errors: list[str] = []
    examine_globs = list(config.get("examine_globs", []))
    if not examine_globs:
        errors.append("cargo-mutants profile has no examine_globs")
        return errors
    for pattern in examine_globs:
        if not _selected_files([pattern], exclude_globs):
            errors.append(f"cargo-mutants examine_glob selects no production files: {pattern}")
    return errors


def _mutation_config() -> dict[str, Any]:
    return tomllib.loads((ROOT / ".cargo/mutants.toml").read_text())


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _mutant_record(outcome: dict[str, Any]) -> dict[str, Any] | None:
    scenario = outcome.get("scenario")
    if not isinstance(scenario, dict):
        return None
    mutant = scenario.get("Mutant")
    return mutant if isinstance(mutant, dict) else None

def _canonical_mutant_file(value: object) -> str:
    """Normalize cargo-mutants file paths to repository-relative POSIX form.

    cargo-mutants emits native path separators on some Windows versions while
    the authored mutation/security policy is intentionally platform-neutral.
    Keep the raw evidence untouched, but canonicalize paths before policy
    comparisons and report inventories.
    """
    if not isinstance(value, str) or not value:
        return ""
    text = value.replace("\\", "/")
    root = str(ROOT).replace("\\", "/").rstrip("/")
    compare_text = text.casefold() if os.name == "nt" else text
    compare_root = root.casefold() if os.name == "nt" else root
    prefix = compare_root + "/"
    if compare_text.startswith(prefix):
        text = text[len(root) + 1:]
    while text.startswith("./"):
        text = text[2:]
    return text


def _load_crypto_policy() -> dict[str, Any]:
    document = json.loads(POLICY.read_text())
    if document.get("schema_version") != 1:
        raise ValueError("unsupported security policy schema")
    policy = dict(document["crypto_mutation_domain"])
    if float(policy.get("minimum_score_percent", 0.0)) != 100.0:
        raise ValueError("cryptographic mutation domain must require exactly 100%")
    if int(policy.get("maximum_timeouts", -1)) != 0:
        raise ValueError("cryptographic mutation domain must require zero timeouts")
    return policy


def summarize_crypto_domain(
    policy: dict[str, Any], output: Path, artifact: Path
) -> tuple[list[str], dict[str, Any]]:
    """Gate explicitly enumerated host-testable crypto/key/signing mutation evidence."""
    results = locate_results(output)
    parsed, errors = read_outcomes(results)
    domain_files = _selected_files(
        list(policy.get("include_globs", [])),
        list(policy.get("exclude_globs", [])),
    )
    if not domain_files:
        errors.append("cryptographic mutation domain selects no production files")

    missing_from_global = sorted(domain_files - _global_mutation_files())
    if missing_from_global:
        errors.append(
            "cryptographic mutation files are outside the cargo-mutants profile: "
            + ", ".join(missing_from_global)
        )

    config = _mutation_config()
    configured_exclude_re = list(config.get("exclude_re", []))
    allowed_exclude_re = list(policy.get("allowed_global_exclude_re", []))
    if configured_exclude_re != allowed_exclude_re:
        errors.append(
            "cargo-mutants exclude_re changed outside the audited cryptographic policy: "
            f"configured={configured_exclude_re!r}, allowed={allowed_exclude_re!r}"
        )
    mutation_skip_files = sorted(
        relative
        for relative in domain_files
        if "mutants::skip" in (ROOT / relative).read_text(errors="replace")
    )
    if mutation_skip_files:
        errors.append(
            "cryptographic mutation domain contains source-level mutants::skip exclusions: "
            + ", ".join(mutation_skip_files)
        )

    run_scope = load_run_scope(results)
    current_scope = mutation_scope_sha256()
    current_tests = workspace_test_sha256()
    current_config = mutation_config_sha256()
    actual_inventory_digest: str | None = None
    if run_scope is not None and run_scope.get("schema_version") == 2:
        try:
            actual_inventory_digest = inventory_sha256(
                load_mutant_inventory(results / "mutants.json")
            )
        except ValueError as error:
            errors.append(f"mutation evidence inventory is invalid: {error}")
    if run_scope is None:
        errors.append("mutation evidence has no immutable run provenance")
    else:
        if run_scope.get("mutation_scope_sha256") != current_scope:
            errors.append("mutation evidence production scope is stale")
        if run_scope.get("workspace_test_sha256") != current_tests:
            errors.append("mutation evidence test scope is stale")
        if (
            run_scope.get("schema_version") == 2
            and run_scope.get("mutation_config_sha256") != current_config
        ):
            errors.append("mutation evidence cargo-mutants configuration is stale")
        if (
            run_scope.get("schema_version") == 2
            and actual_inventory_digest is not None
            and run_scope.get("mutant_inventory_sha256") != actual_inventory_digest
        ):
            errors.append("mutation evidence mutant inventory digest does not match mutants.json")

    candidate_certified = bool(
        run_scope
        and run_scope.get("candidate_certified") is True
        and run_scope.get("evidence_mode") == "certification-fresh"
        and run_scope.get("mutation_scope_sha256") == current_scope
        and run_scope.get("workspace_test_sha256") == current_tests
        and run_scope.get("mutation_config_sha256") == current_config
        and actual_inventory_digest is not None
        and run_scope.get("mutant_inventory_sha256") == actual_inventory_digest
        and run_scope.get("carried_forward_caught") == 0
        and run_scope.get("carried_forward_unviable") == 0
    )

    domain_outcomes: list[dict[str, Any]] = []
    if parsed is not None:
        for outcome in parsed.get("outcomes", []):
            if not isinstance(outcome, dict):
                continue
            mutant = _mutant_record(outcome)
            if mutant is None or _canonical_mutant_file(mutant.get("file")) not in domain_files:
                continue
            domain_outcomes.append(outcome)

    by_summary: dict[str, list[dict[str, Any]]] = {
        "CaughtMutant": [],
        "MissedMutant": [],
        "Timeout": [],
        "Unviable": [],
    }
    for outcome in domain_outcomes:
        summary = outcome.get("summary")
        if summary in by_summary:
            by_summary[summary].append(outcome)

    missed_by_name: dict[str, dict[str, Any]] = {}
    for outcome in by_summary["MissedMutant"]:
        mutant = _mutant_record(outcome) or {}
        name = mutant.get("name")
        if isinstance(name, str):
            missed_by_name[name] = outcome

    approved: list[dict[str, str]] = []
    configured_names: set[str] = set()
    for entry in policy.get("equivalent_mutants", []):
        if not isinstance(entry, dict):
            errors.append("equivalent-mutant policy entries must be objects")
            continue
        name = entry.get("name")
        file_name = entry.get("file")
        function_name = entry.get("function")
        replacement = entry.get("replacement")
        source_sha256 = entry.get("source_sha256")
        justification = entry.get("justification")
        refactor_attempted = entry.get("refactor_attempted")
        values = (
            name, file_name, function_name, replacement, source_sha256,
            justification, refactor_attempted,
        )
        if not all(isinstance(value, str) and value.strip() for value in values):
            errors.append(
                "equivalent-mutant entries require exact name, file, function, replacement, "
                "source_sha256, justification, and refactor_attempted"
            )
            continue
        if len(str(source_sha256)) != 64 or any(
            character not in "0123456789abcdef" for character in str(source_sha256).lower()
        ):
            errors.append(f"equivalent-mutant source_sha256 is invalid: {name}")
            continue
        combined_reason = f"{justification} {refactor_attempted}".lower()
        if any(
            phrase in combined_reason
            for phrase in ("hard to test", "difficult to test", "too hard to test")
        ):
            errors.append(
                "equivalent-mutant entries may not use test difficulty as justification: "
                + str(name)
            )
            continue
        assert isinstance(name, str)
        assert isinstance(file_name, str)
        assert isinstance(function_name, str)
        assert isinstance(replacement, str)
        assert isinstance(source_sha256, str)
        assert isinstance(justification, str)
        assert isinstance(refactor_attempted, str)
        if name in configured_names:
            errors.append(f"duplicate equivalent-mutant entry: {name}")
            continue
        configured_names.add(name)
        outcome = missed_by_name.get(name)
        if outcome is None:
            errors.append(
                "stale or non-missed equivalent-mutant entry does not match current evidence: "
                + name
            )
            continue
        mutant = _mutant_record(outcome) or {}
        function = mutant.get("function") or {}
        actual_file = str(mutant.get("file", ""))
        actual_function = str(function.get("function_name", ""))
        actual_replacement = str(mutant.get("replacement", ""))
        identity_errors: list[str] = []
        if file_name != actual_file:
            identity_errors.append(f"file {file_name!r} != {actual_file!r}")
        if function_name != actual_function:
            identity_errors.append(f"function {function_name!r} != {actual_function!r}")
        if replacement != actual_replacement:
            identity_errors.append(f"replacement {replacement!r} != {actual_replacement!r}")
        current_file = ROOT / actual_file
        actual_source_sha256 = _sha256_file(current_file) if current_file.is_file() else ""
        if source_sha256.lower() != actual_source_sha256:
            identity_errors.append(
                f"source_sha256 {source_sha256!r} != {actual_source_sha256!r}"
            )
        if identity_errors:
            errors.append(
                "equivalent-mutant identity does not match current source/evidence for "
                f"{name}: " + "; ".join(identity_errors)
            )
            continue
        approved.append({
            "name": name,
            "file": actual_file,
            "function": actual_function,
            "replacement": actual_replacement,
            "source_sha256": actual_source_sha256,
            "justification": justification.strip(),
            "refactor_attempted": refactor_attempted.strip(),
        })

    approved_names = {entry["name"] for entry in approved}
    remaining_missed = [
        outcome
        for outcome in by_summary["MissedMutant"]
        if (_mutant_record(outcome) or {}).get("name") not in approved_names
    ]
    timeouts = by_summary["Timeout"]
    caught = len(by_summary["CaughtMutant"])
    viable_non_equivalent = caught + len(remaining_missed) + len(timeouts)
    score = 100.0 * caught / viable_non_equivalent if viable_non_equivalent else 0.0

    if parsed is None:
        errors.append("cryptographic mutation evidence is unavailable")
    if viable_non_equivalent == 0:
        errors.append("cryptographic mutation domain produced no viable non-equivalent mutants")
    if timeouts:
        errors.append(f"cryptographic mutation timeouts {len(timeouts)} exceed 0")
    if remaining_missed:
        errors.append(
            f"cryptographic mutation domain has {len(remaining_missed)} viable non-equivalent missed mutants"
        )
    if score < 100.0:
        errors.append(f"cryptographic mutation score {score:.4f}% is below 100.0000%")

    def describe(outcome: dict[str, Any]) -> dict[str, Any]:
        mutant = _mutant_record(outcome) or {}
        function = mutant.get("function") or {}
        return {
            "name": mutant.get("name"),
            "file": _canonical_mutant_file(mutant.get("file")),
            "function": function.get("function_name"),
            "replacement": mutant.get("replacement"),
            "genre": mutant.get("genre"),
        }

    document = {
        "schema_version": 1,
        "healthy": not errors,
        "claim": (
            "100% of viable, non-equivalent mutants in the explicitly enumerated "
            "host-testable cryptographic/key/signing domain are caught, with zero timeouts."
        ),
        "scope_statement": policy.get("scope_statement"),
        "scope_limitations": list(policy.get("scope_limitations", [])),
        "minimum_score_percent": 100.0,
        "maximum_timeouts": 0,
        "score_percent": round(score, 4),
        "score_formula": "caught / (caught + remaining_missed + timeout)",
        "domain_files": sorted(domain_files),
        "domain_file_sha256": {
            relative: _sha256_file(ROOT / relative)
            for relative in sorted(domain_files)
        },
        "domain_files_with_mutants": sorted({
            canonical
            for outcome in domain_outcomes
            if (canonical := _canonical_mutant_file((_mutant_record(outcome) or {}).get("file")))
        }),
        "domain_files_without_generated_mutants": sorted(
            domain_files
            - {
                canonical
                for outcome in domain_outcomes
                if (canonical := _canonical_mutant_file((_mutant_record(outcome) or {}).get("file")))
            }
        ),
        "cargo_mutants_exclude_re": configured_exclude_re,
        "counts": {
            "caught": caught,
            "missed": len(by_summary["MissedMutant"]),
            "approved_equivalent": len(approved),
            "remaining_missed": len(remaining_missed),
            "timeout": len(timeouts),
            "unviable": len(by_summary["Unviable"]),
            "viable_non_equivalent": viable_non_equivalent,
        },
        "approved_equivalent_mutants": approved,
        "remaining_missed_mutants": [describe(outcome) for outcome in remaining_missed],
        "timeout_mutants": [describe(outcome) for outcome in timeouts],
        "mutation_scope_sha256": current_scope,
        "workspace_test_sha256": current_tests,
        "mutation_config_sha256": current_config,
        "mutant_inventory_sha256": actual_inventory_digest,
        "evidence_mode": run_scope.get("evidence_mode") if run_scope else None,
        "candidate_certified": candidate_certified,
        "evidence_run_scope": run_scope,
        "errors": errors,
    }
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    run_directory = Path(
        os.environ.get(
            "KASSIGNER_SECURITY_RUN_DIR",
            str(ROOT / "target/qa/security/latest"),
        )
    )
    if not run_directory.is_absolute():
        run_directory = ROOT / run_directory
    run_directory.mkdir(parents=True, exist_ok=True)
    (run_directory / "crypto-mutation-summary.json").write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n"
    )
    return errors, document

def summarize(
    policy: dict[str, Any], output: Path, artifact: Path
) -> tuple[list[str], dict[str, Any]]:
    results = locate_results(output)
    parsed, errors = read_outcomes(results)
    scope_digest = mutation_scope_sha256()
    test_digest = workspace_test_sha256()
    config_digest = mutation_config_sha256()
    run_scope = load_run_scope(results)
    actual_inventory_digest: str | None = None
    if run_scope is not None and run_scope.get("schema_version") == 2:
        try:
            actual_inventory_digest = inventory_sha256(
                load_mutant_inventory(results / "mutants.json")
            )
        except ValueError as error:
            errors.append(f"mutation evidence inventory is invalid: {error}")
        if (
            actual_inventory_digest is not None
            and run_scope.get("mutant_inventory_sha256") != actual_inventory_digest
        ):
            errors.append("mutation evidence mutant inventory digest does not match mutants.json")
        if run_scope.get("mutation_config_sha256") != config_digest:
            errors.append("mutation evidence cargo-mutants configuration is stale")
    candidate_certified = bool(
        run_scope
        and run_scope.get("candidate_certified") is True
        and run_scope.get("evidence_mode") == "certification-fresh"
        and run_scope.get("mutation_scope_sha256") == scope_digest
        and run_scope.get("workspace_test_sha256") == test_digest
        and run_scope.get("mutation_config_sha256") == config_digest
        and actual_inventory_digest is not None
        and run_scope.get("mutant_inventory_sha256") == actual_inventory_digest
        and run_scope.get("carried_forward_caught") == 0
        and run_scope.get("carried_forward_unviable") == 0
    )

    if parsed is not None:
        counts = {
            "caught": int(parsed.get("caught", 0)),
            "missed": int(parsed.get("missed", 0)),
            "timeout": int(parsed.get("timeout", 0)),
            "unviable": int(parsed.get("unviable", 0)),
        }
        total_mutants = int(parsed.get("total_mutants", sum(counts.values())))
        tool_version = parsed.get("cargo_mutants_version") or parsed.get("version")
        started_at = parsed.get("start_time")
        completed_at = parsed.get("end_time")
    else:
        counts = {
            name: count_lines(results / f"{name}.txt")
            for name in ("caught", "missed", "timeout", "unviable")
        }
        total_mutants = sum(counts.values())
        tool_version = None
        started_at = None
        completed_at = None

    viable = counts["caught"] + counts["missed"] + counts["timeout"]
    score = round((100.0 * counts["caught"] / viable), 4) if viable else 0.0
    if viable == 0:
        errors.append("mutation run produced no viable mutants")
    if score < float(policy["minimum_score_percent"]):
        errors.append(
            f"mutation score {score:.2f}% is below {float(policy['minimum_score_percent']):.2f}%"
        )
    if counts["timeout"] > int(policy["maximum_timeouts"]):
        errors.append(
            f"mutation timeouts {counts['timeout']} exceed {int(policy['maximum_timeouts'])}"
        )
    if tool_version != policy["cargo_mutants_version"]:
        errors.append(
            "cargo-mutants output version "
            f"{tool_version!r} does not match required {policy['cargo_mutants_version']!r}"
        )

    run_directory = Path(
        os.environ.get(
            "KASSIGNER_SECURITY_RUN_DIR",
            str(ROOT / "target/qa/security/latest"),
        )
    )
    if not run_directory.is_absolute():
        run_directory = ROOT / run_directory
    raw_artifact = run_directory / "mutation-results.zip"
    raw_digest: str | None = None
    try:
        raw_digest = archive_results(results, raw_artifact)
    except (OSError, RuntimeError, zipfile.BadZipFile) as error:
        errors.append(f"mutation evidence could not be persisted: {error}")

    try:
        source_output = str(results.relative_to(ROOT))
    except ValueError:
        source_output = str(results)
    try:
        raw_artifact_text = str(raw_artifact.relative_to(ROOT))
    except ValueError:
        raw_artifact_text = str(raw_artifact)

    document = {
        "schema_version": 2,
        "healthy": not errors,
        "tool": "cargo-mutants",
        "required_version": policy["cargo_mutants_version"],
        "reported_version": tool_version,
        "minimum_score_percent": float(policy["minimum_score_percent"]),
        "maximum_timeouts": int(policy["maximum_timeouts"]),
        "score_percent": score,
        "score_formula": "caught / (caught + missed + timeout)",
        "total_mutants": total_mutants,
        "viable_mutants": viable,
        "counts": counts,
        "started_at_utc": started_at,
        "completed_at_utc": completed_at,
        "errors": errors,
        "source_output": source_output,
        "raw_artifact": raw_artifact_text if raw_digest else None,
        "raw_artifact_sha256": raw_digest,
        "mutation_scope_sha256": scope_digest,
        "workspace_test_sha256": test_digest,
        "mutation_config_sha256": config_digest,
        "mutant_inventory_sha256": actual_inventory_digest,
        "evidence_mode": run_scope.get("evidence_mode") if run_scope else None,
        "candidate_certified": candidate_certified,
        "evidence_run_scope": run_scope,
    }
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    latest_summary = raw_artifact.parent / "mutation-summary.json"
    latest_summary.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    triage = artifact.with_name("mutation-triage.json")
    write_triage(parsed, triage)
    if triage.is_file():
        (raw_artifact.parent / "mutation-triage.json").write_bytes(triage.read_bytes())
    return errors, document



from mutation_runner import execute as _execute_mutation_run  # noqa: E402


def execute(policy: dict[str, Any], *, install: bool, fresh: bool) -> int:
    """Facade preserving the public runner API for tooling tests and CLI callers."""
    return _execute_mutation_run(
        policy, install=install, fresh=fresh, summarize_fn=summarize
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser("setup")
    run_parser = subcommands.add_parser("run")
    run_parser.add_argument("--no-install", action="store_true")
    run_parser.add_argument(
        "--fresh",
        action="store_true",
        help="discard development reuse and run every current mutant for candidate certification",
    )
    summary_parser = subcommands.add_parser("summarize")
    summary_parser.add_argument("--output", type=Path)
    crypto_parser = subcommands.add_parser("crypto-check")
    crypto_parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    try:
        policy = load_policy()
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"ERROR: mutation policy cannot be read: {error}")
        return 2
    try:
        profile_errors = _global_mutation_profile_errors()
    except (OSError, ValueError, tomllib.TOMLDecodeError) as error:
        print(f"ERROR: cargo-mutants profile cannot be read: {error}")
        return 2
    if profile_errors:
        for error in profile_errors:
            print(f"ERROR: {error}")
        return 2
    if arguments.command == "setup":
        return setup(policy)
    if arguments.command == "run":
        return execute(policy, install=not arguments.no_install, fresh=arguments.fresh)
    if arguments.command == "crypto-check":
        try:
            crypto_policy = _load_crypto_policy()
        except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
            print(f"ERROR: cryptographic mutation policy cannot be read: {error}")
            return 2
        output = arguments.output or ROOT / policy["output_directory"]
        errors, document = summarize_crypto_domain(
            crypto_policy, output, ROOT / crypto_policy["artifact"]
        )
        print(
            f"Cryptographic mutation score: {document['score_percent']:.2f}% "
            f"({document['counts']['caught']} caught / "
            f"{document['counts']['viable_non_equivalent']} viable non-equivalent)"
        )
        for error in errors:
            print(f"ERROR: {error}")
        return 1 if errors else 0
    output = arguments.output or ROOT / policy["output_directory"]
    errors, document = summarize(policy, output, ROOT / policy["artifact"])
    print(json.dumps(document, indent=2, sort_keys=True))
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
