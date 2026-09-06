#!/usr/bin/env python3
"""Audit security-critical Rust tests for assertions and required evidence."""

from __future__ import annotations

import argparse
import glob
import json
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
POLICY = ROOT / "qa/checks/security/policy.json"
DEFAULT_OUTPUT = ROOT / "target/qa/security/test-quality.json"
TEST_HEADER = re.compile(r"#\s*\[\s*(?:[A-Za-z_][\w:]*::)?test(?:\([^]]*\))?\s*\]")
FUNCTION = re.compile(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)[^{]*\{")
ASSERTION = re.compile(r"\b(assert|assert_eq|assert_ne|debug_assert|panic|unreachable)!\s*\(")
SIMPLE_LITERAL = re.compile(
    r"^(?:true|false|None|-?[0-9][0-9_]*(?:[iu](?:8|16|32|64|128|size))?"
    r"|0x[0-9a-fA-F_]+|0b[01_]+|\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)')$"
)


def _balanced_macro_contents(text: str, open_paren: int) -> tuple[str, int] | None:
    depth = 0
    in_string = False
    in_char = False
    escaped = False
    for index in range(open_paren, len(text)):
        char = text[index]
        if in_string or in_char:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif in_string and char == '"':
                in_string = False
            elif in_char and char == "'":
                in_char = False
            continue
        if char == '"':
            in_string = True
        elif char == "'":
            in_char = True
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return text[open_paren + 1:index], index + 1
    return None


def _split_top_level_args(contents: str) -> list[str]:
    args: list[str] = []
    start = 0
    paren = bracket = brace = 0
    in_string = False
    in_char = False
    escaped = False
    for index, char in enumerate(contents):
        if in_string or in_char:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif in_string and char == '"':
                in_string = False
            elif in_char and char == "'":
                in_char = False
            continue
        if char == '"':
            in_string = True
        elif char == "'":
            in_char = True
        elif char == "(":
            paren += 1
        elif char == ")":
            paren -= 1
        elif char == "[":
            bracket += 1
        elif char == "]":
            bracket -= 1
        elif char == "{":
            brace += 1
        elif char == "}":
            brace -= 1
        elif char == "," and paren == bracket == brace == 0:
            args.append(contents[start:index].strip())
            start = index + 1
    args.append(contents[start:].strip())
    return args


def _normalized_expression(expression: str) -> str:
    value = re.sub(r"\s+", "", expression)
    while value.startswith("(") and value.endswith(")"):
        parsed = _balanced_macro_contents(value, 0)
        if parsed is None or parsed[1] != len(value):
            break
        value = parsed[0]
    return value


def _top_level_operator(expression: str, operator: str) -> tuple[str, str] | None:
    paren = bracket = brace = 0
    in_string = False
    in_char = False
    escaped = False
    index = 0
    while index <= len(expression) - len(operator):
        char = expression[index]
        if in_string or in_char:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif in_string and char == '"':
                in_string = False
            elif in_char and char == "'":
                in_char = False
            index += 1
            continue
        if char == '"':
            in_string = True
        elif char == "'":
            in_char = True
        elif char == "(":
            paren += 1
        elif char == ")":
            paren -= 1
        elif char == "[":
            bracket += 1
        elif char == "]":
            bracket -= 1
        elif char == "{":
            brace += 1
        elif char == "}":
            brace -= 1
        elif paren == bracket == brace == 0 and expression.startswith(operator, index):
            return expression[:index], expression[index + len(operator):]
        index += 1
    return None


def _simple_literal(expression: str) -> str | None:
    value = _normalized_expression(expression)
    return value if SIMPLE_LITERAL.fullmatch(value) else None


def trivial_assertions(body: str) -> list[str]:
    """Return obvious tautological or constant-only passing assertions."""
    findings: list[str] = []
    for match in ASSERTION.finditer(body):
        macro = match.group(1)
        parsed = _balanced_macro_contents(body, match.end() - 1)
        if parsed is None:
            continue
        args = _split_top_level_args(parsed[0])
        if macro in {"assert", "debug_assert"} and args:
            expression = _normalized_expression(args[0])
            if expression in {"true", "!false"}:
                findings.append(f"{macro}! has constant true condition")
                continue
            equality = _top_level_operator(args[0], "==")
            if equality and _normalized_expression(equality[0]) == _normalized_expression(equality[1]):
                findings.append(f"{macro}! compares an expression with itself")
                continue
            inequality = _top_level_operator(args[0], "!=")
            if inequality:
                left = _simple_literal(inequality[0])
                right = _simple_literal(inequality[1])
                if left is not None and right is not None and left != right:
                    findings.append(f"{macro}! has a constant-only true inequality")
        elif macro in {"assert_eq", "assert_ne"} and len(args) >= 2:
            left = _normalized_expression(args[0])
            right = _normalized_expression(args[1])
            if macro == "assert_eq" and left == right:
                findings.append("assert_eq! compares an expression with itself")
                continue
            left_literal = _simple_literal(args[0])
            right_literal = _simple_literal(args[1])
            if left_literal is not None and right_literal is not None:
                if macro == "assert_eq" and left_literal == right_literal:
                    findings.append("assert_eq! is a constant-only equality")
                elif macro == "assert_ne" and left_literal != right_literal:
                    findings.append("assert_ne! is a constant-only inequality")
    return findings


def load_policy(path: Path) -> dict[str, Any]:
    document = json.loads(path.read_text())
    if document.get("schema_version") != 1:
        raise ValueError("unsupported security policy schema")
    return document


def extract_tests(text: str) -> list[tuple[str, str]]:
    tests: list[tuple[str, str]] = []
    for header in TEST_HEADER.finditer(text):
        function = FUNCTION.search(text, header.end())
        if function is None:
            continue
        start = function.end() - 1
        depth = 0
        in_string = False
        escaped = False
        end = None
        for index in range(start, len(text)):
            char = text[index]
            if in_string:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    in_string = False
                continue
            if char == '"':
                in_string = True
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    end = index + 1
                    break
        if end is not None:
            tests.append((function.group(1), text[function.start():end]))
    return tests


def audit(policy_path: Path = POLICY) -> tuple[list[str], dict[str, Any]]:
    policy = load_policy(policy_path)["test_quality"]
    files: list[Path] = []
    for root in policy.get("critical_test_roots", []):
        path = ROOT / root
        if path.is_file():
            files.append(path)
        elif path.is_dir():
            files.extend(path.rglob("*.rs"))
    files = sorted(set(files))

    test_records: list[dict[str, Any]] = []
    assertion_free: list[str] = []
    trivial_assertion_tests: list[dict[str, Any]] = []
    for path in files:
        text = path.read_text(errors="replace")
        for name, body in extract_tests(text):
            has_assertion = bool(ASSERTION.search(body)) or "#[should_panic" in body
            trivial = trivial_assertions(body)
            record = {
                "path": str(path.relative_to(ROOT)),
                "name": name,
                "assertions": len(ASSERTION.findall(body)),
                "negative_path": bool(re.search(r"\b(?:Err\s*\(|is_err\s*\(|reject|invalid|malformed|corrupt|truncat|fail)", body, re.I)),
                "round_trip": bool(re.search(r"round.?trip|reparse|re-?encode|restor", body, re.I)),
                "state_transition": bool(re.search(r"state|transition|advance|reset|authorize", body, re.I)),
                "exact_error": bool(re.search(r"(?:assert_eq!|matches!)\s*\([\s\S]*?Err\s*\(", body)),
                "has_assertion": has_assertion,
                "trivial_assertions": trivial,
            }
            test_records.append(record)
            if not has_assertion:
                assertion_free.append(f"{record['path']}::{name}")
            if trivial:
                trivial_assertion_tests.append({
                    "test": f"{record['path']}::{name}",
                    "findings": trivial,
                })

    evidence_results: list[dict[str, Any]] = []
    missing_evidence: list[str] = []
    for requirement in policy.get("required_evidence", []):
        contents = []
        resolved = []
        for pattern in requirement.get("files", []):
            matches = [Path(value) for value in glob.glob(str(ROOT / pattern), recursive=True)]
            for path in matches:
                if path.is_file():
                    resolved.append(str(path.relative_to(ROOT)))
                    contents.append(path.read_text(errors="replace"))
        combined = "\n".join(contents).lower()
        missing = [term for term in requirement.get("terms", []) if term.lower() not in combined]
        if not resolved:
            missing.append("<no files resolved>")
        evidence_results.append(
            {
                "id": requirement.get("id"),
                "files": sorted(set(resolved)),
                "required_terms": requirement.get("terms", []),
                "missing_terms": missing,
                "met": not missing,
            }
        )
        for term in missing:
            missing_evidence.append(f"{requirement.get('id')}: missing {term!r}")

    errors = [f"assertion-free critical test: {value}" for value in assertion_free]
    errors.extend(
        f"trivial critical assertion: {item['test']}: {finding}"
        for item in trivial_assertion_tests
        for finding in item["findings"]
    )
    errors.extend(missing_evidence)
    report = {
        "schema_version": 1,
        "healthy": not errors,
        "files_scanned": len(files),
        "tests_scanned": len(test_records),
        "assertion_free_tests": assertion_free,
        "trivial_assertion_tests": trivial_assertion_tests,
        "capabilities": {
            "negative_path_tests": sum(item["negative_path"] for item in test_records),
            "exact_error_tests": sum(item["exact_error"] for item in test_records),
            "round_trip_tests": sum(item["round_trip"] for item in test_records),
            "state_transition_tests": sum(item["state_transition"] for item in test_records),
        },
        "required_evidence": evidence_results,
        "tests": test_records,
        "errors": errors,
    }
    return errors, report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", type=Path, default=POLICY)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    arguments = parser.parse_args()
    try:
        errors, report = audit(arguments.policy)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"ERROR: test-quality audit failed: {error}")
        return 1
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    for error in errors:
        print(f"ERROR: {error}")
    if errors:
        return 1
    capabilities = report["capabilities"]
    print(
        f"PASS: {report['tests_scanned']} critical tests contain assertions and no obvious trivial passes; "
        f"negative={capabilities['negative_path_tests']} exact-errors={capabilities['exact_error_tests']} "
        f"round-trips={capabilities['round_trip_tests']} state-transitions={capabilities['state_transition_tests']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
