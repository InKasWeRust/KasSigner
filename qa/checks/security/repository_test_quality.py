#!/usr/bin/env python3
"""Audit first-party tests for vacuous, tautological, or assertion-free passes."""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path
import sys
from typing import Any

SECURITY_DIR = Path(__file__).resolve().parent
if str(SECURITY_DIR) not in sys.path:
    sys.path.insert(0, str(SECURITY_DIR))
from test_quality import ASSERTION, FUNCTION, extract_tests, trivial_assertions

ROOT = Path(__file__).resolve().parents[3]
DEFAULT_OUTPUT = ROOT / "target/qa/security/repository-test-quality.json"

RUST_ROOTS = (
    ROOT / "crates",
    ROOT / "apps/signer-firmware",
    ROOT / "qa",
    ROOT / "tools",
)
PYTHON_ROOT = ROOT / "qa/tests"
KOTLIN_ROOTS = (
    ROOT / "apps/kassee-android/app/src/test",
    ROOT / "apps/kassee-android/app/src/androidTest",
)
KOTLIN_PORTABLE = ROOT / "apps/kassee-android/portable-tests"
SWIFT_ROOT = ROOT / "apps/kassee-ios/Tests"
JAVASCRIPT_ROOTS = (ROOT / "qa/checks/web", ROOT / "qa/checks/integration")

RUST_STRONG = re.compile(
    r"\b(?:assert(?:_eq|_ne)?|debug_assert|panic|unreachable|"
    r"prop_assert(?:_eq|_ne)?|assert_matches)!\s*\("
)
RUST_FALLIBLE = re.compile(r"\.(?:expect|unwrap|unwrap_err)\s*\(")


def _rust_functions(text: str) -> dict[str, str]:
    functions: dict[str, str] = {}
    for match in FUNCTION.finditer(text):
        start = match.end() - 1
        depth = 0
        in_string = False
        escaped = False
        end: int | None = None
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
            functions[match.group(1)] = text[match.start():end]
    return functions


def _rust_has_helper_assertion(body: str, functions: dict[str, str]) -> bool:
    visited: set[str] = set()

    def inspect(name: str) -> bool:
        if name in visited:
            return False
        visited.add(name)
        helper = functions.get(name)
        if helper is None:
            return False
        if RUST_STRONG.search(helper) or ASSERTION.search(helper):
            return True
        return any(inspect(call) for call in re.findall(r"\b([A-Za-z_]\w*)\s*\(", helper))

    return any(inspect(call) for call in re.findall(r"\b([A-Za-z_]\w*)\s*\(", body))


def audit_rust() -> tuple[list[dict[str, Any]], list[str]]:
    records: list[dict[str, Any]] = []
    errors: list[str] = []
    files: set[Path] = set()
    for root in RUST_ROOTS:
        if root.is_dir():
            files.update(root.rglob("*.rs"))
    for path in sorted(files):
        text = path.read_text(errors="replace")
        functions = _rust_functions(text)
        for name, body in extract_tests(text):
            trivial = trivial_assertions(body)
            strong = bool(RUST_STRONG.search(body) or ASSERTION.search(body) or "#[should_panic" in body)
            delegated = False if strong else _rust_has_helper_assertion(body, functions)
            fallible = bool(RUST_FALLIBLE.search(body) or ("-> Result" in body and "?" in body))
            relative = path.relative_to(ROOT).as_posix()
            record = {
                "language": "rust",
                "path": relative,
                "name": name,
                "strong_assertion": strong,
                "delegated_assertion": delegated,
                "fallible_contract": fallible,
                "trivial_assertions": trivial,
            }
            records.append(record)
            for finding in trivial:
                errors.append(f"trivial Rust test {relative}::{name}: {finding}")
            if not (strong or delegated or fallible):
                errors.append(f"assertion-free Rust test: {relative}::{name}")
    return records, errors


def _ast_same(left: ast.AST, right: ast.AST) -> bool:
    return ast.dump(left, include_attributes=False) == ast.dump(right, include_attributes=False)


def _literal(node: ast.AST) -> object:
    return node.value if isinstance(node, ast.Constant) else _NO_LITERAL


_NO_LITERAL = object()


def _python_trivial(node: ast.AST) -> list[str]:
    findings: list[str] = []
    for item in ast.walk(node):
        if isinstance(item, ast.Assert):
            test = item.test
            if isinstance(test, ast.Constant) and test.value is True:
                findings.append("assert True")
            elif isinstance(test, ast.Compare) and len(test.ops) == len(test.comparators) == 1:
                left = test.left
                right = test.comparators[0]
                if isinstance(test.ops[0], ast.Eq) and _ast_same(left, right):
                    findings.append("assert compares an expression with itself")
                elif isinstance(test.ops[0], ast.NotEq):
                    left_value = _literal(left)
                    right_value = _literal(right)
                    if left_value is not _NO_LITERAL and right_value is not _NO_LITERAL and left_value != right_value:
                        findings.append("assert has a constant-only true inequality")
        elif isinstance(item, ast.Call):
            function = item.func
            name = (
                function.attr
                if isinstance(function, ast.Attribute)
                else function.id
                if isinstance(function, ast.Name)
                else ""
            )
            if name in {"assertTrue", "assert_true"} and item.args:
                if isinstance(item.args[0], ast.Constant) and item.args[0].value is True:
                    findings.append("assertTrue(True)")
            elif name in {"assertFalse", "assert_false"} and item.args:
                if isinstance(item.args[0], ast.Constant) and item.args[0].value is False:
                    findings.append("assertFalse(False)")
            elif name in {"assertEqual", "assert_equal"} and len(item.args) >= 2:
                if _ast_same(item.args[0], item.args[1]):
                    findings.append("assertEqual compares an expression with itself")
            elif name in {"assertNotEqual", "assert_not_equal"} and len(item.args) >= 2:
                left_value = _literal(item.args[0])
                right_value = _literal(item.args[1])
                if left_value is not _NO_LITERAL and right_value is not _NO_LITERAL and left_value != right_value:
                    findings.append("assertNotEqual is a constant-only inequality")
    return findings


def _python_direct_evidence(node: ast.AST, source: str) -> str | None:
    for item in ast.walk(node):
        if isinstance(item, ast.Assert):
            return "assert"
        if not isinstance(item, ast.Call):
            continue
        function = item.func
        name = (
            function.attr
            if isinstance(function, ast.Attribute)
            else function.id
            if isinstance(function, ast.Name)
            else ""
        )
        if name.startswith("assert") or name in {"fail", "raises"}:
            return name
        if name in {"check_call", "check_output"}:
            return f"subprocess.{name}"
        if name == "run":
            for keyword in item.keywords:
                if keyword.arg == "check" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                    return "subprocess.run(check=True)"
    body = ast.get_source_segment(source, node) or ""
    if "subprocess.run" in body and re.search(r"\bassert\b", body):
        return "subprocess embedded assertions"
    return None


def _python_called_helpers(node: ast.AST) -> set[str]:
    calls: set[str] = set()
    for item in ast.walk(node):
        if not isinstance(item, ast.Call):
            continue
        if isinstance(item.func, ast.Name):
            calls.add(item.func.id)
        elif (
            isinstance(item.func, ast.Attribute)
            and isinstance(item.func.value, ast.Name)
            and item.func.value.id == "self"
        ):
            calls.add(item.func.attr)
    return calls


def audit_python() -> tuple[list[dict[str, Any]], list[str]]:
    records: list[dict[str, Any]] = []
    errors: list[str] = []
    if not PYTHON_ROOT.is_dir():
        return records, errors
    for path in sorted(PYTHON_ROOT.rglob("*.py")):
        source = path.read_text(errors="replace")
        try:
            tree = ast.parse(source)
        except SyntaxError as error:
            errors.append(f"Python test file does not parse: {path.relative_to(ROOT)}: {error}")
            continue
        function_map = {
            node.name: node
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        tests = [
            node
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name.startswith("test")
        ]
        for node in tests:
            trivial = _python_trivial(node)
            evidence = _python_direct_evidence(node, source)
            delegated = False
            if evidence is None:
                for helper_name in _python_called_helpers(node):
                    helper = function_map.get(helper_name)
                    if helper is not None and helper is not node and _python_direct_evidence(helper, source):
                        evidence = f"helper:{helper_name}"
                        delegated = True
                        break
            relative = path.relative_to(ROOT).as_posix()
            conditional_skip = any(
                isinstance(item, ast.Call)
                and isinstance(item.func, ast.Attribute)
                and item.func.attr.startswith("skip")
                for item in ast.walk(node)
            ) or any(
                isinstance(decorator, ast.Call)
                and isinstance(decorator.func, ast.Attribute)
                and decorator.func.attr.startswith("skip")
                for decorator in node.decorator_list
            )
            record = {
                "language": "python",
                "path": relative,
                "name": node.name,
                "evidence": evidence,
                "delegated_assertion": delegated,
                "conditional_skip": conditional_skip,
                "trivial_assertions": trivial,
            }
            records.append(record)
            for finding in trivial:
                errors.append(f"trivial Python test {relative}::{node.name}: {finding}")
            if evidence is None and not conditional_skip:
                errors.append(f"assertion-free Python test: {relative}::{node.name}")
    return records, errors


def _brace_block(text: str, opening: int) -> str | None:
    depth = 0
    in_string = False
    escaped = False
    for index in range(opening, len(text)):
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
                return text[opening:index + 1]
    return None


def audit_kotlin() -> tuple[list[dict[str, Any]], list[str]]:
    records: list[dict[str, Any]] = []
    errors: list[str] = []
    files: set[Path] = set()
    for root in KOTLIN_ROOTS:
        if root.is_dir():
            files.update(root.rglob("*.kt"))
    for path in sorted(files):
        source = path.read_text(errors="replace")
        for match in re.finditer(r"@Test\s+fun\s+([A-Za-z_]\w*)\s*\([^)]*\)\s*\{", source):
            block = _brace_block(source, match.end() - 1) or ""
            name = match.group(1)
            relative = path.relative_to(ROOT).as_posix()
            trivial: list[str] = []
            if re.search(r"\b(?:assertTrue|check)\s*\(\s*true\s*\)", block):
                trivial.append("constant true assertion")
            if re.search(r"\bassertFalse\s*\(\s*false\s*\)", block):
                trivial.append("constant false assertion")
            if re.search(r"\bassertEquals\s*\(\s*([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*,\s*\1\s*\)", block):
                trivial.append("self equality")
            if re.search(r"\bassertNotEquals\s*\(\s*1\s*,\s*2\s*\)", block):
                trivial.append("constant-only inequality")
            has_evidence = bool(re.search(r"\b(?:assert\w*|check|fail)\s*\(", block) or ".check(" in block)
            records.append({
                "language": "kotlin",
                "path": relative,
                "name": name,
                "evidence": has_evidence,
                "trivial_assertions": trivial,
            })
            for finding in trivial:
                errors.append(f"trivial Kotlin test {relative}::{name}: {finding}")
            if not has_evidence:
                errors.append(f"assertion-free Kotlin test: {relative}::{name}")
    if KOTLIN_PORTABLE.is_dir():
        for path in sorted(KOTLIN_PORTABLE.rglob("*.kt")):
            source = path.read_text(errors="replace")
            if "fun main(" not in source:
                continue
            relative = path.relative_to(ROOT).as_posix()
            trivial = ["check(true)"] if re.search(r"\bcheck\s*\(\s*true\s*\)", source) else []
            has_evidence = bool(re.search(r"\b(?:check|assert\w*|error)\s*\(", source))
            records.append({
                "language": "kotlin-portable",
                "path": relative,
                "name": "main",
                "evidence": has_evidence,
                "trivial_assertions": trivial,
            })
            for finding in trivial:
                errors.append(f"trivial Kotlin portable test {relative}::main: {finding}")
            if not has_evidence:
                errors.append(f"assertion-free Kotlin portable test: {relative}::main")
    return records, errors


def audit_swift() -> tuple[list[dict[str, Any]], list[str]]:
    records: list[dict[str, Any]] = []
    errors: list[str] = []
    if not SWIFT_ROOT.is_dir():
        return records, errors
    for path in sorted(SWIFT_ROOT.rglob("*.swift")):
        source = path.read_text(errors="replace")
        for match in re.finditer(r"func\s+(test[A-Za-z0-9_]*)\s*\([^)]*\)[^{]*\{", source):
            block = _brace_block(source, match.end() - 1) or ""
            name = match.group(1)
            relative = path.relative_to(ROOT).as_posix()
            trivial: list[str] = []
            if re.search(r"\bXCTAssertTrue\s*\(\s*true\s*\)", block):
                trivial.append("XCTAssertTrue(true)")
            if re.search(r"\bXCTAssertFalse\s*\(\s*false\s*\)", block):
                trivial.append("XCTAssertFalse(false)")
            if re.search(r"\bXCTAssertEqual\s*\(\s*([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*,\s*\1\s*\)", block):
                trivial.append("XCTAssertEqual self equality")
            if re.search(r"\bXCTAssertNotEqual\s*\(\s*1\s*,\s*2\s*\)", block):
                trivial.append("XCTAssertNotEqual constant-only inequality")
            has_evidence = bool(re.search(r"\b(?:XCTAssert\w*|XCTFail|XCTExpectFailure)\s*\(", block))
            records.append({
                "language": "swift",
                "path": relative,
                "name": name,
                "evidence": has_evidence,
                "trivial_assertions": trivial,
            })
            for finding in trivial:
                errors.append(f"trivial Swift test {relative}::{name}: {finding}")
            if not has_evidence:
                errors.append(f"assertion-free Swift test: {relative}::{name}")
    return records, errors



def _strip_javascript_strings_and_comments(source: str) -> str:
    """Replace JS strings/comments with spaces while preserving code/newline positions."""
    out = list(source)
    index = 0
    state = "code"
    quote = ""
    escaped = False
    while index < len(source):
        char = source[index]
        nxt = source[index + 1] if index + 1 < len(source) else ""
        if state == "code":
            if char in {"'", '"', "`"}:
                state = "string"
                quote = char
                out[index] = " "
            elif char == "/" and nxt == "/":
                state = "line-comment"
                out[index] = out[index + 1] = " "
                index += 1
            elif char == "/" and nxt == "*":
                state = "block-comment"
                out[index] = out[index + 1] = " "
                index += 1
        elif state == "string":
            if char == "\n" and quote != "`":
                state = "code"
                quote = ""
            else:
                out[index] = "\n" if char == "\n" else " "
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    state = "code"
                    quote = ""
        elif state == "line-comment":
            if char == "\n":
                state = "code"
            else:
                out[index] = " "
        elif state == "block-comment":
            if char == "*" and nxt == "/":
                out[index] = out[index + 1] = " "
                index += 1
                state = "code"
            else:
                out[index] = "\n" if char == "\n" else " "
        index += 1
    return "".join(out)


def _javascript_test_files() -> list[Path]:
    files: set[Path] = set()
    web = JAVASCRIPT_ROOTS[0]
    if web.is_dir():
        files.update(web.glob("*.test.mjs"))
        files.update(web.glob("check_web_*.mjs"))
    integration = JAVASCRIPT_ROOTS[1]
    if integration.is_dir():
        files.update(integration.glob("*_case.mjs"))
    return sorted(files)


def _javascript_trivial(code: str) -> list[str]:
    findings: list[str] = []
    if re.search(r"\bassert\.ok\s*\(\s*true\s*(?:,|\))", code):
        findings.append("constant true assertion")
    equality = re.compile(
        r"\bassert\.(?:equal|strictEqual|deepEqual|deepStrictEqual)\s*\(\s*"
        r"([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*|-?\d+(?:\.\d+)?|true|false|null)\s*,\s*"
        r"([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*|-?\d+(?:\.\d+)?|true|false|null)\s*(?:,|\))"
    )
    for match in equality.finditer(code):
        left, right = match.groups()
        if left == right:
            findings.append("self/constant equality")
    inequality = re.compile(
        r"\bassert\.(?:notEqual|notStrictEqual|notDeepEqual|notDeepStrictEqual)\s*\(\s*"
        r"(-?\d+(?:\.\d+)?|true|false|null)\s*,\s*"
        r"(-?\d+(?:\.\d+)?|true|false|null)\s*(?:,|\))"
    )
    for match in inequality.finditer(code):
        if match.group(1) != match.group(2):
            findings.append("constant-only inequality")
    return sorted(set(findings))


def audit_javascript() -> tuple[list[dict[str, Any]], list[str]]:
    """Audit executable Node QA scripts as one assertion-bearing test contract each."""
    records: list[dict[str, Any]] = []
    errors: list[str] = []
    for path in _javascript_test_files():
        source = path.read_text(errors="replace")
        code = _strip_javascript_strings_and_comments(source)
        relative = path.relative_to(ROOT).as_posix()
        trivial = _javascript_trivial(code)
        has_assert = bool(re.search(r"\bassert\.(?:\w+)\s*\(", code))
        has_conditional_throw = bool(
            re.search(r"\bif\s*\([^)]*\)\s*(?:\{[^{}]{0,500})?\s*throw\s+new\s+Error\s*\(", code, re.S)
        )
        has_rejection = bool(re.search(r"\bthrow\s+new\s+Error\s*\(", code))
        has_evidence = has_assert or has_conditional_throw or has_rejection
        records.append({
            "language": "javascript",
            "path": relative,
            "name": path.name,
            "evidence": has_evidence,
            "assert_api": has_assert,
            "throw_contract": has_rejection,
            "trivial_assertions": trivial,
        })
        for finding in trivial:
            errors.append(f"trivial JavaScript test {relative}: {finding}")
        if not has_evidence:
            errors.append(f"assertion-free JavaScript QA script: {relative}")
    return records, errors

def audit() -> tuple[list[str], dict[str, Any]]:
    records: list[dict[str, Any]] = []
    errors: list[str] = []
    for runner in (audit_rust, audit_python, audit_javascript, audit_kotlin, audit_swift):
        found, found_errors = runner()
        records.extend(found)
        errors.extend(found_errors)
    by_language: dict[str, int] = {}
    for record in records:
        language = str(record["language"])
        by_language[language] = by_language.get(language, 0) + 1
    conditional_skips = [
        f"{record['path']}::{record['name']}"
        for record in records
        if record.get("conditional_skip")
    ]
    delegated = [
        f"{record['path']}::{record['name']}"
        for record in records
        if record.get("delegated_assertion")
    ]
    report = {
        "schema_version": 1,
        "healthy": not errors,
        "claim": (
            "Static first-party test audit rejecting assertion-free tests and obvious "
            "tautological/constant-only passes across Rust, Python, JavaScript, Kotlin, and Swift."
        ),
        "tests_scanned": len(records),
        "by_language": dict(sorted(by_language.items())),
        "conditional_skips": conditional_skips,
        "delegated_assertion_tests": delegated,
        "limitations": [
            "Static analysis can reject assertion-free and obvious tautological forms but cannot prove every oracle is semantically independent of the implementation under test.",
            "Mutation results provide dynamic oracle-strength evidence only for the configured mutation scope and only under the exact test-workspace provenance recorded by that run.",
        ],
        "errors": errors,
        "tests": records,
    }
    return errors, report


def main() -> int:
    errors, report = audit()
    DEFAULT_OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    DEFAULT_OUTPUT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    for error in errors:
        print(f"ERROR: {error}")
    if errors:
        return 1
    print(
        "PASS: repository test-quality audit scanned "
        f"{report['tests_scanned']} tests with no assertion-free or obvious tautological passes "
        f"({', '.join(f'{key}={value}' for key, value in report['by_language'].items())})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
