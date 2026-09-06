#!/usr/bin/env python3
"""Conservative source-complexity CRAP gate for Android domain and infrastructure production logic.

Coverage-unavailable Kotlin functions are treated as 0% covered, making the
score CC^2 + CC. This is deliberately stricter than measured CRAP and keeps
mobile Android logic below the repository threshold before instrumentation.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[3]
APP = ROOT / "apps/kassee-android/app/src/main/java/org/kassigner/kassigner"
OUT = ROOT / "target/qa/android-crap"
THRESHOLD = 30.0
SCOPE = (APP / "domain", APP / "infrastructure")
FUN = re.compile(r"\bfun\s+(?:<[^>]+>\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)[^{=]*([={])")
DECISION = re.compile(r"\b(?:if|for|while|catch|when)\b|&&|\|\||\?:")


def source_files() -> list[Path]:
    files: list[Path] = []
    for path in SCOPE:
        files.extend(sorted(path.rglob("*.kt")) if path.is_dir() else [path])
    return files


def matching_brace(text: str, opening: int) -> int:
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
                return index
    return len(text) - 1


def functions(path: Path) -> list[dict[str, object]]:
    text = path.read_text(encoding="utf-8")
    rows: list[dict[str, object]] = []
    for match in FUN.finditer(text):
        name, kind = match.group(1), match.group(2)
        if kind == "{":
            opening = match.end() - 1
            body = text[opening + 1:matching_brace(text, opening)]
        else:
            body = text[match.end():].splitlines()[0] if text[match.end():] else ""
        complexity = 1 + len(DECISION.findall(body))
        crap = float(complexity * complexity + complexity)
        line = text.count("\n", 0, match.start()) + 1
        rows.append({
            "file": path.relative_to(ROOT).as_posix(),
            "function": name,
            "line": line,
            "complexity": complexity,
            "coverage": 0.0,
            "crap": crap,
        })
    return rows


def main() -> int:
    rows = [row for path in source_files() for row in functions(path)]
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "report.json").write_text(json.dumps({"threshold": THRESHOLD, "rows": rows}, indent=2) + "\n")
    failures = [row for row in rows if row["crap"] > THRESHOLD]
    if failures:
        for row in failures:
            print(f"ERROR: Android source CRAP {row['crap']:.2f}>{THRESHOLD:.0f}: {row['file']}::{row['function']}:{row['line']} (CC {row['complexity']})")
        return 1
    worst = max(rows, key=lambda row: row["crap"], default=None)
    if worst:
        print(f"PASS: Android source CRAP ({len(rows)} functions; worst {worst['crap']:.2f}, CC {worst['complexity']}; threshold {THRESHOLD:.0f}).")
    else:
        print("ERROR: Android source CRAP scope contained no functions.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
