#!/usr/bin/env python3
"""Fail on unresolved identifiers, broken imports, and unused authored browser bindings."""

from __future__ import annotations

from pathlib import Path
import json
import re
import subprocess
import sys
import tempfile

from typescript_toolchain import (
    TypeScriptToolchainError,
    resolve_typescript_command,
)

ROOT = Path(__file__).resolve().parents[3]
APP_JS_ROOT = ROOT / "apps/kassee-web/web/js"
CONSTELLATION_JS_ROOT = ROOT / "apps/kassee-web/web/constellation/js/source"
GLOBALS = ROOT / "qa/checks/web/browser-globals.d.ts"
ENFORCED_CODES = {
    2300, 2304, 2305, 2307, 2395, 2440, 2451, 2552, 2614, 2724, 6133, 6196,
}
DIAGNOSTIC = re.compile(r"error TS(?P<code>\d+):")


def check_program(
    compiler: list[str],
    label: str,
    files: list[Path],
    include_globals: bool,
) -> list[str]:
    inputs = ([GLOBALS] if include_globals else []) + files
    config_root = ROOT / "target/qa/typescript-check"
    config_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="program-", dir=config_root) as temporary:
        config = Path(temporary) / "tsconfig.json"
        config.write_text(
            json.dumps(
                {
                    "compilerOptions": {
                        "allowJs": True,
                        "checkJs": True,
                        "noEmit": True,
                        "noUnusedLocals": True,
                        "noUnusedParameters": True,
                        "target": "ES2022",
                        "module": "ESNext",
                        "moduleResolution": "Bundler",
                        "lib": ["ES2022", "DOM"],
                        "skipLibCheck": True,
                    },
                    "files": [str(path.resolve()) for path in inputs],
                }
            ),
            encoding="utf-8",
        )
        result = subprocess.run(
            [*compiler, "--project", str(config)],
            cwd=ROOT,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            check=False,
        )
    output = "\n".join(part for part in (result.stdout, result.stderr) if part)
    failures = []
    for line in output.splitlines():
        match = DIAGNOSTIC.search(line)
        if not match or int(match.group("code")) not in ENFORCED_CODES:
            continue
        if int(match.group("code")) == 2307 and "wasm/api.js" in line and "../../pkg/kassee_web.js" in line:
            continue
        failures.append(f"{label}: {line}")
    return failures


def main() -> int:
    try:
        compiler = resolve_typescript_command()
    except TypeScriptToolchainError as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1

    app_files = sorted(APP_JS_ROOT.rglob("*.js"))
    constellation_files = sorted(CONSTELLATION_JS_ROOT.rglob("*.js"))
    failures = [
        *check_program(compiler, "application", app_files, include_globals=True),
        *check_program(
            compiler, "Constellation", constellation_files, include_globals=False
        ),
    ]
    if failures:
        print("FAIL: browser JavaScript identifier/API checks")
        print("\n".join(failures))
        return 1

    print(
        "PASS: browser JavaScript identifiers/imports/unused bindings "
        f"({len(app_files)} application + {len(constellation_files)} Constellation modules)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
