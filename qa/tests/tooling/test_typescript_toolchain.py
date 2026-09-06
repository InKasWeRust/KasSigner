#!/usr/bin/env python3
"""Regression tests for the pinned TypeScript toolchain resolver."""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "qa/checks/web"))

import check_web_javascript  # noqa: E402
from typescript_toolchain import (  # noqa: E402
    TYPESCRIPT_VERSION,
    TypeScriptToolchainError,
    resolve_typescript_command,
)


def completed(
    command: list[str],
    *,
    returncode: int = 0,
    stdout: str = "",
    stderr: str = "",
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(command, returncode, stdout, stderr)


class TypeScriptToolchainTests(unittest.TestCase):
    def test_uses_matching_system_compiler(self) -> None:
        def which(command: str) -> str | None:
            return {"tsc": "/tools/tsc"}.get(command)

        def run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
            return completed(command, stdout=f"Version {TYPESCRIPT_VERSION}\n")

        self.assertEqual(
            resolve_typescript_command(environ={}, which=which, run=run),
            ["/tools/tsc"],
        )

    def test_uses_matching_cached_compiler(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            compiler = (
                root
                / "target/development-tools"
                / f"typescript-{TYPESCRIPT_VERSION}"
                / "node_modules/typescript/lib/tsc.js"
            )
            compiler.parent.mkdir(parents=True)
            compiler.write_text("// test compiler")

            def which(command: str) -> str | None:
                return {"node": "/tools/node"}.get(command)

            def run(
                command: list[str], **_: object
            ) -> subprocess.CompletedProcess[str]:
                return completed(command, stdout=f"Version {TYPESCRIPT_VERSION}\n")

            self.assertEqual(
                resolve_typescript_command(
                    root=root, environ={}, which=which, run=run
                ),
                ["/tools/node", str(compiler)],
            )

    def test_installs_pinned_compiler_when_system_version_differs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            def which(command: str) -> str | None:
                return {
                    "tsc": "/tools/tsc",
                    "node": "/tools/node",
                    "npm": "/tools/npm",
                }.get(command)

            def run(
                command: list[str], **_: object
            ) -> subprocess.CompletedProcess[str]:
                if command[0] == "/tools/tsc":
                    return completed(command, stdout="Version 5.7.2\n")
                if command[0] == "/tools/npm":
                    compiler = (
                        root
                        / "target/development-tools"
                        / f"typescript-{TYPESCRIPT_VERSION}"
                        / "node_modules/typescript/lib/tsc.js"
                    )
                    compiler.parent.mkdir(parents=True)
                    compiler.write_text("// installed compiler")
                    return completed(command)
                return completed(command, stdout=f"Version {TYPESCRIPT_VERSION}\n")

            command = resolve_typescript_command(
                root=root, environ={}, which=which, run=run
            )
            self.assertEqual(command[0], "/tools/node")
            self.assertTrue(Path(command[1]).as_posix().endswith("node_modules/typescript/lib/tsc.js"))


    def test_javascript_checker_uses_project_file_for_large_source_sets(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            compiler = root / "fake_tsc.py"
            compiler.write_text(
                """import json
from pathlib import Path
import sys
if sys.argv[1:2] != ["--project"] or len(sys.argv) != 3:
    raise SystemExit(90)
config = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
if len(config["files"]) != 401:
    raise SystemExit(91)
""",
                encoding="utf-8",
            )
            files = [
                root / "apps" / (f"module_{index:03d}_" + "x" * 120 + ".js")
                for index in range(400)
            ]
            self.assertGreater(sum(len(str(path)) + 1 for path in files), 32767)
            with (
                mock.patch.object(check_web_javascript, "ROOT", root),
                mock.patch.object(
                    check_web_javascript, "GLOBALS", root / "browser-globals.d.ts"
                ),
            ):
                self.assertEqual(
                    check_web_javascript.check_program(
                        [sys.executable, str(compiler)],
                        "application",
                        files,
                        include_globals=True,
                    ),
                    [],
                )

    def test_reports_install_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            def which(command: str) -> str | None:
                return {
                    "node": "/tools/node",
                    "npm": "/tools/npm",
                }.get(command)

            def run(
                command: list[str], **_: object
            ) -> subprocess.CompletedProcess[str]:
                return completed(command, returncode=1, stderr="registry unavailable")

            with self.assertRaisesRegex(
                TypeScriptToolchainError, "registry unavailable"
            ):
                resolve_typescript_command(
                    root=root, environ={}, which=which, run=run
                )


if __name__ == "__main__":
    unittest.main()
