#!/usr/bin/env python3
"""Toolchain, runner, and artifact tests for the consolidated CRAP quality check."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from qa.tests.tooling.crap_check_test_support import (
    CrapCheckTestCase, ROOT, report_document,
)

sys.path.insert(0, str(ROOT / "qa/checks"))
from toolchains import load_toolchains  # noqa: E402

PINS = load_toolchains()


class CrapToolchainTests(CrapCheckTestCase):
    def test_windows_crap_runner_resolves_repository_root(self) -> None:
        import importlib.util

        runner = ROOT / "scripts/windows/quality/crap_windows.py"
        spec = importlib.util.spec_from_file_location("kassigner_crap_windows_root_test", runner)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        self.assertEqual(module.ROOT, ROOT)
        self.assertTrue((module.ROOT / "qa/checks/quality/crap/coverage_manifest.py").is_file())
        self.assertEqual(module.ROOT / "target/qa/crap", ROOT / "target/qa/crap")

    def test_run_all_catalog_invokes_pinned_branch_coverage(self) -> None:
        catalog = (ROOT / "qa/config/run_all_steps.tsv").read_text()
        dispatch = (ROOT / "qa/linux/runner/catalog.sh").read_text()
        rows = [line.split("\t") for line in catalog.splitlines() if line and not line.startswith("#")]
        ids = [row[3] for row in rows]
        test_ids = [row[3] for row in rows if row[0] == "test"]
        self.assertEqual(ids.count("preflight.crap-check"), 1)
        self.assertEqual(ids.count("preflight.core-ci"), 1)
        self.assertEqual(ids[:2], ["preflight.crap-check", "preflight.core-ci"])
        self.assertTrue(test_ids)
        self.assertGreater(min(ids.index(step) for step in test_ids), ids.index("preflight.crap-check"))
        self.assertIn('run_in_directory "$ROOT_DIR" bash qa/linux/run-pinned-branch-coverage.sh', dispatch)
        self.assertNotIn('run_in_directory "$ROOT_DIR" make branch-coverage', dispatch)

        makefile = (ROOT / "Makefile").read_text()
        self.assertIn("scripts/common/lib/make_tasks.py", makefile)
        make_helper = (ROOT / "scripts/common/lib/make_tasks.py").read_text()
        self.assertNotIn("_crap_ratchet_requests_branch", make_helper)
        self.assertNotIn('env["CRAP_ENABLE_BRANCH"]', make_helper)
        generator = ROOT / "scripts/linux/quality/crap.sh"
        runner = (ROOT / "qa/linux/run-pinned-branch-coverage.sh").read_text()
        setup = (ROOT / "scripts/linux/quality/branch-coverage-setup.sh").read_text()
        self.assertTrue(generator.is_file())
        source = generator.read_text()
        self.assertIn("llvm-cov", source)
        self.assertIn('rustup run "$COVERAGE_TOOLCHAIN" cargo crap', source)
        self.assertIn("--strict", runner)
        self.assertIn("ensure_cargo_plugin llvm-cov cargo-llvm-cov", setup)

    @unittest.skipUnless(os.name == "posix", "Linux CRAP runner execution is POSIX-specific")
    def test_optional_generator_skips_when_tools_are_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            for name in ("cargo", "rustup"):
                tool = fake_bin / name
                tool.write_text("#!/usr/bin/env sh\nexit 1\n")
                tool.chmod(0o755)

            output = root / "output"
            environment = dict(os.environ)
            environment["PATH"] = f"{fake_bin}:{environment.get('PATH', '')}"
            environment["CRAP_OUTPUT_DIR"] = str(output)

            result = subprocess.run(
                [str(ROOT / "scripts/linux/quality/crap.sh")],
                cwd=ROOT,
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("CRAP report generation skipped", result.stdout)
            self.assertIn("remaining QA catalog will continue", result.stdout)
            self.assertFalse(output.exists())


    @unittest.skipUnless(os.name == "posix", "Linux CRAP runner execution is POSIX-specific")
    def test_generator_runs_visible_coverage_and_keeps_bundle_in_target_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake_bin = root / "bin"
            fake_bin.mkdir()

            cargo = fake_bin / "cargo"
            cargo.write_text(
                r"""#!/usr/bin/env python3
import json
from pathlib import Path
import sys

args = sys.argv[1:]
if args[:2] == ["llvm-cov", "--version"]:
    print("cargo-llvm-cov 0.6.21")
    raise SystemExit(0)
if args[:2] == ["crap", "--version"]:
    print("cargo-crap " + __import__("os").environ["TEST_CARGO_CRAP_VERSION"])
    raise SystemExit(0)
if args[:1] == ["llvm-cov"]:
    output = Path(args[args.index("--output-path") + 1])
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("TN:\nSF:crates/shared-signer/src/example.rs\nDA:1,1\nend_of_record\n")
    print("running 1 test")
    print("test result: ok. 1 passed; 0 failed")
    raise SystemExit(0)
if args[:1] == ["crap"]:
    output = Path(args[args.index("--output") + 1])
    output.parent.mkdir(parents=True, exist_ok=True)
    report_format = args[args.index("--format") + 1]
    if report_format == "json":
        secondary = "kassee_web" in output.name or "firmware" in output.name
        document = {
            "version": __import__("os").environ["TEST_CARGO_CRAP_VERSION"],
            "entries": [] if secondary else [{
                "file": "crates/shared-signer/src/example.rs",
                "function": "example",
                "line": 1,
                "cyclomatic": 1.0,
                "coverage": 100.0,
                "crap": 1.0
            }]
        }
        if "--lcov" in args:
            document["diagnostics"] = {
                "analyzed_files": 1,
                "lcov_files": 1,
                "matched_files": 1,
                "source_only": {"count": 0, "examples": []},
                "lcov_only": {"count": 0, "examples": []}
            }
        output.write_text(json.dumps(document))
    else:
        output.write_text(
            "│ ✓ ┆ 1.0 ┆ 1 ┆ ██████████ 100.0% ┆ example ┆ ./crates/shared-signer/src/example.rs:1 │\n"
            "✓ 0/1 function(s) exceed CRAP threshold 30.\n"
        )
    raise SystemExit(0)
raise SystemExit(2)
"""
            )
            cargo.chmod(0o755)

            rustup = fake_bin / "rustup"
            rustup.write_text(
                """#!/usr/bin/env sh
if [ "$1 $3" = "run rustc" ]; then
  echo "rustc 1.95.0"
  exit 0
fi
if [ "$1 $3" = "run cargo" ]; then
  shift 3
  exec cargo "$@"
fi
if [ "$1 $2" = "component list" ]; then
  echo "llvm-tools-preview-x86_64-unknown-linux-gnu (installed)"
  exit 0
fi
exit 2
"""
            )
            rustup.chmod(0o755)

            # Keep this tooling unit test focused on the Rust coverage/CRAP
            # runner. The production script still runs both heavyweight browser
            # coverage jobs; this fake Python shim intercepts only those two
            # entry points and emits valid supplemental documents.
            python3 = fake_bin / "python3"
            python3.write_text(
                """#!/usr/bin/env sh
set -eu
case "${1:-}" in
  *run_web_recovery_coverage.py)
    shift
    [ "${1:-}" = "--output-dir" ]
    out="$2"
    mkdir -p "$out"
    cat > "$out/summary.json" <<'JSON'
{"schema_version":1,"domain":"browser_recovery","tests":{"passed":true},"files":{"expected":1,"measured":1,"missing":[],"unexpected":[]},"coverage":{"lines":{"percent":100.0,"available":true,"target":90.0,"met":true},"functions":{"percent":100.0,"available":true,"target":90.0,"met":true},"branches":{"percent":100.0,"available":true,"target":90.0,"met":true}},"met":true}
JSON
    printf '{}\n' > "$out/v8-coverage.json"
    printf 'test browser recovery coverage\n' > "$out/report.txt"
    exit 0
    ;;
  *run_web_runtime_coverage.py)
    shift
    [ "${1:-}" = "--output-dir" ]
    out="$2"
    mkdir -p "$out"
    cat > "$out/summary.json" <<'JSON'
{"schema_version":1,"domain":"web_runtime","tests_passed":true,"files":{"reachable":1,"measured":1,"missing":[],"mapping_percent":100.0},"coverage":{"lines":100.0,"functions":100.0,"branches":100.0},"met":true}
JSON
    printf '{}\n' > "$out/v8-coverage.json"
    printf 'test web runtime coverage\n' > "$out/report.txt"
    exit 0
    ;;
esac
exec __REAL_PYTHON__ "$@"
""".replace("__REAL_PYTHON__", sys.executable)
            )
            python3.chmod(0o755)

            output = root / "output"
            ratchet = root / "ratchet.json"
            ratchet.write_text(json.dumps({
                "schema_version": 1,
                "coverage_profile": {
                    "branch_instrumentation": False,
                    "dev_opt_level": "0",
                    "test_opt_level": "0",
                },
                "host_production_minimum_percent": {
                    "lines": 0.0,
                    "functions": 0.0,
                    "branches": 0.0,
                },
            }))
            environment = dict(os.environ)
            environment["PATH"] = f"{fake_bin}:{environment.get('PATH', '')}"
            environment["CRAP_OUTPUT_DIR"] = str(output)
            environment["CRAP_RATCHET_PATH"] = str(ratchet)
            environment["TEST_CARGO_CRAP_VERSION"] = PINS["KASSIGNER_CARGO_CRAP_VERSION"]

            result = subprocess.run(
                [str(ROOT / "scripts/linux/quality/crap.sh")],
                cwd=ROOT,
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("[CRAP 1/4] Running", result.stdout)
            self.assertIn("scope-aligned coverage completed", result.stdout)
            self.assertIn("[CRAP 4/4] PASS", result.stdout)
            self.assertIn("remaining QA catalog starts now", result.stdout)
            for name in (
                "lcov.info",
                "coverage_run.txt",
                "crap_run.txt",
                "run.json",
                "cargo_crap.json",
                "crap_report_prod.txt",
                "crap_summary.json",
                "health_summary.json",
                "current.json",
            ):
                self.assertTrue((output / name).is_file(), name)
            self.assertGreater((output / "crap_run.txt").stat().st_size, 0)
            self.assertIn("KasSigner CRAP analysis log", (output / "crap_run.txt").read_text())
            run = json.loads((output / "run.json").read_text())
            self.assertGreater(run["artifacts"]["lcov"]["bytes"], 0)
            refreshed = json.loads((output / "current.json").read_text())
            self.assertEqual(refreshed["summary"]["all"]["functions"], 1)
            self.assertFalse((ROOT / "qa/baselines/crap").exists())

    @unittest.skipUnless(os.name == "posix", "Linux CRAP runner execution is POSIX-specific")
    def test_requested_branch_coverage_fails_instead_of_soft_skipping(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake_bin = root / "bin"
            fake_bin.mkdir()

            cargo = fake_bin / "cargo"
            cargo.write_text(
                f"""#!/usr/bin/env sh
if [ "$1 $2" = "llvm-cov --version" ]; then
  echo "cargo-llvm-cov {PINS['KASSIGNER_CARGO_LLVM_COV_VERSION']}"
  exit 0
fi
if [ "$1 $2" = "crap --version" ]; then
  echo "cargo-crap {PINS['KASSIGNER_CARGO_CRAP_VERSION']}"
  exit 0
fi
exit 2
"""
            )
            cargo.chmod(0o755)

            rustup = fake_bin / "rustup"
            rustup.write_text(
                f"""#!/usr/bin/env sh
if [ "$1 $3" = "run rustc" ]; then
  echo "rustc 1.99.0-nightly"
  exit 0
fi
if [ "$1 $3" = "run cargo" ]; then
  shift 3
  exec cargo "$@"
fi
if [ "$1 $2" = "component list" ]; then
  exit 0
fi
exit 2
"""
            )
            rustup.chmod(0o755)

            node = fake_bin / "node"
            node.write_text("#!/usr/bin/env sh\nexit 0\n")
            node.chmod(0o755)

            output = root / "output"
            environment = dict(os.environ)
            environment["PATH"] = f"{fake_bin}:{environment.get('PATH', '')}"
            environment["CRAP_OUTPUT_DIR"] = str(output)
            environment["CRAP_ENABLE_BRANCH"] = "1"
            environment["CRAP_BRANCH_TOOLCHAIN"] = PINS["KASSIGNER_BRANCH_RUST"]

            result = subprocess.run(
                [str(ROOT / "scripts/linux/quality/crap.sh")],
                cwd=ROOT,
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            self.assertIn("requested branch coverage could not run", result.stderr)
            self.assertIn("branch-coverage-setup", result.stderr)
            self.assertNotIn("PASS: CRAP quality check", result.stdout)
            self.assertFalse((output / "run.json").exists())

    def test_windows_branch_coverage_tools_are_repository_local(self) -> None:
        setup = (ROOT / "scripts/windows/quality/branch-coverage-setup.ps1").read_text(encoding="utf-8")
        self.assertIn("target/development-tools/branch-coverage-", setup)
        self.assertIn("'--root',$toolRoot", setup)
        self.assertIn("$env:PATH=$toolBin+';'+$env:PATH", setup)
        self.assertNotIn("Join-Path $HOME '.cargo/bin'", setup)
        self.assertNotIn("Join-Path $env:USERPROFILE '.cargo/bin'", setup)

    def test_windows_direct_cargo_plugin_probe_preserves_subcommand_argv(self) -> None:
        setup = (ROOT / "scripts/windows/quality/branch-coverage-setup.ps1").read_text(encoding="utf-8")
        self.assertIn("$probeArgs=@($sub,'--version')", setup)
        self.assertIn("Invoke-KasSignerCapture -Command $exe -Arguments $probeArgs", setup)
        self.assertNotIn("-Command $exe -Arguments @('--version')", setup)
        self.assertIn("Ensure-Plugin 'llvm-cov' 'cargo-llvm-cov' $llvm", setup)
        self.assertIn("Ensure-Plugin 'crap' 'cargo-crap' $crap", setup)

    def test_internal_branch_coverage_runner_provisions_pinned_tools_first(self) -> None:
        makefile = (ROOT / "Makefile").read_text()
        runner = (ROOT / "qa/linux/run-pinned-branch-coverage.sh").read_text()
        setup = (ROOT / "scripts/linux/quality/branch-coverage-setup.sh").read_text()
        self.assertNotIn("branch-coverage-setup:", makefile)
        self.assertIn("scripts/linux/quality/branch-coverage-setup.sh", runner)
        self.assertIn("scripts/linux/quality/crap.sh", runner)
        self.assertIn("qa/checks/quality/crap/package_branch_artifacts.py", runner)
        self.assertIn("--component llvm-tools-preview", setup)
        self.assertIn('rustup run "$TOOLCHAIN" rustc --version', setup)
        self.assertIn('rustup component add llvm-tools-preview --toolchain "$TOOLCHAIN"', setup)

    def test_pinned_branch_coverage_runner_keeps_fresh_evidence_in_target(self) -> None:
        runner = ROOT / "qa/linux/run-pinned-branch-coverage.sh"
        self.assertTrue(runner.is_file())
        if os.name == "posix":
            self.assertTrue(runner.stat().st_mode & 0o111)
        source = runner.read_text(encoding="utf-8")
        for token in (
            "KASSIGNER_BRANCH_RUST",
            "cargo-llvm-cov",
            "KASSIGNER_CARGO_LLVM_COV_VERSION",
            "cargo-crap",
            "KASSIGNER_CARGO_CRAP_VERSION",
            "llvm-cov clean --workspace",
            "CRAP_ENABLE_BRANCH=1",
            "scripts/linux/quality/crap.sh",
            "qa/checks/quality/crap/package_branch_artifacts.py --validate-only",
            "qa/checks/quality/crap/package_branch_artifacts.py --input-dir",
            "target/qa/kassigner-branch-coverage.zip",
            "Fresh evidence is retained only under target/qa/crap/.",
            "TARGET_BUNDLE_SHA256",
            "sha256sum --check",
        ):
            self.assertIn(token, source)

        packager = (ROOT / "qa/checks/quality/crap/package_branch_artifacts.py").read_text(encoding="utf-8")
        for token in (
            'document.get("branch_coverage_requested") is not True',
            'branches.get("available") is not True',
            'int(branches.get("found", 0)) <= 0',
            'line.startswith("BRF:")',
            '"web_runtime/summary.json"',
            '"web_runtime/v8-coverage.json"',
            '"web_runtime/report.txt"',
            "archive.testzip()",
        ):
            self.assertIn(token, packager)

        artifact_ignore_path = ROOT / "qa/artifacts/.gitignore"
        if artifact_ignore_path.is_file():
            self.assertNotIn("branch-coverage", artifact_ignore_path.read_text())
        self.assertFalse((ROOT / "qa/artifacts/branch-coverage").exists())

    def test_branch_artifact_validation_avoids_inline_python_on_windows(self) -> None:
        windows = (ROOT / "qa/windows/run-pinned-branch-coverage.ps1").read_text(encoding="utf-8")
        linux = (ROOT / "qa/linux/run-pinned-branch-coverage.sh").read_text(encoding="utf-8")
        self.assertIn("package_branch_artifacts.py --validate-only", windows)
        self.assertIn("package_branch_artifacts.py --validate-only", linux)
        self.assertNotIn("$python -c", windows)
        self.assertNotIn("python3 - ", linux)

    def test_branch_artifact_helper_validates_and_self_checks_zip(self) -> None:
        helper = ROOT / "qa/checks/quality/crap/package_branch_artifacts.py"
        required = (
            "cargo_crap.json",
            "current.json",
            "crap_summary.json",
            "health_summary.json",
            "coverage_run.txt",
            "crap_run.txt",
            "crap_report_prod.txt",
            "browser_recovery/summary.json",
            "browser_recovery/v8-coverage.json",
            "browser_recovery/report.txt",
            "web_runtime/summary.json",
            "web_runtime/v8-coverage.json",
            "web_runtime/report.txt",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "crap"
            evidence.mkdir()
            (evidence / "run.json").write_text(
                json.dumps(
                    {
                        "branch_coverage_requested": True,
                        "coverage": {
                            "branches": {
                                "available": True,
                                "found": 4,
                                "hit": 3,
                                "percent": 75.0,
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            (evidence / "lcov.info").write_text("BRF:4\nBRH:3\n", encoding="utf-8")
            for relative in required:
                path = evidence / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("evidence\n", encoding="utf-8")

            validate = subprocess.run(
                [sys.executable, str(helper), "--validate-only", "--input-dir", str(evidence)],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(validate.returncode, 0, validate.stdout + validate.stderr)
            self.assertIn("Requested: True", validate.stdout)
            self.assertIn("First BRF records:", validate.stdout)

            bundle = root / "branch.zip"
            package = subprocess.run(
                [sys.executable, str(helper), "--input-dir", str(evidence), "--output", str(bundle)],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(package.returncode, 0, package.stdout + package.stderr)
            self.assertIn("Validated", package.stdout)
            self.assertTrue(bundle.is_file())

    def test_authoritative_qa_owns_fresh_crap_and_web_runtime_evidence(self) -> None:
        linux_alias = (ROOT / "qa/linux/run-production-hardening.sh").read_text()
        windows_alias = (ROOT / "qa/windows/run-production-hardening.ps1").read_text()
        coverage = (ROOT / "scripts/linux/quality/crap.sh").read_text()
        self.assertIn("--profile full", linux_alias)
        self.assertIn("--profile full", windows_alias)
        self.assertIn('$OUTPUT_DIR/web_runtime/summary.json', coverage)
        self.assertIn("qa/contracts/quality/crap_ratchets.json", coverage)


    def test_remote_ci_does_not_run_private_full_crap_graph(self) -> None:
        core = (ROOT / ".github/workflows/core.yml").read_text()
        fuzz = (ROOT / ".github/workflows/fuzz.yml").read_text()
        self.assertIn('make test STRICT_LOCKFILES=1', core)
        self.assertNotIn('make qa', core)
        self.assertNotIn('target/qa/crap', core)
        self.assertIn('FUZZ_SECONDS=300 bash scripts/linux/quality/security-fuzz.sh', fuzz)
        self.assertNotIn('make qa', fuzz)

    def test_root_crap_and_lcov_share_production_source_filters(self) -> None:
        linux = (ROOT / "scripts/linux/quality/crap.sh").read_text()
        windows = (ROOT / "scripts/windows/quality/crap_windows.py").read_text()
        for source in (linux, windows):
            self.assertIn("ignore-filename-regex", source)
            self.assertIn("unit_tests", source)
            self.assertIn("online-watcher", source)
            self.assertIn("wasm_api", source)
            self.assertIn(r"mod\.rs", source)
            self.assertIn("**/unit_tests/**", source)
            self.assertIn("src/wasm/**", source)
        self.assertEqual(linux.count("--no-default-excludes"), 2)
        self.assertEqual(windows.count("'--no-default-excludes'"), 1)
        self.assertNotIn("common=['--threshold','30','--missing','pessimistic','--no-default-excludes'", windows)
        self.assertIn("KasSigner CRAP analysis log", linux)
        self.assertIn("KasSigner CRAP analysis log", windows)
        self.assertIn('tee -a "$crap_log"', linux)
        self.assertIn("log=crap_log,append=True", windows)

    def test_generator_does_not_install_tools_or_lock_coverage_run(self) -> None:
        source = (ROOT / "scripts/linux/quality/crap.sh").read_text()
        self.assertNotIn("cargo +stable install", source)
        self.assertNotIn("rustup toolchain install", source)
        self.assertNotIn("rustup component add", source)
        self.assertNotIn("--locked", source)
        self.assertIn('rustup run "$toolchain" cargo llvm-cov --version', source)
        self.assertIn('rustup run "$toolchain" cargo crap --version', source)
        self.assertIn("CRAP_BRANCH_TOOLCHAIN", source)

    def test_quality_check_has_one_policy_and_one_compact_ratchet(self) -> None:
        policy_files = sorted(
            path.name for path in (ROOT / "qa/checks/quality/crap").glob("*.json")
        )
        contract_files = sorted(
            path.name for path in (ROOT / "qa/contracts/quality").glob("*.json")
        )
        self.assertEqual(policy_files, ["policy.json"])
        self.assertIn("crap_ratchets.json", contract_files)
        self.assertFalse((ROOT / "qa/baselines/crap").exists())


    def test_obsolete_quality_stage_labels_are_absent(self) -> None:
        changelog = (ROOT / "CHANGELOG.md").read_text(errors="ignore")
        sections = changelog.split("\n## ", 2)
        current_changelog = (sections[1] if len(sections) > 1 else changelog).lower()
        self.assertNotIn("milestone", current_changelog, "current unreleased changelog")
        self.assertNotRegex(current_changelog, r"\bphase\s+[0-9]", "current unreleased changelog")

        checked_paths = [
            ROOT / "Makefile",
            ROOT / "qa/checks/quality/crap",
            ROOT / "qa/linux/runner/catalog.sh",
            ROOT / "tools/install/macos",
            ROOT / "apps/signer-firmware/src/main.rs",
            ROOT / "apps/signer-firmware/src/runtime/unit_tests/boot.rs",
            ROOT / "apps/signer-firmware/src/runtime/unit_tests/software.rs",
            ROOT / "apps/signer-firmware/src/runtime/signing/verification.rs",
            ROOT / "apps/signer-firmware/src/boot",
        ]
        for checked in checked_paths:
            paths = [checked] if checked.is_file() else sorted(checked.rglob("*"))
            for path in paths:
                if not path.is_file() or "__pycache__" in path.parts:
                    continue
                source = path.read_text(errors="ignore").lower()
                self.assertNotIn("milestone", source, path)
                self.assertNotRegex(source, r"\bphase\s+[0-9]", str(path))


if __name__ == "__main__":
    unittest.main()
