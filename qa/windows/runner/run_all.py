#!/usr/bin/env python3
"""Native Windows implementation of the KasSigner master QA catalog."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[3]
PYTHON = sys.executable
STEP_SKIPPED = False


def clean_cargo_fuzz_source_scratch() -> None:
    for relative in ("qa/fuzz/artifacts", "qa/fuzz/corpus"):
        shutil.rmtree(ROOT / relative, ignore_errors=True)

CATALOG = ROOT / "qa/config/run_all_steps.tsv"

def load_catalog() -> tuple[list[tuple[str, str, str, str]], dict[str, str]]:
    steps: list[tuple[str, str, str, str]] = []
    scopes: dict[str, str] = {}
    for raw in CATALOG.read_text(encoding="utf-8").splitlines():
        if not raw or raw.startswith("#"):
            continue
        scope, category, workspace, step_id, description = raw.split("\t", 4)
        if step_id in scopes:
            raise RuntimeError(f"duplicate QA catalog step id: {step_id}")
        steps.append((category, workspace, step_id, description))
        scopes[step_id] = scope
    return steps, scopes

STEPS, STEP_SCOPES = load_catalog()

TEST_FILTER_STEPS = {
"unit.shared-signer","unit.signer-firmware-core","unit.offline-signer","unit.online-watcher","unit.kassee-web","unit.external-rqrr","unit.tools",
"integration.shared-signer-conformance","integration.repository-layout","integration.offline-signer-firmware-signing",
}
WORKSPACES = {"signer-firmware","kassee-ios","kassee-android","online-watcher","offline-signer","shared-signer","signer-firmware-core","external-rqrr","tools","repository","kassee-web"}
CATEGORIES = {"preflight","unit","integration","static","security","coverage","interactive","emulation","hardware","bench","mutation","fuzz"}



def load_toolchains() -> None:
    # Repository sources, docs, fixtures, and generated QA evidence are UTF-8.
    # Force child Python processes into UTF-8 mode so native Windows locale
    # code pages cannot corrupt reads/writes in the platform-neutral test suite.
    os.environ["PYTHONUTF8"] = "1"
    os.environ["PYTHONIOENCODING"] = "utf-8"
    for raw in (ROOT / "qa/config/toolchains.env").read_text(encoding="utf-8").splitlines():
        line=raw.strip()
        if not line or line.startswith("#"): continue
        key,value=line.split("=",1); os.environ[key]=value
    cargo_home=Path(os.environ.get("CARGO_HOME", Path.home()/".cargo"))
    os.environ["PATH"]=str(cargo_home/"bin")+os.pathsep+os.environ.get("PATH","")


def canonical_id(text: str) -> str:
    return {"unit.architecture-imports":"unit.repository-python-qa","fuzz.shared-signer-qr-payload":"fuzz.repository-security-targets"}.get(text,text)


def command_exists(name: str) -> bool: return shutil.which(name) is not None

def _prepend_path(directory: Path, environment: dict[str, str] | None = None) -> dict[str, str]:
    target = dict(environment or {})
    current = target.get("PATH", os.environ.get("PATH", ""))
    entries = current.split(os.pathsep) if current else []
    directory_text = str(directory)
    folded = {entry.casefold() for entry in entries}
    if directory_text.casefold() not in folded:
        current = directory_text + (os.pathsep + current if current else "")
    target["PATH"] = current
    return target


def _local_cargo_tool_root(kind: str, toolchain: str, version: str) -> Path:
    safe_toolchain = toolchain.replace("/", "-").replace("\\", "-")
    return ROOT / "target/development-tools" / f"{kind}-{safe_toolchain}-{version}"


def mutation_tool_environment() -> dict[str, str]:
    toolchain = os.environ["KASSIGNER_STABLE_RUST"]
    version = os.environ["KASSIGNER_CARGO_MUTANTS_VERSION"]
    root = _local_cargo_tool_root("cargo-mutants", toolchain, version)
    bin_dir = root / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    env = _prepend_path(bin_dir)
    env["CARGO_INSTALL_ROOT"] = str(root)
    return env


def configure_fuzz_tool_environment() -> tuple[Path, Path]:
    toolchain = os.environ["KASSIGNER_BRANCH_RUST"]
    version = os.environ["KASSIGNER_CARGO_FUZZ_VERSION"]
    root = _local_cargo_tool_root("cargo-fuzz", toolchain, version)
    bin_dir = root / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    os.environ.update(_prepend_path(bin_dir))
    os.environ["CARGO_INSTALL_ROOT"] = str(root)
    return root, bin_dir


def require(name: str, dry: bool=False) -> None:
    if not dry and not command_exists(name):
        if name=="cargo": raise RuntimeError("required command not found: cargo. Install Rust with rustup for Windows and reopen PowerShell.")
        raise RuntimeError(f"required command not found: {name}")


def run(cmd: list[str], *, cwd: Path=ROOT, env: dict[str,str]|None=None, dry: bool=False, allowed=(0,)) -> int:
    print("  +", subprocess.list2cmdline(cmd))
    if dry: return 0
    merged=os.environ.copy(); merged.update(env or {})
    code=subprocess.run(cmd,cwd=cwd,env=merged,check=False).returncode
    if code not in allowed: raise subprocess.CalledProcessError(code,cmd)
    return code


def capture(cmd: list[str], *, cwd: Path=ROOT, env: dict[str,str]|None=None) -> subprocess.CompletedProcess[str]:
    merged=os.environ.copy(); merged.update(env or {})
    return subprocess.run(cmd,cwd=cwd,env=merged,text=True,capture_output=True,check=False)


def metadata(directory: Path, manifest: str, extra: list[str]) -> subprocess.CompletedProcess[str]:
    return capture(["cargo","metadata","--manifest-path",manifest,"--format-version","1",*extra],cwd=directory)


def reconcile_lock(directory: Path, manifest: str, repair: bool, dry: bool) -> None:
    require("cargo",dry)
    print("  +", subprocess.list2cmdline(["cargo","metadata","--manifest-path",manifest,"--format-version","1","--locked"]))
    if dry:return
    first=metadata(directory,manifest,["--locked"])
    if first.returncode==0:return
    sys.stderr.write(first.stderr)
    if not repair: raise RuntimeError("locked Cargo graph is stale and --strict-lockfiles was requested")
    lock=directory/"Cargo.lock"; existed=lock.exists(); backup=lock.read_bytes() if existed else None
    print(f"  ! Locked graph is stale; refreshing {lock} transactionally.")
    offline=metadata(directory,manifest,["--offline"])
    if offline.returncode!=0:
        if existed: lock.write_bytes(backup or b"")
        elif lock.exists(): lock.unlink()
        print("  ! Offline refresh was unavailable; retrying with registry access.")
        online=metadata(directory,manifest,[])
        if online.returncode!=0:
            if existed: lock.write_bytes(backup or b"")
            elif lock.exists(): lock.unlink()
            raise RuntimeError(f"Cargo could not refresh {lock}.\n{offline.stderr}\n{online.stderr}")
    final=metadata(directory,manifest,["--locked"])
    if final.returncode!=0:
        if existed: lock.write_bytes(backup or b"")
        elif lock.exists(): lock.unlink()
        raise RuntimeError(f"refreshed lockfile still does not resolve under --locked: {lock}\n{final.stderr}")
    print(f"  ! Refreshed and verified: {lock}")


def cargo_test(extra: list[str], ns: argparse.Namespace) -> None:
    cmd=["cargo","test",*extra]
    if ns.test_filter:
        cmd.append(ns.test_filter)
        if ns.exact: cmd += ["--","--exact"]
    env = {"CARGO_TARGET_DIR": str(ROOT / "target/qa")} if "qa/Cargo.toml" in extra else None
    run(cmd, env=env, dry=ns.dry_run)


def ensure_fuzz_toolchain(dry: bool) -> None:
    require("rustup",dry); require("cargo",dry)
    tool_root, tool_bin = configure_fuzz_tool_environment()
    if dry:
        return
    stable=os.environ["KASSIGNER_STABLE_RUST"]; nightly=os.environ["KASSIGNER_BRANCH_RUST"]; ver=os.environ["KASSIGNER_CARGO_FUZZ_VERSION"]
    for tc in (stable,nightly):
        if capture(["rustup","run",tc,"rustc","--version"]).returncode:
            run(["rustup","toolchain","install",tc,"--profile","minimal"])
    # A direct --resume-from fuzz invocation must be self-contained. The earlier
    # branch-coverage gate normally installs LLVM tooling, but fuzz cannot rely
    # on a prior stage having run in this process/session. rustup is idempotent
    # when the pinned component is already present.
    run(["rustup","component","add","llvm-tools-preview","--toolchain",nightly])
    actual=capture(["rustup","run",nightly,"cargo","fuzz","--version"])
    if actual.returncode or f"cargo-fuzz {ver}" not in actual.stdout+actual.stderr:
        install=["rustup","run",stable,"cargo","install","cargo-fuzz","--version",ver,"--locked","--root",str(tool_root)]
        executable = tool_bin / ("cargo-fuzz.exe" if os.name == "nt" else "cargo-fuzz")
        if executable.is_file():
            install.append("--force")
        run(install)
        actual=capture(["rustup","run",nightly,"cargo","fuzz","--version"])
        if actual.returncode or f"cargo-fuzz {ver}" not in actual.stdout+actual.stderr:
            raise RuntimeError(f"expected cargo-fuzz {ver} in repository-local QA tooling")


def run_fuzz(ns: argparse.Namespace) -> None:
    ensure_fuzz_toolchain(ns.dry_run)
    if ns.fuzz_target:
        targets = [ns.fuzz_target]
    elif ns.dry_run:
        # Keep --dry-run completely host-tool-independent while still showing
        # the registered fuzz stage. Registry validity is enforced by normal
        # execution and repository tests.
        targets = ["<registered-fuzz-targets>"]
    else:
        registry = capture([PYTHON, "qa/checks/security/fuzz_targets.py", "--validate"])
        if registry.returncode:
            detail = (registry.stdout + registry.stderr).strip()
            raise RuntimeError(f"fuzz target registry validation failed: {detail}")
        targets = [line.strip() for line in registry.stdout.splitlines() if line.strip()]
    if not targets:
        raise RuntimeError("no fuzz targets are registered")
    state = ROOT / "target/qa/fuzz"
    status_file = state / "statuses.tsv"
    artifact_root = state / "artifacts"
    corpus_root = state / "corpus"
    actual = (
        f"cargo-fuzz {os.environ['KASSIGNER_CARGO_FUZZ_VERSION']}"
        if ns.dry_run
        else capture(["rustup", "run", os.environ["KASSIGNER_BRANCH_RUST"], "cargo", "fuzz", "--version"]).stdout.strip()
    )
    if ns.dry_run:
        for target in targets:
            run(
                [
                    "rustup", "run", os.environ["KASSIGNER_BRANCH_RUST"], "cargo", "fuzz", "run", target,
                    "--no-include-main-msvc", "--", f"-runs={ns.fuzz_passes}",
                    f"-artifact_prefix={artifact_root / target}{os.sep}", str(corpus_root / target),
                ],
                cwd=ROOT / "qa/fuzz", env={"CARGO_TARGET_DIR": str(ROOT / "target/qa")}, dry=True,
            )
        print(
            "  +",
            subprocess.list2cmdline(
                [
                    PYTHON, "qa/checks/security/fuzz_results.py", "--statuses", str(status_file),
                    "--tool", actual, "--started", "<utc>", "--completed", "<utc>",
                    "--runs", str(ns.fuzz_passes),
                ]
            ),
        )
        return

    shutil.rmtree(state, ignore_errors=True)
    artifact_root.mkdir(parents=True)
    corpus_root.mkdir(parents=True)
    statuses: list[str] = []
    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    for target in targets:
        seed = ROOT / "qa/fuzz/seeds" / target
        corpus = corpus_root / target
        artifacts = artifact_root / target
        log = state / f"{target}.log"
        if not seed.is_dir():
            print(f"ERROR: authored fuzz seeds are missing for {target}: {seed}", file=sys.stderr)
            statuses.append(f"{target}\t2\n")
            continue
        corpus.mkdir(parents=True)
        artifacts.mkdir(parents=True)
        for item in seed.iterdir():
            dst = corpus / item.name
            shutil.copytree(item, dst) if item.is_dir() else shutil.copy2(item, dst)
        command = [
            "rustup", "run", os.environ["KASSIGNER_BRANCH_RUST"], "cargo", "fuzz", "run", target,
            "--no-include-main-msvc", "--", f"-runs={ns.fuzz_passes}",
            f"-artifact_prefix={artifacts}{os.sep}", str(corpus),
        ]
        print(f"=== fuzz: {target} ({ns.fuzz_passes} runs) ===")
        print("  +", subprocess.list2cmdline(command))
        with log.open("w", encoding="utf-8") as output:
            fuzz_env = os.environ.copy()
            fuzz_env["CARGO_TARGET_DIR"] = str(ROOT / "target/qa")
            process = subprocess.Popen(
                command, cwd=ROOT / "qa/fuzz", env=fuzz_env, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True, bufsize=1,
            )
            assert process.stdout is not None
            for line in process.stdout:
                output.write(line)
                output.flush()
                print(line, end="")
            status = process.wait()
        statuses.append(f"{target}\t{status}\n")
        if status != 0:
            print(f"FAIL: fuzz target {target} (exit {status})", file=sys.stderr)
    status_file.write_text("".join(statuses), encoding="ascii")
    completed = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    run(
        [
            PYTHON, "qa/checks/security/fuzz_results.py", "--statuses", str(status_file),
            "--tool", actual, "--started", started, "--completed", completed,
            "--runs", str(ns.fuzz_passes),
        ]
    )



def run_core_ci(ns: argparse.Namespace) -> None:
    log_dir = ROOT / "target/qa/core-ci"
    log_path = log_dir / "core-ci.log"
    log_dir.mkdir(parents=True, exist_ok=True)
    stable = os.environ["KASSIGNER_STABLE_RUST"]
    commands = [
        ["rustup", "toolchain", "install", stable, "--profile", "minimal", "--component", "rustfmt", "--component", "clippy"],
        ["rustup", "run", stable, "cargo", "fmt", "--all", "--", "--check"],
        ["rustup", "run", stable, "cargo", "clippy", "--workspace", "--all-targets", "--locked", "--", "-D", "warnings"],
        ["make", "test", "STRICT_LOCKFILES=1"],
        ["git", "diff", "--check"],
    ]
    if ns.dry_run:
        print(f"  + Core CI log: {log_path}")
        for command in commands:
            print("  +", subprocess.list2cmdline(command))
        return

    for required in ("rustup", "cargo", "git", "make"):
        require(required)

    with log_path.open("w", encoding="utf-8", newline="") as output:
        def emit(message: str = "") -> None:
            print(message)
            output.write(message + "\n")
            output.flush()

        def run_logged(command: list[str]) -> int:
            emit("+ " + subprocess.list2cmdline(command))
            process = subprocess.Popen(
                command,
                cwd=ROOT,
                env=os.environ.copy(),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            assert process.stdout is not None
            for line in process.stdout:
                print(line, end="")
                output.write(line)
                output.flush()
            return process.wait()

        def fail(stage: str, status: int) -> None:
            emit()
            emit(f"FAILED: {stage} (exit {status})")
            emit()
            emit(f"Core CI child exit code: {status}")
            emit(f"Full log: {log_path}")
            raise subprocess.CalledProcessError(status, stage)

        emit("===== REPOSITORY =====")
        emit(str(ROOT))
        status = run_logged(["git", "rev-parse", "--show-toplevel"])
        if status != 0:
            fail("repository check", status)
        status = run_logged(["git", "status", "--short"])
        if status != 0:
            fail("repository status", status)
        emit()
        emit(f"KASSIGNER_STABLE_RUST={stable}")
        emit()

        emit("===== INSTALL PINNED CORE TOOLCHAIN =====")
        status = run_logged(commands[0])
        if status != 0:
            fail("toolchain install", status)

        emit()
        emit("===== CORE CI: FORMAT =====")
        status = run_logged(commands[1])
        if status != 0:
            fail("CORE FORMAT", status)

        emit()
        emit("===== CORE CI: CLIPPY =====")
        status = run_logged(commands[2])
        if status != 0:
            fail("CORE CLIPPY", status)

        emit()
        emit("===== CORE CI: TEST =====")
        status = run_logged(commands[3])
        if status != 0:
            fail("CORE TEST", status)

        emit()
        emit("===== FINAL DIFF CHECK =====")
        status = run_logged(commands[4])
        if status != 0:
            fail("git diff --check", status)

        emit()
        emit("================================")
        emit("ALL CORE CI GATES PASSED LOCALLY")
        emit("================================")
        emit()
        emit("Core CI child exit code: 0")
        emit(f"Full log: {log_path}")

def run_step(step_id: str, ns: argparse.Namespace) -> None:
    global STEP_SKIPPED
    STEP_SKIPPED = False
    py=PYTHON
    if step_id=="preflight.kassee-build": run([py,"scripts/common/lib/make_tasks.py","entrypoint","kassee-web-build"],dry=ns.dry_run)
    elif step_id=="preflight.firmware-source-contracts": run([py,"qa/checks/firmware/check_firmware_source_contracts.py"],dry=ns.dry_run)
    elif step_id=="preflight.repository-lockfiles": run([py,"qa/checks/workspace/check_lockfile.py"],dry=ns.dry_run)
    elif step_id=="preflight.crap-check": run([PYTHON,"scripts/common/lib/make_tasks.py","entrypoint","pinned-branch-coverage"],dry=ns.dry_run)
    elif step_id=="preflight.core-ci": run_core_ci(ns)
    elif step_id=="preflight.security-assurance":
        for cmd in [
            [py,"qa/checks/security/security_invariants.py"],
            [py,"qa/checks/security/watcher_only_apps.py"],
            [py,"qa/checks/security/irreversible_action_policy.py"],
            [py,"qa/checks/security/test_quality.py"],
            [py,"qa/checks/security/repository_test_quality.py"],
            [py,"qa/checks/security/security_control_evidence.py"],
        ]: run(cmd,dry=ns.dry_run)
    elif step_id=="preflight.cargo-resolution":
        for directory,manifest in [(ROOT,"Cargo.toml"),(ROOT/"apps/signer-firmware","Cargo.toml"),(ROOT/"apps/kassee-web","Cargo.toml"),(ROOT/"tools","Cargo.toml"),(ROOT/"qa","Cargo.toml")]: reconcile_lock(directory,manifest,ns.repair_lockfiles,ns.dry_run)
    elif step_id=="unit.shared-signer": cargo_test(["--manifest-path","Cargo.toml","-p","shared-signer","--all-features","--locked"],ns)
    elif step_id=="unit.signer-firmware-core": cargo_test(["--manifest-path","Cargo.toml","-p","signer-firmware-core","--all-features","--locked"],ns)
    elif step_id=="unit.offline-signer": cargo_test(["--manifest-path","Cargo.toml","-p","offline-signer","--all-features","--locked"],ns)
    elif step_id=="unit.online-watcher": cargo_test(["--manifest-path","Cargo.toml","-p","online-watcher","--all-features","--locked"],ns)
    elif step_id=="unit.kassee-web": cargo_test(["--manifest-path","apps/kassee-web/Cargo.toml","--lib","--locked"],ns)
    elif step_id=="unit.kassee-ios-core": run([py,"qa/checks/ios/check_ios_architecture.py"],dry=ns.dry_run)
    elif step_id=="unit.kassee-android-core":
        if (command_exists("kotlinc") and command_exists("java")) or ns.dry_run: run([py,"qa/checks/android/run_core_tests.py"],dry=ns.dry_run)
        else:
            STEP_SKIPPED = True
            print("  ~ SKIP: Kotlin/Java toolchain is unavailable; Android core tests cannot run on this host.")
    elif step_id=="unit.signer-firmware":
        run(["cargo","check","--locked","--no-default-features","--features","waveshare,verbose-boot"],cwd=ROOT/"apps/signer-firmware",env={"ESP_HAL_CONFIG_PSRAM_MODE":"octal"},dry=ns.dry_run)
        run(["cargo","check","--locked","--no-default-features","--features","m5stack,verbose-boot"],cwd=ROOT/"apps/signer-firmware",dry=ns.dry_run)
    elif step_id=="unit.external-rqrr": cargo_test(["--manifest-path","external/rqrr-nostd/Cargo.toml","--all-features","--locked"],ns)
    elif step_id=="unit.tools": cargo_test(["--manifest-path","tools/Cargo.toml","--lib","--bins","--locked"],ns)
    elif step_id=="static.qa-orchestration-catalog": run([py,"qa/checks/workspace/check_qa_orchestration.py"],dry=ns.dry_run)
    elif step_id=="unit.repository-python-qa":
        run([py,"-m","unittest","discover","-s","qa/tests/tooling","-p","test_*.py","-v"],dry=ns.dry_run); run([py,"-m","unittest","discover","-s","qa/tests/regression","-p","test_*.py","-v"],dry=ns.dry_run)
    elif step_id=="integration.shared-signer-conformance": cargo_test(["--manifest-path","qa/Cargo.toml","--test","conformance","--locked"],ns)
    elif step_id=="integration.repository-layout": cargo_test(["--manifest-path","qa/Cargo.toml","--test","integration","--locked"],ns)
    elif step_id=="integration.offline-signer-firmware-signing": cargo_test(["--manifest-path","qa/Cargo.toml","--test","tooling_firmware_signing","--locked"],ns)
    elif step_id=="integration.online-watcher-source": run([py,"qa/checks/web/check_web_javascript.py"],dry=ns.dry_run)
    elif step_id=="integration.kassee-web-generated":
        for cmd in [[py,"tools/build/web/build_web_index.py","--check"],[py,"tools/build/web/build_app_css.py","--check"],[py,"tools/build/web/build_constellation_assets.py","--check"],[py,"qa/checks/web/check_web_dom_contract.py"],[py,"qa/checks/web/check_safe_html.py"],["node","--test","qa/checks/web/safe_html_hostile.test.mjs"],["node","qa/checks/web/network_routing.test.mjs"]]: run(cmd,dry=ns.dry_run)
    elif step_id=="integration.kassee-web-browser":
        commands=[["node","qa/checks/web/check_web_runtime.mjs"],["node","qa/checks/web/check_web_covenant_interactions.mjs"],["node","qa/checks/web/covenant_sign_protocol.test.mjs"],["node","qa/checks/web/check_web_critical_paths.mjs"]]
        for cmd in commands: run(cmd,dry=ns.dry_run)
    elif step_id=="integration.kassee-ios-quality":
        run([py,"qa/checks/ios/run_xcode_application_tests.py"],dry=ns.dry_run)
        if command_exists("swift") or ns.dry_run:
            run([py,"qa/checks/ios/swift_crap.py"],dry=ns.dry_run)
        else: print("  ~ SKIP: Swift toolchain is unavailable; iOS CRAP execution cannot run on this host.")
    elif step_id=="integration.kassee-android-gradle": run([py,"scripts/common/lib/make_tasks.py","android","test"],dry=ns.dry_run)
    elif step_id=="integration.kassee-android-quality":
        run([py,"qa/checks/android/check_android_architecture.py"],dry=ns.dry_run)
        run([py,"qa/checks/android/kotlin_crap.py"],dry=ns.dry_run)
        code=run([py,"qa/checks/android/run_instrumentation_tests.py"],dry=ns.dry_run,allowed=(0,77))
        if code==77:
            STEP_SKIPPED = True
            print("  ~ SKIP: connected Android instrumentation requires an attached API-37 device/emulator.")
    elif step_id=="static.firmware-assurance-contracts":
        for script in (
            "qa/checks/firmware/board_partition_contract.py",
            "qa/checks/firmware/m5stack_production_security.py",
            "qa/checks/firmware/production_e2e_coverage.py",
            "qa/checks/firmware/production_runtime_qualification.py",
            "qa/checks/firmware/production_ui_graph.py",
            "qa/checks/firmware/wallet_recovery_contract.py",
        ): run([py,script],dry=ns.dry_run)
    elif step_id=="coverage.critical-branch-targets":
        run([py,"qa/checks/security/branch_ratchets.py"],dry=ns.dry_run); run([py,"qa/checks/security/branch_ratchets.py","--require-target"],dry=ns.dry_run)
    elif step_id=="integration.real-node": run([py,"scripts/common/lib/make_tasks.py","entrypoint","real-node-integration"],dry=ns.dry_run)
    elif step_id=="integration.funded-testnet-e2e":
        code=run([py,"scripts/common/lib/make_tasks.py","entrypoint","funded-testnet-e2e"],dry=ns.dry_run,allowed=(0,77))
        if code==77:
            STEP_SKIPPED = True
            print("  ~ SKIP: funded testnet E2E requires an interactive maintainer terminal.")
    elif step_id=="mutation.kassee-ios":
        code=run([py,"qa/checks/ios/run_mutation_tests.py"],dry=ns.dry_run,allowed=(0,77))
        if code==77:
            STEP_SKIPPED = True
            print("  ~ SKIP: iOS mutation execution requires an eligible macOS/Xcode host.")
    elif step_id=="mutation.kassee-android":
        code=run([py,"qa/checks/android/run_mutation_tests.py"],dry=ns.dry_run,allowed=(0,77))
        if code==77:
            STEP_SKIPPED = True
            print("  ~ SKIP: Android mutation execution requires Gradle plus Android SDK API 37.")
    elif step_id=="mutation.repository-security-fresh": run([py,"qa/checks/security/mutation.py","run","--fresh"],env=mutation_tool_environment(),dry=ns.dry_run)
    elif step_id=="mutation.repository-crypto-certification": run([py,"qa/checks/security/mutation.py","crypto-check"],env=mutation_tool_environment(),dry=ns.dry_run)
    elif step_id=="integration.signer-firmware-builds": run([py,"qa/checks/firmware/check_firmware_builds.py"],dry=ns.dry_run)
    elif step_id=="integration.signer-firmware-lints": run([py,"qa/checks/firmware/check_firmware_lints.py"],dry=ns.dry_run)
    elif step_id=="integration.repository-architecture": run([py,"qa/checks/check_architecture.py"],dry=ns.dry_run)
    elif step_id=="emulation.signer-firmware-qemu": run([py,"scripts/common/lib/make_tasks.py","entrypoint","qemu-test"],dry=ns.dry_run)
    elif step_id=="hardware.signer-firmware-device":
        cmd=[py,"qa/checks/firmware/run_hardware_tests.py","--board",ns.hardware,"--timeout",str(ns.hardware_timeout)]
        if ns.hardware_port: cmd += ["--port",ns.hardware_port]
        run(cmd,dry=ns.dry_run)
    elif step_id=="bench.shared-signer-protocol-throughput": reconcile_lock(ROOT/"qa","Cargo.toml",ns.repair_lockfiles,ns.dry_run); run(["cargo","bench","--manifest-path","qa/Cargo.toml","--bench","protocol_throughput","--locked"],env={"CARGO_TARGET_DIR":str(ROOT/"target/qa")},dry=ns.dry_run)
    elif step_id=="fuzz.repository-security-targets": run_fuzz(ns)
    else: raise RuntimeError(f"unknown catalog step: {step_id}")


def parser() -> argparse.ArgumentParser:
    p=argparse.ArgumentParser(description="Run the complete KasSigner test catalog in a stable, resumable order.")
    p.add_argument("--profile",choices=("full","test"),default="full"); p.add_argument("--list",action="store_true",dest="list_only"); p.add_argument("--resume-from","--from",dest="resume_from",default=""); p.add_argument("--only","--section",dest="only",default="")
    p.add_argument("--category"); p.add_argument("--workspace"); p.add_argument("--test",dest="test_filter",default=""); p.add_argument("--exact",action="store_true")
    p.add_argument("--fuzz-passes",type=int,default=100000); p.add_argument("--fuzz-target",default=""); p.add_argument("--skip-fuzz",action="store_true"); p.add_argument("--skip-qemu",action="store_true")
    p.add_argument("--hardware",choices=("waveshare","waveshare-af","m5stack"),default=""); p.add_argument("--hardware-port",default=""); p.add_argument("--hardware-timeout",type=int,default=240)
    p.add_argument("--dry-run",action="store_true"); p.add_argument("--strict-lockfiles",action="store_false",dest="repair_lockfiles",default=True); p.add_argument("--pause",action="store_true")
    return p


CRAP_RESUME_ARTIFACTS = (
    ROOT / "target/qa/crap/health_summary.json",
    ROOT / "target/qa/crap/lcov.info",
    ROOT / "target/qa/crap/run.json",
    ROOT / "target/qa/crap/cargo_crap.json",
    ROOT / "target/qa/crap/crap_summary.json",
    ROOT / "target/qa/crap/current.json",
)


def ensure_resume_prerequisites(ns: argparse.Namespace, selected: list[tuple[str, str, str, str]]) -> None:
    if not ns.resume_from or ns.profile != "full":
        return
    selected_ids = {record[2] for record in selected}
    if "coverage.critical-branch-targets" not in selected_ids or "preflight.crap-check" in selected_ids:
        return
    missing = [path for path in CRAP_RESUME_ARTIFACTS if not path.is_file() or path.stat().st_size == 0]
    if not missing and not ns.dry_run:
        return
    print("\n[resume prerequisite] Fresh CRAP/coverage artifacts are required by later resumed QA steps.")
    if missing:
        print("  Missing: " + ", ".join(str(path.relative_to(ROOT)) for path in missing))
    print("  Regenerating preflight.crap-check only; already-passed test steps remain skipped.")
    run_step("preflight.crap-check", ns)


def acquire_lock() -> object|None:
    marker=os.environ.get("KASSIGNER_QA_RUN_ALL_LOCK_ROOT")
    if marker and Path(marker).resolve()==ROOT.resolve(): return None
    state=ROOT/"target/qa/state"; state.mkdir(parents=True,exist_ok=True); path=state/"release-workflow.lock"; handle=open(path,"a+b")
    if os.name=="nt":
        import msvcrt
        try: msvcrt.locking(handle.fileno(),msvcrt.LK_NBLCK,1)
        except OSError:
            print("Another KasSigner QA/reproducible-release workflow is active; waiting for it to finish.")
            while True:
                try: msvcrt.locking(handle.fileno(),msvcrt.LK_NBLCK,1); break
                except OSError: time.sleep(0.5)
    os.environ["KASSIGNER_QA_RUN_ALL_LOCK_ROOT"]=str(ROOT)
    return handle


def main(argv: list[str]) -> int:
    clean_cargo_fuzz_source_scratch()
    ns=parser().parse_args(argv)
    if ns.category == "benches": ns.category = "bench"
    if ns.category and ns.category not in CATEGORIES: parser().error(f"unknown category: {ns.category}")
    if ns.workspace:
        if ns.workspace=="kasee-web":ns.workspace="kassee-web"
        if ns.workspace not in WORKSPACES: parser().error(f"unknown workspace: {ns.workspace}")
    if ns.test_filter and "::" in ns.test_filter:
        ws,name=ns.test_filter.split("::",1); ws="kassee-web" if ws=="kasee-web" else ws
        if not name or ws not in WORKSPACES: parser().error("invalid qualified --test")
        if ns.workspace and ns.workspace!=ws: parser().error("--test workspace conflicts with --workspace")
        ns.workspace=ws; ns.test_filter=name
    ns.only=canonical_id(ns.only); ns.resume_from=canonical_id(ns.resume_from)
    if ns.fuzz_passes<=0 or ns.hardware_timeout<=0: parser().error("counts/timeouts must be positive")
    if ns.hardware_port and not ns.hardware: parser().error("--hardware-port requires --hardware BOARD")
    if ns.category=="hardware" and not ns.hardware: parser().error("--category hardware requires --hardware BOARD")
    if ns.only.startswith("hardware.") and not ns.hardware: parser().error("hardware steps require --hardware BOARD")
    if ns.list_only:
        print(f"{'STEP ID':46} {'SCOPE':10} {'WORKSPACE':14} DESCRIPTION"); print(f"{'-------':46} {'-----':10} {'---------':14} -----------")
        for c,w,i,d in STEPS: print(f"{i:46} {STEP_SCOPES[i]:10} {w:14} {d}")
        return 0
    load_toolchains(); os.environ["KASSIGNER_QA_CATALOG_ACTIVE"]="1"; lock=acquire_lock()
    ids=[x[2] for x in STEPS]
    if ns.only and ns.only not in ids: parser().error(f"unknown exact step ID: {ns.only}")
    start=0
    if ns.resume_from:
        for idx,(c,w,i,d) in enumerate(STEPS):
            if i==ns.resume_from or c==ns.resume_from or i.startswith(ns.resume_from): start=idx; break
        else: parser().error(f"unknown resume section: {ns.resume_from}")
    selected=[]
    for rec in STEPS[start:]:
        c,w,i,d=rec
        scope=STEP_SCOPES[i]
        if ns.profile=="test" and scope!="test": continue
        if ns.profile=="full" and scope=="hardware" and ns.category!="hardware" and not ns.hardware: continue
        if ns.profile=="full" and scope not in {"test","qa","hardware"}: continue
        if ns.only and i!=ns.only: continue
        if ns.category and c!=ns.category: continue
        if ns.workspace and w!=ns.workspace: continue
        if ns.test_filter and i not in TEST_FILTER_STEPS: continue
        if c=="hardware" and not ns.hardware: continue
        if c=="fuzz" and ns.skip_fuzz: continue
        if c=="emulation" and ns.skip_qemu: continue
        selected.append(rec)
    if any(record[2] == "preflight.core-ci" for record in selected):
        selected = [record for record in selected if STEP_SCOPES[record[2]] != "test"]
    if not selected: parser().error("the selected filters matched no test steps")
    try:
        ensure_resume_prerequisites(ns, selected)
    except (subprocess.CalledProcessError, RuntimeError) as exc:
        code = exc.returncode if isinstance(exc, subprocess.CalledProcessError) else 1
        print(f"FAIL: resume prerequisite preflight.crap-check (exit {code})", file=sys.stderr)
        return code
    current_c=current_w=""; passed=0; skipped=0
    try:
        for c,w,i,d in selected:
            if c!=current_c:
                current_c=c;current_w=""; heading={"preflight":"PREFLIGHT","static":"STATIC / ARCHITECTURE TESTS","security":"SECURITY POLICY TESTS","coverage":"COVERAGE / CRAP TESTS","interactive":"REAL-NODE / INTERACTIVE E2E TESTS","bench":"BENCHMARKS","mutation":"FRESH MUTATION TESTS","emulation":"QEMU EMULATION TESTS","hardware":"HARDWARE TESTS"}.get(c,c.upper()+" TESTS")
                print("\n"+"="*80+f"\n {heading}\n"+"="*80)
            if w!=current_w: current_w=w;print(f"\n---- {w} ----")
            print(f"\n[{i}] {d}")
            try: run_step(i,ns)
            except (subprocess.CalledProcessError,RuntimeError) as exc:
                code=exc.returncode if isinstance(exc,subprocess.CalledProcessError) else 1
                print(f"FAIL: {i} (exit {code})",file=sys.stderr); return code
            if STEP_SKIPPED:
                skipped+=1; print(f"SKIP: {i}")
            else:
                passed+=1; print(f"PASS: {i}")
        print(f"\nPASS: {passed} passed, {skipped} skipped, {len(selected)} selected test sections completed"); return 0
    finally:
        if lock: lock.close()

if __name__=="__main__":
    status=main(sys.argv[1:])
    if "--pause" in sys.argv[1:]:
        try: input(f"\nTest runner finished with exit code {status}. Press Enter to close this terminal...")
        except EOFError: pass
    raise SystemExit(status)
