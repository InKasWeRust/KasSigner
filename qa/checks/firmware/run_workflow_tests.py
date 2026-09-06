#!/usr/bin/env python3
"""Build, flash, and supervise the opt-in firmware workflow E2E-contract image."""

from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import sys
import tomllib
from contextlib import nullcontext

ROOT = Path(__file__).resolve().parents[3]
FIRMWARE = ROOT / "apps" / "signer-firmware"
TARGET = FIRMWARE / "target" / "xtensa-esp32s3-none-elf" / "release"
HASH_SOURCE = FIRMWARE / "src" / "firmware_hash.rs"
HASH_BUILDER = ROOT / "tools" / "build" / "firmware" / "build_with_hash.sh"
CHECKS_DIR = Path(__file__).resolve().parent
if str(CHECKS_DIR) not in sys.path:
    sys.path.insert(0, str(CHECKS_DIR))

from run_hardware_tests import flash_and_monitor, wait_for_explicit_port  # noqa: E402
from hil_evidence import HilEvidence, reportable_interruptions  # noqa: E402

PASS_MARKER = "KASSIGNER_WORKFLOW_TESTS: PASS ALL"
FAIL_MARKER = "KASSIGNER_WORKFLOW_TESTS: FAIL"
BUILD_LOG = ROOT / "target" / "qa" / "workflow-e2e" / "build.log"
SCENARIOS = ROOT / "qa" / "config" / "workflow" / "production_e2e_scenarios.json"
MANIFEST = ROOT / "qa" / "config" / "workflow" / "production_e2e_manifest.json"
RUNTIME_QUALIFICATION = ROOT / "qa" / "config" / "workflow" / "production_runtime_qualification.json"
LOCKED_SD_ERASE_MARKER = "KASSIGNER_WORKFLOW_TESTS: SD MEDIA QA CARD-LOCK FORCE ERASE BEGIN - DESTRUCTIVE"
LOCKED_SD_RECOVERY_WINDOW_SECONDS = 720
CONNECTED_TRANCHE_DEADLINE_MARKER = "KASSIGNER_WORKFLOW_TESTS: CONNECTED TRANCHE DEADLINE REFRESH"
CONNECTED_TRANCHE_WINDOW_SECONDS = 480
RUNTIME_ACTION_START_PREFIX = "KASSIGNER_WORKFLOW_RUNTIME: ACTION BEGIN "
RUNTIME_ACTION_END_PREFIX = "KASSIGNER_WORKFLOW_RUNTIME: ACTION PASS "
RUNTIME_ACTION_WINDOW_SECONDS = 25
RUNTIME_COOPERATIVE_ACTION_WINDOW_SECONDS = 75
RUNTIME_ACTION_TIMEOUTS = {
    "receive-change-real-derivation": RUNTIME_COOPERATIVE_ACTION_WINDOW_SECONDS,
    "connect-kassee-real-derivation": RUNTIME_COOPERATIVE_ACTION_WINDOW_SECONDS,
    "multisig-kpub-real-derivation": RUNTIME_COOPERATIVE_ACTION_WINDOW_SECONDS,
    "persistent-pin-storage-round-trip": 150,
}
PIN_FLOW_ORDERED_MARKERS = (
    "KASSIGNER_PIN_FLOW: PIN SUBMIT unlock pin",
    "KASSIGNER_PIN_FLOW: LOADING COMMITTED unlock pin",
    "KASSIGNER_PIN_FLOW: LOADING RENDERED unlock pin",
    "KASSIGNER_PIN_FLOW: KDF BEGIN unlock pin",
    "KASSIGNER_PIN_FLOW: KDF DONE unlock pin ok=true",
    "KASSIGNER_PIN_FLOW: RESULT COMMITTED unlock pin success MainMenu",
)
RUNTIME_ACTIONS = (
    "view-words-render",
    "firmware-update-guidance-render",
    "scan-qr-camera",
    "pop-it-prompt-render",
    "receive-change-real-derivation",
    "connect-kassee-real-derivation",
    "multisig-kpub-real-derivation",
    "pin-unlock-loading-order",
    "persistent-pin-storage-round-trip",
    "recoverable-operation-timeout",
    "argon2-persistent-wallet-kdf",
)
CONNECTED_TRANCHES = (
    "ROOT", "REMAINING", "ONBOARDING", "SIGNING", "QR-PROTOCOL",
    "SD-WORKFLOWS", "MULTISIG", "STEGO", "SECURITY-POLICIES", "ADVANCED-TOOLS",
    "RECEIVE",
)
WORKFLOW_FAILURE_CONTEXT_PREFIXES = (
    "KASSIGNER_WORKFLOW_TESTS: CONNECTED BUILD PACKAGE ",
    "KASSIGNER_WORKFLOW_TESTS: CONNECTED MULTISIG FAILURE SNAPSHOT ",
    "KASSIGNER_WORKFLOW_TESTS: CONNECTED FAILED MULTISIG PROBE ",
    "KASSIGNER_WORKFLOW_TESTS: CONNECTED FAILED MULTISIG OUTPUT STAGE ",
    "KASSIGNER_WORKFLOW_TESTS: CONNECTED FAILED MULTISIG SIGN STAGE ",
)

RESUME_ALIASES = {
    "root": 1,
    "remaining": 2,
    "onboarding": 3,
    "signing": 4,
    "qr": 5, "qr-protocol": 5, "qr_protocol": 5,
    "sd": 6, "sd-workflows": 6, "sd_workflows": 6,
    "multisig": 7,
    "stego": 8,
    "security": 9, "security-policies": 9, "security_policies": 9,
    "advanced": 10, "advanced-tools": 10, "advanced_tools": 10,
    "receive": 11,
}

XTENSA_LINKER = "xtensa-esp32s3-elf-gcc"
TOOLCHAINS = ROOT / "qa" / "config" / "toolchains.env"



def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Validate workflow/navigation regression contracts, then flash and supervise "
            "the connected device navigation gate."
        )
    )
    parser.add_argument("--board", required=True, choices=("waveshare", "waveshare-af", "m5stack"))
    parser.add_argument("--port", help="Serial port; omit for safe auto-selection when unambiguous")
    parser.add_argument("--hil", action="store_true", help="CoreS3: initialize real SD/audio/entropy/camera peripherals before connected scenarios")
    parser.add_argument("--timeout", type=int, default=480, help="Monitor timeout in seconds")
    parser.add_argument("--resume-from", "--from", default="1", metavar="TRANCHE", help=f"Connected tranche number/name to start from (1-{len(CONNECTED_TRANCHES)}; e.g. 7 or multisig)")
    args = parser.parse_args()
    if args.timeout < 1:
        parser.error("--timeout must be positive")
    if args.hil and args.board != "m5stack":
        parser.error("--hil is currently supported only for M5Stack CoreS3")
    try:
        args.resume_from = parse_resume_from(args.resume_from)
    except ValueError as error:
        parser.error(str(error))
    return args


def require_tool(name: str, env: dict[str, str] | None = None) -> str:
    path = shutil.which(name, path=(env or os.environ).get("PATH"))
    if path is None:
        raise RuntimeError(f"required command not found: {name}")
    return path


def pinned_toolchain_value(name: str) -> str:
    if not TOOLCHAINS.is_file():
        raise RuntimeError(f"toolchain policy missing: {TOOLCHAINS}")
    for raw in TOOLCHAINS.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key.strip() == name:
            return value.strip().strip('"').strip("'")
    raise RuntimeError(f"toolchain policy missing {name}: {TOOLCHAINS}")


def _source_posix_environment(base_env: dict[str, str]) -> tuple[dict[str, str], tuple[Path, ...]]:
    """Load user-local cargo/espup exports without requiring the parent shell to source them."""
    if os.name == "nt":
        return base_env.copy(), ()
    bash = shutil.which("bash", path=base_env.get("PATH"))
    if bash is None:
        raise RuntimeError("required command not found: bash")
    home = Path(base_env.get("HOME", str(Path.home()))).expanduser()
    cargo_home = Path(base_env.get("CARGO_HOME", str(home / ".cargo"))).expanduser()
    candidates = (cargo_home / "env", home / "export-esp.sh", home / ".espup" / "export-esp.sh")
    readable = tuple(path for path in candidates if path.is_file() and os.access(path, os.R_OK))
    if not readable:
        return base_env.copy(), ()
    script = "set -a; " + " ".join(f'. {json.dumps(str(path))};' for path in readable) + " env -0"
    result = subprocess.run(
        [bash, "-c", script],
        cwd=ROOT,
        env=base_env,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"failed to load ESP toolchain environment: {detail or 'bash exited nonzero'}")
    env = base_env.copy()
    for item in result.stdout.split(b"\0"):
        if not item or b"=" not in item:
            continue
        key, value = item.split(b"=", 1)
        env[key.decode("utf-8", errors="surrogateescape")] = value.decode("utf-8", errors="surrogateescape")
    return env, readable


def _discover_xtensa_linker(env: dict[str, str]) -> Path | None:
    direct = shutil.which(XTENSA_LINKER, path=env.get("PATH"))
    if direct:
        return Path(direct)
    home = Path(env.get("HOME", str(Path.home()))).expanduser()
    rustup_home = Path(env.get("RUSTUP_HOME", str(home / ".rustup"))).expanduser()
    roots = (
        rustup_home / "toolchains" / "esp" / "xtensa-esp-elf",
        home / ".espressif" / "tools" / "xtensa-esp-elf",
        home / ".espressif" / "tools" / "xtensa-esp32s3-elf",
    )
    for root in roots:
        if not root.is_dir():
            continue
        for candidate in root.glob(f"**/bin/{XTENSA_LINKER}"):
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return candidate
    return None


def prepare_esp_build_environment() -> dict[str, str]:
    """Return a build env with the installed ESP Rust/GCC tools made discoverable."""
    env, sourced = _source_posix_environment(os.environ.copy())
    cargo = require_tool("cargo", env)
    require_tool("espflash", env)
    rust_probe = subprocess.run(
        [cargo, "--version"],
        cwd=FIRMWARE,
        env=env,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if rust_probe.returncode != 0:
        version = pinned_toolchain_value("KASSIGNER_ESP_RUST")
        espup_version = pinned_toolchain_value("KASSIGNER_ESPUP_VERSION")
        raise RuntimeError(
            "ESP Rust toolchain selected by apps/signer-firmware/rust-toolchain.toml is unavailable.\n"
            f"Repair it with: cargo install espup --version {espup_version} --locked --force && "
            f"espup install --toolchain-version {version} --targets esp32s3 --export-file $HOME/export-esp.sh"
        )
    linker = _discover_xtensa_linker(env)
    if linker is not None:
        linker_dir = str(linker.parent)
        path_entries = env.get("PATH", "").split(os.pathsep)
        if linker_dir not in path_entries:
            env["PATH"] = linker_dir + os.pathsep + env.get("PATH", "")
        if sourced:
            print("  ESP environment: " + ", ".join(str(path) for path in sourced), flush=True)
        print(f"  Xtensa linker: {linker}", flush=True)
        return env

    version = pinned_toolchain_value("KASSIGNER_ESP_RUST")
    espup_version = pinned_toolchain_value("KASSIGNER_ESPUP_VERSION")
    export_file = Path(env.get("HOME", str(Path.home()))).expanduser() / "export-esp.sh"
    raise RuntimeError(
        f"required ESP32-S3 linker not found: {XTENSA_LINKER}\n"
        "Install/repair the repository-pinned no_std ESP toolchain, then rerun the same command:\n"
        f"  cargo install espup --version {espup_version} --locked --force\n"
        f"  espup install --toolchain-version {version} --targets esp32s3 --export-file {export_file}\n"
        f"  source {export_file}\n"
        "Do not use espup --std: that mode intentionally skips GCC and cannot build this firmware."
    )


def parse_resume_from(value: str) -> int:
    normalized = value.strip().lower()
    if normalized.isdigit():
        index = int(normalized)
        if 1 <= index <= len(CONNECTED_TRANCHES):
            return index
    alias = RESUME_ALIASES.get(normalized)
    if alias is not None:
        return alias
    choices = ", ".join(name.lower() for name in CONNECTED_TRANCHES)
    raise ValueError(f"--resume-from must be 1-{len(CONNECTED_TRANCHES)} or one of: {choices}")


def required_connected_markers(*, include_hil_only: bool = False) -> tuple[str, ...]:
    document = json.loads(SCENARIOS.read_text(encoding="utf-8"))
    markers: set[str] = set()
    for scenario in document.get("scenarios", []):
        if scenario.get("status") != "implemented" or scenario.get("level") != "connected":
            continue
        scenario_markers = set(scenario.get("serial_markers", []))
        if not include_hil_only:
            scenario_markers.difference_update(scenario.get("hil_only_serial_markers", []))
        markers.update(scenario_markers)
    if not markers:
        raise RuntimeError("connected workflow scenario registry contains no runtime evidence markers")
    return tuple(sorted(markers))


def firmware_package_version() -> str:
    manifest = tomllib.loads((FIRMWARE / "Cargo.toml").read_text(encoding="utf-8"))
    return manifest["package"]["version"]


def expected_connected_build_marker() -> str:
    return f"KASSIGNER_WORKFLOW_TESTS: CONNECTED BUILD PACKAGE {firmware_package_version()}"

def required_runtime_evidence_markers(
    resume_from: int, board: str | None = None, *, hil: bool = False
) -> tuple[str, ...]:
    runtime_gui = (
        tuple(f"{RUNTIME_ACTION_END_PREFIX}{name}" for name in RUNTIME_ACTIONS)
        if board == "m5stack" else ()
    )
    pin_flow = PIN_FLOW_ORDERED_MARKERS if board == "m5stack" else ()
    return (
        expected_connected_build_marker(),
        *runtime_gui,
        *pin_flow,
        *required_runtime_markers(resume_from, hil=hil),
    )


def required_runtime_markers(resume_from: int, *, hil: bool = False) -> tuple[str, ...]:
    if resume_from == 1:
        return required_connected_markers(include_hil_only=hil)
    return tuple(
        f"KASSIGNER_WORKFLOW_TESTS: CONNECTED TRANCHE {index}/{len(CONNECTED_TRANCHES)} {CONNECTED_TRANCHES[index - 1]} PASS"
        for index in range(resume_from, len(CONNECTED_TRANCHES) + 1)
    )


def required_physical_render_states(resume_from: int, board: str) -> tuple[str, ...]:
    if board != "m5stack" or resume_from != 1:
        return ()
    document = json.loads(RUNTIME_QUALIFICATION.read_text(encoding="utf-8"))
    states = tuple(document.get("workflow_e2e_physical_render_states", ()))
    if not states:
        raise RuntimeError("production runtime qualification contains no workflow-e2e physical render states")
    return states


def print_coverage_status() -> None:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    summary = manifest["item_coverage_summary"]
    scenarios = manifest.get("scenarios", [])
    connected_scenarios = sum(
        1
        for scenario in scenarios
        if scenario.get("status") == "implemented" and scenario.get("level") == "connected"
    )
    print(
        "  Production E2E inventory: "
        f"items={summary['total']} connected={summary['connected']} hil={summary['hil']} "
        f"qa={summary['qa']} backlog={summary['backlog']}; "
        f"implemented connected scenarios={connected_scenarios}",
        flush=True,
    )
    if summary["backlog"]:
        print(
            "  NOTE: workflow-e2e executes every currently implemented connected scenario; "
            "remaining backlog is not silently credited as tested.",
            flush=True,
        )
    else:
        print(
            "  NOTE: production E2E inventory has zero static backlog; runtime evidence is still required "
            "for every registered connected scenario.",
            flush=True,
        )


def validate_host_contracts() -> None:
    """Fail before flashing unless workflow catalog/navigation contracts are green."""
    print("[workflow-e2e 1/4] Validating host workflow/navigation contracts...", flush=True)
    print_coverage_status()
    qualification = ROOT / "qa" / "checks" / "firmware" / "production_runtime_qualification.py"
    subprocess.run([sys.executable, str(qualification)], cwd=ROOT, check=True)
    tests = [
        ROOT / "qa" / "tests" / "tooling" / "test_hardware_device_runner.py",
        ROOT / "qa" / "tests" / "tooling" / "test_firmware_board_layout.py",
    ]
    regression_dir = ROOT / "qa" / "tests" / "regression"
    registered = {path.resolve() for path in tests}
    for path in sorted(regression_dir.glob("test_*.py")):
        if path.resolve() not in registered:
            tests.append(path)
            registered.add(path.resolve())
    print(
        f"  Pre-flash regression coverage: {len(tests)} test module(s) "
        "(all qa/tests/regression modules plus hardware/board tooling contracts)",
        flush=True,
    )
    command = [sys.executable, "-m", "unittest", *(str(path) for path in tests)]
    print("  +", " ".join(command), flush=True)
    subprocess.run(command, cwd=ROOT, check=True)



def run_logged_build(
    command: list[str], env: dict[str, str], evidence_build_log: Path | None = None
) -> tuple[int, list[str]]:
    """Stream build output and preserve both transient and durable HIL logs."""
    warning_headers: list[str] = []
    suppress_warning = False
    BUILD_LOG.parent.mkdir(parents=True, exist_ok=True)
    if evidence_build_log is not None:
        evidence_build_log.parent.mkdir(parents=True, exist_ok=True)
    durable_context = (
        evidence_build_log.open("w", encoding="utf-8")
        if evidence_build_log is not None and evidence_build_log != BUILD_LOG
        else nullcontext(None)
    )
    with BUILD_LOG.open("w", encoding="utf-8") as log_file, durable_context as durable_log:
        process = subprocess.Popen(
            command,
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        assert process.stdout is not None
        try:
            for line in process.stdout:
                log_file.write(line)
                log_file.flush()
                if durable_log is not None:
                    durable_log.write(line)
                    durable_log.flush()
                if line.startswith("error"):
                    suppress_warning = False
                    print(line, end="", flush=True)
                    continue
                if line.startswith("warning:"):
                    suppress_warning = True
                    stripped = line.strip()
                    if not re.match(r"^warning: .+ generated \d+ warnings?$", stripped):
                        warning_headers.append(stripped)
                    continue
                if suppress_warning:
                    if not line.strip():
                        suppress_warning = False
                    continue
                print(line, end="", flush=True)
            return process.wait(), warning_headers
        except KeyboardInterrupt:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
            raise
        finally:
            process.stdout.close()


def print_compiler_error_summary() -> None:
    """Repeat compiler error blocks at the terminal tail after a failed build."""
    try:
        lines = BUILD_LOG.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return
    error_indexes = [index for index, line in enumerate(lines) if line.startswith("error")]
    if not error_indexes:
        print(f"  No explicit compiler error block was found; inspect {BUILD_LOG}", file=sys.stderr)
        return
    print("\n[workflow-e2e] Compiler error summary:", file=sys.stderr)
    for index in error_indexes[:16]:
        end = index + 1
        while end < len(lines) and lines[end].strip():
            end += 1
        for line in lines[index:end]:
            print(line, file=sys.stderr)
        print(file=sys.stderr)

def build(
    board: str,
    hil: bool = False,
    resume_from: int = 1,
    build_env: dict[str, str] | None = None,
    evidence_build_log: Path | None = None,
) -> Path:
    profile = "workflow-hil-auto" if hil else ("workflow-runtime-auto" if board == "m5stack" else "workflow-test-auto")
    print(f"[workflow-e2e 2/4] Building {board} {profile} firmware...", flush=True)
    env = (build_env or os.environ).copy()
    # Workflow runtime now passes through the exact development firmware
    # verification stage used by `make flash`; sign it with the same public
    # repository TEST key rather than bypassing verification.
    env["KASSIGNER_SIGNING_KEY"] = str(ROOT / "tools" / "build" / "firmware" / "dev_test_signing_key.bin")
    env["KASSIGNER_WORKFLOW_E2E_FROM"] = str(resume_from)
    if board in ("waveshare", "waveshare-af"):
        env.setdefault("ESP_HAL_CONFIG_PSRAM_MODE", "octal")
    feature = "waveshare,ov5640-af" if board == "waveshare-af" else board
    original_hash_source = HASH_SOURCE.read_bytes()
    command = [
        str(HASH_BUILDER),
        "--board",
        board,
        f"{board}-workflow-tests",
        "--no-default-features",
        "--features",
        f"{feature},{profile}",
    ]
    print("  +", " ".join(command), flush=True)
    print(f"  Full compiler log: {BUILD_LOG}", flush=True)
    try:
        returncode, warning_headers = run_logged_build(command, env, evidence_build_log)
        if warning_headers:
            unique_warnings = list(dict.fromkeys(warning_headers))
            print(
                f"ERROR: workflow firmware produced {len(unique_warnings)} unique compiler warning(s) "
                f"across {len(warning_headers)} convergence occurrence(s); warnings are release-blocking "
                f"(see {BUILD_LOG})",
                file=sys.stderr,
            )
            print("[workflow-e2e] Compiler warning summary:", file=sys.stderr)
            for warning in unique_warnings:
                print(f"  {warning}", file=sys.stderr)
            if returncode == 0:
                raise subprocess.CalledProcessError(1, command)
        if returncode != 0:
            print_compiler_error_summary()
            print(f"ERROR: workflow firmware build failed; complete log: {BUILD_LOG}", file=sys.stderr)
            raise subprocess.CalledProcessError(returncode, command)
    finally:
        HASH_SOURCE.write_bytes(original_hash_source)
    image = TARGET / "kassigner-firmware"
    if not image.is_file():
        raise RuntimeError(f"firmware ELF was not produced: {image}")
    return image


@reportable_interruptions()
def main() -> int:
    args = parse_args()
    profile = "workflow-hil-auto" if args.hil else (
        "workflow-runtime-auto" if args.board == "m5stack" else "workflow-test-auto"
    )
    evidence = (
        HilEvidence(
            kind="workflow",
            board=args.board,
            port=args.port,
            timeout_seconds=args.timeout,
            profile=profile,
            include_build_log=True,
        )
        if args.hil
        else None
    )
    code = 1
    error_text: str | None = None
    try:
        if evidence is not None:
            evidence.set_phase("host-contracts")
            evidence.update_details(resume_from=args.resume_from, hil=True)
        print("[workflow-e2e 0/4] Preparing ESP build environment...", flush=True)
        build_env = prepare_esp_build_environment()
        validate_host_contracts()
        if evidence is not None:
            evidence.set_phase("firmware-build")
        image = build(
            args.board,
            args.hil,
            args.resume_from,
            build_env,
            evidence.build_log if evidence is not None else None,
        )
        if evidence is not None:
            evidence.bind_firmware(image)
        port_label = args.port or "auto-detect / espflash prompt"
        if args.resume_from > 1:
            print(
                f"  Resume mode: connected tranche {args.resume_from}/{len(CONNECTED_TRANCHES)} "
                f"{CONNECTED_TRANCHES[args.resume_from - 1]}; earlier connected tranches will be skipped.",
                flush=True,
            )
        print(f"[workflow-e2e 3/4] Flashing test image (port: {port_label})...", flush=True)
        wait_for_explicit_port(args.port)
        print(
            "[workflow-e2e 4/4] Monitoring device. Host catalog/navigation contracts are green; "
            + (
                "M5Stack runtime E2E now exercises real LCD/audio/entropy/camera initialization and redraw paths; "
                "destructive SD-media operations remain reserved for workflow-hil."
                if args.board == "m5stack" and not args.hil
                else "connected E2E exercises the selected board profile; destructive HIL remains explicit."
            ),
            flush=True,
        )
        runtime_markers = required_runtime_evidence_markers(
            args.resume_from, args.board, hil=args.hil
        )
        physical_states = required_physical_render_states(args.resume_from, args.board)
        print(
            f"  Runtime evidence gate: requiring {len(runtime_markers)} connected marker(s) before PASS ALL"
            + (" (resume-scoped)" if args.resume_from > 1 else ""),
            flush=True,
        )
        if physical_states:
            print(
                f"  Physical render gate: requiring {len(physical_states)} declared workflow-e2e physical render states",
                flush=True,
            )
        elif args.board == "m5stack" and args.resume_from > 1:
            print(
                "  Physical render gate: physical-render qualification disabled for resumed run; use RESUME_FROM=1 for release qualification",
                flush=True,
            )
        if evidence is not None:
            evidence.set_phase("flash-and-uart")
            evidence.update_details(
                required_runtime_markers=list(runtime_markers),
                ordered_markers=list(PIN_FLOW_ORDERED_MARKERS if args.board == "m5stack" else ()),
                required_physical_render_states=list(physical_states),
            )
        uart_context = evidence.open_uart() if evidence is not None else nullcontext(None)
        with uart_context as uart_log:
            code = flash_and_monitor(
                args.board,
                image,
                args.port,
                args.timeout,
                pass_marker=PASS_MARKER,
                fail_marker=FAIL_MARKER,
                success_label="workflow E2E contracts",
                status_interval=10,
                repeat_abort_marker="KASSIGNER_WORKFLOW_TESTS: BEGIN",
                repeat_abort_arm_marker="KASSIGNER_WORKFLOW_TESTS: PREBOARD GATE COMPLETE",
                phase_start_marker="BOOT PHASE startup-ui DONE:",
                phase_end_marker="KASSIGNER_WORKFLOW_TESTS: CONNECTED GATE BEGIN",
                phase_timeout=15 if not args.hil else 45,
                deadline_extension_marker=(
                    LOCKED_SD_ERASE_MARKER if args.hil else CONNECTED_TRANCHE_DEADLINE_MARKER
                ),
                deadline_extension_seconds=(
                    LOCKED_SD_RECOVERY_WINDOW_SECONDS
                    if args.hil
                    else CONNECTED_TRANCHE_WINDOW_SECONDS
                ),
                required_markers=runtime_markers,
                ordered_markers=PIN_FLOW_ORDERED_MARKERS if args.board == "m5stack" else None,
                failure_context_prefixes=WORKFLOW_FAILURE_CONTEXT_PREFIXES,
                operation_start_prefix=RUNTIME_ACTION_START_PREFIX if args.board == "m5stack" else None,
                operation_end_prefix=RUNTIME_ACTION_END_PREFIX if args.board == "m5stack" else None,
                operation_timeout=RUNTIME_ACTION_WINDOW_SECONDS if args.board == "m5stack" else None,
                operation_timeouts=RUNTIME_ACTION_TIMEOUTS if args.board == "m5stack" else None,
                runtime_state_prefix="KASSIGNER_UI_RUNTIME: RENDER " if args.board == "m5stack" else None,
                required_runtime_states=physical_states or None,
                uart_log=uart_log,
            )
        if evidence is not None:
            evidence.set_phase("complete" if code == 0 else "flash-and-uart")
    except subprocess.CalledProcessError as error:
        code = error.returncode or 1
        error_text = f"command failed: {error.cmd}"
    except (OSError, RuntimeError) as error:
        code = 1
        error_text = str(error)
        print(f"ERROR: {error}", file=sys.stderr)
    except KeyboardInterrupt:
        code = 130
        error_text = "workflow HIL interrupted" if args.hil else "workflow tests interrupted"
        print("\nWorkflow tests interrupted.", file=sys.stderr)
    finally:
        if evidence is not None:
            evidence.finalize(code, error=error_text)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
