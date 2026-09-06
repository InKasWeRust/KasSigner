#!/usr/bin/env python3
"""Cross-platform helpers for GNU Make recipes.

Keep shell-specific syntax out of Makefile so the same targets run under
Windows cmd.exe/PowerShell-backed GNU Make and under POSIX shells.
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path
LIB_DIR = Path(__file__).resolve().parent
if str(LIB_DIR) not in sys.path:
    sys.path.insert(0, str(LIB_DIR))

from esp_toolchain import prepare_esp_build_environment
from serial_access import SerialAccessError, prepare_serial_command
from make_public import release_build, run_all_profile, test_hardware
from make_clean import clean_workspace
from make_firmware_profiles import owner_firmware_profile, secure_release_profile
ROOT = Path(__file__).resolve().parents[3]
IS_WINDOWS = os.name == "nt" or sys.platform.startswith("win")
IS_MACOS = sys.platform == "darwin"
DEFAULT_SCRIPT_ROOT = ROOT / "scripts" / ("windows" if IS_WINDOWS else "linux")
MAC_SCRIPT_ROOT = ROOT / "scripts" / "mac"
MAC_NATIVE_ENTRYPOINTS = {"ios-runtime-sync", "ios-build"}
ENTRYPOINTS = {
    "run-all": "quality/run-all",
    "funded-testnet-e2e": "quality/funded-testnet-e2e",
    "pinned-branch-coverage": "quality/pinned-branch-coverage",
    "production-hardening": "quality/production-hardening",
    "real-node-integration": "quality/real-node-integration",
    "release-readiness": "quality/release-readiness",
    "security-fuzz": "quality/security-fuzz",
    "software-assurance": "quality/software-assurance",
    "kassee-web-build": "build/kassee-web-build",
    "sdk-build": "build/sdk-build",
    "android-studio": "build/android-studio",
    "android-build": "build/android-build",
    "android-runtime-sync": "build/android-runtime-sync",
    "ios-runtime-sync": "build/ios-runtime-sync",
    "ios-build": "build/ios-build",
    "reproducible-build": "build/reproducible-build",
    "crap": "quality/crap",
    "branch-coverage-setup": "quality/branch-coverage-setup",
    "qemu-setup": "qemu/setup",
    "qemu-build": "qemu/build",
    "qemu-test": "qemu/test",
    "qemu-run": "qemu/run",
    "firmware-build": "build/firmware-build",
    "firmware-build-production": "build/firmware-build-production",
    "firmware-owner-build": "build/firmware-owner-build",
    "firmware-qemu-build": "qemu/firmware-build",
}
def run(command: list[str], *, cwd: Path = ROOT, env: dict[str, str] | None = None) -> int:
    print("+", subprocess.list2cmdline(command), flush=True)
    return subprocess.run(command, cwd=cwd, env=env).returncode


def require_success(rc: int) -> None:
    if rc != 0:
        raise SystemExit(rc)


def platform(entry: str, args: list[str] | None = None, *, env: dict[str, str] | None = None) -> int:
    relative = ENTRYPOINTS.get(entry)
    if relative is None:
        print(f"ERROR: unknown KasSigner script entrypoint: {entry}", file=sys.stderr)
        return 2
    suffix = ".ps1" if IS_WINDOWS else ".sh"
    script_root = MAC_SCRIPT_ROOT if IS_MACOS and entry in MAC_NATIVE_ENTRYPOINTS else DEFAULT_SCRIPT_ROOT
    target = script_root / f"{relative}{suffix}"
    if not target.is_file():
        print(f"ERROR: native platform script is missing: {target}", file=sys.stderr)
        return 2
    if IS_WINDOWS:
        shell = next((shutil.which(name) for name in ("pwsh.exe", "pwsh", "powershell.exe", "powershell") if shutil.which(name)), None)
        if not shell:
            print("ERROR: PowerShell is required for native Windows KasSigner scripts.", file=sys.stderr)
            return 127
        command = [shell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(target), *(args or [])]
    else:
        bash = shutil.which("bash")
        if not bash:
            print("ERROR: bash is required for native POSIX KasSigner scripts.", file=sys.stderr)
            return 127
        command = [bash, str(target), *(args or [])]
    return run(command, env=env)


def build_firmware(board: str) -> tuple[int, Path | None]:
    try:
        env = prepare_esp_build_environment(is_windows=IS_WINDOWS)
    except RuntimeError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1, None
    # Development images are always signed with a repository-public TEST key so
    # the same fail-closed software-verification path is exercised on hardware.
    # Production build entrypoints require the separate operator-supplied key.
    env["KASSIGNER_SIGNING_KEY"] = str(ROOT / "tools/build/firmware/dev_test_signing_key.bin")
    if board == "waveshare":
        env["ESP_HAL_CONFIG_PSRAM_MODE"] = "octal"
        features = "waveshare,workflow-tests,argon2-bench"
    elif board == "m5stack":
        features = "m5stack,workflow-tests,argon2-bench"
    else:
        print(f"ERROR: unsupported development firmware board: {board}", file=sys.stderr)
        return 2, None
    hash_source = ROOT / "apps/signer-firmware/src/firmware_hash.rs"
    original_hash_source = hash_source.read_bytes()
    if IS_WINDOWS:
        build_args = [
            f"{board}-development", "-Board", board,
            "--no-default-features", "--features", features,
        ]
    else:
        build_args = [
            "--board", board, f"{board}-development",
            "--no-default-features", "--features", features,
        ]
    try:
        rc = platform("firmware-build", build_args, env=env)
    finally:
        hash_source.write_bytes(original_hash_source)
    if rc != 0:
        return rc, None
    elf = ROOT / "apps/signer-firmware/target/xtensa-esp32s3-none-elf/release/kassigner-firmware"
    if not elf.is_file():
        print(f"ERROR: firmware ELF was not produced: {elf}", file=sys.stderr)
        return 1, None
    return 0, elf


def secure_release(mode: str, output_dir: str, secure_boot_key: str, signing_key: str) -> int:
    return secure_release_profile(
        ROOT, IS_WINDOWS, run, mode, output_dir, secure_boot_key, signing_key
    )


def owner_firmware(output_dir: str, owner_key: str) -> int:
    return owner_firmware_profile(ROOT, IS_WINDOWS, platform, output_dir, owner_key)


def firmware(board: str) -> int:
    if board == "mirror":
        try:
            env = prepare_esp_build_environment(is_windows=IS_WINDOWS)
        except RuntimeError as error:
            print(f"ERROR: {error}", file=sys.stderr)
            return 1
        env["ESP_HAL_CONFIG_PSRAM_MODE"] = "octal"
        return run(["cargo", "run", "--locked", "--release", "--features", "waveshare,mirror"],
                   cwd=ROOT / "apps/signer-firmware", env=env)
    rc, elf = build_firmware(board)
    if rc == 0 and elf is not None:
        print(f"Built {board} development firmware with on-device E2E menu: {elf}")
        print("Build only: no device was flashed. Use `make flash BOARD=%s PORT=...` to flash." % board)
    return rc


def flash_firmware(board: str, port: str) -> int:
    rc, elf = build_firmware(board)
    if rc != 0 or elf is None:
        return rc or 1
    board_helper = str(ROOT / "tools/build/firmware/board_layout.py")
    connection = subprocess.run(
        [sys.executable, board_helper, "connection-args", "--board", board],
        cwd=ROOT, check=False, text=True, stdout=subprocess.PIPE,
    )
    if connection.returncode != 0:
        return connection.returncode
    layout = subprocess.run(
        [sys.executable, board_helper, "espflash-args", "--board", board],
        cwd=ROOT, check=False, text=True, stdout=subprocess.PIPE,
    )
    if layout.returncode != 0:
        return layout.returncode
    command = ["espflash", "flash", "--monitor", *[line for line in connection.stdout.splitlines() if line], *[line for line in layout.stdout.splitlines() if line]]
    selected_port = port.strip() or None
    if selected_port:
        command.extend(["--port", selected_port])
    command.append(str(elf))
    try:
        command = prepare_serial_command(command, selected_port)
    except SerialAccessError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("Flash will remain in the interactive UART monitor; press CTRL+C to exit.", flush=True)
    rc = run(command)
    # espflash/crossterm may report the user's CTRL+C as SIGINT (130) even
    # though flashing and monitoring completed normally. Treat that explicit
    # operator exit as success for the human-facing Make target.
    if rc == 130:
        print("Serial monitor closed by user after successful flash.")
        return 0
    return rc


def flash_release(board: str, port: str, release_dir: str) -> int:
    """Flash an existing checksum-verified signed normal-release image only."""
    names = {"m5stack": "kassigner-m5stack-full.bin", "waveshare": "kassigner-waveshare-full.bin"}
    base = Path(release_dir).expanduser()
    if not base.is_absolute(): base = ROOT / base
    image = base / names[board]
    guidance = "ERROR: first run make release SIGNING_KEY=/path/to/signing-key"
    if not image.is_file() or image.stat().st_size == 0:
        print(f"ERROR: signed merged release image is missing: {image}", file=sys.stderr)
        print(guidance, file=sys.stderr)
        return 2
    sums = base / "SHA256SUMS"
    if not sums.is_file():
        print(f"ERROR: release checksum manifest is missing: {sums}", file=sys.stderr)
        print(guidance, file=sys.stderr)
        return 2
    import hashlib
    expected = next((parts[0].lower() for line in sums.read_text(encoding="utf-8").splitlines()
                     if len(parts := line.split(maxsplit=1)) == 2
                     and parts[1].lstrip("*").strip() == image.name), None)
    if expected is None or len(expected) != 64:
        print(f"ERROR: {image.name} is not recorded in {sums}", file=sys.stderr)
        return 2
    if hashlib.sha256(image.read_bytes()).hexdigest() != expected:
        print(f"ERROR: signed merged release image checksum mismatch: {image}", file=sys.stderr)
        return 2
    helper = str(ROOT / "tools/build/firmware/board_layout.py")
    connection = subprocess.run([sys.executable, helper, "connection-args", "--board", board],
                                cwd=ROOT, check=False, text=True, stdout=subprocess.PIPE)
    if connection.returncode != 0: return connection.returncode
    command = ["espflash", "write-bin", *filter(None, connection.stdout.splitlines())]
    selected_port = port.strip() or None
    if selected_port: command.extend(["--port", selected_port])
    command.extend(["0x0", str(image)])
    try:
        command = prepare_serial_command(command, selected_port)
    except SerialAccessError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(f"Flashing existing signed normal-release image only: {image}")
    return run(command)

def workflow_e2e(board: str, port: str, timeout: str, resume_from: str) -> int:
    command = [
        sys.executable,
        str(ROOT / "qa/checks/firmware/run_workflow_tests.py"),
        "--board",
        board,
        "--timeout",
        timeout,
    ]
    if port.strip():
        command.extend(["--port", port.strip()])
    if resume_from.strip():
        command.extend(["--resume-from", resume_from.strip()])
    return run(command)


def workflow_hil(board: str, port: str, timeout: str, resume_from: str) -> int:
    if board != "m5stack":
        print("ERROR: workflow-hil currently supports BOARD=m5stack only", file=sys.stderr)
        return 2
    command = [
        sys.executable,
        str(ROOT / "qa/checks/firmware/run_workflow_tests.py"),
        "--board", board, "--timeout", timeout, "--hil",
    ]
    if port.strip():
        command.extend(["--port", port.strip()])
    if resume_from.strip():
        command.extend(["--resume-from", resume_from.strip()])
    return run(command)


def ios_action(action: str) -> int:
    if action in {"build", "release", "test"}:
        return platform("ios-build", [action])
    if action != "qa":
        print(f"ERROR: unsupported iOS action: {action}", file=sys.stderr)
        return 2
    rc = platform("ios-build", ["test"])
    if rc != 0:
        return rc
    for script in (
        "qa/checks/ios/check_ios_architecture.py",
        "qa/checks/ios/swift_crap.py",
        "qa/checks/ios/run_mutation_tests.py",
    ):
        rc = run([sys.executable, str(ROOT / script)])
        if rc != 0:
            return rc
    return 0


def android_action(action: str) -> int:
    if action in {"build", "release", "test"}:
        mode = {"build": "debug", "release": "release", "test": "test"}[action]
        return platform("android-build", [mode])
    if action != "qa":
        print(f"ERROR: unsupported Android action: {action}", file=sys.stderr)
        return 2
    rc = platform("android-build", ["test"])
    if rc != 0:
        return rc
    for script in (
        "qa/checks/android/check_android_architecture.py",
        "qa/checks/android/run_core_tests.py",
        "qa/checks/android/kotlin_crap.py",
        "qa/checks/android/run_instrumentation_tests.py",
        "qa/checks/android/run_mutation_tests.py",
    ):
        if script.endswith("run_core_tests.py") and not (shutil.which("kotlinc") and shutil.which("java")):
            print("  ~ SKIP: standalone Kotlin CLI smoke test unavailable; Gradle JUnit remains authoritative."); continue
        rc = run([sys.executable, str(ROOT / script)])
        if rc == 77:
            print(f"  ~ SKIP: optional Android QA helper unavailable: {script}")
            continue
        if rc != 0:
            return rc
    return 0


def normal_test(strict_lockfiles: str) -> int:
    return run_all_profile(platform, "test", "", strict_lockfiles)


def specialist_qa(fuzz_passes: str, strict_lockfiles: str, resume_from: str) -> int:
    # The full run-all catalog is the single authoritative non-hardware QA graph.
    # Compatibility wrappers such as production-hardening delegate back to it;
    # never invoke them here or the expensive assurance stages would run twice.
    return run_all_profile(platform, "full", fuzz_passes, strict_lockfiles, resume_from)


def clean() -> int:
    return clean_workspace(ROOT, run)


HELP = Path(__file__).with_name("make_help.txt").read_text(encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("entrypoint")
    p.add_argument("name", choices=tuple(sorted(ENTRYPOINTS)))
    p.add_argument("args", nargs=argparse.REMAINDER)

    p = sub.add_parser("firmware")
    p.add_argument("board", choices=("waveshare", "m5stack", "mirror"))

    p = sub.add_parser("owner-firmware")
    p.add_argument("output_dir", nargs="?", default="target/owner-firmware")
    p.add_argument("owner_key", nargs="?", default="")

    p = sub.add_parser("flash")
    p.add_argument("board", choices=("waveshare", "m5stack"))
    p.add_argument("port", nargs="?", default="")

    p = sub.add_parser("flash-release")
    p.add_argument("board", choices=("waveshare", "m5stack"))
    p.add_argument("port", nargs="?", default="")
    p.add_argument("release_dir", nargs="?", default="release")

    p = sub.add_parser("secure-release")
    p.add_argument("mode", choices=("dual", "owner-only"))
    p.add_argument("output_dir", nargs="?", default="")
    p.add_argument("secure_boot_key", nargs="?", default="")
    p.add_argument("signing_key", nargs="?", default="")

    p = sub.add_parser("workflow-e2e")
    p.add_argument("board", choices=("waveshare", "m5stack"))
    p.add_argument("port", nargs="?", default="")
    p.add_argument("timeout", nargs="?", default="240")
    p.add_argument("resume_from", nargs="?", default="")

    p = sub.add_parser("workflow-hil")
    p.add_argument("board", choices=("waveshare", "m5stack"))
    p.add_argument("port", nargs="?", default="")
    p.add_argument("timeout", nargs="?", default="240")
    p.add_argument("resume_from", nargs="?", default="")

    p = sub.add_parser("test")
    p.add_argument("strict_lockfiles", nargs="?", default="")

    p = sub.add_parser("qa")
    p.add_argument("fuzz_passes", nargs="?", default="100000")
    p.add_argument("strict_lockfiles", nargs="?", default="")
    p.add_argument("resume_from", nargs="?", default="")

    p = sub.add_parser("ios")
    p.add_argument("action", choices=("build", "release", "test", "qa"))

    p = sub.add_parser("android")
    p.add_argument("action", choices=("build", "release", "test", "qa"))

    p = sub.add_parser("test-hardware")
    p.add_argument("board", choices=("waveshare", "m5stack"))
    p.add_argument("port", nargs="?", default="")
    p.add_argument("timeout", nargs="?", default="240")
    p.add_argument("strict_lockfiles", nargs="?", default="")

    p = sub.add_parser("release")
    p.add_argument("output_dir", nargs="?", default="release")
    p.add_argument("signing_key", nargs="?", default="")
    p.add_argument("refresh_inputs", nargs="?", default="")

    sub.add_parser("clean")
    sub.add_parser("help")

    args = parser.parse_args(argv)
    if args.command == "entrypoint":
        return platform(args.name, args.args)
    if args.command == "firmware":
        return firmware(args.board)
    if args.command == "owner-firmware":
        return owner_firmware(args.output_dir, args.owner_key)
    if args.command == "flash":
        return flash_firmware(args.board, args.port)
    if args.command == "flash-release":
        return flash_release(args.board, args.port, args.release_dir)
    if args.command == "secure-release":
        return secure_release(args.mode, args.output_dir, args.secure_boot_key, args.signing_key)
    if args.command == "workflow-e2e":
        return workflow_e2e(args.board, args.port, args.timeout, args.resume_from)
    if args.command == "workflow-hil":
        return workflow_hil(args.board, args.port, args.timeout, args.resume_from)
    if args.command == "test":
        return normal_test(args.strict_lockfiles)
    if args.command == "qa":
        return specialist_qa(args.fuzz_passes, args.strict_lockfiles, args.resume_from)
    if args.command == "ios":
        return ios_action(args.action)
    if args.command == "android":
        return android_action(args.action)
    if args.command == "test-hardware":
        return test_hardware(platform, args.board, args.port, args.timeout, args.strict_lockfiles)
    if args.command == "release":
        return release_build(platform, IS_WINDOWS, args.output_dir, args.signing_key, args.refresh_inputs)
    if args.command == "clean":
        return clean()
    if args.command == "help":
        print(HELP, end="")
        return 0
    raise AssertionError(args.command)


if __name__ == "__main__":
    raise SystemExit(main())
