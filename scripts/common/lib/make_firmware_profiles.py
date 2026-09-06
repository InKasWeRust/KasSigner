"""Special CoreS3 production-profile helpers used by the public Make facade."""
from __future__ import annotations

from pathlib import Path
import shutil
import sys
from typing import Callable

from esp_toolchain import prepare_esp_build_environment

RunCommand = Callable[..., int]
PlatformCommand = Callable[..., int]


def _resolve_output(root: Path, requested: str, default_relative: str) -> Path:
    destination = Path(requested).expanduser() if requested.strip() else root / default_relative
    if not destination.is_absolute():
        destination = root / destination
    return destination.resolve()


def secure_release_profile(
    root: Path,
    is_windows: bool,
    run_command: RunCommand,
    mode: str,
    output_dir: str,
    secure_boot_key: str,
    signing_key: str,
) -> int:
    """Build a non-flashing CoreS3 provisioning artifact set for one trust policy."""
    if mode not in {"dual", "owner-only"}:
        print(f"ERROR: unsupported secure release mode: {mode}", file=sys.stderr)
        return 2
    try:
        env = prepare_esp_build_environment(is_windows=is_windows)
    except RuntimeError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1

    key_text = secure_boot_key.strip()
    if not key_text:
        variable = "SECURE_BOOT_KEY" if mode == "dual" else "OWNER_KEY"
        print(
            f"ERROR: {variable} must point to an RSA-3072 Secure Boot v2 private key",
            file=sys.stderr,
        )
        return 2
    key_path = Path(key_text).expanduser().resolve()
    if not key_path.is_file():
        print(f"ERROR: Secure Boot RSA key not found: {key_path}", file=sys.stderr)
        return 2

    if mode == "dual":
        schnorr_text = signing_key.strip()
        if not schnorr_text:
            print(
                "ERROR: SIGNING_KEY must point to the 32-byte vendor Schnorr release key",
                file=sys.stderr,
            )
            return 2
        schnorr_path = Path(schnorr_text).expanduser().resolve()
        if not schnorr_path.is_file():
            print(f"ERROR: Schnorr release key not found: {schnorr_path}", file=sys.stderr)
            return 2
        if schnorr_path.stat().st_size != 32:
            print("ERROR: SIGNING_KEY must be exactly 32 bytes", file=sys.stderr)
            return 2
        env["KASSIGNER_SECURE_BOOT_SIGNING_KEY"] = str(key_path)
        env["KASSIGNER_SIGNING_KEY"] = str(schnorr_path)
        destination = _resolve_output(root, output_dir, "target/secure-provisioning")
    else:
        env["KASSIGNER_OWNER_SECURE_BOOT_KEY"] = str(key_path)
        env.pop("KASSIGNER_SIGNING_KEY", None)
        destination = _resolve_output(root, output_dir, "target/secure-owner-only")

    if is_windows:
        script = root / "tools/build/firmware/prepare_m5stack_secure_release.ps1"
        shell = next(
            (
                shutil.which(name)
                for name in ("pwsh.exe", "pwsh", "powershell.exe", "powershell")
                if shutil.which(name)
            ),
            None,
        )
        if shell is None:
            print("ERROR: PowerShell is required for the Windows secure-release profile.", file=sys.stderr)
            return 127
        command = [
            shell,
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script),
            "-OutputDir",
            str(destination),
        ]
        if mode == "owner-only":
            command.append("-OwnerOnly")
    else:
        script = root / "tools/build/firmware/prepare_m5stack_secure_release.sh"
        bash = shutil.which("bash")
        if bash is None:
            print("ERROR: bash is required for the POSIX secure-release profile.", file=sys.stderr)
            return 127
        command = [bash, str(script)]
        if mode == "owner-only":
            command.append("--owner-only")
        command.append(str(destination))
    return run_command(command, env=env)


def owner_firmware_profile(
    root: Path,
    is_windows: bool,
    platform_command: PlatformCommand,
    output_dir: str,
    owner_key: str,
) -> int:
    """Build an owner-authorized application artifact without inheriting vendor identity."""
    key = owner_key.strip()
    if not key:
        print(
            "ERROR: OWNER_KEY must point to the owner RSA-3072 Secure Boot v2 private key",
            file=sys.stderr,
        )
        return 2
    key_path = Path(key).expanduser().resolve()
    if not key_path.is_file():
        print(f"ERROR: owner Secure Boot key not found: {key_path}", file=sys.stderr)
        return 2
    try:
        env = prepare_esp_build_environment(is_windows=is_windows)
    except RuntimeError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    env["KASSIGNER_OWNER_SECURE_BOOT_KEY"] = str(key_path)
    env.pop("KASSIGNER_SIGNING_KEY", None)
    destination = _resolve_output(root, output_dir, "target/owner-firmware")
    return platform_command("firmware-owner-build", [str(destination)], env=env)
