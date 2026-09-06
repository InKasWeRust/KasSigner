#!/usr/bin/env python3
"""Self-contained ESP Rust/Xtensa toolchain discovery for Make entrypoints."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TOOLCHAINS = ROOT / "qa" / "config" / "toolchains.env"
XTENSA_LINKER = "xtensa-esp32s3-elf-gcc"


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


def _source_posix_environment(
    base_env: dict[str, str],
) -> tuple[dict[str, str], tuple[Path, ...]]:
    """Load Cargo/espup exports so Make does not depend on parent-shell state."""
    bash = shutil.which("bash", path=base_env.get("PATH"))
    if bash is None:
        raise RuntimeError("required command not found: bash")
    home = Path(base_env.get("HOME", str(Path.home()))).expanduser()
    cargo_home = Path(base_env.get("CARGO_HOME", str(home / ".cargo"))).expanduser()
    candidates = (
        cargo_home / "env",
        home / "export-esp.sh",
        home / ".espup" / "export-esp.sh",
    )
    readable = tuple(
        path for path in candidates if path.is_file() and os.access(path, os.R_OK)
    )
    if not readable:
        return base_env.copy(), ()

    script = (
        "set -a; "
        + " ".join(f'. {json.dumps(str(path))};' for path in readable)
        + " env -0"
    )
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
        raise RuntimeError(
            "failed to load ESP toolchain environment: "
            + (detail or "bash exited nonzero")
        )

    env = base_env.copy()
    for item in result.stdout.split(b"\0"):
        if not item or b"=" not in item:
            continue
        key, value = item.split(b"=", 1)
        env[key.decode("utf-8", errors="surrogateescape")] = value.decode(
            "utf-8", errors="surrogateescape"
        )
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


def prepare_esp_build_environment(*, is_windows: bool) -> dict[str, str]:
    """Return an environment containing the pinned ESP Rust/GCC tools."""
    base_env = os.environ.copy()
    if is_windows:
        env, sourced = base_env, ()
    else:
        env, sourced = _source_posix_environment(base_env)

    linker = _discover_xtensa_linker(env)
    if linker is None:
        rust_version = pinned_toolchain_value("KASSIGNER_ESP_RUST")
        espup_version = pinned_toolchain_value("KASSIGNER_ESPUP_VERSION")
        home = Path(env.get("HOME", str(Path.home()))).expanduser()
        export_file = home / "export-esp.sh"
        raise RuntimeError(
            f"required ESP32-S3 linker not found: {XTENSA_LINKER}\n"
            "Install/repair the repository-pinned no_std ESP toolchain, then "
            "rerun the same command:\n"
            f"  cargo install espup --version {espup_version} --locked --force\n"
            f"  espup install --toolchain-version {rust_version} --targets esp32s3 "
            f"--export-file {export_file}\n"
            f"  source {export_file}\n"
            "Do not use espup --std: that mode intentionally skips GCC and "
            "cannot build this firmware."
        )

    linker_dir = str(linker.parent)
    path_entries = env.get("PATH", "").split(os.pathsep)
    if linker_dir not in path_entries:
        env["PATH"] = linker_dir + os.pathsep + env.get("PATH", "")
    if sourced:
        print(
            "  ESP environment: " + ", ".join(str(path) for path in sourced),
            flush=True,
        )
    print(f"  Xtensa linker: {linker}", flush=True)
    return env
