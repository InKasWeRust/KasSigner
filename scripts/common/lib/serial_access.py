#!/usr/bin/env python3
"""Linux serial-device permission preflight for board-aware flash commands.

Never runs firmware tooling as root. If a Linux serial device is protected by the
``dialout`` group and the invoking account lacks that membership, this helper
explains the sudo request, adds only the supplementary group membership, and
returns a command wrapped by ``sg dialout -c`` so the current invocation can
continue without requiring a logout/login. The parent shell is intentionally
left unchanged; future login sessions inherit the persistent membership.
"""
from __future__ import annotations

import glob
import os
from pathlib import Path
import shlex
import shutil
import stat
import subprocess
import sys
from typing import Any

if os.name == "posix":
    import grp
    import pwd
else:  # pragma: no cover - exercised by native Windows wrapper validation
    grp = None  # type: ignore[assignment]
    pwd = None  # type: ignore[assignment]

DIALOUT = "dialout"
SERIAL_GLOBS = ("/dev/ttyACM*", "/dev/ttyUSB*")


class SerialAccessError(RuntimeError):
    """Serial permission remediation could not be completed safely."""


def _username() -> str:
    assert pwd is not None
    return pwd.getpwuid(os.getuid()).pw_name


def _dialout_group() -> Any:
    assert grp is not None
    try:
        return grp.getgrnam(DIALOUT)
    except KeyError as exc:
        raise SerialAccessError(
            "Linux serial group 'dialout' does not exist on this host; "
            "KasSigner will not invent or create a privileged system group."
        ) from exc


def _persistent_member(username: str, group: Any) -> bool:
    assert pwd is not None
    try:
        primary_gid = pwd.getpwnam(username).pw_gid
    except KeyError as exc:
        raise SerialAccessError(f"cannot resolve local account {username!r}") from exc
    return primary_gid == group.gr_gid or username in group.gr_mem


def _active_member(group: Any) -> bool:
    return os.getegid() == group.gr_gid or group.gr_gid in os.getgroups()


def _candidate_ports(explicit_port: str | None) -> list[Path]:
    if explicit_port:
        return [Path(explicit_port)]
    paths = {Path(match) for pattern in SERIAL_GLOBS for match in glob.glob(pattern)}
    return sorted(paths)


def _needs_dialout(path: Path, group: Any) -> bool:
    try:
        info = path.stat()
    except FileNotFoundError:
        return False
    if not stat.S_ISCHR(info.st_mode):
        return False
    if os.access(path, os.R_OK | os.W_OK):
        return False
    return info.st_gid == group.gr_gid


def _sudo_add_membership(username: str) -> None:
    sudo = shutil.which("sudo")
    usermod = shutil.which("usermod")
    if not sudo or not usermod:
        raise SerialAccessError(
            "serial access requires dialout membership, but sudo/usermod is unavailable"
        )
    if not sys.stdin.isatty():
        raise SerialAccessError(
            f"account {username!r} is not in dialout and this is not an interactive terminal; "
            f"run: sudo usermod -aG {DIALOUT} {shlex.quote(username)}"
        )

    print("\nKasSigner needs read/write access to the connected ESP serial device.", flush=True)
    print(
        f"Your account {username!r} is not a member of Linux group {DIALOUT!r}, "
        "which owns /dev/ttyACM* and /dev/ttyUSB* devices on this system.",
        flush=True,
    )
    print(
        "KasSigner will request sudo only to add your existing account to that supplementary group.",
        flush=True,
    )
    print(
        "Your sudo password may be requested. The firmware build and espflash are NOT run as root.",
        flush=True,
    )
    print(f"  + sudo usermod -aG {DIALOUT} {username}", flush=True)
    result = subprocess.run([sudo, usermod, "-aG", DIALOUT, username], check=False)
    if result.returncode != 0:
        raise SerialAccessError("sudo usermod failed; serial permissions were not changed")

    refreshed = _dialout_group()
    if not _persistent_member(username, refreshed):
        raise SerialAccessError("dialout membership was not visible after usermod; refusing to continue")
    print(
        "dialout membership updated. Applying it to this flash command now (newgrp-equivalent via sg).",
        flush=True,
    )


def prepare_serial_command(command: list[str], explicit_port: str | None = None) -> list[str]:
    """Return *command* unchanged or wrapped to obtain current dialout access.

    This is a Linux-only preflight. On other operating systems it is a no-op.
    It never broadens permissions on the device node and never executes espflash
    through sudo/root.
    """
    if os.name != "posix" or not sys.platform.startswith("linux") or os.geteuid() == 0:
        return command

    ports = _candidate_ports(explicit_port)
    if not ports or not any(path.exists() for path in ports):
        return command
    group = _dialout_group()
    protected = [path for path in ports if _needs_dialout(path, group)]
    if not protected:
        return command

    username = _username()
    persistent = _persistent_member(username, group)
    active = _active_member(group)
    if active:
        return command

    if not persistent:
        _sudo_add_membership(username)
    else:
        print(
            f"Account {username!r} is already in dialout, but this shell has stale group credentials. "
            "Applying dialout to this flash command now (newgrp-equivalent via sg).",
            flush=True,
        )

    sg = shutil.which("sg")
    if not sg:
        raise SerialAccessError(
            "dialout membership is configured, but 'sg' is unavailable; log out/in or run 'newgrp dialout'"
        )
    return [sg, DIALOUT, "-c", shlex.join(command)]
