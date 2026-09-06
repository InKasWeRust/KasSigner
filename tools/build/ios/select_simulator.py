#!/usr/bin/env python3
"""Select an available iPhone simulator for KasSigner CI/test runs.

GitHub's macOS runner image changes over time, so a hard-coded simulator name
is intentionally avoided. An explicit KASSIGNER_IOS_TEST_DESTINATION still
wins in the caller; this helper only resolves the default case.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from typing import Any

PREFERRED_IPHONES = (
    "iPhone 16 Pro",
    "iPhone 17 Pro",
    "iPhone 17",
    "iPhone 16e",
)


def _runtime_version(runtime: str) -> tuple[int, ...]:
    marker = ".iOS-"
    if marker not in runtime:
        return ()
    suffix = runtime.split(marker, 1)[1]
    values = [int(part) for part in re.findall(r"\d+", suffix)]
    return tuple(values)


def select_destination(payload: dict[str, Any]) -> str:
    candidates: list[tuple[str, str, tuple[int, ...]]] = []
    devices = payload.get("devices", {})
    if not isinstance(devices, dict):
        raise ValueError("simctl payload does not contain a devices mapping")

    for runtime, entries in devices.items():
        if ".iOS-" not in str(runtime) or not isinstance(entries, list):
            continue
        version = _runtime_version(str(runtime))
        for entry in entries:
            if not isinstance(entry, dict) or entry.get("isAvailable") is False:
                continue
            name = str(entry.get("name", ""))
            udid = str(entry.get("udid", ""))
            if not name.startswith("iPhone ") or not udid:
                continue
            candidates.append((name, udid, version))

    if not candidates:
        raise ValueError("no available iPhone simulator was reported by simctl")

    for preferred in PREFERRED_IPHONES:
        matches = [candidate for candidate in candidates if candidate[0] == preferred]
        if matches:
            _, udid, _ = max(matches, key=lambda candidate: candidate[2])
            return f"platform=iOS Simulator,id={udid}"

    _, udid, _ = max(candidates, key=lambda candidate: (candidate[2], candidate[0]))
    return f"platform=iOS Simulator,id={udid}"


def main() -> int:
    try:
        result = subprocess.run(
            ["xcrun", "simctl", "list", "devices", "available", "--json"],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        )
        payload = json.loads(result.stdout)
        print(select_destination(payload))
    except (FileNotFoundError, subprocess.CalledProcessError, json.JSONDecodeError, ValueError) as error:
        print(f"ERROR: unable to select an iOS simulator: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
