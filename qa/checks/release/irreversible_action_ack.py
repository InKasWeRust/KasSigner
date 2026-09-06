#!/usr/bin/env python3
"""Interactive two-step acknowledgement wrapper for irreversible hardware actions."""

from __future__ import annotations

import argparse
import subprocess
import sys
from typing import TextIO

ACK_PHRASE = "I UNDERSTAND THIS IS IRREVERSIBLE"
DEVICE_TOKEN = "{device}"


def require_acknowledgement(
    action: str,
    device: str,
    input_stream: TextIO = sys.stdin,
    output_stream: TextIO = sys.stderr,
) -> bool:
    """Require an interactive operator to acknowledge permanence and target device."""
    if not input_stream.isatty():
        print(
            "ERROR: irreversible hardware actions require an interactive terminal; "
            "piped/unattended acknowledgement is forbidden.",
            file=output_stream,
        )
        return False

    print("IRREVERSIBLE HARDWARE ACTION", file=output_stream)
    print(f"Action: {action}", file=output_stream)
    print(f"Device: {device}", file=output_stream)
    print(
        "This can permanently burn or lock eFuses/security state and may make the "
        "device impossible to return to its prior state.",
        file=output_stream,
    )
    print(f"Type exactly: {ACK_PHRASE}", file=output_stream)
    phrase = input_stream.readline().rstrip("\r\n")
    if phrase != ACK_PHRASE:
        print("ABORTED: irreversible acknowledgement phrase did not match.", file=output_stream)
        return False

    print(f"Retype the target device exactly: {device}", file=output_stream)
    confirmed_device = input_stream.readline().rstrip("\r\n")
    if confirmed_device != device:
        print("ABORTED: target device confirmation did not match.", file=output_stream)
        return False

    print("ACKNOWLEDGED: irreversible hardware action may proceed.", file=output_stream)
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--action", required=True, help="human-readable irreversible action")
    parser.add_argument("--device", required=True, help="exact target device identifier/path")
    parser.add_argument("command", nargs=argparse.REMAINDER, help="command to execute after --")
    args = parser.parse_args()

    command = list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        print("ERROR: no irreversible command supplied after --", file=sys.stderr)
        return 2
    if DEVICE_TOKEN not in command:
        print(
            f"ERROR: irreversible command must contain the exact {DEVICE_TOKEN!r} token; "
            "the wrapper substitutes the device that the operator retypes.",
            file=sys.stderr,
        )
        return 2
    if not require_acknowledgement(args.action, args.device):
        return 2
    bound_command = [args.device if value == DEVICE_TOKEN else value for value in command]
    return subprocess.run(bound_command, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
