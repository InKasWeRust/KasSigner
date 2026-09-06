#!/usr/bin/env python3
"""Collect and validate ESP32-S3 ROM security state through pinned esptool.

This intentionally uses esptool's structured `get_security_info()` result instead
of parsing human-readable CLI labels. The HIL wrapper executes this script with
the Python interpreter from its repo-local, version-pinned esptool venv.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import esptool

from esptool_security_policy import evaluate_security_info

def collect(port: str) -> tuple[dict, dict]:
    with esptool.detect_chip(port=port) as esp:
        info = esp.get_security_info(cache=False)
        chip_name = esp.CHIP_NAME
    state = evaluate_security_info(chip_name, info)
    raw = {
        "chip": chip_name,
        "esptool_version": esptool.__version__,
        "security_info": info,
    }
    return state, raw


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("port")
    parser.add_argument("state_json", type=Path)
    parser.add_argument("raw_json", type=Path)
    args = parser.parse_args()
    try:
        state, raw = collect(args.port)
    except Exception as error:  # esptool raises several transport-specific exception classes
        print(f"ERROR: {error}", flush=True)
        return 1
    args.state_json.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")
    args.raw_json.write_text(json.dumps(raw, indent=2, sort_keys=True) + "\n")
    print(json.dumps(state, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
