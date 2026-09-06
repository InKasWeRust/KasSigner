#!/usr/bin/env python3
"""Pure policy evaluator for ESP32-S3 ROM `get_security_info()` data."""
from __future__ import annotations

EXPECTED_CHIP = "ESP32-S3"
EXPECTED_CHIP_ID = 9


def flash_encryption_enabled(flash_crypt_cnt: int) -> bool:
    """ESP32-S3 Flash Encryption is active when the burn-count parity is odd."""
    return flash_crypt_cnt.bit_count() % 2 == 1


def evaluate_security_info(chip_name: str, info: dict) -> dict:
    flags = dict(info.get("parsed_flags") or {})
    chip_id = info.get("chip_id")
    crypt_cnt = int(info.get("flash_crypt_cnt", 0))
    state = {
        "chip": chip_name,
        "chip_id": chip_id,
        "secure_boot": bool(flags.get("SECURE_BOOT_EN", False)),
        "flash_encryption": flash_encryption_enabled(crypt_cnt),
        "secure_download_mode": bool(flags.get("SECURE_DOWNLOAD_ENABLE", False)),
        "hard_jtag_disabled": bool(flags.get("HARD_DIS_JTAG", False)),
        "soft_jtag_disabled": bool(flags.get("SOFT_DIS_JTAG", False)),
        "flash_crypt_cnt": crypt_cnt,
        "flags": int(info.get("flags", 0)),
        "parsed_flags": flags,
        "key_purposes": list(info.get("key_purposes") or []),
        "api_version": info.get("api_version"),
    }
    state["jtag_disabled"] = state["hard_jtag_disabled"] or state["soft_jtag_disabled"]
    failures: list[str] = []
    if chip_name != EXPECTED_CHIP or chip_id != EXPECTED_CHIP_ID:
        failures.append(f"expected {EXPECTED_CHIP} chip-id {EXPECTED_CHIP_ID}, got {chip_name} id={chip_id}")
    if not state["secure_boot"]:
        failures.append("Secure Boot v2 is not enabled")
    if not state["flash_encryption"]:
        failures.append("Flash Encryption is not enabled (flash_crypt_cnt parity is not odd)")
    if not state["secure_download_mode"]:
        failures.append("Secure Download Mode is not enabled")
    if not state["jtag_disabled"]:
        failures.append("JTAG is not disabled")
    if failures:
        raise ValueError("; ".join(failures))
    return state
