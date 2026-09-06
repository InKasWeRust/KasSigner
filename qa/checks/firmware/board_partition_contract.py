#!/usr/bin/env python3
"""Fail-closed source contracts for board-owned ESP flash layouts and image identity."""

from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
HELPER_DIR = ROOT / "tools" / "build" / "firmware"
if str(HELPER_DIR) not in sys.path:
    sys.path.insert(0, str(HELPER_DIR))

from board_layout import layout_for, partition_sha256, validate_layout  # noqa: E402


def _read(root: Path, relative: str) -> str:
    return (root / relative).read_text(encoding="utf-8")


def check_board_partition_contract(root: Path, errors: list[str]) -> None:
    try:
        for board in ("waveshare", "waveshare-af", "m5stack"):
            validate_layout(layout_for(board))
    except (OSError, ValueError) as error:
        errors.append(f"board partition contract: {error}")
        return

    m5 = layout_for("m5stack")
    if (
        m5.app_offset != 0x10000
        or m5.app_size != 0x200000
        or m5.flash_size_bytes != 0x1000000
        or m5.state_offset != 0xFFC000
        or m5.state_size != 0x4000
    ):
        errors.append("M5Stack CoreS3 layout must remain 16 MiB flash, 2 MiB OTA slots, and final 16 KiB state reservation")
    if not partition_sha256(m5):
        errors.append("M5Stack CoreS3 partition table must have a reproducible SHA-256")
    for board in ("waveshare", "waveshare-af"):
        layout = layout_for(board)
        if (
            layout.partition_table != "apps/signer-firmware/partitions/waveshare-esp32s3-touch-lcd-2.csv"
            or layout.flash_size_bytes != 0x1000000
            or layout.app_offset != 0x10000
            or layout.app_size != 0xFEC000
            or layout.state_offset != 0xFFC000
            or layout.state_size != 0x4000
        ):
            errors.append(
                f"{board}: must reserve the final 16 KiB of the 16 MiB board flash for persistent state"
            )
        if not partition_sha256(layout):
            errors.append(f"{board}: partition table must have a reproducible SHA-256")

    waveshare_partition_text = _read(
        root, "apps/signer-firmware/partitions/waveshare-esp32s3-touch-lcd-2.csv"
    )
    for fragment in ("factory", "kassigner_state", "0xFFC000", "0x4000"):
        if fragment not in waveshare_partition_text:
            errors.append(f"Waveshare persistent-state partition contract missing {fragment}")

    partition_text = _read(root, "apps/signer-firmware/partitions/m5stack-cores3.csv")
    for fragment in ("otadata", "ota_0", "ota_1", "kassigner_qa", "0xFF8000"):
        if fragment not in partition_text:
            errors.append(f"M5Stack anti-rollback partition contract missing {fragment}")
    if "app,  factory" in partition_text or "app,  test" in partition_text:
        errors.append("M5Stack anti-rollback partition table must not contain factory/test app slots")

    storage = _read(root, "apps/signer-firmware/src/services/persistent_wallet/flash.rs")
    for fragment in (
        "pub(super) const SECTOR_SIZE: u32 = 4096;",
        "const FLASH_SIZE: u32 = 16 * 1024 * 1024;",
        "const STATE_BASE: u32 = FLASH_SIZE - 8 * SECTOR_SIZE;",
        "const STATE_BASE: u32 = FLASH_SIZE - 4 * SECTOR_SIZE;",
        "pub(super) const CONFIG_A: u32 = STATE_BASE;",
        "pub(super) const CONFIG_B: u32 = STATE_BASE + SECTOR_SIZE;",
        "pub(super) const WALLET_A: u32 = STATE_BASE + 2 * SECTOR_SIZE;",
        "pub(super) const WALLET_B: u32 = STATE_BASE + 3 * SECTOR_SIZE;",
    ):
        if fragment not in storage:
            errors.append(f"persistent-wallet flash reservation drifted: missing {fragment}")

    hil = _read(root, "qa/checks/firmware/run_hardware_tests.py")
    for fragment in (
        "HASH_BUILDER",
        '"--board",\n        board,',
        "layout.espflash_args()",
        "validate_layout(layout)",
        "original_hash_source = HASH_SOURCE.read_bytes()",
        "HASH_SOURCE.write_bytes(original_hash_source)",
    ):
        if fragment not in hil:
            errors.append(f"HIL runner must bind build/flash to board layout and converged hash: missing {fragment!r}")

    policy = _read(root, "apps/signer-firmware/src/services/verify/policy.rs")
    if (
        "firmware hash is not configured" not in policy
        or "return VerificationResult::InvalidHash;" not in policy
    ):
        errors.append("hardware-tests must fail closed when the embedded firmware hash is absent")
    if (
        "Firmware code-segment hash verification failed" not in policy
        or "return result;" not in policy
    ):
        errors.append("hardware-tests must fail closed when the on-device mapped code hash mismatches")

    boot_verify = _read(root, "apps/signer-firmware/src/runtime/signing/verification.rs")
    if 'log!("KASSIGNER_HARDWARE_TESTS: FAIL")' not in boot_verify:
        errors.append("firmware verification failure must emit the HIL FAIL marker before halting")

    builder = _read(root, "tools/build/firmware/build_with_hash.sh")
    for fragment in (
        "board_layout.py",
        "verify_image_hash.py",
        "python3 \"$BOARD_HELPER\" check --board \"$BOARD\"",
        "M5Stack builds require explicit --board m5stack",
        'python3 "$VERIFY_HELPER" "$FINAL_IMAGE" "$HASH_SOURCE"',
        'reconcile_tools_lock.py',
        'python3 "$LOCK_RECONCILER" --workspace "$ROOT/tools"',
        'cp -p "$TOOLS_LOCK_BACKUP" "$TOOLS_LOCK"',
    ):
        if fragment not in builder:
            errors.append(f"firmware hash builder is missing board/final-image binding: {fragment!r}")

    dockerfile = _read(root, "Dockerfile")
    for fragment in (
        'converge.sh "M5Stack" "kassigner-m5stack-unsigned" m5stack 0',
        'converge.sh "M5Stack" "kassigner-m5stack" m5stack 1',
        "verify_image_hash.py",
        "kassigner-m5stack-partitions.csv",
        "m5stack-partition-table-sha256=",
        "m5stack-ota-apps=ota_0:0x10000+0x200000,ota_1:0x210000+0x200000",
    ):
        if fragment not in dockerfile:
            errors.append(f"reproducible build must retain the CoreS3 partition/hash contract: {fragment!r}")


def main() -> int:
    errors: list[str] = []
    check_board_partition_contract(ROOT, errors)
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1
    print("PASS: board-specific firmware partition and image-identity contract")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
