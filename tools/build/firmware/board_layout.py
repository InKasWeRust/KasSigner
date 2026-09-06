#!/usr/bin/env python3
"""Board-specific ESP flash layout policy for KasSigner firmware."""

from __future__ import annotations

import argparse
import csv
import hashlib
from dataclasses import dataclass
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
SECTOR_SIZE = 0x1000
APP_ALIGNMENT = 0x10000
PARTITION_TABLE_OFFSET = 0x8000
PARTITION_TABLE_SIZE = 0x1000


@dataclass(frozen=True)
class BoardLayout:
    board: str
    partition_table: str | None = None
    flash_size_cli: str | None = None
    flash_size_bytes: int | None = None
    target_app_partition: str | None = None
    app_offset: int | None = None
    app_size: int | None = None
    state_offset: int | None = None
    state_size: int | None = None

    def partition_path(self) -> Path | None:
        if self.partition_table is None:
            return None
        return ROOT / self.partition_table

    def espflash_args(self) -> list[str]:
        args: list[str] = []
        if self.partition_table is not None:
            args.extend(("--partition-table", str(self.partition_path())))
        if self.flash_size_cli is not None:
            args.extend(("--flash-size", self.flash_size_cli))
        if self.target_app_partition is not None:
            args.extend(("--target-app-partition", self.target_app_partition))
        return args

    def espflash_connection_args(self) -> list[str]:
        """Connection policy shared by public flash and connected QA runners."""
        args = ["--chip", "esp32s3"]
        if self.board == "m5stack":
            # CoreS3 uses the ESP32-S3 native USB Serial/JTAG peripheral.
            # Force its dedicated reset sequence instead of relying on USB PID
            # classification through the host serial library.
            args.extend(("--before", "usb-reset"))
        return args


LAYOUTS = {
    "waveshare": BoardLayout(
        board="waveshare",
        partition_table="apps/signer-firmware/partitions/waveshare-esp32s3-touch-lcd-2.csv",
        flash_size_cli="16mb",
        flash_size_bytes=0x0100_0000,
        target_app_partition="factory",
        app_offset=0x0001_0000,
        app_size=0x00FE_C000,
        state_offset=0x00FF_C000,
        state_size=0x0000_4000,
    ),
    "waveshare-af": BoardLayout(
        board="waveshare-af",
        partition_table="apps/signer-firmware/partitions/waveshare-esp32s3-touch-lcd-2.csv",
        flash_size_cli="16mb",
        flash_size_bytes=0x0100_0000,
        target_app_partition="factory",
        app_offset=0x0001_0000,
        app_size=0x00FE_C000,
        state_offset=0x00FF_C000,
        state_size=0x0000_4000,
    ),
    "m5stack": BoardLayout(
        board="m5stack",
        partition_table="apps/signer-firmware/partitions/m5stack-cores3.csv",
        flash_size_cli="16mb",
        flash_size_bytes=0x0100_0000,
        target_app_partition="ota_0",
        app_offset=0x0001_0000,
        app_size=0x0020_0000,
        state_offset=0x00FF_C000,
        state_size=0x0000_4000,
    ),
}


def layout_for(board: str) -> BoardLayout:
    try:
        return LAYOUTS[board]
    except KeyError as error:
        raise ValueError(f"unsupported firmware board: {board}") from error


def _parse_number(value: str) -> int:
    text = value.strip().lower()
    if not text:
        raise ValueError("blank numeric field")
    multiplier = 1
    if text.endswith("k"):
        multiplier, text = 1024, text[:-1]
    elif text.endswith("m"):
        multiplier, text = 1024 * 1024, text[:-1]
    return int(text, 0) * multiplier


def _read_partitions(path: Path) -> list[tuple[str, str, str, int, int]]:
    rows: list[tuple[str, str, str, int, int]] = []
    with path.open(newline="", encoding="utf-8") as handle:
        for raw in csv.reader(handle):
            if not raw or not any(field.strip() for field in raw):
                continue
            if raw[0].lstrip().startswith("#"):
                continue
            if len(raw) < 5:
                raise ValueError(f"{path}: partition row has fewer than five fields: {raw!r}")
            name, kind, subtype, offset, size = (field.strip() for field in raw[:5])
            rows.append((name, kind, subtype, _parse_number(offset), _parse_number(size)))
    return rows


def validate_layout(layout: BoardLayout) -> None:
    path = layout.partition_path()
    if path is None:
        return
    if not path.is_file():
        raise ValueError(f"{layout.board}: partition table not found: {path}")
    if layout.flash_size_bytes is None:
        raise ValueError(f"{layout.board}: custom partition table requires flash_size_bytes")

    rows = _read_partitions(path)
    if not rows:
        raise ValueError(f"{layout.board}: partition table is empty")
    names = [row[0] for row in rows]
    if len(names) != len(set(names)):
        raise ValueError(f"{layout.board}: duplicate partition names are forbidden")

    ordered = sorted(rows, key=lambda row: row[3])
    previous_end = PARTITION_TABLE_OFFSET + PARTITION_TABLE_SIZE
    for name, kind, _subtype, offset, size in ordered:
        if offset % SECTOR_SIZE != 0 or size <= 0 or size % SECTOR_SIZE != 0:
            raise ValueError(f"{layout.board}: {name} must be non-empty and 4-KiB aligned")
        if kind == "app" and offset % APP_ALIGNMENT != 0:
            raise ValueError(f"{layout.board}: app partition {name} must be 64-KiB aligned")
        end = offset + size
        if offset < previous_end:
            raise ValueError(f"{layout.board}: partition {name} overlaps a previous partition")
        if end > layout.flash_size_bytes:
            raise ValueError(f"{layout.board}: partition {name} exceeds physical flash capacity")
        previous_end = end

    by_name = {row[0]: row for row in rows}
    if layout.board == "m5stack":
        expected_names = {"nvs", "otadata", "phy_init", "ota_0", "ota_1", "owner_stage", "kassigner_bootctl", "kassigner_qa", "kassigner_state"}
        if set(by_name) != expected_names:
            raise ValueError(
                f"{layout.board}: partition names must be exactly {sorted(expected_names)}"
            )
        if by_name["nvs"] != ("nvs", "data", "nvs", 0x9000, 0x4000):
            raise ValueError(f"{layout.board}: NVS layout drifted from the CoreS3 contract")
        if by_name["otadata"] != ("otadata", "data", "ota", 0xD000, 0x2000):
            raise ValueError(f"{layout.board}: OTA data layout drifted from the CoreS3 contract")
        if by_name["phy_init"] != ("phy_init", "data", "phy", 0xF000, 0x1000):
            raise ValueError(f"{layout.board}: PHY layout drifted from the CoreS3 contract")
        if by_name["ota_1"] != ("ota_1", "app", "ota_1", 0x210000, 0x200000):
            raise ValueError(f"{layout.board}: secondary OTA slot drifted from the CoreS3 contract")
        if by_name["owner_stage"] != ("owner_stage", "data", "undefined", 0x410000, 0x200000):
            raise ValueError(f"{layout.board}: owner firmware staging partition drifted from the CoreS3 contract")
        if by_name["kassigner_bootctl"] != ("kassigner_bootctl", "data", "undefined", 0x610000, 0x1000):
            raise ValueError(f"{layout.board}: boot-control partition drifted from the CoreS3 contract")
        if any(row[1] == "app" and row[2] in {"factory", "test"} for row in rows):
            raise ValueError(f"{layout.board}: anti-rollback forbids factory/test app partitions")
    if layout.board in {"waveshare", "waveshare-af"}:
        expected_names = {"factory", "kassigner_state"}
        if set(by_name) != expected_names:
            raise ValueError(
                f"{layout.board}: partition names must be exactly {sorted(expected_names)}"
            )

    app_name = layout.target_app_partition
    if app_name is None or app_name not in by_name:
        raise ValueError(f"{layout.board}: configured target app partition is missing")
    app = by_name[app_name]
    expected_subtype = "ota_0" if layout.board == "m5stack" else "factory"
    if app[1:3] != ("app", expected_subtype):
        raise ValueError(f"{layout.board}: {app_name} must be an app/{expected_subtype} partition")
    if app[3] != layout.app_offset or app[4] != layout.app_size:
        raise ValueError(
            f"{layout.board}: {app_name} must remain at 0x{layout.app_offset:08X} "
            f"with size 0x{layout.app_size:X}"
        )

    if layout.board == "m5stack":
        qa = by_name.get("kassigner_qa")
        if qa != ("kassigner_qa", "data", "undefined", 0xFF8000, 0x4000):
            raise ValueError("m5stack: kassigner_qa must reserve 16 KiB at 0x00FF8000")

    state = by_name.get("kassigner_state")
    if state is None:
        raise ValueError(f"{layout.board}: kassigner_state reservation is missing")
    if state[3] != layout.state_offset or state[4] != layout.state_size:
        raise ValueError(
            f"{layout.board}: kassigner_state must remain at 0x{layout.state_offset:08X} "
            f"with size 0x{layout.state_size:X}"
        )
    if state[3] + state[4] != layout.flash_size_bytes:
        raise ValueError(f"{layout.board}: kassigner_state must terminate at the end of flash")
    if state[1:3] != ("data", "undefined"):
        raise ValueError(f"{layout.board}: kassigner_state must remain a data/undefined reservation")
    if app[3] + app[4] > state[3]:
        raise ValueError(f"{layout.board}: application partition overlaps persistent-wallet storage")


def partition_sha256(layout: BoardLayout) -> str | None:
    path = layout.partition_path()
    if path is None:
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("check", "espflash-args", "connection-args", "sha256"):
        command = sub.add_parser(name)
        command.add_argument("--board", required=True, choices=tuple(LAYOUTS))
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    try:
        layout = layout_for(args.board)
        validate_layout(layout)
        if args.command == "espflash-args":
            for value in layout.espflash_args():
                print(value)
        elif args.command == "connection-args":
            for value in layout.espflash_connection_args():
                print(value)
        elif args.command == "sha256":
            digest = partition_sha256(layout)
            if digest is not None:
                print(digest)
        return 0
    except (OSError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
