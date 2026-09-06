#!/usr/bin/env python3
"""Durable, source/artifact-bound evidence for connected firmware HIL runs."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import tomllib
from pathlib import Path
import signal
import time
from typing import IO, Any

ROOT = Path(__file__).resolve().parents[3]
ARTIFACT_ROOT = ROOT / "target" / "qa" / "hil"
RELEASE_POLICY = ROOT / "apps" / "signer-firmware" / "release-policy.env"
INVENTORY = ROOT / "qa" / "baselines" / "repository_inventory.txt"


def sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _policy_value(name: str) -> str:
    for raw in RELEASE_POLICY.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key.strip() == name:
            return value.strip()
    raise RuntimeError(f"release policy missing {name}: {RELEASE_POLICY}")


def _descriptor(path: Path, base: Path) -> dict[str, object]:
    return {
        "path": path.relative_to(base).as_posix(),
        "sha256": sha256_file(path),
        "bytes": path.stat().st_size,
    }




@contextmanager
def reportable_interruptions():
    """Convert process termination into the same reportable path as Ctrl+C."""
    if not hasattr(signal, "SIGTERM"):
        yield
        return
    previous = signal.getsignal(signal.SIGTERM)

    def interrupted(_signum: int, _frame: object) -> None:
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupted)
    try:
        yield
    finally:
        signal.signal(signal.SIGTERM, previous)

def _status(exit_code: int) -> tuple[str, str]:
    if exit_code == 0:
        return "pass", "PASS"
    if exit_code == 124:
        return "timeout", "TIMEOUT"
    if exit_code in (130, 143):
        return "interrupted", "INTERRUPTION"
    return "fail", "FAIL"


class HilEvidence:
    """Own one immutable HIL run directory and finalize it on every outcome."""

    def __init__(
        self,
        *,
        kind: str,
        board: str,
        port: str | None,
        timeout_seconds: int,
        profile: str,
        include_build_log: bool,
    ) -> None:
        if kind not in {"hardware", "workflow"}:
            raise ValueError(f"unsupported HIL evidence kind: {kind}")
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        self.kind = kind
        self.board = board
        self.port = port
        self.timeout_seconds = timeout_seconds
        self.profile = profile
        self.started_at = datetime.now(timezone.utc)
        self.started_monotonic = time.monotonic()
        self.run_dir = ARTIFACT_ROOT / f"{timestamp}-{board}-{kind}"
        self.run_dir.mkdir(parents=True, exist_ok=False)
        self.uart_log = self.run_dir / "uart.log"
        self.uart_log.touch()
        self.build_log = self.run_dir / "build.log" if include_build_log else None
        if self.build_log is not None:
            self.build_log.touch()
        self.report = self.run_dir / (
            "hardware-hil-report.json" if kind == "hardware" else "workflow-hil-report.json"
        )
        self.phase = "initialization"
        self.error: str | None = None
        self.firmware: dict[str, object] | None = None
        self.details: dict[str, Any] = {}
        self._finalized = False

    def set_phase(self, phase: str) -> None:
        self.phase = phase

    def bind_firmware(self, image: Path) -> None:
        self.firmware = {
            "path": image.relative_to(ROOT).as_posix() if ROOT in image.resolve().parents else str(image),
            "sha256": sha256_file(image),
            "bytes": image.stat().st_size,
        }

    def update_details(self, **values: Any) -> None:
        self.details.update(values)

    def open_uart(self) -> IO[str]:
        return self.uart_log.open("a", encoding="utf-8", newline="")

    def finalize(self, exit_code: int, *, error: str | None = None) -> Path:
        if self._finalized:
            return self.report
        self._finalized = True
        completed = datetime.now(timezone.utc)
        status, outcome = _status(exit_code)
        if error:
            self.error = error
        artifacts: dict[str, object] = {"uart_log": _descriptor(self.uart_log, self.run_dir)}
        if self.build_log is not None:
            artifacts["build_log"] = _descriptor(self.build_log, self.run_dir)
        firmware_manifest = tomllib.loads(
            (ROOT / "apps" / "signer-firmware" / "Cargo.toml").read_text(encoding="utf-8")
        )
        candidate: dict[str, object] = {
            "package_version": firmware_manifest["package"]["version"],
            "release_policy_sha256": sha256_file(RELEASE_POLICY),
            "repository_inventory_sha256": sha256_file(INVENTORY),
        }
        if self.firmware is not None:
            candidate["firmware_elf"] = self.firmware
        document = {
            "schema": "kassigner-hil-evidence",
            "schema_version": 1,
            "kind": self.kind,
            "status": status,
            "outcome": outcome,
            "exit_code": exit_code,
            "phase": self.phase,
            "board": self.board,
            "requested_port": self.port,
            "timeout_seconds": self.timeout_seconds,
            "firmware_profile": self.profile,
            "started_at_utc": self.started_at.isoformat().replace("+00:00", "Z"),
            "completed_at_utc": completed.isoformat().replace("+00:00", "Z"),
            "duration_seconds": round(time.monotonic() - self.started_monotonic, 3),
            "candidate": candidate,
            "artifacts": artifacts,
            "error": self.error,
            "details": self.details,
        }
        self.report.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        self._write_hashes()
        try:
            run_label = self.run_dir.relative_to(ROOT)
        except ValueError:
            run_label = self.run_dir
        print(f"HIL evidence: {run_label}", flush=True)
        print(f"  report: {self.report.name} ({outcome})", flush=True)
        print(f"  UART:   {self.uart_log.name}", flush=True)
        if self.build_log is not None:
            print(f"  build:  {self.build_log.name}", flush=True)
        print("  hashes: SHA256SUMS", flush=True)
        return self.report

    def _write_hashes(self) -> None:
        paths = [self.report, self.uart_log]
        if self.build_log is not None:
            paths.append(self.build_log)
        lines: list[str] = []
        for path in paths:
            digest = sha256_file(path)
            lines.append(f"{digest}  {path.name}\n")
            path.with_name(path.name + ".sha256").write_text(
                f"{digest}  {path.name}\n", encoding="ascii"
            )
        (self.run_dir / "SHA256SUMS").write_text("".join(lines), encoding="ascii")
