#!/usr/bin/env python3
"""Launch ESP32-S3 QEMU, stream UART, and enforce guest test markers."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import queue
import signal
import subprocess
import threading
import sys
import time

BEGIN_MARKER = b"KASSIGNER_QEMU_TESTS_BEGIN"
UART_MARKER = b"KASSIGNER_QEMU_UART_PROBE"
PASS_MARKER = b"KASSIGNER_QEMU_TESTS_PASS"
FAIL_MARKER = b"KASSIGNER_QEMU_TESTS_FAIL"
BOARD_MARKER = b"Board: ESP32-S3 QEMU"
REQUIRED_MARKERS = (BOARD_MARKER, BEGIN_MARKER, UART_MARKER)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the KasSigner ESP32-S3 QEMU hardware test image."
    )
    parser.add_argument("--qemu", required=True, type=Path)
    parser.add_argument("--image", required=True, type=Path)
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--keep-running", action="store_true")
    return parser.parse_args()


def build_command(qemu: Path, image: Path) -> list[str]:
    return [
        str(qemu),
        "-nographic",
        "-machine",
        "esp32s3",
        "-drive",
        f"file={image},if=mtd,format=raw",
        "-global",
        "driver=timer.esp32c3.timg,property=wdt_disable,value=true",
    ]


def stop_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3)


def validate_paths(qemu: Path, image: Path) -> None:
    if not qemu.is_file() or not os.access(qemu, os.X_OK):
        raise SystemExit(f"ERROR: QEMU executable is not runnable: {qemu}")
    if not image.is_file():
        raise SystemExit(f"ERROR: QEMU flash image does not exist: {image}")


def missing_required(seen: set[bytes]) -> list[str]:
    return [marker.decode() for marker in REQUIRED_MARKERS if marker not in seen]


def launch(args: argparse.Namespace) -> int:
    validate_paths(args.qemu, args.image)
    command = build_command(args.qemu, args.image)
    print("QEMU test command:", " ".join(command), flush=True)
    process = subprocess.Popen(
        command,
        # Automated QEMU tests never need keyboard input.  Give -nographic a
        # private pipe so it cannot put the maintainer console into raw/no-echo
        # mode, while keeping the input stream open for the life of the guest.
        # Explicit keep-running mode remains interactive for Ctrl-A/X.
        stdin=None if args.keep_running else subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=0,
    )
    assert process.stdout is not None

    output_queue: queue.Queue[tuple[str, object]] = queue.Queue()

    def read_stdout() -> None:
        try:
            while True:
                chunk = process.stdout.read(4096)
                if not chunk:
                    break
                output_queue.put(("data", chunk))
        except BaseException as exc:  # surfaced to the main thread below
            output_queue.put(("error", exc))
        finally:
            output_queue.put(("eof", None))

    reader = threading.Thread(target=read_stdout, name="qemu-uart-reader", daemon=True)
    reader.start()

    deadline = time.monotonic() + args.timeout
    observed = bytearray()
    seen: set[bytes] = set()
    passed = False
    stdout_eof = False

    def forward_signal(signum: int, _frame: object) -> None:
        if process.poll() is None:
            process.send_signal(signum)

    previous_int = signal.signal(signal.SIGINT, forward_signal)
    previous_term = signal.signal(signal.SIGTERM, forward_signal)
    try:
        while True:
            if not passed and time.monotonic() >= deadline:
                print(
                    f"\nERROR: QEMU tests timed out after {args.timeout} seconds.",
                    file=sys.stderr,
                )
                stop_process(process)
                return 124

            try:
                event, payload = output_queue.get(timeout=0.1)
            except queue.Empty:
                event, payload = "idle", None

            while event != "idle":
                if event == "data":
                    chunk = payload
                    assert isinstance(chunk, bytes)
                    sys.stdout.buffer.write(chunk)
                    sys.stdout.buffer.flush()
                    observed.extend(chunk)
                    if len(observed) > 65536:
                        del observed[:-32768]
                    for marker in (*REQUIRED_MARKERS, PASS_MARKER, FAIL_MARKER):
                        if marker in observed:
                            seen.add(marker)
                elif event == "error":
                    stop_process(process)
                    print(
                        f"\nERROR: failed while reading QEMU UART output: {payload}",
                        file=sys.stderr,
                    )
                    return 1
                elif event == "eof":
                    stdout_eof = True

                try:
                    event, payload = output_queue.get_nowait()
                except queue.Empty:
                    event, payload = "idle", None

            if FAIL_MARKER in seen:
                print("\nERROR: guest QEMU hardware tests failed.", file=sys.stderr)
                stop_process(process)
                return 1

            if PASS_MARKER in seen and not passed:
                missing = missing_required(seen)
                if missing:
                    print(
                        "\nERROR: guest passed without required markers: "
                        + ", ".join(missing),
                        file=sys.stderr,
                    )
                    stop_process(process)
                    return 1
                passed = True
                print("\nPASS: ESP32-S3 QEMU hardware tests completed.", flush=True)
                if not args.keep_running:
                    stop_process(process)
                    return 0
                print(
                    "QEMU runtime remains active. Exit with Ctrl-A, then X.",
                    flush=True,
                )

            status = process.poll()
            if status is not None and stdout_eof:
                if passed:
                    return 0
                print(
                    f"\nERROR: QEMU exited before the pass marker (exit {status}).",
                    file=sys.stderr,
                )
                return status or 1
    finally:
        signal.signal(signal.SIGINT, previous_int)
        signal.signal(signal.SIGTERM, previous_term)


def main() -> int:
    args = parse_args()
    if args.timeout <= 0:
        raise SystemExit("ERROR: --timeout must be a positive integer")
    return launch(args)


if __name__ == "__main__":
    sys.exit(main())
