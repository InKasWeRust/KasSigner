#!/usr/bin/env python3
"""Build, flash, and supervise the opt-in KasSigner ESP hardware test image."""

from __future__ import annotations

import argparse
import glob
import os
from pathlib import Path
import queue
import re
import signal
import shutil
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from typing import TextIO

ROOT = Path(__file__).resolve().parents[3]
FIRMWARE = ROOT / "apps" / "signer-firmware"
TARGET = FIRMWARE / "target" / "xtensa-esp32s3-none-elf" / "release"
HASH_SOURCE = FIRMWARE / "src" / "firmware_hash.rs"
HASH_BUILDER = ROOT / "tools" / "build" / "firmware" / "build_with_hash.sh"
BOARD_HELPER_DIR = ROOT / "tools" / "build" / "firmware"
if str(BOARD_HELPER_DIR) not in sys.path:
    sys.path.insert(0, str(BOARD_HELPER_DIR))
CHECKS_DIR = Path(__file__).resolve().parent
if str(CHECKS_DIR) not in sys.path:
    sys.path.insert(0, str(CHECKS_DIR))
SERIAL_HELPER_DIR = ROOT / "scripts" / "common" / "lib"
if str(SERIAL_HELPER_DIR) not in sys.path:
    sys.path.insert(0, str(SERIAL_HELPER_DIR))

from board_layout import layout_for, validate_layout  # noqa: E402
from serial_access import SerialAccessError, prepare_serial_command  # noqa: E402
from hil_evidence import HilEvidence, reportable_interruptions  # noqa: E402

PASS_MARKER = "KASSIGNER_HARDWARE_TESTS: PASS"
FAIL_MARKER = "KASSIGNER_HARDWARE_TESTS: FAIL"
FLASH_COMPLETE_MARKER = "Flashing has completed!"
FLASH_CONNECT_ATTEMPTS = 3
M5STACK_FLASH_RESET_STRATEGIES = ("usb-reset", "no-reset", "default-reset")
MONITOR_RECONNECT_ATTEMPTS = 3
FLASH_TRANSPORT_TIMEOUT_SECONDS = 180
SERIAL_REENUMERATION_TIMEOUT_SECONDS = 15
RETRYABLE_TRANSPORT_MARKERS = (
    "espflash::connection_failed",
    "failed to connect to the device",
    "error while connecting to device",
    "failed to open serial port",
    "serial port not found",
    "no serial ports",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Flash a connected ESP32-S3 and run all registered on-device tests."
    )
    parser.add_argument("--board", required=True, choices=("waveshare", "waveshare-af", "m5stack"))
    parser.add_argument("--port", help="Serial port; omit for safe auto-selection when unambiguous")
    parser.add_argument("--timeout", type=int, default=240, help="Monitor timeout in seconds")
    args = parser.parse_args()
    if args.timeout < 1:
        parser.error("--timeout must be positive")
    return args


def require_tool(name: str) -> None:
    if shutil.which(name) is None:
        raise RuntimeError(f"required command not found: {name}")


def build(board: str) -> Path:
    env = os.environ.copy()
    # Hardware-test images are development images and must exercise the same
    # fail-closed software-verification path as normal development firmware.
    # Use the repository-public TEST key; production release keys are never used
    # by HIL. Without this, build_with_hash converges the code hash but emits
    # FIRMWARE_SIGNED=false and the connected device correctly rejects the image.
    hil_signing_key = ROOT / "tools" / "build" / "firmware" / "dev_test_signing_key.bin"
    if not hil_signing_key.is_file() or hil_signing_key.stat().st_size != 32:
        raise RuntimeError(f"HIL development signing key is missing or invalid: {hil_signing_key}")
    env["KASSIGNER_SIGNING_KEY"] = str(hil_signing_key)
    if board in ("waveshare", "waveshare-af"):
        env.setdefault("ESP_HAL_CONFIG_PSRAM_MODE", "octal")
    feature = "ov5640-af" if board == "waveshare-af" else board
    original_hash_source = HASH_SOURCE.read_bytes()
    command = [
        str(HASH_BUILDER),
        "--board",
        board,
        f"{board}-hardware-tests",
        "--no-default-features",
        "--features",
        f"{feature},hardware-tests",
    ]
    print("  +", " ".join(command), flush=True)
    try:
        subprocess.run(command, cwd=ROOT, env=env, check=True)
    finally:
        # The generated hash is a build artifact. HIL must execute the ELF
        # containing the converged value, but QA must not leave the source
        # checkout dirty after the test completes or fails.
        HASH_SOURCE.write_bytes(original_hash_source)
    image = TARGET / "kassigner-firmware"
    if not image.is_file():
        raise RuntimeError(f"firmware ELF was not produced: {image}")
    return image


def reader(stream: object, lines: queue.Queue[str | None]) -> None:
    assert hasattr(stream, "readline")
    while True:
        line = stream.readline()  # type: ignore[attr-defined]
        if line == "":
            break
        lines.put(line)
    lines.put(None)


def stop_process(process: subprocess.Popen[str]) -> None:
    if process.poll() is None:
        if os.name == "nt":
            process.terminate()
        else:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            if os.name == "nt":
                process.kill()
            else:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            process.wait(timeout=3)
    if process.stdout is not None:
        process.stdout.close()


@contextmanager
def private_monitor_input():
    """Give espflash a private TTY without attaching the caller's keyboard.

    Pinned espflash 3.3 initializes an interactive input reader whenever monitor
    mode is active. On POSIX, a private pseudo-terminal satisfies that contract
    while keeping the user's terminal completely outside the child process.
    """
    if os.name != "posix":
        yield None
        return
    import pty

    master_fd, slave_fd = pty.openpty()
    try:
        yield slave_fd
    finally:
        for fd in (slave_fd, master_fd):
            try:
                os.close(fd)
            except OSError:
                pass


@contextmanager
def preserved_terminal():
    """Restore the caller terminal exactly after the supervised monitor exits."""
    if os.name == "nt" or not sys.stdin.isatty():
        yield
        return
    try:
        import termios
    except ImportError:
        yield
        return
    try:
        fd = sys.stdin.fileno()
        attributes = termios.tcgetattr(fd)
    except (OSError, termios.error):
        yield
        return
    try:
        yield
    finally:
        try:
            termios.tcsetattr(fd, termios.TCSADRAIN, attributes)
        except (OSError, termios.error):
            pass


def _usb_vid_pid(port: Path) -> tuple[str, str] | None:
    """Best-effort Linux sysfs VID/PID lookup for a tty node."""
    if not sys.platform.startswith("linux"):
        return None
    device = Path("/sys/class/tty") / port.name / "device"
    try:
        resolved = device.resolve(strict=True)
    except OSError:
        return None
    for candidate in (resolved, *resolved.parents):
        vendor = candidate / "idVendor"
        product = candidate / "idProduct"
        if vendor.is_file() and product.is_file():
            try:
                return vendor.read_text().strip().lower(), product.read_text().strip().lower()
            except OSError:
                return None
    return None


def resolve_noninteractive_port(port: str | None) -> str | None:
    """Choose an unambiguous POSIX port without allowing an unattended prompt."""
    if port or os.name != "posix":
        return port
    candidates = sorted({*glob.glob("/dev/ttyACM*"), *glob.glob("/dev/ttyUSB*")})
    if len(candidates) == 1:
        print(f"  Auto-selected the only visible serial port: {candidates[0]}", flush=True)
        return candidates[0]
    if len(candidates) <= 1:
        return None
    espressif = [
        candidate
        for candidate in candidates
        if (_usb_vid_pid(Path(candidate)) or ("", ""))[0] == "303a"
    ]
    if len(espressif) == 1:
        print(f"  Auto-selected the only Espressif USB serial port: {espressif[0]}", flush=True)
        return espressif[0]
    visible = ", ".join(candidates)
    raise RuntimeError(
        "multiple serial ports are visible and the supervised monitor cannot safely prompt for one; "
        f"set PORT explicitly. Visible serial ports: {visible}"
    )


def serial_port_owners(port: str | None) -> tuple[tuple[int, str], ...]:
    """Return Linux processes that currently hold an fd to *port*.

    This is best-effort diagnostics only: it never kills processes, changes
    permissions, or depends on external tools such as lsof/fuser.
    """
    if (
        not port
        or os.name != "posix"
        or not sys.platform.startswith("linux")
        or not port.startswith("/dev/")
    ):
        return ()
    try:
        target = Path(port).resolve(strict=True)
    except OSError:
        return ()
    owners: list[tuple[int, str]] = []
    proc = Path("/proc")
    for process_dir in proc.iterdir():
        if not process_dir.name.isdigit():
            continue
        fd_dir = process_dir / "fd"
        try:
            descriptors = tuple(fd_dir.iterdir())
        except OSError:
            continue
        owns_port = False
        for descriptor in descriptors:
            try:
                if descriptor.resolve(strict=True) == target:
                    owns_port = True
                    break
            except OSError:
                continue
        if not owns_port:
            continue
        pid = int(process_dir.name)
        command = ""
        try:
            raw = (process_dir / "cmdline").read_bytes().replace(b"\0", b" ").strip()
            command = raw.decode(errors="replace")
        except OSError:
            pass
        if not command:
            try:
                command = (process_dir / "comm").read_text(errors="replace").strip()
            except OSError:
                command = "unknown"
        owners.append((pid, command or "unknown"))
    return tuple(sorted(owners))


def _process_parent_pid(pid: int) -> int | None:
    """Read one Linux process parent without depending on ps/procps."""
    try:
        for line in (Path("/proc") / str(pid) / "status").read_text(errors="replace").splitlines():
            if line.startswith("PPid:"):
                return int(line.split(":", 1)[1].strip())
    except (OSError, ValueError):
        return None
    return None


def _process_command(pid: int) -> str:
    try:
        raw = (Path("/proc") / str(pid) / "cmdline").read_bytes().replace(b"\0", b" ").strip()
        return raw.decode(errors="replace")
    except OSError:
        return ""


def _process_has_environment(pid: int, key: str, value: str) -> bool:
    try:
        raw = (Path("/proc") / str(pid) / "environ").read_bytes()
    except OSError:
        return False
    expected = f"{key}={value}".encode()
    return expected in raw.split(b"\0")


def _has_connected_runner_ancestor(pid: int) -> bool:
    """Return whether *pid* belongs to another live connected KasSigner runner."""
    seen: set[int] = set()
    current = pid
    for _ in range(24):
        parent = _process_parent_pid(current)
        if parent is None or parent <= 1 or parent in seen:
            return False
        seen.add(parent)
        command = _process_command(parent)
        if "run_workflow_tests.py" in command or "run_hardware_tests.py" in command:
            return True
        current = parent
    return False


def _looks_like_managed_kassigner_espflash(command: str) -> bool:
    """Recognize the supervised flash+monitor command emitted by this repository."""
    normalized = command.replace("\\", "/")
    firmware_root = str(FIRMWARE).replace("\\", "/")
    return (
        "espflash flash --monitor" in normalized
        and firmware_root in normalized
        and "/partitions/" in normalized
        and "/target/xtensa-esp32s3-none-elf/release/kassigner-firmware" in normalized
    )


def _reclaim_stale_managed_owner(pid: int, command: str, port: str) -> bool:
    """Reap an orphaned monitor from an earlier KasSigner connected run only."""
    if os.name == "nt" or not sys.platform.startswith("linux"):
        return False
    if not _looks_like_managed_kassigner_espflash(command):
        return False
    if _has_connected_runner_ancestor(pid):
        return False
    parent = _process_parent_pid(pid)
    managed_marker = _process_has_environment(pid, "KASSIGNER_MANAGED_SERIAL_MONITOR", "1")
    # Supervised monitors carry an explicit environment marker. For a legacy
    # command that can already be stranded on a developer
    # machine, reclaim only when it has become a true orphan (PPID 1). Never
    # kill a manually launched lookalike that is still owned by an interactive shell.
    if not managed_marker and parent not in (0, 1):
        return False
    try:
        if os.getpgid(pid) != pid:
            return False
    except (OSError, ProcessLookupError):
        return True

    print(
        f"  [transport] reclaiming stale KasSigner espflash monitor PID {pid} holding {port}",
        flush=True,
    )
    try:
        os.killpg(pid, signal.SIGTERM)
    except ProcessLookupError:
        return True
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        if all(owner_pid != pid for owner_pid, _ in serial_port_owners(port)):
            return True
        time.sleep(0.05)
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        return True
    deadline = time.monotonic() + 1.0
    while time.monotonic() < deadline:
        if all(owner_pid != pid for owner_pid, _ in serial_port_owners(port)):
            return True
        time.sleep(0.05)
    return False


def ensure_serial_port_available(port: str | None) -> None:
    """Fail on live owners, but reclaim orphaned KasSigner-supervised monitors."""
    owners = serial_port_owners(port)
    if not owners:
        return
    remaining: list[tuple[int, str]] = []
    for pid, command in owners:
        if port and _reclaim_stale_managed_owner(pid, command, port):
            continue
        remaining.append((pid, command))
    if not remaining:
        return
    details = "; ".join(f"PID {pid}: {command}" for pid, command in remaining)
    raise RuntimeError(
        f"serial port {port} is already open by another live process ({details}); "
        "close that serial monitor/process before running connected QA"
    )


def wait_for_explicit_port(port: str | None, timeout: int = SERIAL_REENUMERATION_TIMEOUT_SECONDS) -> None:
    """Wait for the exact POSIX serial node to exist after USB re-enumeration."""
    if not port or os.name != "posix" or not port.startswith("/dev/"):
        return
    path = Path(port)
    if path.exists():
        return
    print(f"  Waiting up to {timeout}s for serial port {port} to appear...", flush=True)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            print(f"  Serial port ready: {port}", flush=True)
            return
        time.sleep(0.25)
    candidates = sorted({*glob.glob("/dev/ttyACM*"), *glob.glob("/dev/ttyUSB*")})
    visible = ", ".join(candidates) if candidates else "none"
    raise RuntimeError(
        f"serial port {port} did not appear within {timeout}s; visible serial ports: {visible}"
    )


def retryable_transport_failure(output: list[str], flash_complete: bool) -> bool:
    if flash_complete:
        return False
    lowered = "\n".join(output).lower()
    return any(marker in lowered for marker in RETRYABLE_TRANSPORT_MARKERS)


def _replace_before_mode(command: list[str], mode: str) -> list[str]:
    """Return a copy of an espflash command with exactly one --before mode."""
    updated = list(command)
    try:
        before = updated.index("--before")
    except ValueError:
        insert_at = 3 if len(updated) >= 3 else len(updated)
        updated[insert_at:insert_at] = ["--before", mode]
        return updated
    if before + 1 >= len(updated):
        raise RuntimeError("espflash --before option is missing its reset mode")
    updated[before + 1] = mode
    return updated


def flash_attempt_command(base_command: list[str], board: str, attempt: int) -> tuple[list[str], str]:
    """Apply a board-specific pre-flash recovery strategy for this attempt."""
    if board != "m5stack":
        return list(base_command), "board-default"
    if not 1 <= attempt <= len(M5STACK_FLASH_RESET_STRATEGIES):
        raise RuntimeError(f"invalid CoreS3 flash attempt: {attempt}")
    mode = M5STACK_FLASH_RESET_STRATEGIES[attempt - 1]
    return _replace_before_mode(base_command, mode), mode


def print_transport_diagnostics(board: str, port: str | None, attempts: int) -> None:
    """Print bounded, actionable diagnostics without mutating host/device state."""
    print(
        f"ERROR: unable to establish the ESP32-S3 flashing transport after {attempts} attempt(s).",
        file=sys.stderr,
    )
    if port:
        path = Path(port)
        exists = path.exists()
        print(f"  serial port: {port} (exists={str(exists).lower()})", file=sys.stderr)
        if exists and os.name == "posix":
            readable = os.access(path, os.R_OK)
            writable = os.access(path, os.W_OK)
            print(
                f"  caller-shell access before any dialout wrapper: read={str(readable).lower()} "
                f"write={str(writable).lower()}",
                file=sys.stderr,
            )
            owners = serial_port_owners(port)
            if owners:
                print("  serial port owner(s):", file=sys.stderr)
                for pid, command in owners:
                    print(f"    PID {pid}: {command}", file=sys.stderr)
    else:
        print("  serial port: auto-detect", file=sys.stderr)
    if board == "m5stack":
        strategies = " -> ".join(M5STACK_FLASH_RESET_STRATEGIES)
        print(
            f"  CoreS3 automatic reset ladder exhausted: {strategies}.",
            file=sys.stderr,
        )
        print(
            "  Close any other serial monitor. If all software entry modes fail, the running "
            "application may have left native USB unable to drive ROM download entry; a physical "
            "RESET/BOOT recovery can then be required.",
            file=sys.stderr,
        )


def print_failure_context(output: list[str], prefixes: tuple[str, ...] | None) -> None:
    if not prefixes:
        return
    matched: list[str] = []
    seen: set[str] = set()
    for raw in output:
        line = raw.strip()
        if not line or line in seen:
            continue
        if any(prefix in line for prefix in prefixes):
            matched.append(line)
            seen.add(line)
    if not matched:
        return
    print("  [monitor] failure context replay:", file=sys.stderr)
    for line in matched[-32:]:
        print(f"    {line}", file=sys.stderr)


def _run_flash_monitor_attempt(
    command: list[str],
    timeout: int,
    *,
    monitor_only: bool = False,
    pass_marker: str,
    fail_marker: str,
    success_label: str,
    status_interval: int | None,
    repeat_abort_marker: str | None,
    repeat_abort_arm_marker: str | None,
    phase_start_marker: str | None,
    phase_end_marker: str | None,
    phase_timeout: int | None,
    deadline_extension_marker: str | None,
    deadline_extension_seconds: int | None,
    required_markers: tuple[str, ...] | None = None,
    seen_markers: set[str] | None = None,
    ordered_markers: tuple[str, ...] | None = None,
    ordered_progress: list[int] | None = None,
    failure_context_prefixes: tuple[str, ...] | None = None,
    operation_start_prefix: str | None = None,
    operation_end_prefix: str | None = None,
    operation_timeout: int | None = None,
    operation_timeouts: dict[str, int] | None = None,
    runtime_state_prefix: str | None = None,
    required_runtime_states: tuple[str, ...] | None = None,
    seen_runtime_states: set[str] | None = None,
    uart_log: TextIO | None = None,
) -> tuple[int, bool, bool, bool]:
    """Run one supervised process; return code/retry/flash-complete/terminal-result."""
    output: list[str] = []
    if seen_markers is None:
        seen_markers = set()
    if ordered_progress is None:
        ordered_progress = [0]
    if seen_runtime_states is None:
        seen_runtime_states = set()
    flash_complete = monitor_only
    try:
        with preserved_terminal(), private_monitor_input() as monitor_stdin:
            process_env = os.environ.copy()
            process_env["KASSIGNER_MANAGED_SERIAL_MONITOR"] = "1"
            process = subprocess.Popen(
                command,
                cwd=FIRMWARE,
                env=process_env,
                stdin=monitor_stdin,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                start_new_session=(os.name != "nt"),
            )
            assert process.stdout is not None
            lines: queue.Queue[str | None] = queue.Queue()
            thread = threading.Thread(target=reader, args=(process.stdout, lines), daemon=True)
            thread.start()
            transport_started = time.monotonic()
            transport_deadline = transport_started + FLASH_TRANSPORT_TIMEOUT_SECONDS
            test_started: float | None = transport_started if monitor_only else None
            deadline: float | None = transport_started + timeout if monitor_only else None
            next_status: float | None = (
                transport_started + status_interval
                if monitor_only and status_interval
                else None
            )
            phase_deadline: float | None = None
            operation_deadline: float | None = None
            operation_name: str | None = None
            active_operation_timeout: int | None = None
            panic_diagnostic_deadline: float | None = None

            try:
                while True:
                    now = time.monotonic()
                    if panic_diagnostic_deadline is not None and now >= panic_diagnostic_deadline:
                        print(
                            f"FAIL: connected ESP device panicked during {success_label}; "
                            "diagnostic tail captured",
                            file=sys.stderr,
                        )
                        return 1, False, flash_complete, True
                    active_deadline = deadline if deadline is not None else transport_deadline
                    remaining = active_deadline - now
                    if remaining <= 0:
                        if deadline is None:
                            print(
                                f"ERROR: espflash transport did not reach flash completion within "
                                f"{FLASH_TRANSPORT_TIMEOUT_SECONDS}s",
                                file=sys.stderr,
                            )
                            return 124, not flash_complete, flash_complete, False
                        assert test_started is not None
                        print(
                            f"ERROR: {success_label} timed out after {int(now - test_started)}s",
                            file=sys.stderr,
                        )
                        return 124, False, flash_complete, True
                    try:
                        line = lines.get(timeout=min(0.25, remaining))
                    except queue.Empty:
                        if process.poll() is not None:
                            code = process.returncode or 1
                            retryable = retryable_transport_failure(output, flash_complete)
                            print(
                                f"ERROR: espflash exited with code {process.returncode} before a result marker",
                                file=sys.stderr,
                            )
                            return code, (monitor_only or retryable), flash_complete, False
                        now = time.monotonic()
                        if phase_deadline is not None and now >= phase_deadline:
                            print(
                                f"ERROR: {success_label} stalled after {phase_start_marker!r}; "
                                f"did not reach {phase_end_marker!r} within {phase_timeout}s",
                                file=sys.stderr,
                            )
                            return 124, False, flash_complete, True
                        if operation_deadline is not None and now >= operation_deadline:
                            print(
                                f"ERROR: {success_label} runtime action {operation_name!r} exceeded "
                                f"the {active_operation_timeout}s production-liveness budget",
                                file=sys.stderr,
                            )
                            return 124, False, flash_complete, True
                        if next_status is not None and now >= next_status:
                            assert test_started is not None and deadline is not None
                            elapsed = int(now - test_started)
                            remaining_seconds = max(0, int(deadline - now))
                            print(
                                f"  [monitor] device test still running: {elapsed}s elapsed, "
                                f"{remaining_seconds}s until timeout",
                                flush=True,
                            )
                            assert status_interval is not None
                            next_status = now + status_interval
                        continue
                    if line is None:
                        if process.poll() is not None:
                            code = process.returncode or 1
                            retryable = retryable_transport_failure(output, flash_complete)
                            print(
                                f"ERROR: serial monitor closed with code {process.returncode} before a result marker",
                                file=sys.stderr,
                            )
                            return code, (monitor_only or retryable), flash_complete, False
                        continue
                    output.append(line)
                    if uart_log is not None:
                        uart_log.write(line)
                        uart_log.flush()
                    print(line, end="", flush=True)
                    if runtime_state_prefix and runtime_state_prefix in line:
                        raw_state = line.split(runtime_state_prefix, 1)[1].strip()
                        match = re.match(r"([A-Za-z][A-Za-z0-9_]*)", raw_state)
                        if match:
                            seen_runtime_states.add(match.group(1))
                    if FLASH_COMPLETE_MARKER in line and not flash_complete:
                        flash_complete = True
                        test_started = time.monotonic()
                        deadline = test_started + timeout
                        next_status = test_started + status_interval if status_interval else None
                        print(
                            f"  [monitor] flash complete; starting the {timeout}s device-test deadline now",
                            flush=True,
                        )
                    if operation_start_prefix and operation_start_prefix in line:
                        operation_name = line.split(operation_start_prefix, 1)[1].strip()
                        active_operation_timeout = (operation_timeouts or {}).get(
                            operation_name, operation_timeout
                        )
                        if active_operation_timeout:
                            operation_deadline = time.monotonic() + active_operation_timeout
                            print(
                                f"  [monitor] runtime action {operation_name!r} must complete within "
                                f"{active_operation_timeout}s", flush=True,
                            )
                        else:
                            operation_deadline = None
                    if operation_end_prefix and operation_end_prefix in line:
                        ended = line.split(operation_end_prefix, 1)[1].strip()
                        if operation_name is None or ended == operation_name:
                            operation_deadline = None
                            operation_name = None
                            active_operation_timeout = None
                    if required_markers:
                        for marker in required_markers:
                            if marker in line:
                                seen_markers.add(marker)
                    if ordered_markers and ordered_progress[0] < len(ordered_markers):
                        pending = ordered_markers[ordered_progress[0]:]
                        matched_offset = next(
                            (index for index, marker in enumerate(pending) if marker in line),
                            None,
                        )
                        if matched_offset is not None:
                            if matched_offset != 0:
                                expected = pending[0]
                                observed = pending[matched_offset]
                                print(
                                    f"FAIL: {success_label} runtime evidence arrived out of order; "
                                    f"expected {expected!r} before {observed!r}",
                                    file=sys.stderr,
                                )
                                return 1, False, flash_complete, True
                            ordered_progress[0] += 1
                    # Fake monitor tests and future espflash formatting changes can
                    # emit the firmware result before the informational flash line.
                    # A terminal device marker wins only after every required runtime
                    # evidence marker has actually been observed across reconnects.
                    if pass_marker in line:
                        missing = [
                            marker for marker in (required_markers or ())
                            if marker not in seen_markers
                        ]
                        if missing:
                            print(
                                f"FAIL: connected ESP device emitted the terminal pass marker but "
                                f"{len(missing)} required runtime evidence marker(s) were never observed",
                                file=sys.stderr,
                            )
                            for marker in missing[:20]:
                                print(f"  missing: {marker}", file=sys.stderr)
                            if len(missing) > 20:
                                print(f"  ... and {len(missing) - 20} more", file=sys.stderr)
                            return 1, False, flash_complete, True
                        missing_states = [
                            state for state in (required_runtime_states or ())
                            if state not in seen_runtime_states
                        ]
                        if missing_states:
                            print(
                                f"FAIL: connected ESP device emitted the terminal pass marker but "
                                f"{len(missing_states)} graph-derived stable screen(s) were never physically rendered",
                                file=sys.stderr,
                            )
                            for state in missing_states[:30]:
                                print(f"  missing render: {state}", file=sys.stderr)
                            if len(missing_states) > 30:
                                print(f"  ... and {len(missing_states) - 30} more", file=sys.stderr)
                            return 1, False, flash_complete, True
                        if ordered_markers and ordered_progress[0] != len(ordered_markers):
                            expected = ordered_markers[ordered_progress[0]]
                            print(
                                f"FAIL: connected ESP device emitted the terminal pass marker before "
                                f"ordered runtime evidence {expected!r}",
                                file=sys.stderr,
                            )
                            return 1, False, flash_complete, True
                        print(f"PASS: connected ESP device completed {success_label}")
                        return 0, False, flash_complete, True
                    if fail_marker in line:
                        print_failure_context(output, failure_context_prefixes)
                        print(f"FAIL: connected ESP device reported {success_label} failure", file=sys.stderr)
                        return 1, False, flash_complete, True
                    if (
                        deadline is not None
                        and deadline_extension_marker
                        and deadline_extension_marker in line
                        and deadline_extension_seconds
                        and deadline_extension_seconds > 0
                    ):
                        extended = time.monotonic() + deadline_extension_seconds
                        if extended > deadline:
                            deadline = extended
                            print(
                                f"  [monitor] long-running device operation detected; "
                                f"deadline extended by up to {deadline_extension_seconds}s from now",
                                flush=True,
                            )
                    if phase_start_marker and phase_start_marker in line and phase_timeout:
                        phase_deadline = time.monotonic() + phase_timeout
                        print(
                            f"  [monitor] phase handoff must reach {phase_end_marker!r} "
                            f"within {phase_timeout}s",
                            flush=True,
                        )
                    if phase_end_marker and phase_end_marker in line:
                        phase_deadline = None
                    if repeat_abort_marker and flash_complete:
                        repeat_key = f"__repeat_abort__:{repeat_abort_marker}"
                        repeat_arm_key = f"__repeat_abort_armed__:{repeat_abort_marker}"
                        if repeat_abort_arm_marker and repeat_abort_arm_marker in line:
                            # The arm marker proves the first boot advanced beyond the BEGIN line.
                            # This deliberately tolerates a duplicate/replayed BEGIN emitted by the
                            # espflash monitor before the immediately-following PREBOARD marker.
                            seen_markers.add(repeat_key)
                            seen_markers.add(repeat_arm_key)
                        if repeat_abort_marker in line:
                            if repeat_key in seen_markers:
                                armed = repeat_abort_arm_marker is None or repeat_arm_key in seen_markers
                                if armed:
                                    print(
                                        f"FAIL: connected ESP device rebooted before {success_label} completed "
                                        f"({repeat_abort_marker!r} appeared again after the first boot advanced "
                                        f"past {repeat_abort_arm_marker!r})",
                                        file=sys.stderr,
                                    )
                                    return 1, False, flash_complete, True
                                print(
                                    f"  [monitor] duplicate/replayed {repeat_abort_marker!r} before "
                                    f"{repeat_abort_arm_marker!r}; ignoring",
                                    flush=True,
                                )
                            else:
                                seen_markers.add(repeat_key)
                    if any(marker in line for marker in (
                        "====================== PANIC",
                        "panicked at ",
                        "Guru Meditation Error",
                    )):
                        if panic_diagnostic_deadline is None:
                            panic_diagnostic_deadline = time.monotonic() + 1.5
                            print(
                                "  [monitor] panic detected; capturing the diagnostic tail before aborting",
                                flush=True,
                            )
            finally:
                stop_process(process)
    finally:
        print("  Serial monitor stopped; terminal state restored.", flush=True)


def monitor_reconnect_command(image: Path, port: str | None) -> list[str]:
    """Attach to already-running firmware without resetting or synchronizing it."""
    command = [
        "espflash",
        "monitor",
        "--non-interactive",
        "--chip",
        "esp32s3",
        "--before",
        "no-reset-no-sync",
        "--elf",
        str(image),
    ]
    if port:
        command.extend(("--port", port))
    return command


def reconnect_monitor(
    image: Path,
    port: str | None,
    timeout: int,
    *,
    pass_marker: str,
    fail_marker: str,
    success_label: str,
    status_interval: int | None,
    repeat_abort_marker: str | None,
    repeat_abort_arm_marker: str | None = None,
    phase_start_marker: str | None,
    phase_end_marker: str | None,
    phase_timeout: int | None,
    deadline_extension_marker: str | None,
    deadline_extension_seconds: int | None,
    required_markers: tuple[str, ...] | None = None,
    seen_markers: set[str] | None = None,
    ordered_markers: tuple[str, ...] | None = None,
    ordered_progress: list[int] | None = None,
    failure_context_prefixes: tuple[str, ...] | None = None,
    operation_start_prefix: str | None = None,
    operation_end_prefix: str | None = None,
    operation_timeout: int | None = None,
    operation_timeouts: dict[str, int] | None = None,
    runtime_state_prefix: str | None = None,
    required_runtime_states: tuple[str, ...] | None = None,
    seen_runtime_states: set[str] | None = None,
    uart_log: TextIO | None = None,
) -> int:
    """Recover a dropped post-flash monitor without ever reflashing the device."""
    if seen_markers is None:
        seen_markers = set()
    if ordered_progress is None:
        ordered_progress = [0]
    if seen_runtime_states is None:
        seen_runtime_states = set()
    base_command = monitor_reconnect_command(image, port)
    for attempt in range(1, MONITOR_RECONNECT_ATTEMPTS + 1):
        try:
            wait_for_explicit_port(port)
            command = prepare_serial_command(base_command, port)
        except (RuntimeError, SerialAccessError) as error:
            print(f"ERROR: {error}", file=sys.stderr)
            if attempt == MONITOR_RECONNECT_ATTEMPTS:
                return 1
            time.sleep(min(0.75 * attempt, 1.5))
            continue
        print(
            f"  [monitor] reconnect {attempt}/{MONITOR_RECONNECT_ATTEMPTS} without reflashing: "
            + " ".join(command),
            flush=True,
        )
        code, retryable, _flash_complete, terminal_result = _run_flash_monitor_attempt(
            command,
            timeout,
            monitor_only=True,
            pass_marker=pass_marker,
            fail_marker=fail_marker,
            success_label=success_label,
            status_interval=status_interval,
            repeat_abort_marker=repeat_abort_marker,
            repeat_abort_arm_marker=repeat_abort_arm_marker,
            phase_start_marker=phase_start_marker,
            phase_end_marker=phase_end_marker,
            phase_timeout=phase_timeout,
            deadline_extension_marker=deadline_extension_marker,
            deadline_extension_seconds=deadline_extension_seconds,
            required_markers=required_markers,
            seen_markers=seen_markers,
            ordered_markers=ordered_markers,
            ordered_progress=ordered_progress,
            failure_context_prefixes=failure_context_prefixes,
            operation_start_prefix=operation_start_prefix,
            operation_end_prefix=operation_end_prefix,
            operation_timeout=operation_timeout,
            operation_timeouts=operation_timeouts,
            runtime_state_prefix=runtime_state_prefix,
            required_runtime_states=required_runtime_states,
            seen_runtime_states=seen_runtime_states,
            uart_log=uart_log,
        )
        if code == 0 or terminal_result or not retryable:
            return code
        if attempt < MONITOR_RECONNECT_ATTEMPTS:
            time.sleep(min(0.75 * attempt, 1.5))
    return code


def flash_and_monitor(
    board: str,
    image: Path,
    port: str | None,
    timeout: int,
    *,
    pass_marker: str = PASS_MARKER,
    fail_marker: str = FAIL_MARKER,
    success_label: str = "hardware tests",
    status_interval: int | None = None,
    repeat_abort_marker: str | None = None,
    repeat_abort_arm_marker: str | None = None,
    phase_start_marker: str | None = None,
    phase_end_marker: str | None = None,
    phase_timeout: int | None = None,
    deadline_extension_marker: str | None = None,
    deadline_extension_seconds: int | None = None,
    required_markers: tuple[str, ...] | None = None,
    ordered_markers: tuple[str, ...] | None = None,
    failure_context_prefixes: tuple[str, ...] | None = None,
    operation_start_prefix: str | None = None,
    operation_end_prefix: str | None = None,
    operation_timeout: int | None = None,
    operation_timeouts: dict[str, int] | None = None,
    runtime_state_prefix: str | None = None,
    required_runtime_states: tuple[str, ...] | None = None,
    uart_log: TextIO | None = None,
    connected_transport: bool = True,
) -> int:
    seen_markers: set[str] = set()
    seen_runtime_states: set[str] = set()
    ordered_progress = [0]
    if connected_transport:
        try:
            port = resolve_noninteractive_port(port)
            ensure_serial_port_available(port)
        except RuntimeError as error:
            print(f"ERROR: {error}", file=sys.stderr)
            return 1
    layout = layout_for(board)
    validate_layout(layout)
    base_command = [
        "espflash",
        "flash",
        "--monitor",
        *layout.espflash_connection_args(),
        *layout.espflash_args(),
    ]
    if port:
        base_command.extend(("--port", port))
    base_command.append(str(image))

    print("  +", " ".join(base_command), flush=True)
    print(
        f"  Transport may retry up to {FLASH_CONNECT_ATTEMPTS} times; the {timeout}s "
        "device-test deadline starts only after flashing completes.",
        flush=True,
    )
    if os.name == "posix":
        print("  Supervised monitor uses a private pseudo-terminal; your keyboard is not attached.", flush=True)
    else:
        print("  Supervised monitor reserves the console only while the pinned espflash monitor is active.", flush=True)

    for attempt in range(1, FLASH_CONNECT_ATTEMPTS + 1):
        attempt_command, reset_strategy = flash_attempt_command(base_command, board, attempt)
        if attempt > 1:
            print(
                f"  [transport] retry {attempt}/{FLASH_CONNECT_ATTEMPTS} after ESP connection failure...",
                flush=True,
            )
            time.sleep(min(0.75 * (attempt - 1), 1.5))
        if board == "m5stack":
            suffix = " (sync-only; preserve prior ROM-download state)" if reset_strategy == "no-reset" else ""
            print(
                f"  [transport] CoreS3 reset strategy {attempt}/{FLASH_CONNECT_ATTEMPTS}: "
                f"{reset_strategy}{suffix}",
                flush=True,
            )
        try:
            wait_for_explicit_port(port)
            command = prepare_serial_command(attempt_command, port)
        except (RuntimeError, SerialAccessError) as error:
            print(f"ERROR: {error}", file=sys.stderr)
            if attempt == FLASH_CONNECT_ATTEMPTS:
                print_transport_diagnostics(board, port, attempt)
                return 1
            continue

        code, retryable, flash_complete, terminal_result = _run_flash_monitor_attempt(
            command,
            timeout,
            pass_marker=pass_marker,
            fail_marker=fail_marker,
            success_label=success_label,
            status_interval=status_interval,
            repeat_abort_marker=repeat_abort_marker,
            repeat_abort_arm_marker=repeat_abort_arm_marker,
            phase_start_marker=phase_start_marker,
            phase_end_marker=phase_end_marker,
            phase_timeout=phase_timeout,
            deadline_extension_marker=deadline_extension_marker,
            deadline_extension_seconds=deadline_extension_seconds,
            required_markers=required_markers,
            seen_markers=seen_markers,
            ordered_markers=ordered_markers,
            ordered_progress=ordered_progress,
            failure_context_prefixes=failure_context_prefixes,
            operation_start_prefix=operation_start_prefix,
            operation_end_prefix=operation_end_prefix,
            operation_timeout=operation_timeout,
            operation_timeouts=operation_timeouts,
            runtime_state_prefix=runtime_state_prefix,
            required_runtime_states=required_runtime_states,
            seen_runtime_states=seen_runtime_states,
            uart_log=uart_log,
        )
        if code == 0 or terminal_result:
            return code
        if flash_complete:
            # Never reflash once device execution may have started. A dropped
            # USB monitor is recovered with no-reset/no-sync monitor attachment.
            print(
                "  [monitor] flash completed but the serial monitor closed; "
                "recovering monitor only (firmware will NOT be reflashed).",
                flush=True,
            )
            return reconnect_monitor(
                image,
                port,
                timeout,
                pass_marker=pass_marker,
                fail_marker=fail_marker,
                success_label=success_label,
                status_interval=status_interval,
                repeat_abort_marker=repeat_abort_marker,
                repeat_abort_arm_marker=repeat_abort_arm_marker,
                phase_start_marker=phase_start_marker,
                phase_end_marker=phase_end_marker,
                phase_timeout=phase_timeout,
                deadline_extension_marker=deadline_extension_marker,
                deadline_extension_seconds=deadline_extension_seconds,
                required_markers=required_markers,
                seen_markers=seen_markers,
                ordered_markers=ordered_markers,
                ordered_progress=ordered_progress,
                failure_context_prefixes=failure_context_prefixes,
                operation_start_prefix=operation_start_prefix,
                operation_end_prefix=operation_end_prefix,
                operation_timeout=operation_timeout,
                operation_timeouts=operation_timeouts,
                runtime_state_prefix=runtime_state_prefix,
                required_runtime_states=required_runtime_states,
                seen_runtime_states=seen_runtime_states,
                uart_log=uart_log,
            )
        if not retryable:
            return code
        if attempt == FLASH_CONNECT_ATTEMPTS:
            print_transport_diagnostics(board, port, attempt)
            return code

    return 1


@reportable_interruptions()
def main() -> int:
    args = parse_args()
    feature = "ov5640-af" if args.board == "waveshare-af" else args.board
    evidence = HilEvidence(
        kind="hardware",
        board=args.board,
        port=args.port,
        timeout_seconds=args.timeout,
        profile=f"{feature},hardware-tests",
        include_build_log=False,
    )
    code = 1
    error_text: str | None = None
    try:
        evidence.set_phase("tool-preflight")
        require_tool("cargo")
        require_tool("espflash")
        require_tool("python3")
        validate_layout(layout_for(args.board))
        evidence.set_phase("firmware-build")
        image = build(args.board)
        evidence.bind_firmware(image)
        evidence.set_phase("flash-and-uart")
        with evidence.open_uart() as uart_log:
            code = flash_and_monitor(
                args.board, image, args.port, args.timeout, uart_log=uart_log
            )
        evidence.set_phase("complete" if code == 0 else "flash-and-uart")
    except subprocess.CalledProcessError as error:
        code = error.returncode or 1
        error_text = f"command failed: {error.cmd}"
    except (OSError, RuntimeError) as error:
        code = 1
        error_text = str(error)
        print(f"ERROR: {error}", file=sys.stderr)
    except KeyboardInterrupt:
        code = 130
        error_text = "hardware tests interrupted"
        print("\nHardware tests interrupted.", file=sys.stderr)
    finally:
        evidence.finalize(code, error=error_text)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
