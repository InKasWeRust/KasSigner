#!/usr/bin/env python3
"""Full-scope mutation gate for the remaining native iOS shell.

Candidates are discovered from the live weather-cover components and native
infrastructure rather than a fixed allowlist. There is no parallel native wallet
layer and no per-file sampling. When Xcode is available, every viable semantic
mutant must be killed by the focused XCTest suite or fail-closed architecture
contracts.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import threading
import queue
import time
from typing import Optional

ROOT = Path(__file__).resolve().parents[3]
APP = ROOT / "apps/kassee-ios"
SOURCE = APP / "KasSigner"
SCOPE_ROOTS = (SOURCE / "Features/Cover/Components", SOURCE / "Infrastructure")
ARCH = ROOT / "qa/checks/ios/check_ios_architecture.py"
SKIP = 77
MINIMUM_SCORE_PERCENT = 100.0
DERIVED_DATA = ROOT / "target/ios/DerivedData"
RUNTIME_SYNC = ROOT / "scripts/mac/build/ios-runtime-sync.sh"
BASELINE_TIMEOUT_SECONDS = 900
MUTANT_TIMEOUT_SECONDS = 300


@dataclass(frozen=True)
class Rule:
    name: str
    pattern: re.Pattern[str]
    replacement: str


@dataclass(frozen=True)
class Mutant:
    path: Path
    rule: Rule
    start: int
    end: int
    after: str
    line: int


RULES = (
    Rule("equality", re.compile(r"=="), "!="),
    Rule("inequality", re.compile(r"!="), "=="),
    Rule("less-or-equal", re.compile(r"<="), "<"),
    Rule("greater-or-equal", re.compile(r">="), ">"),
    Rule("and-to-or", re.compile(r"&&"), "||"),
    Rule("or-to-and", re.compile(r"\|\|"), "&&"),
    Rule("true-to-false", re.compile(r"\btrue\b"), "false"),
    Rule("false-to-true", re.compile(r"\bfalse\b"), "true"),
    Rule("nil-equality", re.compile(r"==\s*nil"), "!= nil"),
    Rule("nil-inequality", re.compile(r"!=\s*nil"), "== nil"),
    Rule("zero-clamp", re.compile(r"max\(0,"), "max(1,"),
)


def lexical_mask(text: str) -> str:
    out = list(text)
    i = 0
    block = False
    string = False
    escaped = False
    while i < len(text):
        if block:
            if text.startswith("*/", i):
                out[i:i + 2] = "  "; i += 2; block = False
            else:
                if out[i] != "\n": out[i] = " "
                i += 1
            continue
        if string:
            ch = text[i]
            if escaped: escaped = False
            elif ch == "\\": escaped = True
            elif ch == '"': string = False
            if out[i] != "\n": out[i] = " "
            i += 1
            continue
        if text.startswith("//", i):
            while i < len(text) and text[i] != "\n": out[i] = " "; i += 1
            continue
        if text.startswith("/*", i): out[i:i + 2] = "  "; i += 2; block = True; continue
        if text[i] == '"': string = True; out[i] = " "; i += 1; continue
        i += 1
    return "".join(out)


def discover() -> tuple[list[Mutant], list[Path]]:
    files = sorted(path for root in SCOPE_ROOTS for path in root.rglob("*.swift"))
    mutants: list[Mutant] = []
    for path in files:
        text = path.read_text(encoding="utf-8")
        masked = lexical_mask(text)
        candidates: list[tuple[int, int, int, Rule, re.Match[str]]] = []
        for priority, rule in enumerate(RULES):
            for match in rule.pattern.finditer(masked):
                candidates.append((match.start(), -(match.end() - match.start()), priority, rule, match))
        occupied: list[tuple[int, int]] = []
        for _start, _neg_width, _priority, rule, match in sorted(candidates):
            if any(match.start() < end and start < match.end() for start, end in occupied):
                continue
            occupied.append((match.start(), match.end()))
            mutants.append(Mutant(path, rule, match.start(), match.end(), rule.replacement,
                                  text.count("\n", 0, match.start()) + 1))
    return mutants, files


def run(command: list[str], timeout: int = 600) -> subprocess.CompletedProcess[str]:
    process = subprocess.Popen(
        command,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=(os.name != "nt"),
    )
    try:
        output, _ = process.communicate(timeout=timeout)
        return subprocess.CompletedProcess(command, process.returncode, output or "")
    except subprocess.TimeoutExpired:
        if os.name == "nt":
            process.kill()
        else:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        try:
            output, _ = process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            if os.name == "nt":
                process.kill()
            else:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            output, _ = process.communicate()
        output = output or ""
        output += f"\nERROR: command timed out after {timeout}s: {' '.join(command)}\n"
        return subprocess.CompletedProcess(command, 124, output)


def xctest_verdict(output: str) -> Optional[bool]:
    """Return True for a completed passing suite, False for completed test failures.

    A verdict is accepted only after XCTest's aggregate ``All tests`` suite has
    printed an execution summary with at least one executed test.  Build errors,
    simulator launch failures, and zero-test runs intentionally return None so
    the caller continues waiting for xcodebuild's real exit status.
    """
    summaries = re.findall(
        r"Test Suite 'All tests' (passed|failed) at .*?\n\s*Executed (\d+) tests?, with (\d+) failures?",
        output,
        flags=re.DOTALL,
    )
    if not summaries:
        return None
    status, executed_text, failures_text = summaries[-1]
    executed = int(executed_text)
    failures = int(failures_text)
    if executed <= 0:
        return None
    if status == "passed" and failures == 0:
        return True
    if status == "failed" and failures > 0:
        return False
    return None


def _terminate_process_group(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    if os.name == "nt":
        process.terminate()
    else:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        if os.name == "nt":
            process.kill()
        else:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        process.wait()


def run_xctest(command: list[str], *, timeout: int, stop_on_verdict: bool) -> subprocess.CompletedProcess[str]:
    """Run xcodebuild while observing XCTest's aggregate verdict in real time.

    During mutation execution XCTest failure is the expected signal that a
    mutant was killed.  Xcode can spend minutes finalizing result bundles after
    XCTest has already printed a conclusive aggregate summary.  Once that
    summary is present, stop waiting for post-test cleanup and return the
    semantic test verdict.  Baseline execution still waits for xcodebuild's
    normal exit so infrastructure failures remain visible.
    """
    process = subprocess.Popen(
        command,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=1,
        start_new_session=(os.name != "nt"),
    )
    assert process.stdout is not None
    lines: queue.Queue = queue.Queue()

    def reader() -> None:
        try:
            for line in process.stdout:
                lines.put(line)
        finally:
            lines.put(None)

    threading.Thread(target=reader, daemon=True).start()
    output_parts: list[str] = []
    deadline = time.monotonic() + timeout
    stream_closed = False

    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _terminate_process_group(process)
            output = "".join(output_parts)
            output += f"\nERROR: command timed out after {timeout}s: {' '.join(command)}\n"
            return subprocess.CompletedProcess(command, 124, output)
        try:
            item = lines.get(timeout=min(1.0, remaining))
        except queue.Empty:
            if process.poll() is not None and stream_closed:
                break
            continue
        if item is None:
            stream_closed = True
            if process.poll() is not None:
                break
            continue
        output_parts.append(item)
        if stop_on_verdict and "Executed " in item and "tests" in item:
            verdict = xctest_verdict("".join(output_parts[-20:]))
            if verdict is not None:
                _terminate_process_group(process)
                output = "".join(output_parts)
                output += "\nMutation harness: accepted completed XCTest aggregate verdict; skipped xcodebuild post-test finalization.\n"
                return subprocess.CompletedProcess(command, 0 if verdict else 1, output)

    return subprocess.CompletedProcess(command, process.returncode or 0, "".join(output_parts))


def prepare_runtime() -> subprocess.CompletedProcess[str]:
    return run(["/bin/bash", str(RUNTIME_SYNC)], BASELINE_TIMEOUT_SECONDS)


def xcode_unit_tests(*, timeout: int, stop_on_verdict: bool = False) -> subprocess.CompletedProcess[str]:
    destination = os.environ.get(
        "KASSIGNER_IOS_TEST_DESTINATION",
        "platform=iOS Simulator,name=iPhone 16 Pro",
    )
    DERIVED_DATA.mkdir(parents=True, exist_ok=True)
    command = [
        "xcodebuild", "-project", str(APP / "KasSigner.xcodeproj"), "-scheme", "KasSigner",
        "-configuration", "Debug", "-destination", destination,
        "-derivedDataPath", str(DERIVED_DATA),
        "KASSIGNER_IOS_RUNTIME_SYNCED=1",
        "-only-testing:KasSignerAppTests", "test",
    ]
    return run_xctest(command, timeout=timeout, stop_on_verdict=stop_on_verdict)


def architecture() -> subprocess.CompletedProcess[str]:
    return run([sys.executable, str(ARCH)], 180)


def main() -> int:
    mutants, files = discover()
    if not files or not mutants:
        print("ERROR: iOS full-scope mutation discovery found no production files/mutants.")
        return 1
    if not shutil.which("swift"):
        print("SKIP: Swift toolchain unavailable for iOS mutation execution.")
        return SKIP
    if not shutil.which("xcodebuild"):
        base = architecture()
        if base.returncode:
            print(base.stdout, end="")
            return base.returncode
        print(f"iOS mutation scope: {len(files)} live native security/weather files scanned; {len(mutants)} semantic mutation sites discovered.")
        print("SKIP: full iOS mutation execution requires Xcode; source architecture/parse baseline is green.")
        return SKIP

    runtime = prepare_runtime()
    if runtime.returncode:
        print("ERROR: iOS mutation baseline failed: KasSee runtime sync")
        print(runtime.stdout, end="")
        return 1

    for label, result in (
        ("architecture", architecture()),
        ("XCTest", xcode_unit_tests(timeout=BASELINE_TIMEOUT_SECONDS)),
    ):
        if result.returncode:
            print(f"ERROR: iOS mutation baseline failed: {label}")
            print(result.stdout, end="")
            return 1

    killed = 0
    survivors: list[Mutant] = []
    for index, mutant in enumerate(mutants, 1):
        original = mutant.path.read_text(encoding="utf-8")
        mutant.path.write_text(original[:mutant.start] + mutant.after + original[mutant.end:], encoding="utf-8")
        try:
            contract = architecture()
            if contract.returncode == 124:
                print(contract.stdout, end="")
                print(f"ERROR: iOS mutation infrastructure timed out during architecture check for mutant {index}/{len(mutants)}.")
                return 1
            if contract.returncode:
                survives = False
            else:
                tests = xcode_unit_tests(timeout=MUTANT_TIMEOUT_SECONDS, stop_on_verdict=True)
                if tests.returncode == 124:
                    print(tests.stdout, end="")
                    print(f"ERROR: iOS mutation infrastructure timed out during XCTest for mutant {index}/{len(mutants)}; mutant was not counted as killed.")
                    return 1
                survives = tests.returncode == 0
        finally:
            mutant.path.write_text(original, encoding="utf-8")
        label = f"{mutant.path.relative_to(ROOT)}:{mutant.line} {mutant.rule.name}"
        if survives:
            survivors.append(mutant)
            print(f"FAIL mutant {index}/{len(mutants)} survived: {label}")
        else:
            killed += 1
            print(f"PASS mutant {index}/{len(mutants)} killed: {label}")
    score = killed * 100.0 / len(mutants)
    if score < MINIMUM_SCORE_PERCENT or survivors:
        print(f"ERROR: iOS full-scope mutation score {killed}/{len(mutants)} ({score:.2f}%); 100% required.")
        return 1
    print(f"PASS: iOS live native security/weather mutation gate ({killed}/{len(mutants)} killed; {score:.2f}%).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
