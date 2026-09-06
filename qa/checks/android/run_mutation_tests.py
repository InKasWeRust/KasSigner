#!/usr/bin/env python3
"""Full-scope Android mutation gate for domain/ and infrastructure/.

Unlike the former eight-entry curated list, candidates are discovered from every
Kotlin source file under both production layers. Every non-overlapping semantic
mutation site is included; there is no per-file sampling or file allowlist. Every
viable mutant must be killed by the real Gradle JUnit/Robolectric suite or an
architecture contract.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
APP = ROOT / "apps/kassee-android"
SOURCE = APP / "app/src/main/java/org/kassigner/kassigner"
SCOPE_ROOTS = (SOURCE / "domain", SOURCE / "infrastructure")
ARCH = ROOT / "qa/checks/android/check_android_architecture.py"
PORTABLE = ROOT / "qa/checks/android/run_core_tests.py"
MINIMUM_SCORE_PERCENT = 100.0
SKIP = 77
IS_WINDOWS = os.name == "nt" or sys.platform.startswith("win")


def _toolchain_value(name: str) -> str | None:
    value = os.environ.get(name)
    if value:
        return value.strip()
    config = ROOT / "qa/config/toolchains.env"
    if not config.is_file():
        return None
    for raw in config.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, candidate = line.partition("=")
        if sep and key.strip() == name:
            return candidate.strip()
    return None


def _required_gradle_java_major() -> int | None:
    central = _toolchain_value("KASSIGNER_ANDROID_JDK")
    daemon = APP / "gradle/gradle-daemon-jvm.properties"
    daemon_version: str | None = None
    if daemon.is_file():
        for raw in daemon.read_text(encoding="utf-8", errors="replace").splitlines():
            key, sep, value = raw.partition("=")
            if sep and key.strip() == "toolchainVersion":
                daemon_version = value.strip()
                break
    if not central or not central.isdigit() or not daemon_version or not daemon_version.isdigit():
        return None
    if central != daemon_version:
        return None
    return int(central)


def _java_major(java: Path) -> int | None:
    if not java.is_file():
        return None
    try:
        result = subprocess.run(
            [str(java), "-version"], cwd=ROOT, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode:
        return None
    match = re.search(r'version\s+"(?:(?:1\.)?)(\d+)', result.stdout)
    return int(match.group(1)) if match else None


def configure_gradle_java() -> bool:
    """Select the exact repository-pinned JVM for Gradle mutation execution.

    The normal Android QA build immediately before mutation auto-provisions the
    managed JDK. Mutation runs are launched by the Python master runner, so they
    must re-select that JDK instead of inheriting an unrelated system Java.
    """
    required = _required_gradle_java_major()
    if required is None:
        return False
    home = _user_home()
    candidates: list[Path] = []
    if home is not None:
        if IS_WINDOWS:
            candidates.append(home / f".kassigner/tools/jdk-{required}/bin/java.exe")
        else:
            candidates.append(home / f".local/share/kassigner/jdk-{required}/bin/java")
    java_home = os.environ.get("JAVA_HOME")
    if java_home:
        candidates.append(Path(java_home) / "bin" / ("java.exe" if IS_WINDOWS else "java"))
    path_java = shutil.which("java")
    if path_java:
        candidates.append(Path(path_java))

    seen: set[str] = set()
    for candidate in candidates:
        key = str(candidate).casefold() if IS_WINDOWS else str(candidate)
        if key in seen:
            continue
        seen.add(key)
        if _java_major(candidate) != required:
            continue
        java_bin = candidate.parent
        os.environ["JAVA_HOME"] = str(java_bin.parent)
        current = os.environ.get("PATH", "")
        entries = current.split(os.pathsep) if current else []
        normalized = {entry.casefold() if os.name == "nt" else entry for entry in entries}
        java_bin_text = str(java_bin)
        compare = java_bin_text.casefold() if IS_WINDOWS else java_bin_text
        if compare not in normalized:
            os.environ["PATH"] = java_bin_text + (os.pathsep + current if current else "")
        return True
    return False


def _user_home() -> Path | None:
    """Resolve a user home without assuming pathlib can query the host shell.

    Native Windows/MSYS Python can fail Path.home() when USERPROFILE is absent
    even though HOME is available. Prefer explicit environment homes and only
    fall back to pathlib. Callers must treat a missing home as optional.
    """
    for key in ("USERPROFILE", "HOME"):
        value = os.environ.get(key)
        if value:
            return Path(value).expanduser()
    if IS_WINDOWS:
        drive = os.environ.get("HOMEDRIVE", "")
        tail = os.environ.get("HOMEPATH", "")
        if drive and tail:
            return Path(drive + tail)
    try:
        return Path.home()
    except (OSError, RuntimeError):
        return None


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
    before: str
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
    Rule("empty-polarity", re.compile(r"\.isEmpty\(\)"), ".isNotEmpty()"),
    Rule("nonempty-polarity", re.compile(r"\.isNotEmpty\(\)"), ".isEmpty()"),
    Rule("zero-clamp", re.compile(r"coerceAtLeast\(0\)"), "coerceAtLeast(1)"),
)


def lexical_mask(text: str) -> str:
    """Preserve offsets while blanking Kotlin strings and comments."""
    out = list(text)
    i = 0
    block = False
    string: str | None = None
    escaped = False
    while i < len(text):
        if block:
            if text.startswith("*/", i):
                out[i:i + 2] = "  "
                i += 2
                block = False
            else:
                if out[i] != "\n": out[i] = " "
                i += 1
            continue
        if string is not None:
            ch = text[i]
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == string:
                string = None
            if out[i] != "\n": out[i] = " "
            i += 1
            continue
        if text.startswith("//", i):
            while i < len(text) and text[i] != "\n":
                out[i] = " "
                i += 1
            continue
        if text.startswith("/*", i):
            out[i:i + 2] = "  "
            i += 2
            block = True
            continue
        if text[i] in ('"', "'"):
            string = text[i]
            out[i] = " "
            i += 1
            continue
        i += 1
    return "".join(out)


def discover() -> tuple[list[Mutant], list[Path]]:
    mutants: list[Mutant] = []
    files = sorted(path for root in SCOPE_ROOTS for path in root.rglob("*.kt"))
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
            before = text[match.start():match.end()]
            mutants.append(Mutant(
                path=path, rule=rule, start=match.start(), end=match.end(), before=before,
                after=rule.replacement, line=text.count("\n", 0, match.start()) + 1,
            ))
    return mutants, files


def _read_local_sdk_dir() -> Path | None:
    properties = APP / "local.properties"
    if not properties.is_file():
        return None
    for raw in properties.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "!")):
            continue
        key, separator, value = line.partition("=")
        if separator and key.strip() == "sdk.dir":
            decoded = value.strip().replace(r"\ ", " ").replace(r"\:", ":").replace(r"\\", "\\")
            return Path(os.path.expanduser(decoded))
    return None


def _api37_jar(root: Path) -> Path | None:
    platforms = root / "platforms"
    if not platforms.is_dir():
        return None
    for candidate in sorted(platforms.glob("android-*")):
        jar = candidate / "android.jar"
        if not jar.is_file():
            continue
        api: int | None = None
        properties = candidate / "source.properties"
        if properties.is_file():
            match = re.search(
                r"(?m)^AndroidVersion\.ApiLevel\s*=\s*(\d+)\s*$",
                properties.read_text(encoding="utf-8", errors="replace"),
            )
            if match:
                api = int(match.group(1))
        if api is None:
            match = re.fullmatch(r"android-(\d+)(?:\.\d+)?", candidate.name)
            if match:
                api = int(match.group(1))
        if api == 37:
            return jar
    return None


def android_sdk_root() -> Path | None:
    candidates: list[Path] = []
    for value in (
        os.environ.get("KASSIGNER_ANDROID_SDK_ROOT"),
        os.environ.get("ANDROID_SDK_ROOT"),
        os.environ.get("ANDROID_HOME"),
    ):
        if value:
            candidates.append(Path(value).expanduser())
    local = _read_local_sdk_dir()
    if local is not None:
        candidates.append(local)
    home = _user_home()
    if home is not None:
        candidates.extend((
            home / "Android/Sdk",
            home / "Android/sdk",
            home / ".android/sdk",
        ))
    candidates.extend((
        Path("/mnt/Extra/android-dev/sdk"),
        Path("/opt/android-sdk"),
        Path("/usr/local/android-sdk"),
        Path("/usr/local/lib/android/sdk"),
        Path("/usr/lib/android-sdk"),
    ))
    seen: set[Path] = set()
    for candidate in candidates:
        try:
            resolved = candidate.resolve()
        except OSError:
            resolved = candidate
        if resolved in seen:
            continue
        seen.add(resolved)
        if _api37_jar(resolved) is not None:
            return resolved
    return None


def _pinned_gradle_version() -> str | None:
    properties = APP / "gradle/wrapper/gradle-wrapper.properties"
    if not properties.is_file():
        return None
    match = re.search(
        r"(?m)^distributionUrl=.*?/gradle-([0-9]+(?:\.[0-9]+)*)-(?:bin|all)\.zip(?:[?#].*)?$",
        properties.read_text(encoding="utf-8", errors="replace"),
    )
    return match.group(1) if match else None


def _gradle_version(command: str) -> str | None:
    try:
        result = subprocess.run(
            [command, "--version"], cwd=ROOT, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode:
        return None
    match = re.search(r"(?m)^Gradle\s+([^\s]+)", result.stdout)
    return match.group(1) if match else None


def _usable_gradle(candidate: str | Path, version: str) -> str | None:
    text = str(candidate)
    path = Path(text).expanduser()
    if path.is_absolute() or path.parent != Path("."):
        if not path.is_file():
            return None
        if not IS_WINDOWS and not os.access(path, os.X_OK):
            return None
        resolved = str(path)
    else:
        resolved = shutil.which(text) or ""
        if not resolved:
            return None
    return resolved if _gradle_version(resolved) == version else None


def gradle_binary() -> str | None:
    """Return only the repository-pinned Gradle version.

    The normal Android wrapper provisions Gradle into the KasSigner cache. The
    later mutation phase runs in the Python master process and must not silently
    switch to an arbitrary global Gradle that happens to be earlier on PATH.
    """
    version = _pinned_gradle_version()
    if version is None:
        return None
    requested = os.environ.get("GRADLE_BIN")
    if requested:
        return _usable_gradle(requested, version)

    gradle_homes: list[Path] = []
    if os.environ.get("GRADLE_USER_HOME"):
        gradle_homes.append(Path(os.environ["GRADLE_USER_HOME"]).expanduser())

    # Keep home-derived cache locations optional. GRADLE_USER_HOME remains
    # authoritative when provided; the shared resolver handles native Windows
    # and MSYS Python environments where pathlib.Path.home() can fail.
    home = _user_home()
    if home is not None:
        gradle_homes.append(home / ".gradle")
    gradle_homes.append(Path("/mnt/Extra/android-dev/gradle"))

    candidates = [
        root / f"kassigner/distributions/gradle-{version}/bin/gradle"
        for root in gradle_homes
    ]
    if home is not None:
        candidates.append(home / f".local/share/kassigner/gradle-{version}/bin/gradle")
    if IS_WINDOWS:
        windows_candidates: list[Path] = []
        for candidate in candidates:
            windows_candidates.extend((candidate.with_suffix(".bat"), candidate.with_suffix(".exe")))
        candidates = windows_candidates + candidates
    for candidate in candidates:
        usable = _usable_gradle(candidate, version)
        if usable:
            return usable

    # A globally installed Gradle is an acceptable final fallback only when it
    # exactly matches the wrapper pin. Never allow an unverified host version.
    for name in (("gradle.bat", "gradle.exe", "gradle") if IS_WINDOWS else ("gradle",)):
        usable = _usable_gradle(name, version)
        if usable:
            return usable
    return None


def gradle_command() -> list[str] | None:
    gradle = gradle_binary()
    sdk = android_sdk_root()
    if not gradle or sdk is None or not configure_gradle_java():
        return None
    os.environ["ANDROID_SDK_ROOT"] = str(sdk)
    os.environ["ANDROID_HOME"] = str(sdk)
    # Run the real Gradle dependency graph. The Android app declares generated
    # KasSee assets through syncKasSeeWebUi; excluding that task (or one of its
    # runtime prerequisites) leaves mergeDebugAssets with an unresolved output
    # provider under Gradle 9.x. These tasks are incremental and become
    # UP-TO-DATE after the baseline, so mutation iterations do not need unsafe
    # task exclusions.
    return [
        gradle, "--project-dir", str(APP), "--no-daemon", ":app:testDebugUnitTest",
    ]


def portable_toolchain_available() -> bool:
    return shutil.which("kotlinc") is not None and shutil.which("java") is not None


def run(command: list[str], *, timeout: int = 420) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=ROOT, text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, timeout=timeout)


def baseline(command: list[str]) -> bool:
    checks: list[list[str]] = []
    if portable_toolchain_available():
        checks.append([sys.executable, str(PORTABLE)])
    else:
        print("INFO: standalone kotlinc/java portable smoke test unavailable; Gradle JUnit/Robolectric baseline remains authoritative.")
    checks.extend(([sys.executable, str(ARCH)], command))
    for check in checks:
        try:
            result = run(list(check))
        except subprocess.TimeoutExpired:
            print("ERROR: Android mutation baseline timed out.")
            return False
        if result.returncode:
            print("ERROR: Android mutation baseline is not green.")
            print(result.stdout, end="")
            return False
    return True


def mutant_survives(mutant: Mutant, command: list[str]) -> bool:
    original = mutant.path.read_text(encoding="utf-8")
    mutated = original[:mutant.start] + mutant.after + original[mutant.end:]
    mutant.path.write_text(mutated, encoding="utf-8")
    try:
        test = run(command)
        if test.returncode:
            return False
        architecture = run([sys.executable, str(ARCH)], timeout=120)
        return architecture.returncode == 0
    finally:
        mutant.path.write_text(original, encoding="utf-8")


def main() -> int:
    mutants, files = discover()
    if not files or not mutants:
        print("ERROR: Android full-scope mutation discovery found no production files/mutants.")
        return 1
    roots_seen = {part for path in files for part in ("domain", "infrastructure") if part in path.parts}
    if roots_seen != {"domain", "infrastructure"}:
        print("ERROR: Android mutation scope must include both domain/ and infrastructure/.")
        return 1
    print(f"Android mutation scope: {len(files)} files scanned; {len(mutants)} semantic mutation sites discovered.")
    command = gradle_command()
    if command is None:
        sdk = android_sdk_root()
        gradle = gradle_binary()
        if sdk is None:
            print("SKIP: Android mutation execution requires an Android SDK containing API 37; checked project local.properties, environment variables, and standard SDK locations.")
        elif gradle is None:
            print("SKIP: Android mutation execution requires pinned Gradle from PATH/GRADLE_BIN or the KasSigner Gradle cache; API 37 SDK was found.")
        elif not configure_gradle_java():
            required = _required_gradle_java_major()
            print(f"SKIP: Android mutation execution requires the repository-pinned Gradle JVM JDK {required or 'unknown'}; run the normal Android QA build bootstrap first.")
        else:
            print("SKIP: Android mutation Gradle command could not be prepared from the discovered API-37 toolchain.")
        return SKIP
    if not baseline(command):
        return 1

    killed = 0
    survivors: list[Mutant] = []
    for index, mutant in enumerate(mutants, 1):
        try:
            survives = mutant_survives(mutant, command)
        except subprocess.TimeoutExpired:
            killed += 1
            label = f"{mutant.path.relative_to(ROOT)}:{mutant.line} {mutant.rule.name}"
            print(f"PASS mutant {index}/{len(mutants)} killed by timeout: {label}")
            continue
        label = f"{mutant.path.relative_to(ROOT)}:{mutant.line} {mutant.rule.name}"
        if survives:
            survivors.append(mutant)
            print(f"FAIL mutant {index}/{len(mutants)} survived: {label}")
        else:
            killed += 1
            print(f"PASS mutant {index}/{len(mutants)} killed: {label}")
    score = killed * 100.0 / len(mutants)
    if score < MINIMUM_SCORE_PERCENT or survivors:
        print(f"ERROR: Android full-scope mutation score {killed}/{len(mutants)} ({score:.2f}%); 100% required.")
        return 1
    print(f"PASS: Android full domain/infrastructure mutation gate ({killed}/{len(mutants)} killed; {score:.2f}%).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
