from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import urllib.error
import urllib.request


def load_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or not key or not value:
            raise ValueError(f"invalid environment assignment: {raw}")
        values[key] = value
    return values


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


NETWORK_ATTEMPTS = 6
NETWORK_RETRY_DELAYS = (1, 2, 4, 8, 16)


def _retryable_network_error(error: BaseException) -> bool:
    if isinstance(error, urllib.error.HTTPError):
        return error.code == 429 or 500 <= error.code < 600
    return isinstance(error, (urllib.error.URLError, TimeoutError, ConnectionError))


def _network_attempt(label: str, operation):
    last_error: BaseException | None = None
    for attempt in range(1, NETWORK_ATTEMPTS + 1):
        try:
            return operation()
        except Exception as error:  # normalized below; non-network errors are re-raised
            if not _retryable_network_error(error):
                raise
            last_error = error
            if attempt >= NETWORK_ATTEMPTS:
                break
            delay = NETWORK_RETRY_DELAYS[min(attempt - 1, len(NETWORK_RETRY_DELAYS) - 1)]
            print(
                f"  transient network failure during {label} "
                f"(attempt {attempt}/{NETWORK_ATTEMPTS}): {error}; retrying",
                flush=True,
            )
            time.sleep(delay)
    raise RuntimeError(
        f"{label} failed after {NETWORK_ATTEMPTS} attempts: {last_error}"
    ) from last_error


def atomic_download(url: str, destination: Path, headers: dict[str, str] | None = None) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".part")
    request_headers = headers or {"User-Agent": "KasSigner-reproducible-prefetch/1"}

    def fetch() -> None:
        temporary.unlink(missing_ok=True)
        request = urllib.request.Request(url, headers=request_headers)
        try:
            with urllib.request.urlopen(request, timeout=120) as response, temporary.open("wb") as output:
                shutil.copyfileobj(response, output)
            temporary.replace(destination)
        finally:
            temporary.unlink(missing_ok=True)

    _network_attempt(f"download {url}", fetch)


def download_json(url: str, headers: dict[str, str] | None = None) -> dict[str, object]:
    request_headers = headers or {"User-Agent": "KasSigner-reproducible-prefetch/1"}

    def fetch() -> dict[str, object]:
        request = urllib.request.Request(url, headers=request_headers)
        with urllib.request.urlopen(request, timeout=120) as response:
            value = json.load(response)
        if not isinstance(value, dict):
            raise RuntimeError(f"expected JSON object from {url}")
        return value

    return _network_attempt(f"request {url}", fetch)


def run(command: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None) -> None:
    printable = " ".join(command)
    print(f"  + {printable}")
    result = subprocess.run(command, cwd=cwd, env=env)
    if result.returncode != 0:
        raise RuntimeError(f"command failed with exit {result.returncode}: {printable}")


def require_command(name: str) -> str:
    value = shutil.which(name)
    if value is None:
        raise RuntimeError(f"required host command not found: {name}")
    return value


def deterministic_file_manifest(root: Path, output: Path, *, exclude: set[Path] | None = None) -> None:
    excluded = exclude or set()
    lines: list[str] = []
    for path in sorted(candidate for candidate in root.rglob("*") if candidate.is_file()):
        relative = path.relative_to(root)
        if relative in excluded:
            continue
        lines.append(f"{sha256_file(path)}  {relative.as_posix()}")
    output.write_text("\n".join(lines) + ("\n" if lines else ""))



def verify_file_manifest(root: Path, manifest: Path) -> None:
    for raw in manifest.read_text().splitlines():
        if not raw.strip():
            continue
        expected, separator, relative = raw.partition("  ")
        if not separator or len(expected) != 64:
            raise RuntimeError(f"invalid SHA-256 manifest row: {raw}")
        path = root / relative
        if not path.is_file():
            raise RuntimeError(f"prefetched input is missing: {relative}")
        actual = sha256_file(path)
        if actual != expected:
            raise RuntimeError(f"prefetched input SHA-256 mismatch for {relative}: expected {expected}, got {actual}")

def clean_environment(home: Path) -> dict[str, str]:
    env = dict(os.environ)
    env.update(
        {
            "HOME": str(home),
            "CARGO_HOME": str(home / ".cargo"),
            "RUSTUP_HOME": str(home / ".rustup"),
            "CARGO_TERM_COLOR": "never",
        }
    )
    return env
