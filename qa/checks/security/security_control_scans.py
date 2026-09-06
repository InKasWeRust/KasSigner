"""Source scanners used by the internal security control-evidence gate."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[3]

OFFLINE_FORBIDDEN = (
    "web-sys",
    "web_sys",
    "wasm-bindgen",
    "wasm_bindgen",
    "reqwest",
    "tokio",
    "tungstenite",
    "std::net",
    "TcpStream",
    "UdpSocket",
)

PRODUCTION_REVIEW_ROOTS = (
    "apps/signer-firmware/src",
    "crates/signer-firmware-core/src",
    "crates/shared-signer/src",
    "crates/offline-signer/src",
    "crates/online-watcher/src",
)
UNSAFE_MANIFEST = ROOT / "qa/checks/security/review/unsafe_sites.json"
PANIC_MANIFEST = ROOT / "qa/checks/security/review/panic_sites.json"
UNSAFE_PATTERN = re.compile(r"\bunsafe\s*(?:\{|fn\b)")


SECRET_IDENTIFIERS = re.compile(
    r"\b(seed|mnemonic|private_key|secret_key|xprv|entropy_pool|signing_entropy|raw_key)\b",
    re.IGNORECASE,
)
STRING_LITERAL = re.compile(r'"(?:\\.|[^"\\])*"')
PANIC_PATTERN = re.compile(r"\.(?:unwrap|expect)\(|\b(?:panic|unreachable)!\(")


def relative(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def rust_files(roots: Iterable[str]) -> list[Path]:
    files: set[Path] = set()
    for root in roots:
        path = ROOT / root
        if path.is_file() and path.suffix == ".rs":
            files.add(path)
        elif path.is_dir():
            files.update(path.rglob("*.rs"))
    return sorted(files)




def is_production_source(path: Path) -> bool:
    relative_path = relative(path)
    return (
        "/unit_tests/" not in f"/{relative_path}"
        and "/tests/" not in f"/{relative_path}"
        and not path.name.endswith("_tests.rs")
        and path.name != "tests.rs"
    )


def collect_text(relative_path: str) -> tuple[list[str], str]:
    path = ROOT / relative_path
    if path.is_file():
        return [relative_path], path.read_text(encoding="utf-8", errors="replace")
    return [], ""


def extract_macro_calls(text: str, macro: str) -> list[str]:
    marker = f"{macro}!"
    calls: list[str] = []
    start = 0
    while True:
        index = text.find(marker, start)
        if index < 0:
            break
        open_index = text.find("(", index + len(marker))
        if open_index < 0:
            break
        depth = 0
        quote = False
        escaped = False
        for cursor in range(open_index, len(text)):
            char = text[cursor]
            if quote:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    quote = False
                continue
            if char == '"':
                quote = True
            elif char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    calls.append(text[index : cursor + 1])
                    start = cursor + 1
                    break
        else:
            break
    return calls


def strip_cfg_test_regions(text: str) -> str:
    """Blank #[cfg(test)] modules while preserving line numbering."""
    chars = list(text)
    for match in list(re.finditer(r"#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]", text)):
        mod_index = text.find("mod", match.end())
        brace = text.find("{", mod_index if mod_index >= 0 else match.end())
        if mod_index < 0 or brace < 0:
            continue
        depth = 0
        quote = None
        escaped = False
        end = None
        for i in range(brace, len(text)):
            ch = text[i]
            if quote:
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == quote:
                    quote = None
                continue
            if ch == '"':
                quote = ch
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break
        if end is not None:
            for i in range(match.start(), end):
                if chars[i] != "\n":
                    chars[i] = " "
    return "".join(chars)


def site_fingerprint(path: Path, line_number: int, source: str) -> str:
    import hashlib
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    lo = max(0, line_number - 2)
    hi = min(len(lines), line_number + 1)
    context = "\n".join(line.strip() for line in lines[lo:hi])
    return hashlib.sha256((relative(path) + "\n" + source.strip() + "\n" + context).encode()).hexdigest()


def load_review_manifest(path: Path) -> dict[tuple[str, int, str], dict[str, Any]]:
    import json
    if not path.is_file():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    return {(item["path"], int(item["line"]), item["fingerprint"]): item for item in data.get("sites", [])}


def reviewed_sites(pattern: re.Pattern[str], manifest_path: Path) -> tuple[list[dict[str, Any]], list[str]]:
    manifest = load_review_manifest(manifest_path)
    observed: list[dict[str, Any]] = []
    errors: list[str] = []
    seen: set[tuple[str, int, str]] = set()
    for path in filter(is_production_source, rust_files(PRODUCTION_REVIEW_ROOTS)):
        original = path.read_text(encoding="utf-8", errors="replace")
        scanned = strip_cfg_test_regions(original)
        for number, line in enumerate(scanned.splitlines(), 1):
            if line.lstrip().startswith("//") or not pattern.search(line):
                continue
            source = original.splitlines()[number - 1].strip()
            fingerprint = site_fingerprint(path, number, source)
            key = (relative(path), number, fingerprint)
            review = manifest.get(key)
            item = {
                "path": relative(path),
                "line": number,
                "source": source,
                "fingerprint": fingerprint,
                "rationale": review.get("rationale") if review else None,
                "reviewed": review is not None and bool(review.get("rationale", "").strip()),
            }
            observed.append(item)
            seen.add(key)
            if not item["reviewed"]:
                errors.append(f"unreviewed source site in {relative(path)}:{number}: {source}")
    stale = sorted(set(manifest) - seen)
    for path, number, _ in stale:
        errors.append(f"stale reviewed source site no longer matches: {path}:{number}")
    return observed, errors



def strip_comment_only_evidence(text: str, suffix: str) -> str:
    """Blank comments while preserving strings and line numbers for evidence probes."""
    if suffix == ".rs":
        chars = list(text)
        i = 0
        block_depth = 0
        quote: str | None = None
        escaped = False
        while i < len(text):
            ch = text[i]
            nxt = text[i + 1] if i + 1 < len(text) else ""
            if block_depth:
                if ch == "/" and nxt == "*":
                    block_depth += 1
                    if chars[i] != "\n": chars[i] = " "
                    if chars[i + 1] != "\n": chars[i + 1] = " "
                    i += 2
                    continue
                if ch == "*" and nxt == "/":
                    block_depth -= 1
                    if chars[i] != "\n": chars[i] = " "
                    if chars[i + 1] != "\n": chars[i + 1] = " "
                    i += 2
                    continue
                if ch != "\n": chars[i] = " "
                i += 1
                continue
            if quote:
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == quote:
                    quote = None
                i += 1
                continue
            if ch == '"':
                quote = ch
                i += 1
                continue
            if ch == "/" and nxt == "/":
                while i < len(text) and text[i] != "\n":
                    chars[i] = " "
                    i += 1
                continue
            if ch == "/" and nxt == "*":
                block_depth = 1
                chars[i] = chars[i + 1] = " "
                i += 2
                continue
            i += 1
        return "".join(chars)
    lines = []
    for line in text.splitlines(keepends=True):
        stripped = line.lstrip()
        if (suffix in {".sh", ".ps1", ".py"} and stripped.startswith("#")) or stripped.startswith("<!--"):
            lines.append("\n" if line.endswith("\n") else "")
        else:
            lines.append(line)
    return "".join(lines)


def evidence_matches(relative_path: str, term: str) -> list[dict[str, Any]]:
    """Return non-comment, token-aware evidence locations and source fingerprints."""
    path = ROOT / relative_path
    if not path.is_file():
        return []
    original = path.read_text(encoding="utf-8", errors="replace")
    scanned = strip_comment_only_evidence(original, path.suffix.lower())
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", term):
        pattern = re.compile(rf"(?<![A-Za-z0-9_]){re.escape(term)}(?![A-Za-z0-9_])")
    else:
        pattern = re.compile(re.escape(term))
    original_lines = original.splitlines()
    matches: list[dict[str, Any]] = []
    for match in pattern.finditer(scanned):
        line_number = scanned.count("\n", 0, match.start()) + 1
        line = original_lines[line_number - 1] if line_number <= len(original_lines) else ""
        matches.append({
            "term": term,
            "line": line_number,
            "fingerprint": site_fingerprint(path, line_number, line.strip()),
        })
    return matches

def source_scans() -> tuple[list[str], dict[str, Any]]:
    errors: list[str] = []

    offline_files = [
        ROOT / "crates/offline-signer/Cargo.toml",
        ROOT / "crates/shared-signer/Cargo.toml",
        ROOT / "crates/signer-firmware-core/Cargo.toml",
        *rust_files((
            "crates/offline-signer/src",
            "crates/shared-signer/src",
            "crates/signer-firmware-core/src",
        )),
    ]
    network_hits: list[dict[str, Any]] = []
    for path in offline_files:
        text = path.read_text(encoding="utf-8", errors="replace")
        for term in OFFLINE_FORBIDDEN:
            if term in text:
                network_hits.append({"path": relative(path), "term": term})
                errors.append(f"offline boundary: {relative(path)} contains {term!r}")

    unsafe_sites, unsafe_errors = reviewed_sites(UNSAFE_PATTERN, UNSAFE_MANIFEST)
    errors.extend(f"unsafe inventory: {error}" for error in unsafe_errors)

    panic_sites, panic_errors = reviewed_sites(PANIC_PATTERN, PANIC_MANIFEST)
    errors.extend(f"panic inventory: {error}" for error in panic_errors)

    secret_log_sites: list[dict[str, Any]] = []
    for path in filter(
        is_production_source,
        rust_files(
        (
            "apps/signer-firmware/src/runtime",
            "apps/signer-firmware/src/services",
            "crates/offline-signer/src",
            "crates/shared-signer/src",
            "crates/signer-firmware-core/src",
        )
        ),
    ):
        for call in extract_macro_calls(path.read_text(encoding="utf-8", errors="replace"), "log"):
            arguments_without_messages = STRING_LITERAL.sub("", call)
            match = SECRET_IDENTIFIERS.search(arguments_without_messages)
            if match:
                site = {
                    "path": relative(path),
                    "identifier": match.group(0),
                    "call": " ".join(call.split())[:240],
                }
                secret_log_sites.append(site)
                errors.append(
                    f"secret-bearing log argument {match.group(0)!r} in {relative(path)}"
                )

    scans = {
        "offline_network_boundary": {"hits": network_hits, "met": not network_hits},
        "unsafe_inventory": {
            "sites": unsafe_sites,
            "unreviewed": sum(not item["reviewed"] for item in unsafe_sites),
            "met": not unsafe_errors,
        },
        "panic_inventory": {
            "sites": panic_sites,
            "unreviewed": sum(not item["reviewed"] for item in panic_sites),
            "met": not panic_errors,
        },
        "secret_log_arguments": {"sites": secret_log_sites, "met": not secret_log_sites},
    }
    return errors, scans


