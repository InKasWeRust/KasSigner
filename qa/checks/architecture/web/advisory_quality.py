"""Warning-only web DOM dependency and interaction-flow checks."""

from __future__ import annotations

from pathlib import Path
import re
import subprocess

DOM_ID_RE = re.compile(r'''\bid=["']([^"']+)["']''')
EL_RE = re.compile(r'''context\.el\(\s*["']([^"']+)["']\s*\)\s*[.[]''')
GUARD_RE = re.compile(r'''if\s*\(\s*context\.el\(\s*["']([^"']+)["']''')


def _relative(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def _declared_dom_ids(root: Path) -> set[str]:
    ids: set[str] = set()
    roots = (
        root / "apps/kassee-web/web/html",
        root / "apps/kassee-web/web/js",
    )
    for source_root in roots:
        suffix = ".html" if source_root.name == "html" else ".js"
        for path in source_root.rglob(f"*{suffix}"):
            for dom_id in DOM_ID_RE.findall(path.read_text(errors="ignore")):
                if "${" not in dom_id:
                    ids.add(dom_id)
    return ids


def _guarded(lines: list[str], line_index: int, dom_id: str) -> bool:
    for candidate in lines[max(0, line_index - 1):line_index + 1]:
        match = GUARD_RE.search(candidate)
        if match and match.group(1) == dom_id:
            return True
    return False


def _dom_dependency_warnings(root: Path) -> list[str]:
    declared = _declared_dom_ids(root)
    warnings: list[str] = []
    js_root = root / "apps/kassee-web/web/js"
    for path in sorted(js_root.rglob("*.js")):
        if "lib" in path.parts or "pkg" in path.parts:
            continue
        source = path.read_text(errors="ignore")
        lines = source.splitlines()
        for match in EL_RE.finditer(source):
            dom_id = match.group(1)
            if "${" in dom_id or dom_id in declared:
                continue
            line_index = source.count("\n", 0, match.start())
            if _guarded(lines, line_index, dom_id):
                continue
            warnings.append(
                "ARCH-W011 required DOM dependency is not declared: "
                f"{_relative(root, path)}:{line_index + 1}::{dom_id}"
            )
    return warnings


def _interaction_flow_warnings(root: Path) -> list[str]:
    checks = (
        ("browser-feature-interactions", ["node", "qa/checks/web/check_web_covenant_interactions.mjs"]),
    )
    warnings: list[str] = []
    for name, command in checks:
        try:
            result = subprocess.run(
                command,
                cwd=root,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            warnings.append(f"ARCH-W012 interaction-flow check unavailable: {name}: {error}")
            continue
        if result.returncode:
            detail = (result.stderr or result.stdout).strip().splitlines()
            suffix = detail[-1] if detail else f"exit {result.returncode}"
            warnings.append(f"ARCH-W012 interaction-flow check failed: {name}: {suffix}")
    return warnings


def _unused_css_selector_warnings(root: Path) -> list[str]:
    css_root = root / "apps/kassee-web/web/css/app"
    consumer_roots = (root / "apps/kassee-web/web/html", root / "apps/kassee-web/web/js")
    consumers = "\n".join(
        path.read_text(errors="ignore")
        for source_root in consumer_roots
        for path in source_root.rglob("*")
        if path.is_file() and path.suffix in {".html", ".js"}
        and "lib" not in path.parts and "pkg" not in path.parts
    )
    warnings: list[str] = []
    seen: set[str] = set()
    selector_re = re.compile(r"(?<![\w-])\.([A-Za-z_][\w-]*)")
    for path in sorted(css_root.rglob("*.css")):
        source = path.read_text(errors="ignore")
        for match in selector_re.finditer(source):
            name = match.group(1)
            if name in seen:
                continue
            seen.add(name)
            if re.search(rf"(?<![\w-]){re.escape(name)}(?![\w-])", consumers):
                continue
            line = source.count("\n", 0, match.start()) + 1
            warnings.append(
                "ARCH-W017 authored CSS selector has no HTML/JavaScript consumer: "
                f"{_relative(root, path)}:{line}::.{name}"
            )
    return warnings


def check(root: Path) -> list[str]:
    return sorted([
        *_dom_dependency_warnings(root),
        *_interaction_flow_warnings(root),
        *_unused_css_selector_warnings(root),
    ])
