"""Warning-only detection for retained commented implementation code."""

from __future__ import annotations

from pathlib import Path
import re

from architecture.core.source_quality import production_sources

MIN_COMMENTED_CODE_LINES = 8


def _relative(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def _comment_code_score(comment: str) -> tuple[int, int, int]:
    code_lines = 0
    meaningful_lines = 0
    structural_lines = 0
    statement_patterns = (
        r"^(?:pub\s+)?(?:async\s+)?fn\s+[A-Za-z_]",
        r"^(?:let|const|var)\s+[A-Za-z_$].*;?$",
        r"^(?:if|for|while|match)\s*(?:\(|[A-Za-z_]).*\{?$",
        r"^return\b.*;?$",
        r"^(?:impl|struct|enum|class)\s+[A-Za-z_]",
        r"^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*\s*\([^)]*\)\s*;$",
        r"^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*\s*=.*;$",
        r"^(?:\{|\}|\};|\}\);)$",
    )
    structural_patterns = (r";\s*$", r"^(?:\{|\}|\};|\}\);)$", r"=>")
    for raw_line in comment.splitlines():
        line = raw_line.strip().lstrip("*").strip()
        if not line or re.fullmatch(r"[-=─]+", line):
            continue
        meaningful_lines += 1
        if any(re.search(pattern, line) for pattern in statement_patterns):
            code_lines += 1
        if any(re.search(pattern, line) for pattern in structural_patterns):
            structural_lines += 1
    return code_lines, meaningful_lines, structural_lines


def _looks_like_commented_implementation(comment: str) -> bool:
    code_lines, meaningful_lines, structural_lines = _comment_code_score(comment)
    return (
        code_lines >= 6
        and structural_lines >= 4
        and meaningful_lines > 0
        and code_lines / meaningful_lines >= 0.60
    )


def _large_commented_code_warnings(root: Path) -> list[str]:
    warnings: list[str] = []
    for path in production_sources(root):
        source = path.read_text(errors="ignore")
        for match in re.finditer(r"/\*(?!\*)(.*?)\*/", source, re.S):
            comment = match.group(1)
            line_count = comment.count("\n") + 1
            if line_count >= MIN_COMMENTED_CODE_LINES and _looks_like_commented_implementation(comment):
                line_number = source.count("\n", 0, match.start()) + 1
                warnings.append(
                    f"ARCH-W006 possible block-commented implementation: "
                    f"{_relative(root, path)}:{line_number} ({line_count} comment lines)"
                )
        lines = source.splitlines()
        start: int | None = None
        content: list[str] = []
        for index, line in enumerate([*lines, ""], start=1):
            stripped = line.lstrip()
            if stripped.startswith("//") and not stripped.startswith("///"):
                if start is None:
                    start = index
                content.append(stripped[2:])
                continue
            if start is not None and len(content) >= MIN_COMMENTED_CODE_LINES:
                comment = "\n".join(content)
                if _looks_like_commented_implementation(comment):
                    warnings.append(
                        f"ARCH-W006 possible line-commented implementation: "
                        f"{_relative(root, path)}:{start} ({len(content)} comment lines)"
                    )
            start = None
            content = []
    return warnings


SMALL_JS_CODE = re.compile(
    r"^(?:"
    r"(?:context\.)?el\([^)]*\)\.(?:onclick|onchange|oninput)\s*="
    r"|[A-Za-z_$][\w$]*\.addEventListener\("
    r"|(?:import|export)\s+"
    r"|(?:export\s+)?(?:async\s+)?function\s+[A-Za-z_$]"
    r")"
)
SMALL_HTML_CODE = re.compile(
    r"<(?:button|input|select|textarea|div|section|form)\b[^>]*(?:\bid=|\bonclick=)",
    re.I | re.S,
)


def _small_commented_code_warnings(root: Path) -> list[str]:
    warnings: list[str] = []
    js_root = root / "apps/kassee-web/web/js"
    for path in sorted(js_root.rglob("*.js")) if js_root.exists() else ():
        for index, line in enumerate(path.read_text(errors="ignore").splitlines(), start=1):
            stripped = line.lstrip()
            if not stripped.startswith("//") or stripped.startswith("///"):
                continue
            body = stripped[2:].strip()
            if SMALL_JS_CODE.search(body):
                warnings.append(
                    f"ARCH-W006 possible small commented JavaScript implementation: "
                    f"{_relative(root, path)}:{index}"
                )
    html_root = root / "apps/kassee-web/web/html"
    for path in sorted(html_root.rglob("*.html")) if html_root.exists() else ():
        source = path.read_text(errors="ignore")
        for match in re.finditer(r"<!--(.*?)-->", source, re.S):
            if SMALL_HTML_CODE.search(match.group(1)):
                line_number = source.count("\n", 0, match.start()) + 1
                warnings.append(
                    f"ARCH-W006 possible small commented HTML implementation: "
                    f"{_relative(root, path)}:{line_number}"
                )
    return warnings


def check(root: Path) -> list[str]:
    return sorted([
        *_large_commented_code_warnings(root),
        *_small_commented_code_warnings(root),
    ])
