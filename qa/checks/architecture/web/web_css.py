from __future__ import annotations

from pathlib import Path
import hashlib
import re

from architecture.core.common import relative_posix

REQUIRED_CSS_MODULES = [
    "foundation/tokens.css",
    "foundation/base.css",
    "layout/header_and_menu.css",
    "layout/screens.css",
    "components/cards.css",
    "components/buttons.css",
    "components/forms.css",
    "components/qr_and_address.css",
    "components/scanner_and_results.css",
    "components/feedback_and_utilities.css",
    "utilities/semantic_utilities.css",
    "screens/system.css",
    "screens/privacy.css",
    "screens/covenant_creation.css",
    "screens/covenant_activity.css",
    "screens/covenant_proofs.css",
    "screens/send_and_fees.css",
    "screens/history_and_assets.css",
    "screens/donation_and_safe_area.css",
    "screens/pskt.css",
    "screens/covenants.css",
]


def _css_rules(source: str, errors: list[str]) -> list[tuple[tuple[str, ...], str]]:
    source = re.sub(r"/\*.*?\*/", "", source, flags=re.S)

    def parse_region(region: str) -> list[tuple[tuple[str, ...], str]]:
        rules: list[tuple[tuple[str, ...], str]] = []
        cursor = 0
        header_start = 0
        while cursor < len(region):
            if region[cursor] != "{":
                cursor += 1
                continue
            header = region[header_start:cursor].strip()
            depth = 1
            index = cursor + 1
            quote = ""
            while index < len(region) and depth:
                char = region[index]
                if quote:
                    if char == "\\":
                        index += 2
                        continue
                    if char == quote:
                        quote = ""
                elif char in ("'", '"'):
                    quote = char
                elif char == "{":
                    depth += 1
                elif char == "}":
                    depth -= 1
                index += 1
            if depth:
                errors.append("generated app.css contains an unclosed block")
                return rules
            body = region[cursor + 1:index - 1]
            if header.startswith(("@media", "@supports")):
                rules.extend(parse_region(body))
            elif not header.startswith("@") and header:
                selectors = tuple(" ".join(selector.split()) for selector in header.split(","))
                rules.append((selectors, " ".join(body.split())))
            header_start = index
            cursor = index
        return rules

    return parse_region(source)


def _check_css_composition(root: Path) -> tuple[list[str], str]:
    errors: list[str] = []
    css_root = root / "apps/kassee-web/web/css"
    source_root = css_root / "app"
    manifest = source_root / "manifest.txt"
    actual_modules = sorted(
        relative_posix(path, source_root) for path in source_root.rglob("*.css")
    ) if source_root.exists() else []
    missing_required = sorted(set(REQUIRED_CSS_MODULES) - set(actual_modules))
    if missing_required:
        errors.append(f"required KasSee CSS modules missing: {missing_required}")

    manifest_modules: list[str] = []
    if not manifest.is_file():
        errors.append("KasSee CSS manifest is missing")
    else:
        manifest_modules = [
            line.strip()
            for line in manifest.read_text().splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        if len(manifest_modules) != len(set(manifest_modules)):
            errors.append("KasSee CSS manifest contains duplicate modules")
        if set(manifest_modules) != set(actual_modules):
            errors.append(
                "KasSee CSS manifest and source inventory differ: "
                f"unlisted={sorted(set(actual_modules) - set(manifest_modules))}, "
                f"missing={sorted(set(manifest_modules) - set(actual_modules))}"
            )
        required_positions = [manifest_modules.index(name) for name in REQUIRED_CSS_MODULES if name in manifest_modules]
        if required_positions != sorted(required_positions):
            errors.append("required KasSee CSS modules changed relative cascade order")
        utility_positions = [i for i, name in enumerate(manifest_modules) if name.startswith("utilities/")]
        screen_positions = [i for i, name in enumerate(manifest_modules) if name.startswith("screens/")]
        if utility_positions and screen_positions and max(utility_positions) > min(screen_positions):
            errors.append("KasSee utility CSS modules must load before screen modules")

    generated = css_root / "app.css"
    if manifest_modules and generated.is_file():
        expected = "\n\n".join(
            (source_root / relative).read_text().rstrip() for relative in manifest_modules
        ) + "\n"
        source = generated.read_text()
        if source != expected:
            errors.append("web/css/app.css is stale; run tools/build/web/build_app_css.py")
        # app.css is a generated aggregate and is intentionally exempt from source-file
        # line limits. Individual authored modules remain bounded below.
    else:
        errors.append("generated web/css/app.css is missing")
        source = ""

    for relative in actual_modules:
        path = source_root / relative
        line_count = len(path.read_text().splitlines())
        if line_count > 600:
            errors.append(f"web CSS module exceeds SRP size limit: {relative} ({line_count} lines)")

    local_imports = [
        value
        for value in re.findall(r"@import\s+(?:url\()?['\"]([^'\"]+)", source)
        if not value.startswith("https://fonts.googleapis.com/")
    ]
    if local_imports:
        errors.append(f"generated app.css must not use runtime local imports: {local_imports}")
    return errors, source


def _check_css_contracts(source: str) -> list[str]:
    errors: list[str] = []
    rules = _css_rules(source, errors)
    properties = sorted(set(re.findall(r"(?m)^\s*(--[A-Za-z0-9_-]+)\s*:", source)))
    digest = hashlib.sha256("\n".join(properties).encode()).hexdigest()
    if len(properties) != 19 or digest != "42357b86e731f3e89c968bbba38d1da59e79909ec4c9936f76754de7e5ccd911":
        errors.append(f"browser CSS token contract changed: {len(properties)} properties / {digest}")

    normalized = [(selectors, declarations) for selectors, declarations in rules]
    if len(normalized) != len(set(normalized)):
        errors.append("generated app.css contains exact duplicate rule blocks")
    if source.count(".pskt-header {") != 1:
        errors.append("PSKT review styles must have exactly one canonical rule block")
    return errors


def check(root: Path) -> list[str]:
    composition_errors, source = _check_css_composition(root)
    return [*composition_errors, *_check_css_contracts(source)]
