from __future__ import annotations

from pathlib import Path
import hashlib
import re

from architecture.core.common import relative_posix

EXPECTED_CSS_MODULES = [
    "foundation.css",
    "screens.css",
    "act.css",
    "navigation.css",
    "tooltips.css",
    "derivation_flow.css",
    "diagram_styles.css",
    "utilities_01.css",
    "utilities_02.css",
]
EXPECTED_JS_MODULES = [
    "app/device_and_cursor.js",
    "app/screen_manager.js",
    "content/acts/ethos.js",
    "content/acts/multisig.js",
    "content/acts/chain.js",
    "content/acts/build.js",
    "content/acts/device.js",
    "content/acts/kassee.js",
    "content/acts/security.js",
    "content/acts/sovereign.js",
    "content/acts/stego.js",
    "content/acts.js",
    "content/satellites/utxo_flow.js",
    "content/satellites/derivation_flow.js",
    "scene/model.js",
    "scene/background_renderer.js",
    "scene/satellite_renderer.js",
    "scene/node_renderer.js",
    "scene/canvas.js",
    "scene/mini_map.js",
    "app/navigation.js",
    "diagrams/controls.js",
]


def _ordered_manifest(path: Path, root: Path, errors: list[str]) -> list[str]:
    if not path.is_file():
        errors.append(f"missing Constellation manifest: {path.relative_to(root)}")
        return []
    entries = [
        line.strip()
        for line in path.read_text().splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if len(entries) != len(set(entries)):
        errors.append(f"duplicate entries in Constellation manifest: {path.relative_to(root)}")
    return entries


def _check_generated_assets(root: Path) -> tuple[list[str], str]:
    errors: list[str] = []
    constellation_root = root / "apps/kassee-web/web/constellation"
    css_root = constellation_root / "css"
    css_source = css_root / "source"
    js_root = constellation_root / "js"
    js_source = js_root / "source"

    css_manifest = _ordered_manifest(css_source / "manifest.txt", root, errors)
    js_manifest = _ordered_manifest(js_source / "manifest.txt", root, errors)
    if css_manifest != EXPECTED_CSS_MODULES:
        errors.append(
            "Constellation CSS module order changed: expected "
            f"{EXPECTED_CSS_MODULES}, got {css_manifest}"
        )
    if js_manifest != EXPECTED_JS_MODULES:
        errors.append(
            "Constellation JavaScript module order changed: expected "
            f"{EXPECTED_JS_MODULES}, got {js_manifest}"
        )

    actual_css = sorted(relative_posix(path, css_source) for path in css_source.rglob("*.css"))
    actual_js = sorted(relative_posix(path, js_source) for path in js_source.rglob("*.js"))
    if actual_css != sorted(EXPECTED_CSS_MODULES):
        errors.append(
            "Constellation CSS module inventory changed: expected "
            f"{sorted(EXPECTED_CSS_MODULES)}, got {actual_css}"
        )
    if actual_js != sorted(EXPECTED_JS_MODULES):
        errors.append(
            "Constellation JavaScript module inventory changed: expected "
            f"{sorted(EXPECTED_JS_MODULES)}, got {actual_js}"
        )

    generated_css = css_root / "constellation.css"
    if css_manifest and generated_css.is_file():
        expected = "".join((css_source / relative).read_text() for relative in css_manifest)
        if generated_css.read_text() != expected:
            errors.append("Constellation CSS is stale; run tools/build/web/build_constellation_assets.py")
    else:
        errors.append("generated Constellation CSS is missing")

    generated_js = js_root / "main.js"
    if js_manifest and generated_js.is_file():
        expected = "".join((js_source / relative).read_text() for relative in js_manifest)
        js_text = generated_js.read_text()
        if js_text != expected:
            errors.append(
                "Constellation JavaScript is stale; run tools/build/web/build_constellation_assets.py"
            )
    else:
        errors.append("generated Constellation JavaScript is missing")
        js_text = ""

    for source_root, suffix in ((css_source, ".css"), (js_source, ".js")):
        for source_path in source_root.rglob(f"*{suffix}"):
            source_text = source_path.read_text()
            line_count = len(source_text.splitlines())
            if line_count > 600:
                errors.append(
                    f"Constellation source module exceeds SRP size limit: "
                    f"{source_path.relative_to(root)} ({line_count} lines)"
                )
            longest_line = max((len(line) for line in source_text.splitlines()), default=0)
            if longest_line > 4_096:
                errors.append(
                    f"Constellation source contains an embedded monolith: "
                    f"{source_path.relative_to(root)} ({longest_line} characters on one line)"
                )
            if suffix == ".js" and ("new Function" in source_text or "window._dv" in source_text):
                errors.append(
                    f"Constellation source restores a dynamic global bridge: "
                    f"{source_path.relative_to(root)}"
                )
            if suffix == ".js" and re.search(r"\sstyle=[\"']|\.style\.cssText", source_text):
                errors.append(
                    f"Constellation source contains static inline presentation: "
                    f"{source_path.relative_to(root)}"
                )
    return errors, js_text


def _check_route_shell(root: Path) -> list[str]:
    errors: list[str] = []
    index = root / "apps/kassee-web/web/constellation/index.html"
    if not index.is_file():
        return ["Constellation route index is missing"]

    html = index.read_text(errors="ignore")
    if len(html.splitlines()) > 80:
        errors.append(f"Constellation index exceeds 80-line shell limit: {len(html.splitlines())}")
    if re.search(r"<style(?:\s|>)", html, flags=re.I):
        errors.append("Constellation index must not contain an inline stylesheet")
    if re.search(r"\sstyle=[\"']", html, flags=re.I):
        errors.append("Constellation index must not contain inline style attributes")
    if "data:image" in html:
        errors.append("Constellation index must not contain embedded image assets")
    if re.search(r"<script(?![^>]*\bsrc=)[^>]*>", html, flags=re.I):
        errors.append("Constellation index must not contain an inline script")
    if len(re.findall(r"href=['\"]css/constellation\.css['\"]", html)) != 1:
        errors.append("Constellation index must load css/constellation.css exactly once")
    if len(re.findall(r"src=['\"]js/main\.js['\"]", html)) != 1:
        errors.append("Constellation index must load js/main.js exactly once")

    static_ids = sorted(set(re.findall(r'\bid="([^"]+)"', html)))
    digest = hashlib.sha256("\n".join(static_ids).encode()).hexdigest()
    if len(static_ids) != 10 or digest != "e4da387befb46704a0c69944a808ec45b83a20a66c88e0bdd723fb839efd919b":
        errors.append(f"Constellation static DOM contract changed: {len(static_ids)} IDs / {digest}")
    return errors


def _check_javascript_contract(js_text: str) -> list[str]:
    errors: list[str] = []
    functions = sorted(set(re.findall(
        r"(?m)^function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(", js_text
    )))
    digest = hashlib.sha256("\n".join(functions).encode()).hexdigest()
    if len(functions) != 32 or digest != "28ee15f40927a4d30c160a6c33830664efc27b2d169da61d8905298457e70757":
        errors.append(f"Constellation function contract changed: {len(functions)} functions / {digest}")

    dom_references = sorted(set(re.findall(r"getElementById\(['\"]([^'\"]+)['\"]\)", js_text)))
    digest = hashlib.sha256("\n".join(dom_references).encode()).hexdigest()
    if len(dom_references) != 16 or digest != "2491cf735513fb0e34ff133a387bc3955d130ad45e7a59c62076f582e3c0b1e7":
        errors.append(
            f"Constellation JavaScript DOM contract changed: {len(dom_references)} IDs / {digest}"
        )
    return errors


def check(root: Path) -> list[str]:
    asset_errors, js_text = _check_generated_assets(root)
    return [
        *asset_errors,
        *_check_route_shell(root),
        *_check_javascript_contract(js_text),
    ]
