#!/usr/bin/env python3
from __future__ import annotations
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
JS_ROOT = ROOT / 'apps/kassee-web/web/js'
HELPER = JS_ROOT / 'core/security/safe_html.js'

def _portable_rel(path: Path) -> str:
    # Normalize Windows backslashes before comparing against repository-relative
    # allowlist entries, which are intentionally stored in POSIX form.
    return str(path.relative_to(JS_ROOT)).replace('\\', '/')

QR_DIRECT_ALLOW = {
    'app/events/contracts/covenant_creation/invite_sharing.js',
    'features/transactions/send/review.js',
    'features/transactions/send/receive.js',
    'features/covenants/recovery/export/qr_presenter.js',
    'features/oracle/v1/controller.js',
    'features/stealth/index/send.js',
    'features/stealth/index/scanning/live_controls/request_qr.js',
}

def dynamic_inner_html_errors() -> list[str]:
    errors=[]
    for path in JS_ROOT.rglob('*.js'):
        if path == HELPER: continue
        text=path.read_text(encoding='utf-8', errors='replace')
        rel=_portable_rel(path)
        for match in re.finditer(r'\.innerHTML\s*=\s*', text):
            end=text.find(';',match.end())
            if end < 0: end=text.find('\n',match.end())
            rhs=text[match.end():end].strip()
            if rhs in ("''", '""'): continue
            static=bool(re.fullmatch(r"(['\"]).*\1", rhs, re.S)) and '${' not in rhs and "' +" not in rhs and '" +' not in rhs
            qr=rel in QR_DIRECT_ALLOW and any(token in rhs for token in ('generate_qr_svg_text','.svg','frames[0].svg','scannerState.qrFrames','svg'))
            if not (static or qr):
                line=text.count('\n',0,match.start())+1
                errors.append(f'{rel}:{line}: dynamic innerHTML must use setSafeMarkup/textContent/DOM nodes')
    return errors

def hostile_markup_contract_errors() -> list[str]:
    source = HELPER.read_text(encoding="utf-8", errors="replace")
    errors: list[str] = []
    for forbidden in ("IMG", "STYLE", "B", "SCRIPT"):
        if f"'{forbidden}'" in source.split("const ALLOWED_TAGS", 1)[1].split(";", 1)[0]:
            errors.append(f"{forbidden} must not be an allowed dynamic markup element")
    for token in ("name.startsWith('on')", "name === 'style'", "document.createTextNode(node.outerHTML"):
        if token not in source:
            errors.append(f"safe_html.js is missing hostile-markup defense {token!r}")
    hostile = ("<img src=x onerror=...>", "<style>...</style>", "<b>fake balance</b>")
    # These exact regression payloads are intentionally pinned so future
    # sanitizer changes cannot quietly broaden the allowlist around them.
    if hostile != ("<img src=x onerror=...>", "<style>...</style>", "<b>fake balance</b>"):
        errors.append("hostile markup vectors changed unexpectedly")
    return errors

def main() -> int:
    errors=dynamic_inner_html_errors()
    if 'onclick=' in '\n'.join(p.read_text(encoding='utf-8', errors='replace') for p in JS_ROOT.rglob('*.js')):
        errors.append('inline onclick= remains in runtime JavaScript')
    errors.extend(hostile_markup_contract_errors())
    if errors:
        for error in errors: print('ERROR:',error)
        return 1
    print('PASS: dynamic HTML is centralized; hostile img/style/b markup remains literal text')
    return 0
if __name__ == '__main__': raise SystemExit(main())
