from __future__ import annotations

from pathlib import Path
import re


def check_scoped_context(web_js_root: Path) -> list[str]:
    """Require direct, sealed domain state and forbid generic capability routing."""
    errors: list[str] = []
    state_root = web_js_root / "app/state"
    if not state_root.is_dir():
        return ["browser domain state directory is missing"]
    for path in sorted(state_root.rglob("*_state.js")):
        source = path.read_text(errors="ignore")
        if "Object.seal({" not in source:
            errors.append(f"browser domain state must be sealed: {path.relative_to(state_root)}")
        if re.search(r"\b(?:get|set|install|register)\s*\(", source):
            errors.append(f"browser state module exposes generic property routing: {path.relative_to(state_root)}")
    for relative in ("app/context.js", "app/contracts", "app/stores"):
        if (web_js_root / relative).exists():
            errors.append(f"generic browser capability infrastructure must not return: {relative}")
    return errors


def check_shared_browser_infrastructure(web_js_root: Path) -> list[str]:
    errors: list[str] = []
    subscription_source = (
        web_js_root / "features/covenants/watchers_and_ui/watcher/subscription_and_time.js"
    ).read_text(errors="ignore")
    if "createBlockAddedSubscription" not in subscription_source:
        errors.append("generic covenant watcher must use the shared BlockAdded subscription")

    message_source = (
        web_js_root / "features/covenants/watchers_and_ui/watcher/subscription/message.js"
    ).read_text(errors="ignore")
    for forbidden in ("findSignatureForOutpoint", "isBlockAddedNotification", "readU32Le"):
        if forbidden in message_source:
            errors.append(f"duplicate covenant subscription parser must not return: {forbidden}")

    outpoint_source = (
        web_js_root / "features/covenants/blockchain/outpoint_parser.js"
    ).read_text(errors="ignore")
    if "core/bytes.js" not in outpoint_source or re.search(r"function\s+hexToBytes\b", outpoint_source):
        errors.append("covenant outpoint parsing must use the shared hexadecimal decoder")

    transport = web_js_root / "core/node/block_added_transport.js"
    if not transport.exists():
        errors.append("shared BlockAdded transport is missing")
    else:
        for path in web_js_root.rglob("*.js"):
            if path == transport or "pkg" in path.parts or "lib" in path.parts:
                continue
            if "build_vcc_subscribe_request(43n)" in path.read_text(errors="ignore"):
                errors.append(
                    f"BlockAdded transport duplicated outside shared boundary: {path.relative_to(web_js_root)}"
                )

    oracle_source = (
        web_js_root / "features/oracle/model_b/controller/polling/block_watcher.js"
    ).read_text(errors="ignore")
    if "createBlockAddedTransport" not in oracle_source or "hexToBytes" not in oracle_source:
        errors.append("oracle block watcher must use shared BlockAdded and hexadecimal infrastructure")

    for retired_raw_signature_path in (
        web_js_root / "app/events/contracts/adaptor_swap.js",
        web_js_root / "app/events/contracts/adaptor_swap",
        web_js_root / "app/state/covenants/adaptor_state.js",
        web_js_root / "features/covenants/payload_and_swaps/adaptor_policy.js",
        web_js_root / "features/covenants/payload_and_swaps/adaptor_watcher.js",
        web_js_root / "features/covenants/payload_and_swaps/adaptor_watcher",
    ):
        if retired_raw_signature_path.exists():
            errors.append(
                "retired raw-signature browser implementation must remain absent: "
                + retired_raw_signature_path.relative_to(web_js_root).as_posix()
            )

    whole_buffer_patterns = (
        re.compile(r"Array\.from\([\s\S]{0,180}?toString\(16\)\.padStart\(2[\s\S]{0,80}?\.join\("),
        re.compile(r"match\(/\.\{(?:1,)?2\}/g\)[\s\S]{0,100}?(?:Number\.)?parseInt\("),
    )
    bytes_module = (web_js_root / "core/bytes.js").resolve()
    for path in web_js_root.rglob("*.js"):
        if path.resolve() == bytes_module or "pkg" in path.parts or "lib" in path.parts:
            continue
        source = path.read_text(errors="ignore")
        if any(pattern.search(source) for pattern in whole_buffer_patterns):
            errors.append(
                f"whole-buffer hexadecimal conversion bypasses core/bytes.js: {path.relative_to(web_js_root)}"
            )

    stealth_catch_up = (
        web_js_root / "features/stealth/index/scanning/catch_up.js"
    ).read_text(errors="ignore")
    if "exactUnsignedJsonField(raw, 'blueScore'" not in stealth_catch_up or "exactUnsignedJsonField(blockRaw, 'blueScore'" not in stealth_catch_up:
        errors.append("stealth catch-up blueScore must be parsed losslessly from raw JSON text")
    if re.search(r"parseInt\([^\n]{0,120}blueScore|Number\([^\n]{0,120}blueScore", stealth_catch_up):
        errors.append("consensus blueScore must never route through JavaScript Number")
    if '"gte":${gte.toString()}' not in stealth_catch_up or '"lt":${lt.toString()}' not in stealth_catch_up:
        errors.append("stealth blue-score search bounds must serialize directly from BigInt decimal strings")

    assets_client = (web_js_root / "features/assets/client.js").read_text(errors="ignore")
    for required in (
        "exactUnsigned(token.balance",
        "balance: 0n",
        "current.balance += balance",
    ):
        if required not in assets_client:
            errors.append(f"KRC20 exact-balance contract changed: {required}")
    for forbidden in (
        "Number(token.balance",
        "parseInt(token.balance",
        "parseFloat(token.balance",
    ):
        if forbidden in assets_client:
            errors.append(f"KRC20 monetary balance must not use JavaScript Number: {forbidden}")

    assets_render = (web_js_root / "features/assets/render.js").read_text(errors="ignore")
    if "exactUnsigned(balance, 'KRC20 balance')" not in assets_render:
        errors.append("KRC20 rendering must preserve balance as an exact integer")
    if re.search(r"token\.balance\s*/|Number\(token\.balance", assets_render):
        errors.append("KRC20 rendering must not convert exact balances to Number")

    expected_result_modules = {
        "primary_advanced/commit_reveal.js",
        "primary_advanced/crowdfund.js",
        "primary_advanced/defaults.js",
        "primary_advanced/merkle.js",
        "primary_advanced/payjoin.js",
        "primary_advanced/shipment.js",
        "auxiliary/commit_reveal.js",
        "auxiliary/invite.js",
    }
    result_root = web_js_root / "features/covenants/watchers_and_ui/ui/result_buttons"
    actual_result_modules = {
        path.relative_to(result_root).as_posix()
        for path in result_root.rglob("*.js")
        if path.parent.name in {"primary_advanced", "auxiliary"}
    }
    if actual_result_modules != expected_result_modules:
        errors.append(
            f"covenant family result-action inventory changed: expected {sorted(expected_result_modules)}, "
            f"got {sorted(actual_result_modules)}"
        )
    return errors
