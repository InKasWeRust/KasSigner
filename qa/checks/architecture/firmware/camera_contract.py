from __future__ import annotations

from pathlib import Path
import hashlib
import re

def check_camera_controllers(root: Path) -> list[str]:
    ROOT = root
    errors: list[str] = []
    camera_facade = ROOT / "apps/signer-firmware/src/runtime/interactions/camera_loop.rs"
    camera_root = ROOT / "apps/signer-firmware/src/runtime/interactions/camera_loop"
    required_camera_modules = (
        camera_root / "cycle.rs",
        camera_root / "decoder.rs",
        camera_root / "dispatch.rs",
        camera_root / "dvp_capture.rs",
        camera_root / "multiframe.rs",
        camera_root / "session.rs",
        camera_root / "state.rs",
        camera_root / "timing.rs",
        camera_root / "touch_input.rs",
        camera_root / "waveshare_capture.rs",
        camera_root / "dispatch/address.rs",
        camera_root / "dispatch/covenant.rs",
        camera_root / "dispatch/kpub.rs",
        camera_root / "dispatch/descriptor.rs",
        camera_root / "dispatch/text/mod.rs",
        camera_root / "dispatch/text/message.rs",
        camera_root / "dispatch/secret.rs",
        camera_root / "dispatch/seed.rs",
        camera_root / "dispatch/stealth.rs",
        camera_root / "dispatch/transaction.rs",
    )
    for required in required_camera_modules:
        if not required.exists():
            errors.append(f"required firmware camera module is missing: {required.relative_to(ROOT)}")
    if camera_facade.exists():
        camera_facade_source = camera_facade.read_text(errors="ignore")
        if len(camera_facade_source.splitlines()) > 90:
            errors.append("controllers/camera_loop.rs must remain a small stable module root")
        if re.search(r"\bfn\s+run_camera_cycle\s*\(", camera_facade_source):
            errors.append("controllers/camera_loop.rs must delegate the capture cycle")
    camera_production_files = list(camera_root.rglob("*.rs")) if camera_root.exists() else []
    for path in camera_production_files:
        line_count = len(path.read_text(errors="ignore").splitlines())
        if line_count > 400:
            errors.append(
                f"firmware camera module exceeds 400-line SRP limit: "
                f"{path.relative_to(ROOT)} ({line_count} lines)"
            )
    cycle_source = (camera_root / "cycle.rs").read_text(errors="ignore") if (camera_root / "cycle.rs").exists() else ""
    for delegation in ("prepare_cycle(", "waveshare_capture::run_capture(", "dvp_capture::run_capture("):
        if delegation not in cycle_source:
            errors.append(f"firmware camera cycle lost delegated stage: {delegation}")
    if "clippy::too_many_lines" in cycle_source or "clippy::cognitive_complexity" in cycle_source:
        errors.append("firmware camera cycle facade no longer requires complexity exceptions")
    dispatch_source = (camera_root / "dispatch.rs").read_text(errors="ignore") if (camera_root / "dispatch.rs").exists() else ""
    confirmed = dispatch_source[dispatch_source.find("fn process_confirmed_qr"):dispatch_source.find("fn process_pending")]
    pending = dispatch_source[dispatch_source.find("fn process_pending"):dispatch_source.find("fn dispatch_payload")]
    routed = dispatch_source[dispatch_source.find("fn dispatch_payload"):dispatch_source.find("fn dispatch_unknown")]
    payload_order = (
        "QrPayloadKind::AntiKlepto", "QrPayloadKind::KaspaAddress", "QrPayloadKind::CompactKspt",
        "QrPayloadKind::StandardPskt", "QrPayloadKind::SeedQr", "QrPayloadKind::RawSeedEntropy",
        "QrPayloadKind::StealthRequest", "QrPayloadKind::FirmwareUpdate", "QrPayloadKind::CovenantRaw",
        "QrPayloadKind::CovenantHex", "QrPayloadKind::Unknown => dispatch_unknown",
    )
    payload_positions = [routed.find(marker) for marker in payload_order]
    precedence_ok = (
        0 <= confirmed.find("process_pending") < confirmed.find("classify_qr_payload")
        and 0 <= pending.find("text::message::is_pending") < pending.find("secret::is_pending")
        and all(position >= 0 for position in payload_positions)
        and payload_positions == sorted(payload_positions)
        and 0 <= dispatch_source.find("if descriptor::matches(data, len)") < dispatch_source.find("else if kpub::matches(data, len)")
        and "descriptor::process(data, len, ad, liveness)" in dispatch_source
        and "kpub::process(data, len, ad, liveness)" in dispatch_source
    )
    if not precedence_ok:
        errors.append("firmware camera payload precedence changed")
    if "clippy::too_many_lines" in dispatch_source or "clippy::cognitive_complexity" in dispatch_source:
        errors.append("firmware camera dispatch router no longer requires complexity exceptions")
    camera_source = "\n".join(
        path.read_text(errors="ignore") for path in [camera_facade, *camera_production_files]
        if path.exists()
    )
    camera_signature_pattern = re.compile(
        r"(?ms)^\s*pub\s+fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*(.*?)\{"
    )
    camera_signatures = sorted(
        " ".join(f"pub fn {name} {tail}".split())
        for name, tail in camera_signature_pattern.findall(camera_source)
    )
    camera_signature_hash = hashlib.sha256(
        "\n".join(camera_signatures).encode()
    ).hexdigest()
    if len(camera_signatures) != 1 or camera_signature_hash != (
        "08afb5374041983627e2ead8835a36de9bd5f0bc9cfabcd9b3f47d7bf3bfdd77"
    ):
        errors.append(
            f"firmware camera API changed: expected run_camera_cycle with the locked digest, got "
            f"{len(camera_signatures)} signatures / {camera_signature_hash}"
        )
    return errors
