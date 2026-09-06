"""Stage-2 firmware navigation-kernel ownership checks."""
from __future__ import annotations

from pathlib import Path
import re

KERNEL = "apps/signer-firmware/src/runtime/navigation/kernel.rs"
EVENT = "apps/signer-firmware/src/runtime/navigation/event.rs"
EFFECTS = "apps/signer-firmware/src/runtime/effects.rs"
EXPORT_STATE = "apps/signer-firmware/src/runtime/data/export.rs"

DIRECT_WRITE_RE = re.compile(r"navigation\.(?:app\.state|committed_state|owner)\s*=(?!=)")
FORBIDDEN_APIS = ("effects::navigate", "runtime::effects::navigate", "navigation::transition(")


def _read(root: Path, relative: str) -> str:
    return (root / relative).read_text(encoding="utf-8", errors="ignore")


def check(root: Path) -> list[str]:
    errors: list[str] = []
    firmware = root / "apps/signer-firmware/src"

    for path in firmware.rglob("*.rs"):
        relative = path.relative_to(root).as_posix()
        source = path.read_text(encoding="utf-8", errors="ignore")
        if relative != KERNEL and DIRECT_WRITE_RE.search(source):
            errors.append(f"navigation tuple mutation is outside the stage-2 kernel: {relative}")
        if relative != EVENT and "UiRoute::new" in source:
            errors.append(f"UiRoute construction bypasses route macros: {relative}")
        if relative not in {EVENT, "apps/signer-firmware/src/runtime/navigation/mod.rs"} and "ContinuationRoute::new" in source:
            errors.append(f"ContinuationRoute construction bypasses continuation macros: {relative}")
        if "route_dynamic!" in source:
            errors.append(f"retired stage-2 dynamic-route adapter remains in {relative}")
        for token in FORBIDDEN_APIS:
            if token in source:
                errors.append(f"retired navigation escape hatch remains in {relative}: {token}")

    effects = _read(root, EFFECTS)
    for required in ("UiEvent", "menu_select", "return_to", "route(ad"):
        if required not in effects:
            errors.append(f"runtime effect boundary is missing typed navigation API: {required}")

    kernel = _read(root, KERNEL)
    for required in (
        "enum HistoryEffect", "struct Transition", "fn reduce(", "fn apply(",
        "UiEvent::MenuSelect", "ad.navigation.history.push", "ad.navigation.app.state = transition.next",
        "ad.navigation.committed_state = transition.next", "ad.navigation.owner = transition.owner",
    ):
        if required not in kernel:
            errors.append(f"stage-2 navigation kernel contract missing: {required}")

    export_state = _read(root, EXPORT_STATE)
    for retired in ("seed_backup_return", "address_return", "kpub_export_return"):
        if retired in export_state:
            errors.append(f"legacy export return-state field remains after stage 2: {retired}")

    # Stage 7 retires raw `AppState` continuation storage. AppState remains valid
    # for the authoritative current-state discriminator and bounded navigation
    # history, but domain workflow destinations must be opaque ContinuationRoute
    # tokens so only the navigation package can unwrap and commit them.
    continuation_state_files = (
        firmware / "runtime/data/storage.rs",
        firmware / "runtime/data/pop_it.rs",
        firmware / "runtime/data/qr.rs",
        firmware / "runtime/data/navigation.rs",
        firmware / "runtime/interactions/text_files.rs",
        firmware / "runtime/interactions/sd/common/encryption_prompt.rs",
        firmware / "runtime/interactions/sd/common/import_scan.rs",
        firmware / "runtime/interactions/sd/common/list_navigation.rs",
        firmware / "runtime/interactions/sd/common/filename.rs",
        firmware / "runtime/interactions/sd/common/passphrase.rs",
    )
    raw_destination = re.compile(r"(?:back_state|next_state|success_state|return_state|close_state|overwrite_back|delete_return)\s*:\s*(?:Option<)?(?:crate::runtime::input::)?AppState")
    for path in continuation_state_files:
        source = path.read_text(encoding="utf-8", errors="ignore")
        if raw_destination.search(source):
            errors.append(
                "raw AppState continuation storage remains after stage 7: "
                + path.relative_to(root).as_posix()
            )

    allowed_dynamic_conversion = {
        "apps/signer-firmware/src/runtime/navigation/mod.rs",
        "apps/signer-firmware/src/runtime/power_state.rs",
        "apps/signer-firmware/src/runtime/interactions/sd/backup/import.rs",
        "apps/signer-firmware/src/runtime/interactions/sd/backup/seed.rs",
        "apps/signer-firmware/src/runtime/interactions/sd/common/list_navigation.rs",
        "apps/signer-firmware/src/runtime/interactions/sd/common/filename.rs",
    }
    for path in firmware.rglob("*.rs"):
        relative = path.relative_to(root).as_posix()
        if relative in allowed_dynamic_conversion:
            continue
        if "continuation_from_state(" in path.read_text(encoding="utf-8", errors="ignore"):
            errors.append(f"unscoped AppState-to-continuation conversion remains in {relative}")

    return errors
