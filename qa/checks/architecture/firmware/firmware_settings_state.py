from __future__ import annotations

from pathlib import Path
import re


def check(root: Path) -> list[str]:
    errors: list[str] = []
    data_root = root / "apps/signer-firmware/src/runtime/data/settings"
    expectations = {
        data_root / "persistent_display.rs": {
            "DisplayPreferences": ("require_pin_after_dim", "dirty"),
        },
        data_root / "audio.rs": {
            "AudioPreferences": ("muted", "startup_sound_enabled"),
        },
    }
    for path, structs in expectations.items():
        source = path.read_text(errors="ignore") if path.exists() else ""
        for name, expected in structs.items():
            match = re.search(
                rf"(?ms)(?:pub\(super\)\s+)?struct {name}\s*\{{(?P<body>.*?)^\}}",
                source,
            )
            if not match:
                errors.append(f"settings state group is missing: {name}")
                continue
            actual = tuple(
                re.findall(
                    r"(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*:",
                    match.group("body"),
                )
            )
            if actual != expected:
                errors.append(
                    f"settings state group {name} changed: expected {expected}, got {actual}"
                )
            if len(re.findall(r"(?m):\s*bool\b", match.group("body"))) > 3:
                errors.append(f"settings state group {name} exceeds three boolean fields")

    settings = (root / "apps/signer-firmware/src/runtime/data/settings.rs").read_text(
        errors="ignore"
    )
    for field, type_name in (
        ("display_preferences", "DisplayPreferences"),
        ("audio_preferences", "AudioPreferences"),
    ):
        if not re.search(rf"(?m)^\s*{field}:\s*{type_name},", settings):
            errors.append(f"SettingsState must retain focused {field} ownership")
    return errors
