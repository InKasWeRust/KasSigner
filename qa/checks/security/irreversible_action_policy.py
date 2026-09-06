#!/usr/bin/env python3
"""Enforce operator acknowledgement and on-device consent around irreversible actions."""

from __future__ import annotations

import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[3]
OUTPUT = ROOT / "target/qa/security/irreversible-action-policy.json"
ACK_WRAPPER = "qa/checks/release/irreversible_action_ack.py"

SCRIPT_ROOTS = (
    ROOT / "qa/linux",
    ROOT / "qa/windows",
    ROOT / "scripts",
    ROOT / "tools",
)
SCRIPT_SUFFIXES = {".sh", ".ps1", ".cmd", ".bat", ".py"}
MARKDOWN_ROOTS = (ROOT / "docs", ROOT / "qa/release")
PRODUCTION_SOURCE_ROOTS = (ROOT / "apps", ROOT / "crates", ROOT / "scripts", ROOT / "tools")
SOURCE_SUFFIXES = {".rs", ".py", ".c", ".h", ".cpp", ".cc"}
BOOTLOADER_PATCHER = ROOT / "tools/build/firmware/secure_bootloader/m5stack/patch_pop_it_bootloader.py"
BOOTLOADER_SECURITY_SOURCES = {
    ROOT / "tools/build/firmware/secure_bootloader/m5stack/owner_bootloader_patch.py",
    ROOT / "tools/build/firmware/secure_bootloader/m5stack/owner_secure_boot_patch.py",
}
FENCED_CODE = re.compile(r"```[^\n]*\n(.*?)```", re.DOTALL)
IRREVERSIBLE_COMMAND = re.compile(
    r"\b(?:burn[_-]efuse|burn[_-]key(?:[_-]digest)?|write[_-]protect[_-]efuse|"
    r"burn[_-]block|burn[_-]bit|burn[_-]custom[_-]mac)\b",
    re.IGNORECASE,
)
IRREVERSIBLE_API = re.compile(
    r"\b(?:esp_secure_boot_v2_permanently_enable|"
    r"esp_efuse_(?:write\w*|batch_write_commit|set_write_protect\w*))\b"
)


def executable_scripts() -> list[Path]:
    paths: set[Path] = set()
    for root in SCRIPT_ROOTS:
        if not root.is_dir():
            continue
        for path in root.rglob("*"):
            if path.is_file() and path.suffix.lower() in SCRIPT_SUFFIXES:
                paths.add(path)
    return sorted(paths)


def live_command_lines(path: Path) -> list[str]:
    lines: list[str] = []
    for raw in path.read_text(errors="replace").splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith(("#", "//", "*")):
            continue
        if IRREVERSIBLE_COMMAND.search(stripped):
            lines.append(stripped)
    return lines


def script_commands_are_guarded(path: Path) -> bool:
    lines = path.read_text(errors="replace").splitlines()
    matched = []
    for index, raw in enumerate(lines):
        stripped = raw.strip()
        if stripped and not stripped.startswith(("#", "//", "*")) and IRREVERSIBLE_COMMAND.search(stripped):
            matched.append(index)
    for index in matched:
        start = max(0, index - 8)
        end = min(len(lines), index + 9)
        context = "\n".join(lines[start:end])
        if ACK_WRAPPER not in context or "{device}" not in context:
            return False
    return True


def unauthorized_irreversible_source_calls() -> list[str]:
    violations: list[str] = []
    for root in PRODUCTION_SOURCE_ROOTS:
        if not root.is_dir():
            continue
        for path in root.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in SOURCE_SUFFIXES:
                continue
            if path == BOOTLOADER_PATCHER or path in BOOTLOADER_SECURITY_SOURCES:
                continue
            for number, raw in enumerate(path.read_text(errors="replace").splitlines(), start=1):
                if IRREVERSIBLE_API.search(raw):
                    relative = path.relative_to(ROOT).as_posix()
                    violations.append(f"{relative}:{number}: {raw.strip()}")
    return violations


def unguarded_markdown_blocks(path: Path) -> list[str]:
    failures: list[str] = []
    for block in FENCED_CODE.findall(path.read_text(errors="replace")):
        if not IRREVERSIBLE_COMMAND.search(block):
            continue
        if ACK_WRAPPER not in block or "{device}" not in block:
            first = next(
                (line.strip() for line in block.splitlines() if IRREVERSIBLE_COMMAND.search(line)),
                "irreversible command",
            )
            failures.append(first)
    return failures


def audit() -> tuple[list[str], dict[str, object]]:
    errors: list[str] = []
    guarded_scripts: list[str] = []
    destructive_scripts: list[dict[str, object]] = []

    for path in executable_scripts():
        commands = live_command_lines(path)
        if not commands:
            continue
        relative = path.relative_to(ROOT).as_posix()
        guarded = script_commands_are_guarded(path)
        destructive_scripts.append(
            {"path": relative, "guarded": guarded, "matched_lines": commands}
        )
        if guarded:
            guarded_scripts.append(relative)
        else:
            errors.append(
                f"{relative} contains an irreversible eFuse/security command without "
                f"the mandatory interactive wrapper {ACK_WRAPPER} and bound {{device}} token"
            )

    guarded_markdown: list[str] = []
    for root in MARKDOWN_ROOTS:
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*.md")):
            failures = unguarded_markdown_blocks(path)
            relative = path.relative_to(ROOT).as_posix()
            if failures:
                for command in failures:
                    errors.append(
                        f"{relative} contains a copy-pasteable irreversible command without "
                        f"{ACK_WRAPPER} and the bound {{device}} token: {command}"
                    )
            elif any(IRREVERSIBLE_COMMAND.search(block) for block in FENCED_CODE.findall(path.read_text(errors="replace"))):
                guarded_markdown.append(relative)

    source_violations = unauthorized_irreversible_source_calls()
    for violation in source_violations:
        errors.append(
            "irreversible production eFuse API exists outside the single Pop It-gated "
            f"bootloader patcher: {violation}"
        )

    ui = (ROOT / "apps/signer-firmware/src/ui/screens/device/pop_it.rs").read_text()
    controller = (
        ROOT / "apps/signer-firmware/src/runtime/interactions/settings/advanced/pop_it.rs"
    ).read_text()
    secure_boot_source = (
        ROOT / "tools/build/firmware/secure_bootloader/m5stack/owner_secure_boot_patch.py"
    ).read_text()
    owner_boot_source = (
        ROOT / "tools/build/firmware/secure_bootloader/m5stack/owner_bootloader_patch.py"
    ).read_text()
    owner_ui = (ROOT / "apps/signer-firmware/src/ui/screens/device/owner_firmware.rs").read_text()
    owner_controller = (
        ROOT / "apps/signer-firmware/src/runtime/interactions/settings/advanced/owner_firmware.rs"
    ).read_text()
    boot_control = (
        ROOT / "apps/signer-firmware/src/services/persistent_wallet/device/boot_control.rs"
    ).read_text()

    user_consent_checks = {
        "warns_permanent": "This permanently burns security eFuses." in ui,
        "warns_cannot_undo": "It cannot be undone or reset later." in ui,
        "requires_typed_pop_it": "FINAL: TYPE POP IT" in ui
        and "confirmation_phrase_valid" in controller,
        "arms_one_shot_request": "persistence.request_pop_it()" in controller,
    }
    for name, met in user_consent_checks.items():
        if not met:
            errors.append(f"on-device irreversible consent contract missing: {name}")

    try:
        armed = secure_boot_source.split("POP_IT_GATED_BLOCK = r'''", 1)[1].split("'''", 1)[0]
        commit = secure_boot_source.split("POP_IT_COMMIT_BLOCK = r'''", 1)[1].split("'''", 1)[0]
    except IndexError:
        armed = commit = ""
    take = commit.find("kassigner_bootctl_take(KASSIGNER_BOOTCTL_OP_POP_IT")
    burn = commit.find("esp_secure_boot_v2_permanently_enable(image_data)")
    bootloader_gated = (
        "kassigner_pop_it_transition_armed = true" in armed
        and take >= 0 and burn > take
        and "esp_secure_boot_v2_permanently_enable" not in armed
    )
    if not bootloader_gated:
        errors.append(
            "bootloader irreversible Secure Boot enable call is not ordered after the "
            "consumed Pop It one-shot request"
        )

    owner_consent_checks = {
        "warns_permanent_owner_key": "permanent" in owner_ui and "cannot be undone" in owner_ui,
        "requires_typed_owner_enroll": "ENROLL OWNER" in owner_ui and 'b"ENROLL OWNER"' in owner_controller,
        "requires_typed_owner_install": "INSTALL OWNER" in owner_ui and 'b"INSTALL OWNER"' in owner_controller,
        "secure_profile_only_boot_control": '#[cfg(feature="secure-provisioning-core")]' in boot_control,
        "development_simulation_only": owner_controller.count("DEVELOPMENT SIMULATION") >= 2,
        "owner_efuse_bootloader_owned": "esp_efuse_write_key" in owner_boot_source
        and "esp_efuse_set_write_protect_of_digest_revoke" in owner_boot_source,
        "pop_it_enrollment_prerequisite": "Do this BEFORE Pop It" in owner_ui,
        "owner_only_requires_enrollment": 'cfg!(feature = "secure-owner-only")' in owner_controller
        or 'cfg!(feature = "secure-owner-only")' in (ROOT / "apps/signer-firmware/src/runtime/interactions/settings/advanced/pop_it.rs").read_text(),
        "owner_only_sole_authority_policy": "KASSIGNER_OWNER_ONLY_AUTHORITY" in owner_boot_source
        and "esp_efuse_set_digest_revoke(1)" in owner_boot_source
        and "esp_efuse_set_digest_revoke(2)" in owner_boot_source,
    }
    for name, met in owner_consent_checks.items():
        if not met:
            errors.append(f"owner-authority irreversible consent contract missing: {name}")

    wrapper = (ROOT / ACK_WRAPPER).read_text()
    wrapper_checks = {
        "explicit_irreversible_phrase": "I UNDERSTAND THIS IS IRREVERSIBLE" in wrapper,
        "interactive_only": "isatty()" in wrapper,
        "device_retype": "Retype the target device exactly" in wrapper,
        "command_device_binding": 'DEVICE_TOKEN = "{device}"' in wrapper
        and "bound_command" in wrapper,
        "no_environment_bypass": "os.environ" not in wrapper,
    }
    for name, met in wrapper_checks.items():
        if not met:
            errors.append(f"developer irreversible acknowledgement contract missing: {name}")

    document: dict[str, object] = {
        "schema_version": 1,
        "healthy": not errors,
        "developer_ack_wrapper": ACK_WRAPPER,
        "destructive_scripts": destructive_scripts,
        "guarded_scripts": guarded_scripts,
        "guarded_markdown_runbooks": guarded_markdown,
        "unauthorized_irreversible_source_calls": source_violations,
        "user_consent": user_consent_checks,
        "owner_authority_consent": owner_consent_checks,
        "bootloader_pop_it_precedes_irreversible_call": bootloader_gated,
        "developer_acknowledgement": wrapper_checks,
        "errors": errors,
    }
    return errors, document


def main() -> int:
    errors, document = audit()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    for error in errors:
        print(f"ERROR: {error}")
    if errors:
        return 1
    print(
        "PASS: irreversible hardware actions require interactive developer acknowledgement; "
        "CoreS3 Secure Boot remains gated by typed on-device Pop It consent"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
