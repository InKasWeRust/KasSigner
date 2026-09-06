#!/usr/bin/env python3
"""Patch the pinned ESP-IDF bootloader for a KasSigner Secure Boot authority profile.

The patch is intentionally source-anchored to ESP-IDF v6.0.2.  Any upstream
source drift causes the operation to fail closed instead of applying a fuzzy
security patch.
"""
from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path

def _load_helper(filename: str, module_name: str):
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"Could not load bootloader patch templates: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_owner = _load_helper("owner_bootloader_patch.py", "kassigner_owner_bootloader_patch")
_secure = _load_helper("owner_secure_boot_patch.py", "kassigner_owner_secure_boot_patch")

UTILITY_HELPER_ANCHOR = _owner.UTILITY_HELPER_ANCHOR
LOAD_BOOT_ANCHOR = _owner.LOAD_BOOT_ANCHOR
SECURE_BOOT_PREFLIGHT_ANCHOR = _secure.SECURE_BOOT_PREFLIGHT_ANCHOR
SECURE_BOOT_BLOCK = _secure.SECURE_BOOT_BLOCK
FLASH_ENCRYPTION_MUTATION_ANCHOR = "    if (!flash_encryption_enabled) {"
FLASH_ENCRYPTION_COMMIT_ANCHOR = "#endif // CONFIG_SECURE_FLASH_ENC_ENABLED\n#ifdef CONFIG_SECURE_BOOT_V1_ENABLED"
ANTI_ROLLBACK_FUNCTION_ANCHOR = "static void update_anti_rollback(const esp_partition_pos_t *partition)\n{\n"


def _render(template: str, expected_digest: bytes, owner_only: bool) -> str:
    return (template
        .replace("__KASSIGNER_EXPECTED_DIGEST__", _owner.digest_initializer(expected_digest))
        .replace("__KASSIGNER_OWNER_ONLY__", "1" if owner_only else "0"))


def patch_secure_boot(path: Path, expected_digest: bytes, owner_only: bool = False) -> None:
    text = path.read_text()
    marker = "KasSigner exact-key Secure Boot v2 verification helpers"
    if marker in text:
        raise SystemExit(f"Already patched: {path}")
    if text.count(SECURE_BOOT_PREFLIGHT_ANCHOR) != 1:
        raise SystemExit("Pinned ESP-IDF secure_boot.c anchor changed; refusing to patch")
    helpers = _render(_secure.SECURE_BOOT_HELPER_TEMPLATE, expected_digest, owner_only)
    path.write_text(text.replace(SECURE_BOOT_PREFLIGHT_ANCHOR, helpers + "\n" + SECURE_BOOT_PREFLIGHT_ANCHOR, 1))


def patch_utility(path: Path, expected_digest: bytes, owner_only: bool = False) -> None:
    text = path.read_text()
    marker = "KasSigner owner-authority boot-control and OTA handoff"
    if marker in text:
        raise SystemExit(f"Already patched: {path}")
    for anchor, label in (
        (UTILITY_HELPER_ANCHOR, "helper"),
        (LOAD_BOOT_ANCHOR, "load-boot"),
        (SECURE_BOOT_BLOCK, "Secure Boot"),
        (FLASH_ENCRYPTION_COMMIT_ANCHOR, "flash-encryption commit"),
        (ANTI_ROLLBACK_FUNCTION_ANCHOR, "anti-rollback"),
    ):
        if text.count(anchor) != 1:
            raise SystemExit(f"Pinned ESP-IDF bootloader {label} anchor changed; refusing to patch")
    if text.count(FLASH_ENCRYPTION_MUTATION_ANCHOR) != 2:
        raise SystemExit("Pinned ESP-IDF flash-encryption mutation anchors changed; refusing to patch")

    helpers = _render(_owner.UTILITY_HELPERS_TEMPLATE, expected_digest, owner_only)
    text = text.replace(UTILITY_HELPER_ANCHOR, UTILITY_HELPER_ANCHOR + helpers, 1)
    text = text.replace(
        LOAD_BOOT_ANCHOR,
        LOAD_BOOT_ANCHOR + "    if (kassigner_process_owner_boot_control(bs, start_index)) { return; }\n",
        1,
    )
    text = text.replace(SECURE_BOOT_BLOCK, _secure.POP_IT_GATED_BLOCK, 1)
    # ESP-IDF release-mode flash encryption normally provisions itself on first
    # boot. Gate both initialization and enable/encrypt phases on the same
    # explicit Pop It request so ordinary secure-profile boots are read-only.
    text = text.replace(
        FLASH_ENCRYPTION_MUTATION_ANCHOR,
        "    if (!flash_encryption_enabled && kassigner_pop_it_transition_armed) {",
    )
    text = text.replace(
        FLASH_ENCRYPTION_COMMIT_ANCHOR,
        "#endif // CONFIG_SECURE_FLASH_ENC_ENABLED\n" + _secure.POP_IT_COMMIT_BLOCK + "#ifdef CONFIG_SECURE_BOOT_V1_ENABLED",
        1,
    )
    # Hardware anti-rollback is also irreversible. It may advance only after
    # Pop It has already enabled hardware Secure Boot.
    text = text.replace(
        ANTI_ROLLBACK_FUNCTION_ANCHOR,
        ANTI_ROLLBACK_FUNCTION_ANCHOR
        + '    if (!esp_secure_boot_enabled()) {\n'
        + '        ESP_LOGI(TAG, "KasSigner: anti-rollback eFuse update deferred until Pop It");\n'
        + '        return;\n'
        + '    }\n',
        1,
    )
    path.write_text(text)


def patch(path: Path, expected_digest: bytes | None = None) -> None:
    """Compatibility wrapper used by source-contract tests."""
    if expected_digest is None:
        expected_digest = bytes(32)
    patch_utility(path, expected_digest, False)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("bootloader_support", type=Path, help="copied ESP-IDF bootloader_support component")
    parser.add_argument(
        "--expected-key-digest",
        type=Path,
        required=True,
        help="32-byte Secure Boot v2 public-key digest generated from the selected authority key",
    )
    parser.add_argument(
        "--authority-mode",
        choices=("dual", "owner-only"),
        default="dual",
        help="dual = vendor digest0 plus optional owner digest1; owner-only = owner digest0 only",
    )
    args = parser.parse_args()
    utility = args.bootloader_support / "src" / "bootloader_utility.c"
    secure_boot = args.bootloader_support / "src" / "secure_boot_v2" / "secure_boot.c"
    for source in (utility, secure_boot):
        if not source.is_file():
            raise SystemExit(f"Missing bootloader source: {source}")

    expected_digest = args.expected_key_digest.read_bytes()
    if len(expected_digest) != 32:
        raise SystemExit(f"Expected 32-byte Secure Boot v2 digest, got {len(expected_digest)}")
    owner_only = args.authority_mode == "owner-only"
    patch_secure_boot(secure_boot, expected_digest, owner_only)
    patch_utility(utility, expected_digest, owner_only)
    print(f"Patched KasSigner {args.authority_mode} boot-control/authority integration: {utility}")
    print(f"Patched KasSigner exact-authority signature helpers: {secure_boot}")


if __name__ == "__main__":
    main()
