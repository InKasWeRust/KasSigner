#!/usr/bin/env python3
"""Regression coverage for the public documentation and platform QA layout."""
from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "qa/checks"))

from architecture.core.common import is_generated_tree  # noqa: E402

DOCS = ROOT / "docs"
QA = ROOT / "qa"


class RepositoryOrganizationTests(unittest.TestCase):
    def test_docs_are_grouped_with_a_guided_hub(self) -> None:
        self.assertEqual(
            {path.name for path in DOCS.iterdir() if path.is_dir()},
            {"development", "features", "guides", "hardware", "integration", "kassee", "protocol", "security"},
        )
        self.assertEqual(
            {path.name for path in DOCS.iterdir() if path.is_file()},
            {"README.md", "EFUSE_RUNBOOK.md"},
        )
        expected = {
            "README.md",
            "EFUSE_RUNBOOK.md",
            "development/BUILDING.md",
            "development/BUILD_FLASH_GUIDE.md",
            "development/FIRMWARE_ARCHITECTURE.md",
            "development/REPOSITORY_ARCHITECTURE.md",
            "development/REPRODUCIBLE_BUILD.md",
            "development/WORKFLOW_E2E.md",
            "features/FEATURES.md",
            "guides/KasSee_User_Guide.pdf",
            "guides/KasSigner_Kassee_Covenants_Stealth_Guide.pdf",
            "guides/KasSigner_Quick_Start_Guide.pdf",
            "guides/KasSigner_Security_Architecture.pdf",
            "guides/KasSigner_Seed_Cards.pdf",
            "guides/KasSigner_User_Guide.pdf",
            "hardware/HARDWARE.md",
            "integration/WALLET_INTEGRATION.md",
            "integration/vectors/kassigner_sdk_v2.json",
            "kassee/KASSEE.md",
            "protocol/COVENANT_SIGN.md",
            "security/EFUSE_RUNBOOK.md",
            "security/ENTROPY_SOURCES.md",
            "security/POP_IT_SECURE_BOOT.md",
            "security/SECURITY_OVERVIEW.md",
            "security/STEGANOGRAPHY.md",
        }
        self.assertEqual(
            {path.relative_to(DOCS).as_posix() for path in DOCS.rglob("*") if path.is_file()},
            expected,
        )
        self.assertFalse((DOCS / "readme").exists())
        self.assertTrue((QA / "specs/production_e2e_requirements.md").is_file())
        self.assertTrue((QA / "generated/production_ui_map.md").is_file())
        self.assertFalse((DOCS / "development/PRODUCTION_E2E_REQUIREMENTS.md").exists())
        self.assertFalse((DOCS / "development/PRODUCTION_E2E_REQUIREMENT_ITEMS.md").exists())
        self.assertFalse((DOCS / "development/PRODUCTION_UI_MAP.md").exists())

    def test_documentation_hub_and_readmes_use_breadcrumb_navigation(self) -> None:
        hub = (DOCS / "README.md").read_text(encoding="utf-8")
        self.assertTrue(hub.startswith("[KasSigner](../README.md) › Documentation"))
        for token in (
            "features/FEATURES.md", "development/BUILDING.md", "kassee/KASSEE.md",
            "security/SECURITY_OVERVIEW.md", "hardware/HARDWARE.md",
            "development/REPOSITORY_ARCHITECTURE.md", "integration/WALLET_INTEGRATION.md",
        ):
            self.assertIn(token, hub)

        root = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("**Navigate:** [Documentation](docs/README.md)", root)
        self.assertNotIn("docs/readme/", root)

        component_readmes = [
            path for path in ROOT.rglob("README.md")
            if path != ROOT / "README.md" and not is_generated_tree(path, ROOT)
        ]
        self.assertTrue(component_readmes)
        for path in component_readmes:
            first = path.read_text(encoding="utf-8").splitlines()[0]
            self.assertTrue(first.startswith("[KasSigner]("), path.relative_to(ROOT).as_posix())
            self.assertIn("Documentation", first, path.relative_to(ROOT).as_posix())

    def test_platform_specific_qa_scripts_live_under_platform_trees(self) -> None:
        escaped = [
            path.relative_to(ROOT).as_posix()
            for path in QA.rglob("*")
            if path.is_file()
            and path.suffix.lower() in {".sh", ".ps1", ".desktop"}
            and QA / "linux" not in path.parents
            and QA / "windows" not in path.parents
        ]
        self.assertEqual(escaped, [])
        self.assertFalse(list((QA / "linux").rglob("*.ps1")))
        self.assertFalse(list((QA / "windows").rglob("*.sh")))
        self.assertFalse(list((QA / "windows").rglob("*.desktop")))

    def test_native_qa_entrypoints_are_mirrored(self) -> None:
        linux = {
            path.relative_to(QA / "linux").with_suffix("").as_posix()
            for path in (QA / "linux").rglob("*.sh")
            if "runner" not in path.parts and "lib" not in path.parts
        }
        windows = {
            path.relative_to(QA / "windows").with_suffix("").as_posix()
            for path in (QA / "windows").rglob("*.ps1")
        }
        self.assertEqual(linux, windows)

    def test_firmware_features_are_manifest_documentation_not_a_public_make_target(self) -> None:
        manifest = tomllib.loads((ROOT / "apps/signer-firmware/Cargo.toml").read_text(encoding="utf-8"))
        self.assertTrue(manifest["features"])
        self.assertFalse((ROOT / "tools/dev/list_firmware_features.py").exists())
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        help_text = subprocess.run(["make", "help"], cwd=ROOT, text=True, capture_output=True, check=True).stdout
        self.assertNotIn("firmware-features:", makefile)
        self.assertNotIn("make firmware-features", help_text)

    def test_public_docs_present_make_as_the_developer_interface(self) -> None:
        public = [
            ROOT / "README.md",
            ROOT / "CONTRIBUTING.md",
            ROOT / ".github/PULL_REQUEST_TEMPLATE.md",
            *DOCS.rglob("*.md"),
        ]
        forbidden = (
            "./qa/linux/run-all.sh",
            ".\\qa\\windows\\run-all.ps1",
            "python3 qa/checks/",
            "python qa/checks/",
            "docker build --platform",
            "docker run --rm kassigner-build",
        )
        internal_safety_runbooks = {ROOT / "docs/EFUSE_RUNBOOK.md"}
        for path in public:
            text = path.read_text(encoding="utf-8")
            for token in forbidden:
                if path in internal_safety_runbooks and token in {"python3 qa/checks/", "python qa/checks/"}:
                    continue
                self.assertNotIn(token, text, f"{path.relative_to(ROOT)} advertises internal helper {token}")
        root = (ROOT / "README.md").read_text(encoding="utf-8")
        contributing = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
        building = (ROOT / "docs/development/BUILDING.md").read_text(encoding="utf-8")
        for token in ("make test", "make qa", "make firmware", "make flash", "make release"):
            self.assertIn(token, root + contributing + building)


    def test_public_docs_only_advertise_real_make_targets(self) -> None:
        import re

        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        targets = set(re.findall(r"^([A-Za-z0-9_.-]+):(?:\s|$)", makefile, re.MULTILINE))
        public = [
            ROOT / "README.md",
            ROOT / "CONTRIBUTING.md",
            ROOT / "SECURITY.md",
            *DOCS.rglob("*.md"),
            *[path for path in (ROOT / "apps").rglob("README.md") if not is_generated_tree(path, ROOT)],
            *[path for path in (ROOT / "crates").rglob("README.md") if not is_generated_tree(path, ROOT)],
            ROOT / "qa/release/README.md",
        ]
        stale: list[str] = []
        for path in public:
            if not path.is_file():
                continue
            in_fence = False
            for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                stripped = line.strip()
                if stripped.startswith("```"):
                    in_fence = not in_fence
                    continue
                candidates: list[str] = [
                    span for span in re.findall(r"`([^`]*)`", line)
                    if re.search(r"\bmake\s+[A-Za-z0-9_.-]+", span)
                ]
                if in_fence and re.match(r"^(?:[A-Z_][A-Z0-9_]*=[^ ]+\s+)*make\s+", stripped):
                    candidates.append(stripped)
                for candidate in candidates:
                    for match in re.finditer(r"\bmake\s+([A-Za-z0-9_.-]+)", candidate):
                        target = match.group(1)
                        if target not in targets:
                            stale.append(f"{path.relative_to(ROOT)}:{line_number}: make {target}")
        self.assertEqual(stale, [])

    def test_public_docs_use_neutral_validation_wording(self) -> None:
        for relative in (
            "README.md",
            "SECURITY.md",
            "docs/development/BUILD_FLASH_GUIDE.md",
            "docs/EFUSE_RUNBOOK.md",
        ):
            text = (ROOT / relative).read_text(encoding="utf-8").lower()
            self.assertNotIn("maintainer", text, relative)

    def test_readme_keeps_original_top_level_structure_and_current_compatibility_claims(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        headings = [line[3:] for line in readme.splitlines() if line.startswith("## ")]
        self.assertEqual(headings, [
            "Features",
            "Verify First: Reproducible Builds",
            "Steganographic Backup: A beautiful way",
            "Covenants++",
            "Wallet Slot Types",
            "Supported Hardware",
            "Building",
            "KasSee: Watch-Only Companion Wallet",
            "What KasSigner Is",
            "What KasSigner Is NOT",
            "Security Architecture",
            "Documentation",
            "Hardware References",
            "Cryptographic Notice",
            "Contributing",
            "License",
            "Disclaimer",
        ])
        normalized = readme.replace("**", "").lower()
        for token in (
            "or dice rolls",
            "steganographic backup tool",
            "optionally stateless",
            "kasware-style raw-key exports",
            "https://kassigner.org/",
            "wss://",
            "ws://",
            "external/hardware/",
            "esp32-s3 technical reference manual",
            "waveshare esp32-s3-touch-lcd-2 wiki",
        ):
            self.assertIn(token, normalized)

        dice_source = (ROOT / "apps/signer-firmware/src/ui/screens/wallet/seed_generation.rs").read_text(encoding="utf-8")
        raw_key_source = (ROOT / "apps/signer-firmware/src/services/raw_key.rs").read_text(encoding="utf-8")
        self.assertIn("draw_dice_screen", dice_source)
        self.assertIn("payload.len() != 64", raw_key_source)
        self.assertIn("pubkey_from_raw_key(&key)", raw_key_source)

    def test_public_markdown_local_links_resolve_after_reorganization(self) -> None:
        import re
        paths = [
            ROOT / "README.md", ROOT / "CONTRIBUTING.md", ROOT / "SECURITY.md", ROOT / "CHANGELOG.md",
            *DOCS.rglob("*.md"), * (ROOT / ".github").rglob("*.md"),
        ]
        missing: list[str] = []
        for path in paths:
            if not path.is_file():
                continue
            for match in re.finditer(r"\[[^\]]*\]\(([^)]+)\)", path.read_text(encoding="utf-8")):
                target = match.group(1).split("#", 1)[0].strip()
                if not target or "://" in target or target.startswith(("mailto:", "#")):
                    continue
                if not (path.parent / target).resolve().exists():
                    missing.append(f"{path.relative_to(ROOT)} -> {target}")
        self.assertEqual(missing, [])


if __name__ == "__main__":
    unittest.main()
