#!/usr/bin/env python3
"""Regression coverage for generated KasSee wasm-bindgen output."""

from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "qa/checks"))

from architecture.core.source_quality import production_module_sources  # noqa: E402


class GeneratedWebPkgTests(unittest.TestCase):
    def test_generated_wasm_pkg_is_not_authored_production_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            generated = root / "target/kassee-web/site/pkg/kassee_web.js"
            local_generated = root / "apps/kassee-web/web/pkg/kassee_web.js"
            authored = root / "apps/kassee-web/web/js/app.js"
            for path in (generated, local_generated):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("\n".join("generated();" for _ in range(1000)))
            authored.parent.mkdir(parents=True)
            authored.write_text("export function app() {}\n")

            sources = production_module_sources(root)

            self.assertIn(authored, sources)
            self.assertNotIn(generated, sources)
            self.assertNotIn(local_generated, sources)

    def test_android_gradle_and_generated_web_assets_are_not_authored_production_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            generated_paths = [
                root / "apps/kassee-android/.kotlin/sessions/generated.js",
                root / "apps/kassee-android/app/build/intermediates/assets/debug/mergeDebugAssets/kassee/pkg/kassee_web.js",
                root / "apps/kassee-android/app/build/generated/kassigner-runtime/web/pkg/kassee_web.js",
            ]
            authored = root / "apps/kassee-android/app/src/main/java/example/source.js"
            for generated in generated_paths:
                generated.parent.mkdir(parents=True, exist_ok=True)
                generated.write_text("\n".join("generated();" for _ in range(1000)))
            authored.parent.mkdir(parents=True, exist_ok=True)
            authored.write_text("export function authored() {}\n")

            sources = production_module_sources(root)

            self.assertIn(authored, sources)
            for generated in generated_paths:
                self.assertNotIn(generated, sources)


if __name__ == "__main__":
    unittest.main()
