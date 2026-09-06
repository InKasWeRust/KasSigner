#!/usr/bin/env python3
"""Keep browser QA hermetic without deleting a previously built WASM package."""

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
HELPER = ROOT / "qa/checks/web/web_pkg_fixture.mjs"


class WebPackageFixturePolicyTests(unittest.TestCase):
    def test_browser_harnesses_use_the_shared_package_fixture(self) -> None:
        for relative in (
            "qa/checks/web/check_web_runtime.mjs",
            "qa/checks/web/check_web_covenant_interactions.mjs",
        ):
            source = (ROOT / relative).read_text(encoding="utf-8")
            self.assertIn("isolateWebPackage", source, relative)
            self.assertIn(".restore()", source, relative)
            self.assertNotIn("web/pkg already exists", source, relative)

        recovery_test = (ROOT / "qa/checks/web/web_recovery_coverage.test.mjs").read_text(encoding="utf-8")
        recovery_harness = (ROOT / "qa/checks/web/web_recovery_test_harness.mjs").read_text(encoding="utf-8")
        self.assertIn("web_recovery_test_harness.mjs", recovery_test)
        self.assertIn("isolateWebPackage", recovery_harness)
        self.assertIn(".restore()", recovery_harness)
        self.assertNotIn("web/pkg already exists", recovery_harness)

    def test_fixture_restores_an_existing_package_and_removes_a_temporary_one(self) -> None:
        node = shutil.which("node")
        if node is None:
            self.skipTest("node is unavailable")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            existing = root / "existing" / "pkg"
            existing.mkdir(parents=True)
            sentinel = b"real generated wasm package\n"
            (existing / "sentinel.bin").write_bytes(sentinel)
            absent = root / "absent" / "pkg"

            program = """
                import fs from 'node:fs/promises';
                const { isolateWebPackage } = await import(process.argv[1]);
                const existing = process.argv[2];
                const absent = process.argv[3];

                const preserved = await isolateWebPackage(existing);
                await preserved.create();
                await fs.writeFile(`${existing}/temporary.js`, 'stub');
                await preserved.restore();

                const temporary = await isolateWebPackage(absent);
                await temporary.create();
                await fs.writeFile(`${absent}/temporary.js`, 'stub');
                await temporary.restore();
            """
            subprocess.run(
                [
                    node,
                    "--input-type=module",
                    "--eval",
                    program,
                    HELPER.resolve().as_uri(),
                    str(existing),
                    str(absent),
                ],
                cwd=ROOT,
                check=True,
                text=True,
                capture_output=True,
            )

            self.assertEqual((existing / "sentinel.bin").read_bytes(), sentinel)
            self.assertFalse((existing / "temporary.js").exists())
            self.assertFalse(absent.exists())
            self.assertEqual(list(root.rglob(".qa-preserved-pkg-*")), [])


if __name__ == "__main__":
    unittest.main()
