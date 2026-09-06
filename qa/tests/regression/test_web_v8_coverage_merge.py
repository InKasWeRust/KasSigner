import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SUPPORT = ROOT / "qa/checks/web/web_recovery_coverage_support.py"
spec = importlib.util.spec_from_file_location("web_cov_support_merge_test", SUPPORT)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
assert spec.loader is not None
spec.loader.exec_module(mod)


class WebV8CoverageMergeTests(unittest.TestCase):
    def test_overlapping_zero_range_cannot_erase_coverage_from_another_run(self):
        source = "function f(x) {\n  if (x) {\n    hit();\n  }\n  tail();\n}\n"
        whole = (0, len(source))
        body_start = source.index("  if")
        body_end = source.index("  tail")
        hit_start = source.index("    hit")
        hit_end = source.index("  }", hit_start) + 3
        existing = {"functions": [{
            "functionName": "f", "isBlockCoverage": True,
            "ranges": [
                {"startOffset": whole[0], "endOffset": whole[1], "count": 1},
                # Run A did not enter the if branch; V8 reports a broad cold range.
                {"startOffset": body_start, "endOffset": body_end, "count": 0},
            ],
        }]}
        incoming = {"functions": [{
            "functionName": "f", "isBlockCoverage": True,
            "ranges": [
                {"startOffset": whole[0], "endOffset": whole[1], "count": 1},
                # Run B entered it, but V8 used a narrower partition.
                {"startOffset": hit_start, "endOffset": hit_end, "count": 1},
            ],
        }]}
        mod._merge_script(existing, incoming)
        totals = mod.summarize_script(existing, source)
        self.assertEqual(totals.covered_lines, totals.total_lines)
        ranges = existing["functions"][0]["ranges"]
        self.assertEqual(ranges, sorted(ranges, key=lambda item: (item["startOffset"], -item["endOffset"])))


    def test_windows_file_url_is_canonicalized_against_repository_root(self):
        root = r"C:\Users\qauser\Downloads\kassigner"
        url = (
            "file:///C:/Users/qauser/Downloads/kassigner/"
            "apps/kassee-web/web/js/features/covenants/recovery/active.js"
        )
        self.assertEqual(
            mod.relative_file_url(url, root),
            "apps/kassee-web/web/js/features/covenants/recovery/active.js",
        )

    def test_windows_file_url_drive_and_directory_case_are_case_insensitive(self):
        root = r"C:\Users\QaUser\Downloads\KasSigner"
        url = (
            "file:///c:/users/qauser/downloads/kassigner/"
            "apps/kassee-web/web/js/features/covenants/recovery/export.js"
        )
        self.assertEqual(
            mod.relative_file_url(url, root),
            "apps/kassee-web/web/js/features/covenants/recovery/export.js",
        )

    def test_file_url_outside_repository_is_rejected(self):
        self.assertIsNone(
            mod.relative_file_url(
                "file:///C:/Users/qauser/Downloads/other/recovery.js",
                r"C:\Users\qauser\Downloads\kassigner",
            )
        )

    def test_branch_stays_uncovered_when_every_run_is_cold(self):
        source = "function f(x) {\n  if (x) {\n    hit();\n  }\n  tail();\n}\n"
        start = source.index("  if")
        end = source.index("  tail")
        base = {"functionName": "f", "isBlockCoverage": True, "ranges": [
            {"startOffset": 0, "endOffset": len(source), "count": 1},
            {"startOffset": start, "endOffset": end, "count": 0},
        ]}
        existing = {"functions": [{**base, "ranges": [dict(x) for x in base["ranges"]]}]}
        incoming = {"functions": [{**base, "ranges": [dict(x) for x in base["ranges"]]}]}
        mod._merge_script(existing, incoming)
        totals = mod.summarize_script(existing, source)
        self.assertLess(totals.covered_lines, totals.total_lines)


if __name__ == "__main__":
    unittest.main()
