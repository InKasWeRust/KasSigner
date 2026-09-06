from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]
BROWSER_LOG = ROOT / "crates/online-watcher/src/infrastructure/browser_log.rs"
INFRASTRUCTURE_MOD = ROOT / "crates/online-watcher/src/infrastructure/mod.rs"
NATIVE_TEST = ROOT / "crates/online-watcher/src/infrastructure/unit_tests/mod.rs"


class OnlineWatcherNativeLoggingTests(unittest.TestCase):
    def test_browser_logging_is_target_gated(self) -> None:
        source = BROWSER_LOG.read_text()
        self.assertIn('#[cfg(target_arch = "wasm32")]', source)
        self.assertIn('#[cfg(not(target_arch = "wasm32"))]', source)

        wasm_start = source.index('#[cfg(target_arch = "wasm32")]')
        native_start = source.index('#[cfg(not(target_arch = "wasm32"))]')
        wasm_source = source[wasm_start:native_start]
        native_source = source[native_start:]

        self.assertIn("JsValue::from_str", wasm_source)
        self.assertIn("web_sys::console::log_1", wasm_source)
        self.assertNotIn("JsValue", native_source)
        self.assertNotIn("web_sys", native_source)

    def test_native_noop_has_direct_rust_regression_coverage(self) -> None:
        self.assertIn("mod unit_tests;", INFRASTRUCTURE_MOD.read_text())
        test_source = NATIVE_TEST.read_text()
        self.assertIn('#[cfg(not(target_arch = "wasm32"))]', test_source)
        self.assertIn("browser_log::info", test_source)


if __name__ == "__main__":
    unittest.main()
