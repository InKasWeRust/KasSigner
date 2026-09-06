import errno
import importlib.util
import io
from pathlib import Path
import shutil
import tempfile
import urllib.request
import unittest
from contextlib import redirect_stderr
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]


def load_real_node_runner():
    path = ROOT / "qa/checks/integration/real_node_browser.py"
    spec = importlib.util.spec_from_file_location("kassigner_real_node_browser", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RealNodeIntegrationContractTests(unittest.TestCase):
    def test_gate_uses_real_wasm_and_public_resolver_only(self):
        shell = (ROOT / "qa/linux/run-real-node-integration.sh").read_text()
        runner = (ROOT / "qa/checks/integration/real_node_browser.py").read_text()
        case = (ROOT / "qa/checks/integration/browser_real_node_case.mjs").read_text()
        resolver = (ROOT / "apps/kassee-web/web/js/core/node/resolver.js").read_text()
        makefile = (ROOT / "Makefile").read_text()
        catalog = (ROOT / "qa/config/run_all_steps.tsv").read_text()

        self.assertIn('pkg/kassee_web_bg.wasm', runner)
        self.assertIn('implausibly small; fixture/stub builds are forbidden', runner)
        self.assertIn("withNodeRetry", case)
        self.assertIn("networkState.customNodeUrl = null", case)
        self.assertIn("public-node gate requires mainnet", case)
        self.assertIn("resolver returned a local endpoint", case)
        self.assertIn('wasm.get_virtual_daa_score', case)
        self.assertIn('wasm.get_fee_estimate', case)
        self.assertIn('wasm.fetch_utxos_for_address_js', case)
        self.assertIn('/__qa_real_node_result__', runner)
        self.assertIn('/__qa_real_node_result__', case)
        self.assertIn('time.monotonic()', runner)
        self.assertIn('--remote-debugging-port=', runner)
        self.assertNotIn('--virtual-time-budget', runner)
        self.assertNotIn('--dump-dom', runner)
        self.assertNotIn('wasm.broadcast_signed', case)

        combined = "\n".join((shell, runner, case, makefile))
        self.assertNotIn('KASPAD_BIN', combined)
        self.assertNotIn('KASPAD_EXTRA_ARGS', combined)
        self.assertNotIn('local_kaspad', combined)
        self.assertNotIn('"--simnet"', combined)
        self.assertNotIn('rpclisten-borsh', combined)
        self.assertNotIn('run-real-node-integration.sh both', combined)
        self.assertIn("globalThis.location?.protocol === 'https:' ? 'tls' : 'any'", resolver)
        self.assertIn("if (security === 'tls') return url.startsWith('wss://')", resolver)
        self.assertIn("/${security}/wrpc/borsh", resolver)
        self.assertIn('official resolver pool', shell)
        self.assertIn('kassigner_reconcile_host_locks', shell)
        self.assertIn('--evidence', shell)
        self.assertIn('complete_hardening.py', shell)
        self.assertIn('parser.add_argument("--evidence"', runner)
        self.assertIn('write_evidence(args.evidence, detail)', runner)
        self.assertIn('integration.real-node', catalog)
        self.assertIn('tempfile.mkdtemp(prefix="kassigner-real-node-chrome-")', runner)
        self.assertIn('stop_chromium(process)', runner)
        self.assertIn('start_new_session=os.name == "posix"', runner)
        self.assertIn('os.killpg(process.pid, signal.SIGTERM)', runner)
        self.assertIn('cleanup_chromium_profile(profile_dir)', runner)
        self.assertNotIn('TemporaryDirectory(prefix="kassigner-real-node-chrome-")', runner)


    def test_http_server_uses_browser_safe_module_mime_and_ignores_favicon(self):
        runner = load_real_node_runner()
        with runner.http_server() as port:
            with urllib.request.urlopen(
                f"http://127.0.0.1:{port}/qa/checks/integration/browser_real_node_case.mjs"
            ) as response:
                self.assertEqual(response.status, 200)
                self.assertEqual(response.headers.get_content_type(), "text/javascript")
                self.assertIn(b"withNodeRetry", response.read())
            with urllib.request.urlopen(
                f"http://127.0.0.1:{port}/apps/kassee-web/web/js/core/node/resolver.js"
            ) as response:
                self.assertEqual(response.headers.get_content_type(), "text/javascript")
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/favicon.ico") as response:
                self.assertEqual(response.status, 204)

    def test_browser_discovery_accepts_windows_edge_and_chrome_install_paths(self):
        runner = load_real_node_runner()
        with tempfile.TemporaryDirectory(prefix="real-node-browser-discovery-") as tmp:
            root = Path(tmp)
            program_files = root / "Program Files"
            local_app_data = root / "LocalAppData"
            edge = program_files / "Microsoft/Edge/Application/msedge.exe"
            chrome = local_app_data / "Google/Chrome/Application/chrome.exe"
            edge.parent.mkdir(parents=True)
            chrome.parent.mkdir(parents=True)
            edge.write_bytes(b"edge")
            chrome.write_bytes(b"chrome")

            env = {
                "PROGRAMFILES": str(program_files),
                "LOCALAPPDATA": str(local_app_data),
            }
            with patch.object(runner.shutil, "which", return_value=None):
                self.assertEqual(runner.browser_executable(platform_name="nt", environ=env), str(edge))

            edge.unlink()
            with patch.object(runner.shutil, "which", return_value=None):
                self.assertEqual(runner.browser_executable(platform_name="nt", environ=env), str(chrome))

    def test_browser_discovery_prefers_path_browser(self):
        runner = load_real_node_runner()
        with patch.object(runner.shutil, "which", side_effect=lambda name: "C:/Browser/msedge.exe" if name == "msedge.exe" else None):
            self.assertEqual(runner.browser_executable(), "C:/Browser/msedge.exe")

    def test_profile_cleanup_retries_directory_not_empty_race(self):
        runner = load_real_node_runner()
        profile = Path(tempfile.mkdtemp(prefix="real-node-cleanup-test-"))
        (profile / "Default").mkdir()
        (profile / "Default" / "Preferences").write_text("{}")
        real_rmtree = shutil.rmtree
        calls = 0

        def flaky_rmtree(path):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise OSError(errno.ENOTEMPTY, "Directory not empty", str(Path(path) / "Default"))
            real_rmtree(path)

        with patch.object(runner.shutil, "rmtree", side_effect=flaky_rmtree), patch.object(runner.time, "sleep") as sleep:
            runner.cleanup_chromium_profile(profile, attempts=3, delay_seconds=0.01)

        self.assertEqual(calls, 2)
        sleep.assert_called_once_with(0.01)
        self.assertFalse(profile.exists())

    def test_profile_cleanup_never_overwrites_integration_result(self):
        runner = load_real_node_runner()
        profile = Path(tempfile.mkdtemp(prefix="real-node-cleanup-test-"))
        error = OSError(errno.ENOTEMPTY, "Directory not empty", str(profile / "Default"))
        stderr = io.StringIO()
        try:
            with patch.object(runner.shutil, "rmtree", side_effect=error), patch.object(runner.time, "sleep"):
                with redirect_stderr(stderr):
                    runner.cleanup_chromium_profile(profile, attempts=2, delay_seconds=0.01)
            self.assertIn("WARNING: could not fully remove temporary Chromium profile", stderr.getvalue())
            self.assertTrue(profile.exists())
        finally:
            real_rmtree = shutil.rmtree
            real_rmtree(profile, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
