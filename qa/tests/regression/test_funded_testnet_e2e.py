from pathlib import Path
import importlib.util
import os
import tempfile
import unittest
import urllib.request
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
RUNNER_PATH = ROOT / "qa/checks/integration/funded_testnet_e2e.py"


def load_runner():
    spec = importlib.util.spec_from_file_location("funded_testnet_e2e_under_test", RUNNER_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FundedTestnetE2EContractTests(unittest.TestCase):
    def test_network_wallet_and_local_address_precede_public_node_status(self):
        runner = RUNNER_PATH.read_text(encoding="utf-8")
        main = runner[runner.index("def main()") : runner.index("def entrypoint()")]
        self.assertLess(main.index("select_network()"), main.index("build_real_wasm()"))
        self.assertLess(main.index("select_network()"), main.index("ensure_wallet(network)"))
        self.assertLess(main.index('"phase": "address"'), main.index("status_with_retries"))
        self.assertLess(main.index("print_wallet_address"), main.index("wait_for_funding_confirmation"))
        self.assertLess(main.index("wait_for_funding_confirmation"), main.index("status_with_retries"))
        self.assertIn('("1", "testnet-10", "Testnet-10")', runner)
        self.assertIn('("2", "testnet-12", "Testnet-12")', runner)
        self.assertIn('"testnet-10": "https://faucet-testnet.kaspanet.io/"', runner)
        self.assertIn('"testnet-12": "https://faucet-tn12.kaspanet.io/"', runner)
        self.assertNotIn("no Enter key is required", runner)

    def test_funded_flow_uses_local_address_then_real_wasm_and_public_resolver(self):
        browser = (ROOT / "qa/checks/integration/funded_testnet_e2e_case.mjs").read_text()
        runner = RUNNER_PATH.read_text(encoding="utf-8")
        signer = (ROOT / "tools/dev/funded_e2e_signer.rs").read_text()
        gitignore = (ROOT / ".gitignore").read_text()
        resolver = (ROOT / "apps/kassee-web/web/js/core/node/resolver.js").read_text()
        balance = (ROOT / "apps/kassee-web/web/js/features/wallet/core/balance.js").read_text()

        self.assertIn("if (input.phase === 'address') return addressCase(input, wallet)", browser)
        self.assertLess(browser.index("if (input.phase === 'address')"), browser.index("configureNetwork(input.network)"))
        self.assertIn("withNodeRetry", browser)
        self.assertIn("withFundedNodeRetry", browser)
        self.assertNotIn("await resolvePublicNode()", browser)
        self.assertIn("networkState.customNodeUrl = null", browser)
        self.assertIn("wasm.create_send_pskb", browser)
        self.assertIn("wasm.pskt_relay_to_kspt", browser)
        self.assertIn("wasm.kassigner_sdk_complete", browser)
        self.assertIn("const merged = signed.psktHex", browser)
        self.assertNotIn("wasm.pskt_merge_signed_kspt", browser)
        self.assertIn("wasm.pskt_finalize_and_broadcast", browser)
        self.assertIn("wasm.fetch_utxos_for_address_js", browser)
        self.assertIn("BigInt(value)", browser)
        self.assertNotIn("Number(utxo.amount)", browser)
        self.assertIn("sign_transaction_multi_addr_with_entropy", signer)
        self.assertIn("review_transaction", signer)
        self.assertIn("OsRng.fill_bytes", signer)
        self.assertIn("/target/", gitignore)
        self.assertIn('Path.home() / ".local/state"', runner)
        self.assertIn('"kassigner/funded-e2e"', runner)
        self.assertIn("KASSIGNER_FUNDED_E2E_STATE_DIR", runner)
        self.assertIn("globalThis.location?.protocol === 'https:' ? 'tls' : 'any'", resolver)
        self.assertIn("if (security === 'tls') return url.startsWith('wss://')", resolver)
        self.assertIn("activeWsUrl = wsUrl", browser)
        self.assertIn("attemptedWsUrls.push(wsUrl)", browser)
        self.assertIn("ws_urls_attempted", browser)
        self.assertIn("ws_urls_failed", browser)
        self.assertIn("resolver repeated previously failed WebSocket endpoint", browser)
        self.assertIn("return withNodeRetry", browser)
        self.assertIn("return resolvePublicNode()", balance)

    def test_funded_http_server_uses_browser_safe_module_mime_and_ignores_favicon(self):
        runner = load_runner()
        with runner.http_server() as port:
            with urllib.request.urlopen(
                f"http://127.0.0.1:{port}/qa/checks/integration/funded_testnet_e2e_case.mjs"
            ) as response:
                self.assertEqual(response.status, 200)
                self.assertEqual(response.headers.get_content_type(), "text/javascript")
                self.assertIn(b"withFundedNodeRetry", response.read())
            with urllib.request.urlopen(
                f"http://127.0.0.1:{port}/apps/kassee-web/web/js/core/node/resolver.js"
            ) as response:
                self.assertEqual(response.headers.get_content_type(), "text/javascript")
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/favicon.ico") as response:
                self.assertEqual(response.status, 204)

    def test_browser_websocket_reports_close_and_timeout_stage(self):
        transport = (ROOT / "crates/online-watcher/src/infrastructure/browser_websocket.rs").read_text()
        errors = (ROOT / "crates/online-watcher/src/network/error.rs").read_text()
        cargo = (ROOT / "crates/online-watcher/Cargo.toml").read_text()

        self.assertIn('"CloseEvent"', cargo)
        self.assertIn("set_onclose", transport)
        self.assertIn("CloseEvent", transport)
        self.assertIn("request_sent.set(true)", transport)
        self.assertIn("NetworkError::ConnectTimeout", transport)
        self.assertIn("NetworkError::ResponseTimeout", transport)
        self.assertIn('"WebSocket connect timeout (15s)"', errors)
        self.assertIn('"WebSocket RPC response timeout (15s)"', errors)
        self.assertNotIn("NetworkError::Timeout", transport)


    def test_funded_signer_helper_uses_pinned_stable_rust_and_verified_tools_graph(self):
        wrapper = (ROOT / "qa/linux/run-funded-testnet-e2e.sh").read_text()
        runner = RUNNER_PATH.read_text(encoding="utf-8")
        self.assertIn('source "$ROOT/qa/config/toolchains.env"', wrapper)
        self.assertIn('export KASSIGNER_STABLE_RUST', wrapper)
        self.assertIn('source "$ROOT/scripts/linux/lib/rustup_bootstrap.sh"', wrapper)
        self.assertIn('kassigner_ensure_rust_toolchain "$KASSIGNER_STABLE_RUST"', wrapper)
        self.assertIn('"rustup"', runner)
        self.assertIn('"run"', runner)
        self.assertIn('toolchain', runner)
        self.assertIn('"--locked"', runner)
        self.assertIn("def ensure_tools_lock_current", runner)
        lock_guard = runner[runner.index("def ensure_tools_lock_current") : runner.index("def run_signer_helper")]
        self.assertIn('"--offline"', lock_guard)
        self.assertIn('original = lockfile.read_bytes()', lock_guard)
        self.assertIn('refreshed tools/Cargo.lock still fails --locked', lock_guard)
        main = runner[runner.index("def main()") : runner.index("def entrypoint()")]
        self.assertLess(main.index("ensure_tools_lock_current()"), main.index("ensure_wallet(network)"))

    def test_browser_close_reason_keeps_browser_only_adapter_complexity_bounded(self):
        transport = (ROOT / "crates/online-watcher/src/infrastructure/browser_websocket.rs").read_text()
        helper = transport[transport.index("fn close_reason") : transport.index("fn complete")]
        self.assertNotIn("if ", helper)
        self.assertNotIn("match ", helper)
        self.assertIn(".take(160)", helper)
        self.assertIn("!character.is_control()", helper)
        self.assertIn("code {}", helper)
        self.assertIn("clean={}", helper)

    def test_funded_wallet_state_defaults_outside_the_repository_tree(self):
        runner = load_runner()
        with mock.patch.dict(runner.os.environ, {}, clear=True), mock.patch.object(
            runner.Path, "home", return_value=Path("/home/tester")
        ):
            self.assertEqual(
                runner.funded_state_root(),
                Path("/home/tester/.local/state/kassigner/funded-e2e"),
            )
        with mock.patch.dict(
            runner.os.environ,
            {"KASSIGNER_FUNDED_E2E_STATE_DIR": "/tmp/kassigner-funded"},
            clear=True,
        ):
            self.assertEqual(runner.funded_state_root(), Path("/tmp/kassigner-funded"))

    def test_funding_confirmation_requires_explicit_yes_and_can_quit(self):
        runner = load_runner()
        with mock.patch("builtins.input", side_effect=["", "no", "y"]):
            runner.wait_for_funding_confirmation()
        with mock.patch("builtins.input", return_value="q"):
            with self.assertRaises(SystemExit) as raised:
                runner.wait_for_funding_confirmation()
        self.assertIn("stopped before public-node access", str(raised.exception))

    def test_funding_prompt_uses_network_specific_faucet(self):
        runner = load_runner()
        with mock.patch("builtins.print") as printed:
            runner.print_funding_prompt(
                "testnet-12", "Testnet-12", "kaspatest:qexample", existing=False
            )
        text = "\n".join(" ".join(map(str, call.args)) for call in printed.call_args_list)
        self.assertIn("https://faucet-tn12.kaspanet.io/", text)
        self.assertNotIn("https://faucet-testnet.kaspanet.io/", text)
        self.assertIn("No public-node request will run until you explicitly confirm", text)

    def test_interactive_input_does_not_require_tty_stdout(self):
        runner = load_runner()

        class InteractiveInput:
            def isatty(self):
                return True

        self.assertTrue(runner.interactive_stdin_available(InteractiveInput()))

    def test_interactive_prompts_repair_windows_console_line_and_echo_mode(self):
        runner = load_runner()
        source = RUNNER_PATH.read_text(encoding="utf-8")
        self.assertIn("restore_windows_console_line_input()", source)
        self.assertIn("enable_line_input = 0x0002", source)
        self.assertIn("enable_echo_input = 0x0004", source)
        self.assertIn("enable_virtual_terminal_input = 0x0200", source)
        self.assertIn("& ~enable_virtual_terminal_input", source)
        self.assertIn('interactive_input("Network [1]: ")', source)
        self.assertIn('interactive_input("Funding complete and ready to query the public node? [y/q]: ")', source)

        with mock.patch.object(runner, "restore_windows_console_line_input") as repair, mock.patch(
            "builtins.input", return_value="1"
        ) as raw_input:
            self.assertEqual(runner.interactive_input("Network [1]: "), "1")
        repair.assert_called_once_with()
        raw_input.assert_called_once_with("Network [1]: ")

        import ctypes
        import types

        class FakeStream:
            def fileno(self):
                return 0

        class FakeKernel32:
            def __init__(self):
                self.updated = None

            def GetConsoleMode(self, _handle, pointer):
                pointer._obj.value = 0x0200
                return 1

            def SetConsoleMode(self, _handle, mode):
                self.updated = mode
                return 1

        kernel32 = FakeKernel32()
        fake_msvcrt = types.SimpleNamespace(get_osfhandle=lambda _fd: 99)
        with mock.patch.object(runner.os, "name", "nt"), mock.patch.dict(
            "sys.modules", {"msvcrt": fake_msvcrt}
        ), mock.patch.object(ctypes, "windll", types.SimpleNamespace(kernel32=kernel32), create=True):
            self.assertTrue(runner.restore_windows_console_line_input(FakeStream()))
        self.assertEqual(kernel32.updated, 0x0007)

    def test_windows_funded_browser_discovery_finds_edge_without_path_entry(self):
        runner = load_runner()
        with tempfile.TemporaryDirectory() as temporary:
            program_files = Path(temporary) / "Program Files"
            edge = program_files / "Microsoft/Edge/Application/msedge.exe"
            edge.parent.mkdir(parents=True)
            edge.write_bytes(b"MZ")
            with mock.patch.object(runner.shutil, "which", return_value=None):
                found = runner.browser_executable(
                    platform_name="nt",
                    environ={"PROGRAMFILES": str(program_files)},
                )
            self.assertEqual(found, str(edge))

    def test_chromium_timeout_is_controlled_and_phase_specific(self):
        runner = load_runner()

        class FakeProcess:
            def __init__(self):
                self.pid = 4242
                self.returncode = None

            def poll(self):
                return self.returncode

            def terminate(self):
                self.returncode = 0

            def wait(self, timeout=None):
                self.returncode = 0
                return 0

            def kill(self):
                self.returncode = -9

        with mock.patch.object(runner, "browser_executable", return_value="/usr/bin/chromium"), mock.patch.object(
            runner.subprocess, "Popen", return_value=FakeProcess()
        ) as popen, mock.patch.object(runner.subprocess, "run"), mock.patch.object(
            runner, "wait_for_chromium_debugger"
        ), mock.patch.object(
            runner, "open_chromium_target"
        ), mock.patch.object(runner.time, "monotonic", side_effect=[0.0, 61.0]):
            with self.assertRaises(runner.BrowserPhaseError) as raised:
                runner.chromium_result(12345, {"phase": "status", "network": "testnet-12"}, timeout=60)
        command = popen.call_args.args[0]
        self.assertFalse(any(argument.startswith("--virtual-time-budget=") for argument in command))
        self.assertFalse(any(argument.startswith("--timeout=") for argument in command))
        self.assertNotIn("--dump-dom", command)
        self.assertTrue(any(argument.startswith("--user-data-dir=") for argument in command))
        message = str(raised.exception)
        self.assertIn("phase 'status' timed out after 60 wall-clock seconds", message)
        self.assertIn("/usr/bin/chromium", message)
        self.assertTrue(raised.exception.retryable)
        self.assertGreaterEqual(runner.STATUS_TIMEOUT_SECONDS, 90)
        self.assertGreaterEqual(runner.RPC_PHASE_TIMEOUT_SECONDS, 180)

    def test_devtools_target_creation_is_loopback_put_with_encoded_url(self):
        runner = load_runner()

        class FakeResponse:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self):
                return b'{"id":"target-1"}'

        with mock.patch.object(runner.urllib.request, "urlopen", return_value=FakeResponse()) as urlopen:
            runner.open_chromium_target(9222, "http://127.0.0.1:12345/__qa_funded_e2e__")
        request = urlopen.call_args.args[0]
        self.assertEqual(request.get_method(), "PUT")
        self.assertTrue(request.full_url.startswith("http://127.0.0.1:9222/json/new?"))
        self.assertIn("http%3A%2F%2F127.0.0.1%3A12345%2F__qa_funded_e2e__", request.full_url)

    def test_browser_result_callback_drives_completion_without_dom_capture(self):
        runner = load_runner()

        class FakeProcess:
            def __init__(self):
                self.pid = 4242
                self.returncode = None

            def poll(self):
                return self.returncode

            def terminate(self):
                self.returncode = 0

            def wait(self, timeout=None):
                self.returncode = 0
                return 0

            def kill(self):
                self.returncode = -9

        def launch(*_args, **_kwargs):
            runner.FundedHandler.result_payload = {
                "status": "pass",
                "detail": {"phase": "address", "funding_address": "kaspatest:qexample"},
            }
            runner.FundedHandler.result_event.set()
            return FakeProcess()

        with mock.patch.object(runner, "browser_executable", return_value="/usr/bin/chromium"), mock.patch.object(
            runner.subprocess, "Popen", side_effect=launch
        ) as popen, mock.patch.object(runner.subprocess, "run"), mock.patch.object(
            runner, "wait_for_chromium_debugger"
        ), mock.patch.object(
            runner, "open_chromium_target"
        ) as open_target:
            status, detail = runner.chromium_result(12345, {"phase": "address", "network": "testnet-10"}, timeout=10)
        self.assertEqual(status, "pass")
        self.assertEqual(detail["funding_address"], "kaspatest:qexample")
        command = popen.call_args.args[0]
        self.assertNotIn("--dump-dom", command)
        self.assertFalse(any(argument.startswith("--timeout=") for argument in command))
        self.assertFalse(any(argument.startswith("--virtual-time-budget=") for argument in command))
        self.assertTrue(any(argument.startswith("--remote-debugging-port=") for argument in command))
        open_target.assert_called_once()
        self.assertEqual(open_target.call_args.args[1], "http://127.0.0.1:12345/__qa_funded_e2e__")

    def test_real_network_browser_uses_wall_clock_result_callback(self):
        runner = RUNNER_PATH.read_text(encoding="utf-8")
        browser = (ROOT / "qa/checks/integration/funded_testnet_e2e_case.mjs").read_text()
        self.assertNotIn('f"--virtual-time-budget=', runner)
        self.assertNotIn('f"--timeout=', runner)
        self.assertNotIn('"--dump-dom"', runner)
        self.assertIn("subprocess.Popen", runner)
        self.assertIn("--remote-debugging-address=127.0.0.1", runner)
        self.assertIn("open_chromium_target", runner)
        self.assertIn("result_event.wait", runner)
        self.assertIn("/__qa_funded_result__", runner)
        self.assertIn("fetch('/__qa_funded_result__'", browser)
        self.assertIn("await run();", browser)
        self.assertIn("Python", browser)


    def test_funded_gate_is_catalogued_after_real_node_and_before_long_campaigns(self):
        catalog = (ROOT / "qa/config/run_all_steps.tsv").read_text(encoding="utf-8").splitlines()
        ids = [line.split("\t")[3] for line in catalog if line and not line.startswith("#")]
        dispatch = (ROOT / "scripts/common/lib/make_tasks.py").read_text(encoding="utf-8")
        entry = ROOT / "scripts/linux/quality/funded-testnet-e2e.sh"
        runner = RUNNER_PATH.read_text(encoding="utf-8")
        self.assertIn('"funded-testnet-e2e": "quality/funded-testnet-e2e"', dispatch)
        self.assertTrue(entry.is_file())
        if os.name == "posix":
            self.assertTrue(entry.stat().st_mode & 0o111)
        self.assertLess(ids.index("integration.real-node"), ids.index("integration.funded-testnet-e2e"))
        self.assertLess(ids.index("integration.funded-testnet-e2e"), ids.index("mutation.repository-security-fresh"))
        self.assertIn("NONINTERACTIVE_SKIP = 77", runner)
        self.assertIn("interactive_stdin_available()", runner)
        self.assertIn("GetConsoleMode", runner)
        self.assertNotIn("sys.stdout.isatty()", runner)


if __name__ == "__main__":
    unittest.main()
