#!/usr/bin/env python3
"""Persistent funded-wallet E2E against a real Kaspa public testnet node."""

from __future__ import annotations

import contextlib
from collections.abc import Mapping
import http.server
import json
import os
from pathlib import Path
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[3]
SITE = ROOT / "target/kassee-web/site"
PKG_JS = SITE / "pkg/kassee_web.js"
PKG_WASM = SITE / "pkg/kassee_web_bg.wasm"
def funded_state_root() -> Path:
    override = os.environ.get("KASSIGNER_FUNDED_E2E_STATE_DIR")
    if override:
        return Path(override).expanduser()
    xdg_state = os.environ.get("XDG_STATE_HOME")
    base = Path(xdg_state).expanduser() if xdg_state else Path.home() / ".local/state"
    return base / "kassigner/funded-e2e"


STATE_ROOT = funded_state_root()
FAUCETS = {
    "testnet-10": "https://faucet-testnet.kaspanet.io/",
    "testnet-12": "https://faucet-tn12.kaspanet.io/",
}
NETWORKS = (("1", "testnet-10", "Testnet-10"), ("2", "testnet-12", "Testnet-12"))
POLL_SECONDS = 10
CONFIRMATION_TIMEOUT_SECONDS = 600
STATUS_TIMEOUT_SECONDS = 90
RPC_PHASE_TIMEOUT_SECONDS = 180
STATUS_ATTEMPTS = 3
STATUS_RETRY_SECONDS = 5
LOCAL_ADDRESS_TIMEOUT_SECONDS = 20
NONINTERACTIVE_SKIP = 77



def interactive_stdin_available(stream=None) -> bool:
    """Return whether funded-E2E can safely ask the maintainer for input.

    Only stdin needs to be interactive.  stdout is frequently tee'd or captured
    by Windows launchers even while the console remains available for input.
    On native Windows, fall back to GetConsoleMode for runtimes whose isatty()
    does not recognize the inherited console handle.
    """
    input_stream = sys.stdin if stream is None else stream
    if input_stream is None:
        return False
    try:
        if input_stream.isatty():
            return True
    except (AttributeError, OSError, ValueError):
        return False
    if os.name != "nt":
        return False
    try:
        import ctypes
        import msvcrt

        handle = msvcrt.get_osfhandle(input_stream.fileno())
        mode = ctypes.c_ulong()
        return bool(ctypes.windll.kernel32.GetConsoleMode(handle, ctypes.byref(mode)))
    except (AttributeError, OSError, ValueError):
        return False

class BrowserPhaseError(RuntimeError):
    def __init__(self, message: str, *, retryable: bool = False) -> None:
        super().__init__(message)
        self.retryable = retryable


def restore_windows_console_line_input(stream=None) -> bool:
    """Restore normal line/echo input before an interactive Windows prompt.

    Native console programs such as QEMU may temporarily switch the shared
    console input handle into raw/VT mode.  A later Python input() can then
    appear frozen: keystrokes are not echoed and Enter does not complete the
    line normally.  Keep this repair Windows-only and only touch a real console
    handle; redirected/non-console stdin is left unchanged.
    """
    if os.name != "nt":
        return False
    input_stream = sys.stdin if stream is None else stream
    if input_stream is None:
        return False
    try:
        import ctypes
        import msvcrt

        handle = msvcrt.get_osfhandle(input_stream.fileno())
        mode = ctypes.c_ulong()
        kernel32 = ctypes.windll.kernel32
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        enable_processed_input = 0x0001
        enable_line_input = 0x0002
        enable_echo_input = 0x0004
        enable_virtual_terminal_input = 0x0200
        repaired = (
            mode.value
            | enable_processed_input
            | enable_line_input
            | enable_echo_input
        ) & ~enable_virtual_terminal_input
        if repaired != mode.value and not kernel32.SetConsoleMode(handle, repaired):
            return False
        return True
    except (AttributeError, OSError, ValueError):
        return False


def interactive_input(prompt: str) -> str:
    # Reassert canonical line/echo mode before every prompt because make qa can
    # run native console programs immediately beforehand.
    restore_windows_console_line_input()
    return input(prompt)


def select_network() -> tuple[str, str]:
    print("Choose the Kaspa network for the funded wallet E2E:")
    for number, _network, label in NETWORKS:
        print(f"  {number}) {label}")
    while True:
        choice = interactive_input("Network [1]: ").strip() or "1"
        for number, network, label in NETWORKS:
            if choice in (number, network, label.lower()):
                return network, label
        print("Please choose 1 (Testnet-10) or 2 (Testnet-12).")


def build_real_wasm() -> None:
    print("\n==> Building the real KasSee WebAssembly package")
    subprocess.run(["make", "kassee"], cwd=ROOT, check=True)


def require_real_wasm() -> None:
    missing = [str(path.relative_to(ROOT)) for path in (PKG_JS, PKG_WASM) if not path.is_file()]
    if missing:
        raise SystemExit("ERROR: real KasSee WASM package is missing: " + ", ".join(missing))
    if PKG_WASM.stat().st_size < 4096:
        raise SystemExit("ERROR: KasSee WASM package is implausibly small; fixture/stub builds are forbidden here")


def windows_browser_candidates(environ: Mapping[str, str] | None = None) -> list[Path]:
    env = os.environ if environ is None else environ
    roots = [
        Path(value)
        for variable in ("PROGRAMFILES", "PROGRAMFILES(X86)", "LOCALAPPDATA")
        if (value := env.get(variable))
    ]
    relative_candidates = (
        Path("Microsoft/Edge/Application/msedge.exe"),
        Path("Google/Chrome/Application/chrome.exe"),
        Path("Chromium/Application/chrome.exe"),
    )
    return [root / relative for root in roots for relative in relative_candidates]


def browser_executable(*, platform_name: str | None = None, environ: Mapping[str, str] | None = None) -> str:
    for name in (
        "chromium", "chromium-browser", "google-chrome", "google-chrome-stable",
        "chrome", "chrome.exe", "msedge", "msedge.exe",
    ):
        value = shutil.which(name)
        if value:
            return value
    if (os.name if platform_name is None else platform_name) == "nt":
        for candidate in windows_browser_candidates(environ):
            if candidate.is_file():
                return str(candidate)
    raise SystemExit(
        "ERROR: required Chromium-family browser not found "
        "(Chromium, Google Chrome, or Microsoft Edge)"
    )


def stop_browser(process: subprocess.Popen[str]) -> None:
    if os.name == "nt" and process.poll() is None:
        # Chromium is a process tree on Windows. Kill the tree so renderer and
        # profile-writer children cannot leak into the next funded-E2E phase.
        subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
        )
    elif process.poll() is None:
        process.terminate()
    if process.poll() is None:
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def cleanup_browser_profile(profile_dir: Path, *, attempts: int = 10, delay_seconds: float = 0.05) -> None:
    last_error: OSError | None = None
    for attempt in range(attempts):
        try:
            shutil.rmtree(profile_dir)
            return
        except FileNotFoundError:
            return
        except OSError as error:
            last_error = error
            if attempt + 1 < attempts:
                time.sleep(delay_seconds)
    if profile_dir.exists():
        print(
            f"WARNING: could not fully remove temporary funded-E2E browser profile {profile_dir}: {last_error}",
            file=sys.stderr,
        )


def ensure_state_directory() -> None:
    STATE_ROOT.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        STATE_ROOT.chmod(stat.S_IRWXU)


def ensure_tools_lock_current() -> None:
    """Refresh a stale tools lock transactionally, then require --locked."""
    toolchain = os.environ.get("KASSIGNER_STABLE_RUST", "").strip()
    if not re.fullmatch(r"[0-9]+(?:\.[0-9]+){2}", toolchain):
        raise SystemExit("ERROR: KASSIGNER_STABLE_RUST is not a pinned stable Rust version")

    manifest = ROOT / "tools/Cargo.toml"
    lockfile = ROOT / "tools/Cargo.lock"
    base = [
        "rustup",
        "run",
        toolchain,
        "cargo",
        "metadata",
        "--manifest-path",
        str(manifest),
        "--format-version",
        "1",
    ]
    locked = subprocess.run([*base, "--locked"], cwd=ROOT, capture_output=True, text=True)
    if locked.returncode == 0:
        return

    original = lockfile.read_bytes() if lockfile.exists() else None
    print("  Funded-E2E tools lock is stale; refreshing it transactionally with pinned Cargo.")
    refresh = subprocess.run([*base, "--offline"], cwd=ROOT, capture_output=True, text=True)
    if refresh.returncode != 0:
        refresh = subprocess.run(base, cwd=ROOT, capture_output=True, text=True)
    if refresh.returncode != 0:
        if original is None:
            lockfile.unlink(missing_ok=True)
        else:
            lockfile.write_bytes(original)
        detail = (refresh.stderr or refresh.stdout).strip()
        raise SystemExit(f"ERROR: funded-E2E could not refresh tools/Cargo.lock\n{detail}")

    verified = subprocess.run([*base, "--locked"], cwd=ROOT, capture_output=True, text=True)
    if verified.returncode != 0:
        if original is None:
            lockfile.unlink(missing_ok=True)
        else:
            lockfile.write_bytes(original)
        detail = (verified.stderr or verified.stdout).strip()
        raise SystemExit(f"ERROR: refreshed tools/Cargo.lock still fails --locked\n{detail}")
    print("  Refreshed and verified tools/Cargo.lock with pinned Cargo.")


def run_signer_helper(*args: str) -> str:
    toolchain = os.environ.get("KASSIGNER_STABLE_RUST", "").strip()
    if not re.fullmatch(r"[0-9]+(?:\.[0-9]+){2}", toolchain):
        raise SystemExit("ERROR: KASSIGNER_STABLE_RUST is not a pinned stable Rust version")
    command = [
        "rustup",
        "run",
        toolchain,
        "cargo",
        "run",
        "--quiet",
        "--locked",
        "--manifest-path",
        str(ROOT / "tools/Cargo.toml"),
        "--bin",
        "kassigner-funded-e2e",
        "--",
        *args,
    ]
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise SystemExit(f"ERROR: funded-E2E signer helper failed\n{detail}")
    return result.stdout.strip()


def ensure_wallet(network: str) -> tuple[Path, str, bool]:
    ensure_state_directory()
    secret_path = STATE_ROOT / f"{network}.wallet"
    output = run_signer_helper("wallet", str(secret_path))
    values = dict(line.split("=", 1) for line in output.splitlines() if "=" in line)
    kpub = values.get("kpub", "")
    if not kpub.startswith("kpub1:"):
        raise SystemExit("ERROR: funded-E2E helper did not return a canonical kpub")
    return secret_path, kpub, values.get("created") == "1"


def sign_kspt(secret_path: Path, kspt_hex: str) -> str:
    signed = run_signer_helper("sign", str(secret_path), kspt_hex)
    if not re.fullmatch(r"[0-9a-f]+", signed):
        raise SystemExit("ERROR: funded-E2E signer helper returned invalid signed KSPT")
    return signed


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class FundedHandler(http.server.SimpleHTTPRequestHandler):
    _deterministic_mime_types = {
        ".js": "text/javascript",
        ".mjs": "text/javascript",
        ".wasm": "application/wasm",
        ".json": "application/json",
    }

    def guess_type(self, path: str) -> str:
        """Use browser-safe MIME types independent of the Windows registry."""
        suffix = Path(urllib.parse.urlsplit(path).path).suffix.lower()
        content_type = self._deterministic_mime_types.get(suffix)
        if content_type is not None:
            return content_type
        return super().guess_type(path)

    config: dict[str, object] = {}
    result_event = threading.Event()
    result_payload: dict[str, object] | None = None
    max_result_bytes = 8 * 1024 * 1024

    def log_message(self, _format: str, *_args: object) -> None:
        pass

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
        if not self.path.startswith("/__qa_funded_result__"):
            self.send_error(404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_error(400, "invalid Content-Length")
            return
        if length <= 0 or length > type(self).max_result_bytes:
            self.send_error(413, "invalid funded-E2E result size")
            return
        try:
            payload = json.loads(self.rfile.read(length))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self.send_error(400, "invalid funded-E2E result JSON")
            return
        if not isinstance(payload, dict) or payload.get("status") not in {"pass", "pending", "fail"}:
            self.send_error(400, "invalid funded-E2E result payload")
            return
        detail = payload.get("detail")
        if not isinstance(detail, dict):
            self.send_error(400, "invalid funded-E2E result detail")
            return
        type(self).result_payload = {"status": payload["status"], "detail": detail}
        self.send_response(204)
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        type(self).result_event.set()

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        if urllib.parse.urlsplit(self.path).path == "/favicon.ico":
            self.send_response(204)
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            return
        if self.path.startswith("/__qa_funded_config__"):
            body = json.dumps(type(self).config, separators=(",", ":")).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.startswith("/__qa_funded_e2e__"):
            body = b"""<!doctype html><html><body>running<script type=module>
const publishBootstrapFailure = async (error) => {
  const detail = {
    phase: 'bootstrap',
    message: `funded-E2E browser module failed to load: ${error instanceof Error ? error.message : String(error)}`,
    stack: error instanceof Error ? error.stack : null,
  };
  document.documentElement.dataset.qaStatus = 'fail';
  document.body.textContent = JSON.stringify(detail);
  try {
    await fetch('/__qa_funded_result__', {
      method: 'POST',
      cache: 'no-store',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: 'fail', detail }),
    });
  } catch (_) {}
};
import('/qa/checks/integration/funded_testnet_e2e_case.mjs').catch(publishBootstrapFailure);
</script></body></html>"""
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        super().do_GET()


@contextlib.contextmanager
def http_server():
    port = free_port()
    handler = lambda *args, **kwargs: FundedHandler(*args, directory=str(ROOT), **kwargs)
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()



def wait_for_chromium_debugger(debug_port: int, process: subprocess.Popen[str], timeout: float = 10.0) -> None:
    endpoint = f"http://127.0.0.1:{debug_port}/json/version"
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        returncode = process.poll()
        if returncode is not None:
            raise RuntimeError(f"Chromium exited before DevTools became ready (exit {returncode})")
        try:
            with urllib.request.urlopen(endpoint, timeout=0.25) as response:
                if response.status == 200:
                    return
        except (OSError, TimeoutError, urllib.error.URLError) as error:
            last_error = error
        time.sleep(0.05)
    suffix = f": {last_error}" if last_error else ""
    raise TimeoutError(f"Chromium DevTools did not become ready within {timeout:.0f}s{suffix}")


def open_chromium_target(debug_port: int, target_url: str) -> None:
    encoded = urllib.parse.quote(target_url, safe="")
    request = urllib.request.Request(
        f"http://127.0.0.1:{debug_port}/json/new?{encoded}",
        method="PUT",
    )
    with urllib.request.urlopen(request, timeout=2.0) as response:
        if response.status != 200:
            raise RuntimeError(f"Chromium DevTools target creation failed: HTTP {response.status}")
        payload = json.load(response)
    if not isinstance(payload, dict) or not payload.get("id"):
        raise RuntimeError("Chromium DevTools target creation returned no target id")


def browser_log_tail(browser_log, limit: int = 5000) -> str:
    browser_log.flush()
    browser_log.seek(0)
    return browser_log.read()[-limit:]


def chromium_result(
    port: int,
    config: dict[str, object],
    timeout: int = RPC_PHASE_TIMEOUT_SECONDS,
) -> tuple[str, dict[str, object]]:
    FundedHandler.config = config
    FundedHandler.result_payload = None
    FundedHandler.result_event.clear()
    chromium = browser_executable()
    phase = str(config.get("phase", "unknown"))
    debug_port = free_port()
    profile_dir = Path(tempfile.mkdtemp(prefix="kassigner-funded-chrome-"))

    # Run a normal real-time browser session. DevTools HTTP is used only to
    # create the test tab; the page itself executes the same KasSee WASM and
    # public-node code as before, then POSTs its structured result to the local
    # QA server. No DOM-capture or virtual-time flag participates in completion.
    try:
        with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as browser_log:
            command = [
                chromium,
                "--headless=new",
                "--no-sandbox",
                "--disable-gpu",
                "--disable-dev-shm-usage",
                "--no-first-run",
                "--no-default-browser-check",
                "--remote-debugging-address=127.0.0.1",
                f"--remote-debugging-port={debug_port}",
                f"--user-data-dir={profile_dir}",
                "about:blank",
            ]
            process = subprocess.Popen(
                command,
                cwd=ROOT,
                stdout=browser_log,
                stderr=subprocess.STDOUT,
                text=True,
            )
            try:
                try:
                    wait_for_chromium_debugger(debug_port, process)
                    open_chromium_target(
                        debug_port,
                        f"http://127.0.0.1:{port}/__qa_funded_e2e__",
                    )
                except (OSError, RuntimeError, TimeoutError, urllib.error.URLError) as error:
                    output = browser_log_tail(browser_log)
                    suffix = f"\n{output}" if output else ""
                    raise BrowserPhaseError(
                        f"funded-wallet browser phase '{phase}' could not start its Chromium test tab: {error}{suffix}",
                        retryable=phase == "status",
                    ) from None

                deadline = time.monotonic() + timeout
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        output = browser_log_tail(browser_log)
                        suffix = f"\nLast browser output:\n{output}" if output else ""
                        raise BrowserPhaseError(
                            f"funded-wallet browser phase '{phase}' timed out after {timeout} wall-clock seconds "
                            f"using {chromium}. The wallet/address remains saved locally; this phase can be retried."
                            f"{suffix}",
                            retryable=phase == "status",
                        )
                    if FundedHandler.result_event.wait(timeout=min(0.25, remaining)):
                        break
                    returncode = process.poll()
                    if returncode is not None:
                        output = browser_log_tail(browser_log)
                        raise BrowserPhaseError(
                            f"funded-wallet browser phase '{phase}' exited before returning a structured result "
                            f"(exit {returncode})\n{output}",
                            retryable=phase == "status",
                        )

                payload = FundedHandler.result_payload
                if payload is None:
                    raise BrowserPhaseError(
                        f"funded-wallet browser phase '{phase}' signaled completion without a result payload",
                        retryable=phase == "status",
                    )
                status = str(payload["status"])
                detail = payload["detail"]
                if not isinstance(detail, dict):
                    raise BrowserPhaseError(
                        f"funded-wallet browser phase '{phase}' returned invalid result detail",
                        retryable=phase == "status",
                    )
                if status == "fail":
                    raise BrowserPhaseError(
                        f"funded-wallet browser phase '{phase}' failed\n{json.dumps(detail, indent=2)}",
                        retryable=phase == "status",
                    )
                return status, detail
            finally:
                stop_browser(process)
    finally:
        cleanup_browser_profile(profile_dir)


def status_with_retries(port: int, network: str, kpub: str) -> dict[str, object]:
    last_error: BrowserPhaseError | None = None
    for attempt in range(1, STATUS_ATTEMPTS + 1):
        try:
            _status, detail = chromium_result(
                port,
                {"phase": "status", "network": network, "kpub": kpub},
                timeout=STATUS_TIMEOUT_SECONDS,
            )
            return detail
        except BrowserPhaseError as error:
            last_error = error
            if not error.retryable or attempt == STATUS_ATTEMPTS:
                raise
            print(
                f"  Public-node status attempt {attempt}/{STATUS_ATTEMPTS} failed; "
                f"retrying in {STATUS_RETRY_SECONDS}s...",
                file=sys.stderr,
            )
            time.sleep(STATUS_RETRY_SECONDS)
    assert last_error is not None
    raise last_error


def metadata_path(network: str) -> Path:
    return STATE_ROOT / f"{network}.meta.json"


def destination_index(network: str) -> int:
    path = metadata_path(network)
    if not path.is_file():
        return 1
    try:
        current = json.loads(path.read_text())
        previous = int(current.get("destination_index", 0))
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return 1
    return 1 if previous >= 19 or previous < 1 else previous + 1


def record_success(network: str, txid: str, destination: str, index: int) -> None:
    path = metadata_path(network)
    previous_runs = 0
    if path.is_file():
        try:
            previous_runs = int(json.loads(path.read_text()).get("successful_runs", 0))
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            previous_runs = 0
    data = {
        "network": network,
        "successful_runs": previous_runs + 1,
        "destination_index": index,
        "destination": destination,
        "last_txid": txid,
    }
    path.write_text(json.dumps(data, indent=2) + "\n")


def wait_for_resulting_utxo(port: int, config: dict[str, object]) -> dict[str, object]:
    deadline = time.monotonic() + CONFIRMATION_TIMEOUT_SECONDS
    while True:
        status, detail = chromium_result(port, config)
        if status == "pass":
            return detail
        if status != "pending":
            raise SystemExit(f"ERROR: unexpected funded-E2E verification status: {status}")
        if time.monotonic() >= deadline:
            raise SystemExit(
                "ERROR: public node accepted the transaction but the resulting controlled UTXO "
                f"was not observed within {CONFIRMATION_TIMEOUT_SECONDS} seconds; txid={config['txid']}"
            )
        print("  Transaction accepted; waiting for the public node to report the resulting UTXO...")
        time.sleep(POLL_SECONDS)


def print_wallet_address(network_label: str, address: str, existing: bool) -> None:
    print("\n" + "=" * 72)
    print("FUNDED-E2E WALLET")
    print("=" * 72)
    print(f"Network: {network_label}")
    print(f"Funding address: {address}")
    print(
        "Wallet state: existing dedicated local wallet."
        if existing
        else "Wallet state: new dedicated local wallet created outside the repository tree."
    )
    print("The public-node funding check has not run yet.")
    print("=" * 72 + "\n")


def print_funding_prompt(network: str, network_label: str, address: str, existing: bool) -> None:
    faucet = FAUCETS.get(network)
    if faucet is None:
        raise SystemExit(f"ERROR: no funded-E2E faucet is configured for {network}")
    print("\n" + "=" * 72)
    print("TESTNET WALLET REQUIRES FUNDING")
    print("=" * 72)
    print(f"Network: {network_label}")
    print(f"Address: {address}")
    print("Send at least 1 test KAS to this address.")
    print(f"Faucet: {faucet}")
    if existing:
        print("Wallet state: existing dedicated local wallet; funding may already be present.")
    else:
        print("Wallet state: new dedicated local wallet created outside the repository history.")
    print("No public-node request will run until you explicitly confirm that funding is ready.")
    print("=" * 72 + "\n")


def wait_for_funding_confirmation() -> None:
    while True:
        answer = interactive_input("Funding complete and ready to query the public node? [y/q]: ").strip().lower()
        if answer in {"y", "yes"}:
            return
        if answer in {"q", "quit"}:
            raise SystemExit(
                "Funded-E2E stopped before public-node access. "
                "The dedicated wallet remains saved locally for a later retry."
            )
        print("Type y when the address is funded and ready, or q to quit.")


def main() -> int:
    if not interactive_stdin_available():
        print(
            "SKIP: funded testnet E2E requires an interactive input terminal for network/funding confirmation; "
            "run make qa from a maintainer terminal or invoke the funded E2E entrypoint directly."
        )
        return NONINTERACTIVE_SKIP

    network, network_label = select_network()
    build_real_wasm()
    require_real_wasm()
    ensure_tools_lock_current()
    secret_path, kpub, created = ensure_wallet(network)

    with http_server() as port:
        _local_status, local_wallet = chromium_result(
            port,
            {"phase": "address", "network": network, "kpub": kpub},
            timeout=LOCAL_ADDRESS_TIMEOUT_SECONDS,
        )
        funding_address = str(local_wallet.get("funding_address", ""))
        if not funding_address.startswith("kaspatest:"):
            raise BrowserPhaseError("local funded-E2E wallet derivation returned an invalid testnet address")

        print_wallet_address(network_label, funding_address, existing=not created)
        print_funding_prompt(network, network_label, funding_address, existing=not created)

        while True:
            wait_for_funding_confirmation()
            status = status_with_retries(port, network, kpub)
            status_address = str(status.get("funding_address", ""))
            if status_address != funding_address:
                raise BrowserPhaseError(
                    "public-node status phase derived a different funding address than the local wallet phase"
                )
            if status.get("funded"):
                break
            balance = int(str(status["balance_sompi"]))
            print(
                "Public node does not yet report the required funding: "
                f"{balance / 100_000_000:.8f} KAS. "
                "Fund the address, then confirm again."
            )

        print("\nWallet funded; running the automated funded-wallet E2E.")
        index = destination_index(network)
        _status, prepared = chromium_result(
            port,
            {"phase": "prepare", "network": network, "kpub": kpub, "destination_index": index},
        )
        signed_kspt = sign_kspt(secret_path, str(prepared["kspt_wire_hex"]))
        _status, broadcast = chromium_result(
            port,
            {
                "phase": "broadcast",
                "network": network,
                "kpub": kpub,
                "pskb_wire_hex": prepared["pskb_wire_hex"],
                "signed_kspt_hex": signed_kspt,
            },
        )
        txid = str(broadcast["txid"])
        destination = str(prepared["destination"])
        verified = wait_for_resulting_utxo(
            port,
            {
                "phase": "verify",
                "network": network,
                "kpub": kpub,
                "txid": txid,
                "destination": destination,
            },
        )
        record_success(network, txid, destination, index)

    print("\nPASS: funded KasSigner transaction E2E completed against a real Kaspa public testnet node")
    print(f"Network: {network_label}")
    print(f"TXID: {txid}")
    print(f"Controlled destination: {destination}")
    print(f"Resulting UTXO: {verified['resulting_utxo_amount_sompi']} sompi")
    print(f"Wallet balance after acceptance: {verified['wallet_balance_sompi']} sompi")
    return 0


def entrypoint() -> int:
    try:
        return main()
    except BrowserPhaseError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(entrypoint())
