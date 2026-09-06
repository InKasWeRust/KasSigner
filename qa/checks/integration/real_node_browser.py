#!/usr/bin/env python3
"""Run real KasSee WASM against the public Kaspa resolver in real-time Chromium."""

from __future__ import annotations

import argparse
import contextlib
from collections.abc import Mapping
import http.server
import json
import os
import signal
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import shutil
import sys
import socket
import subprocess
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


class RealNodeBrowserError(RuntimeError):
    pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--timeout", type=int, default=75)
    parser.add_argument("--evidence", type=Path)
    return parser.parse_args()




def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_evidence(path: Path, detail: dict[str, object]) -> None:
    path = path if path.is_absolute() else ROOT / path
    path.parent.mkdir(parents=True, exist_ok=True)
    document = {
        "schema_version": 1,
        "healthy": True,
        "status": "pass",
        "completed_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "network": "mainnet",
        "mode": "production-public-resolver",
        "detail": detail,
        "inputs": {
            "browser_case_sha256": sha256_file(ROOT / "qa/checks/integration/browser_real_node_case.mjs"),
            "browser_runner_sha256": sha256_file(Path(__file__).resolve()),
            "production_resolver_sha256": sha256_file(ROOT / "apps/kassee-web/web/js/core/node/resolver.js"),
            "wasm_sha256": sha256_file(PKG_WASM),
        },
    }
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")

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
    """Return an installed Chromium-family browser on the current host."""
    path_names = (
        "chromium",
        "chromium-browser",
        "google-chrome",
        "google-chrome-stable",
        "chrome",
        "chrome.exe",
        "msedge",
        "msedge.exe",
    )
    for name in path_names:
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


def require_real_wasm() -> None:
    missing = [str(path.relative_to(ROOT)) for path in (PKG_JS, PKG_WASM) if not path.is_file()]
    if missing:
        raise SystemExit("ERROR: real KasSee WASM package is missing: " + ", ".join(missing) + ". Run `make kassee`.")
    if PKG_WASM.stat().st_size < 4096:
        raise SystemExit("ERROR: KasSee WASM package is implausibly small; fixture/stub builds are forbidden here")


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class RealNodeHandler(http.server.SimpleHTTPRequestHandler):
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

    result_event = threading.Event()
    result_payload: dict[str, object] | None = None
    max_result_bytes = 1024 * 1024

    def log_message(self, _format: str, *_args: object) -> None:
        pass

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
        if not self.path.startswith("/__qa_real_node_result__"):
            self.send_error(404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_error(400, "invalid Content-Length")
            return
        if length <= 0 or length > type(self).max_result_bytes:
            self.send_error(413, "invalid real-node result size")
            return
        try:
            payload = json.loads(self.rfile.read(length))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self.send_error(400, "invalid real-node result JSON")
            return
        if not isinstance(payload, dict) or payload.get("status") not in {"pass", "fail"}:
            self.send_error(400, "invalid real-node result payload")
            return
        detail = payload.get("detail")
        if not isinstance(detail, dict):
            self.send_error(400, "invalid real-node result detail")
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
        if self.path.startswith("/__qa_real_node__"):
            body = b"""<!doctype html><html><body>running<script type=module>
const publishBootstrapFailure = async (error) => {
  const detail = {
    message: `real-node browser module failed to load: ${error instanceof Error ? error.message : String(error)}`,
    stack: error instanceof Error ? error.stack : null,
  };
  document.documentElement.dataset.qaStatus = 'fail';
  document.body.textContent = JSON.stringify(detail);
  try {
    await fetch('/__qa_real_node_result__', {
      method: 'POST',
      cache: 'no-store',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: 'fail', detail }),
    });
  } catch (_) {}
};
import('/qa/checks/integration/browser_real_node_case.mjs').catch(publishBootstrapFailure);
</script></body></html>"""
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        super().do_GET()


@contextlib.contextmanager
def http_server():
    port = free_port()
    handler = lambda *args, **kwargs: RealNodeHandler(*args, directory=str(ROOT), **kwargs)
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
            raise RealNodeBrowserError(f"Chromium exited before DevTools became ready (exit {returncode})")
        try:
            with urllib.request.urlopen(endpoint, timeout=0.25) as response:
                if response.status == 200:
                    return
        except (OSError, TimeoutError, urllib.error.URLError) as error:
            last_error = error
        time.sleep(0.05)
    suffix = f": {last_error}" if last_error else ""
    raise RealNodeBrowserError(f"Chromium DevTools did not become ready within {timeout:.0f}s{suffix}")


def open_chromium_target(debug_port: int, target_url: str) -> None:
    encoded = urllib.parse.quote(target_url, safe="")
    request = urllib.request.Request(
        f"http://127.0.0.1:{debug_port}/json/new?{encoded}",
        method="PUT",
    )
    with urllib.request.urlopen(request, timeout=2.0) as response:
        if response.status != 200:
            raise RealNodeBrowserError(f"Chromium DevTools target creation failed: HTTP {response.status}")
        payload = json.load(response)
    if not isinstance(payload, dict) or not payload.get("id"):
        raise RealNodeBrowserError("Chromium DevTools target creation returned no target id")


def browser_log_tail(browser_log, limit: int = 5000) -> str:
    browser_log.flush()
    browser_log.seek(0)
    return browser_log.read()[-limit:]


def stop_chromium(process: subprocess.Popen[str]) -> None:
    """Stop Chromium and its POSIX child process group, then reap the parent."""
    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    elif process.poll() is None:
        process.terminate()

    if process.poll() is None:
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            if os.name == "posix":
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            else:
                process.kill()
            process.wait(timeout=5)

    # The Chromium parent may exit before all renderer/profile-writer children.
    # A dedicated POSIX process group lets us reap those stragglers as well.
    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def cleanup_chromium_profile(
    profile_dir: Path,
    *,
    attempts: int = 10,
    delay_seconds: float = 0.05,
) -> None:
    """Best-effort cleanup resilient to Chromium's late profile writers."""
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

    # Profile cleanup must never overwrite the integration result. This directory
    # contains only ephemeral QA browser state under the OS temporary directory.
    if profile_dir.exists():
        print(
            f"WARNING: could not fully remove temporary Chromium profile {profile_dir}: {last_error}",
            file=sys.stderr,
        )


def chromium_run(port: int, timeout: int) -> dict[str, object]:
    chromium = browser_executable()
    debug_port = free_port()
    RealNodeHandler.result_payload = None
    RealNodeHandler.result_event.clear()
    profile_dir = Path(tempfile.mkdtemp(prefix="kassigner-real-node-chrome-"))

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
                start_new_session=os.name == "posix",
            )
            try:
                wait_for_chromium_debugger(debug_port, process)
                open_chromium_target(
                    debug_port,
                    f"http://127.0.0.1:{port}/__qa_real_node__?network=mainnet",
                )

                deadline = time.monotonic() + timeout
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        output = browser_log_tail(browser_log)
                        suffix = f"\nLast browser output:\n{output}" if output else ""
                        raise RealNodeBrowserError(
                            f"KasSee public-node E2E timed out after {timeout} wall-clock seconds using {chromium}{suffix}"
                        )
                    if RealNodeHandler.result_event.wait(timeout=min(0.25, remaining)):
                        break
                    returncode = process.poll()
                    if returncode is not None:
                        output = browser_log_tail(browser_log)
                        raise RealNodeBrowserError(
                            f"Chromium public-node E2E exited before returning a structured result "
                            f"(exit {returncode})\n{output}"
                        )

                payload = RealNodeHandler.result_payload
                if payload is None:
                    raise RealNodeBrowserError("public-node browser signaled completion without a result payload")
                detail = payload.get("detail")
                if not isinstance(detail, dict):
                    raise RealNodeBrowserError("public-node browser returned invalid structured detail")
                if payload.get("status") != "pass":
                    raise RealNodeBrowserError("KasSee public-node E2E did not pass\n" + json.dumps(detail, indent=2))
                return detail
            finally:
                stop_chromium(process)
    finally:
        cleanup_chromium_profile(profile_dir)


def main() -> int:
    args = parse_args()
    require_real_wasm()
    try:
        with http_server() as http_port:
            detail = chromium_run(http_port, args.timeout)
    except (OSError, RealNodeBrowserError, TimeoutError, urllib.error.URLError) as error:
        raise SystemExit(f"ERROR: {error}") from None

    if args.evidence is not None:
        write_evidence(args.evidence, detail)

    print("PASS: real KasSee WASM connected to mainnet through the production Kaspa public-node resolver")
    ws_url = detail.get("ws_url")
    if ws_url:
        print(f"Node: {ws_url}")
    attempted = detail.get("ws_urls_attempted")
    if isinstance(attempted, list) and attempted:
        print(f"Resolver/retry attempts: {len(attempted)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
