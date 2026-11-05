"""Browser tests: a real server, a real browser, the scripted U2 driver.

Run with: pytest -m e2e tests/e2e
Plain `pytest` deselects these (see addopts), so it never needs a browser.

The server is a local process by default. With U2_E2E_IMAGE set (CI sets it to
the image's test target), each test runs that image instead: a fresh container
and volume per test, on the host network, so the browser and the server reach
the mock identity provider at the same address. Nothing here needs Docker
unless U2_E2E_IMAGE is set.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
import uuid
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path

import httpx
import pytest
from playwright.sync_api import Browser, Page

REPO_ROOT = Path(__file__).resolve().parents[2]
SECRET_KEY = "e2e-secret-key-" + "k" * 32
START_TIMEOUT_SECONDS = 60.0


def image_from_env(environ: Mapping[str, str]) -> str:
    """Return U2_E2E_IMAGE, or "" for process mode when it is not set at all.

    A variable that is present but empty is a misconfigured CI step; running the
    suite in process mode instead would pass without ever testing the image.
    """
    if "U2_E2E_IMAGE" not in environ:
        return ""
    image = environ["U2_E2E_IMAGE"].strip()
    if not image:
        raise RuntimeError("U2_E2E_IMAGE is set but empty. Name the image, or unset the variable.")
    return image


E2E_IMAGE = image_from_env(os.environ)


@dataclass
class Server:
    """A running server under test: a local process, or a container when `container` is set."""

    base_url: str
    data_dir: Path
    env: dict[str, str]
    container: str | None = None

    def url(self, path: str) -> str:
        """Return an absolute URL on this server."""
        return f"{self.base_url}{path}"

    def _run(self, argv: list[str]) -> str:
        if self.container:
            argv = ["docker", "exec", self.container, *argv]
        completed = subprocess.run(  # noqa: S603 - fixed argv, test-only
            argv,
            env=None if self.container else self.env,
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=True,
            timeout=60,
        )
        return completed.stdout

    def admin_cli(self, *args: str) -> str:
        """Run `u2-mcp admin ...` where the server runs, as an operator would."""
        if self.container:
            return self._run(["u2-mcp", "admin", *args])
        return self._run([sys.executable, "-m", "u2_mcp", "admin", *args])

    def python(self, code: str) -> str:
        """Run Python where the server runs, with the server's environment."""
        return self._run(["python" if self.container else sys.executable, "-c", code])

    def setup_code(self) -> str:
        """Read the setup code the way an operator would: from the CLI."""
        return self.admin_cli("show-setup-code").strip()


class _Process:
    def __init__(self, process: subprocess.Popen[bytes], log_path: Path) -> None:
        self.process = process
        self.log_path = log_path

    def alive(self) -> bool:
        return self.process.poll() is None

    def log(self) -> str:
        return _read_log(self.log_path)

    def stop(self) -> None:
        _stop(self.process)


class _Container:
    def __init__(self, container_id: str, volume: str, log_path: Path) -> None:
        self.id = container_id
        self.volume = volume
        self.log_path = log_path

    def alive(self) -> bool:
        state = subprocess.run(  # noqa: S603, S607 - fixed argv, test-only
            ["docker", "inspect", "-f", "{{.State.Running}}", self.id],
            capture_output=True,
            text=True,
        )
        return state.stdout.strip() == "true"

    def log(self) -> str:
        logs = subprocess.run(  # noqa: S603, S607 - fixed argv, test-only
            ["docker", "logs", self.id], capture_output=True, text=True
        )
        return logs.stdout + logs.stderr

    def stop(self) -> None:
        self.log_path.write_text(self.log(), encoding="utf-8")
        subprocess.run(["docker", "rm", "-f", self.id], capture_output=True)  # noqa: S603, S607
        subprocess.run(["docker", "volume", "rm", "-f", self.volume], capture_output=True)  # noqa: S603, S607


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _start_process(data_dir: Path, port: int, settings: dict[str, str]) -> tuple[_Process, Server]:
    env = {key: value for key, value in os.environ.items() if not key.startswith("U2_")}
    env.update(settings)
    env.update(
        {
            "U2_DATA_DIR": str(data_dir),
            "U2_DRIVER": "tests.mocks.sim_driver",
            "PYTHONPATH": os.pathsep.join((str(REPO_ROOT / "src"), str(REPO_ROOT))),
            "PYTHONUNBUFFERED": "1",
        }
    )
    log_path = data_dir / "server.log"
    with log_path.open("wb") as log:
        process = subprocess.Popen(  # noqa: S603 - fixed argv, test-only
            [sys.executable, "-m", "u2_mcp", "--streamable-http"],
            env=env,
            cwd=REPO_ROOT,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
    return _Process(process, log_path), Server(f"http://127.0.0.1:{port}", data_dir, env)


def _start_container(
    data_dir: Path, port: int, settings: dict[str, str]
) -> tuple[_Container, Server]:
    volume = f"u2-e2e-{uuid.uuid4().hex[:12]}"
    subprocess.run(["docker", "volume", "create", volume], check=True, capture_output=True)  # noqa: S603, S607
    env_args = [arg for key, value in settings.items() for arg in ("-e", f"{key}={value}")]
    started = subprocess.run(  # noqa: S603, S607 - fixed argv, test-only
        ["docker", "run", "-d", "--network", "host", "-v", f"{volume}:/data", *env_args, E2E_IMAGE],
        capture_output=True,
        text=True,
    )
    if started.returncode != 0:
        subprocess.run(["docker", "volume", "rm", "-f", volume], capture_output=True)  # noqa: S603, S607
        raise RuntimeError(f"docker run {E2E_IMAGE} failed:\n{started.stderr}")
    container_id = started.stdout.strip()
    handle = _Container(container_id, volume, data_dir / "server.log")
    return handle, Server(f"http://127.0.0.1:{port}", data_dir, dict(settings), container_id)


def launch_server(data_dir: Path) -> tuple[_Process | _Container, Server]:
    """Start a server on empty data and wait until /health answers.

    This is the only place that knows how the server is started: a local process,
    or (U2_E2E_IMAGE) the Docker image.
    """
    port = _free_port()
    settings = {
        "U2_SECRET_KEY": SECRET_KEY,
        "U2_HTTP_HOST": "127.0.0.1",
        "U2_HTTP_PORT": str(port),
    }
    starter = _start_container if E2E_IMAGE else _start_process
    handle, server = starter(data_dir, port, settings)
    try:
        deadline = time.monotonic() + START_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            if not handle.alive():
                raise RuntimeError(f"The server exited early:\n{handle.log()}")
            try:
                if httpx.get(server.url("/health"), timeout=1.0).status_code == 200:
                    return handle, server
            except httpx.HTTPError:
                pass
            time.sleep(0.2)
        raise RuntimeError(f"The server did not answer /health:\n{handle.log()}")
    except BaseException:
        # Never leave a server running behind a failed start (or Ctrl+C).
        handle.stop()
        raise


def _read_log(log_path: Path) -> str:
    return log_path.read_text(encoding="utf-8", errors="replace")


def _stop(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


@pytest.fixture
def server(tmp_path: Path) -> Iterator[Server]:
    """A fresh server with an empty data directory."""
    handle, running = launch_server(tmp_path)
    try:
        yield running
    finally:
        handle.stop()


@pytest.fixture
def other_page(browser: Browser) -> Iterator[Page]:
    """A page in a second, separate browser context (another person or browser)."""
    context = browser.new_context()
    try:
        yield context.new_page()
    finally:
        context.close()


@dataclass
class Idp:
    """The mock identity provider, running as a local process."""

    issuer: str
    client_id: str = "u2-mcp"
    client_secret: str = "e2e-client-secret"

    @property
    def discovery_url(self) -> str:
        return f"{self.issuer}/.well-known/openid-configuration"

    def next_user(self, **person: object) -> None:
        """Queue who signs in next: sub, email, name, groups, overage, extra."""
        httpx.post(f"{self.issuer}/_control/next-user", json=person, timeout=5).raise_for_status()


@pytest.fixture
def idp(server: Server, tmp_path: Path) -> Iterator[Idp]:
    """A fresh mock OIDC provider on 127.0.0.1, registered for this server's callbacks.

    It runs on the host. Container mode uses the host network, so the browser and
    the server in the container reach it at the same 127.0.0.1 address.
    """
    port = _free_port()
    running = Idp(f"http://127.0.0.1:{port}")
    log_path = tmp_path / "idp.log"
    with log_path.open("wb") as log:
        process = subprocess.Popen(  # noqa: S603 - fixed argv, test-only
            [
                sys.executable,
                "-m",
                "tests.mocks.oidc_provider",
                "--port",
                str(port),
                "--client-id",
                running.client_id,
                "--client-secret",
                running.client_secret,
                "--redirect-uri",
                server.url("/admin/sign-in/sso/callback"),
                "--redirect-uri",
                server.url("/oauth/callback"),
            ],
            env={**os.environ, "PYTHONPATH": str(REPO_ROOT)},
            cwd=REPO_ROOT,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
    try:
        deadline = time.monotonic() + START_TIMEOUT_SECONDS
        while True:
            if process.poll() is not None:
                raise RuntimeError(f"The mock provider exited early:\n{_read_log(log_path)}")
            try:
                if httpx.get(running.discovery_url, timeout=1.0).status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            if time.monotonic() > deadline:
                raise RuntimeError(f"The mock provider did not start:\n{_read_log(log_path)}")
            time.sleep(0.2)
        yield running
    finally:
        _stop(process)
