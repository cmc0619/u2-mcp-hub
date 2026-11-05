"""U2_TLS_CERT / U2_TLS_KEY naming a missing file stop startup with a clear message."""

from pathlib import Path

import pytest
import uvicorn

from u2_mcp import server


@pytest.fixture
def tls_env(monkeypatch: pytest.MonkeyPatch, mock_env: dict[str, str]) -> None:
    monkeypatch.setattr(uvicorn, "run", lambda app, **kwargs: pytest.fail("must not start"))


@pytest.mark.parametrize("setting", ["U2_TLS_CERT", "U2_TLS_KEY"])
def test_a_missing_tls_file_is_named_in_the_error(
    monkeypatch: pytest.MonkeyPatch, tls_env: None, tmp_path: Path, setting: str
) -> None:
    present = tmp_path / "present.pem"
    present.write_text("x")
    missing = tmp_path / "missing.pem"
    other = "U2_TLS_KEY" if setting == "U2_TLS_CERT" else "U2_TLS_CERT"
    monkeypatch.setenv(setting, str(missing))
    monkeypatch.setenv(other, str(present))
    with pytest.raises(SystemExit) as raised:
        server.run_streamable_http_server()
    message = str(raised.value)
    assert setting in message and str(missing) in message


def test_an_unreadable_tls_path_is_named_in_the_error(
    monkeypatch: pytest.MonkeyPatch, tls_env: None, tmp_path: Path
) -> None:
    # A directory is not a readable file on any platform, and chmod is unreliable on Windows.
    monkeypatch.setenv("U2_TLS_CERT", str(tmp_path))
    monkeypatch.setenv("U2_TLS_KEY", str(tmp_path))
    with pytest.raises(SystemExit, match="U2_TLS_CERT"):
        server.run_streamable_http_server()
