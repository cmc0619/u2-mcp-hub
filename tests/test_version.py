"""The admin footer names the running code: version and commit."""

from pathlib import Path

import pytest

from u2_mcp.version import commit_from_git_dir

SHA = "0123456789abcdef0123456789abcdef01234567"


@pytest.mark.parametrize(
    ("files", "expected"),
    [
        ({"HEAD": "ref: refs/heads/main\n", "refs/heads/main": SHA + "\n"}, SHA),
        (
            {
                "HEAD": "ref: refs/heads/main\n",
                "packed-refs": f"# pack-refs\n{SHA} refs/heads/main\n",
            },
            SHA,
        ),
        ({"HEAD": SHA + "\n"}, SHA),  # detached
        ({}, None),  # no .git at all
        ({"HEAD": "ref: refs/heads/gone\n"}, None),
    ],
)
def test_the_commit_is_read_from_the_git_files(
    tmp_path: Path, files: dict[str, str], expected: str | None
) -> None:
    for name, text in files.items():
        path = tmp_path / ".git" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    assert commit_from_git_dir(tmp_path) == expected
