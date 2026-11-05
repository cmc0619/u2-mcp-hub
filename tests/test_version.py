"""The admin footer names the running code: version and commit."""

from pathlib import Path

import pytest

from u2_mcp.version import build_stamp, commit_from_git_dir

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


def test_without_git_the_build_stamps_a_source_fingerprint(tmp_path: Path) -> None:
    """A download of the repo has no .git; the stamp still changes with the code."""
    (tmp_path / "src" / "u2_mcp").mkdir(parents=True)
    module = tmp_path / "src" / "u2_mcp" / "a.py"
    module.write_text("x = 1", encoding="utf-8")
    first = build_stamp(tmp_path)

    module.write_text("x = 2", encoding="utf-8")

    assert first.startswith("src:") and len(first) == 11
    assert build_stamp(tmp_path) != first
