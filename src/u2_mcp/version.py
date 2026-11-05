"""Which code is running: the package version and, when known, its commit.

The Docker build stamps the commit into the installed package (BUILD_COMMIT),
reading it from the build context's .git files. A run from a checkout reads the
same files directly. Neither needs the git program.
"""

from __future__ import annotations

import sys
from functools import lru_cache
from importlib import metadata
from pathlib import Path

_STAMP = Path(__file__).with_name("BUILD_COMMIT")


def commit_from_git_dir(root: Path) -> str | None:
    """The commit checked out at root, from .git/HEAD and its ref, or None."""
    git = root / ".git"
    try:
        head = (git / "HEAD").read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if not head.startswith("ref: "):
        return head or None  # a detached HEAD holds the commit itself
    ref = head.removeprefix("ref: ")
    try:
        return (git / ref).read_text(encoding="utf-8").strip() or None
    except OSError:
        pass
    try:  # a fresh clone keeps its refs in packed-refs
        for line in (git / "packed-refs").read_text(encoding="utf-8").splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[1] == ref:
                return parts[0]
    except OSError:
        pass
    return None


@lru_cache(maxsize=1)
def running_version() -> str:
    """'0.9.0 · 1a2b3c4', or just the version when the commit is unknown."""
    try:
        version = metadata.version("u2-mcp")
    except metadata.PackageNotFoundError:
        version = "unknown"
    try:
        commit = _STAMP.read_text(encoding="utf-8").strip() or None
    except OSError:
        commit = commit_from_git_dir(Path(__file__).resolve().parents[2])
    return f"{version} · {commit[:7]}" if commit else version


if __name__ == "__main__":
    # Docker build: python -m u2_mcp.version <build context>
    _STAMP.write_text(commit_from_git_dir(Path(sys.argv[1])) or "", encoding="utf-8")
