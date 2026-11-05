"""Which code is running: the package version and, when known, its commit.

The Docker build stamps the commit into the installed package (BUILD_COMMIT),
reading it from the build context's .git files. A run from a checkout reads the
same files directly. Neither needs the git program.
"""

from __future__ import annotations

import hashlib
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


def source_fingerprint(root: Path) -> str:
    """'src:1a2b3c4': a hash of every file under root/src, for builds without .git.

    It names no commit, but it changes whenever the code does.
    """
    digest = hashlib.sha256()
    for path in sorted((root / "src").rglob("*")):
        if path.is_file() and "__pycache__" not in path.parts:
            digest.update(path.relative_to(root).as_posix().encode())
            digest.update(path.read_bytes().replace(b"\r\n", b"\n"))
    return "src:" + digest.hexdigest()[:7]


def build_stamp(root: Path) -> str:
    """The commit at root, or the source fingerprint when there is no .git."""
    return commit_from_git_dir(root) or source_fingerprint(root)


@lru_cache(maxsize=1)
def running_version() -> str:
    """'0.9.0 · 1a2b3c4' (commit), '0.9.0 · src:1a2b3c4' (no .git), or '0.9.0'."""
    try:
        version = metadata.version("u2-mcp")
    except metadata.PackageNotFoundError:
        version = "unknown"
    try:
        stamp = _STAMP.read_text(encoding="utf-8").strip() or None
    except OSError:
        stamp = commit_from_git_dir(Path(__file__).resolve().parents[2])
    if not stamp:
        return version
    return f"{version} · {stamp if stamp.startswith('src:') else stamp[:7]}"


if __name__ == "__main__":
    # Docker build: python -m u2_mcp.version <build context>
    _STAMP.write_text(build_stamp(Path(sys.argv[1])), encoding="utf-8")
