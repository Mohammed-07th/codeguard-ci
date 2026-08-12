"""Filesystem sandbox for tool calls.

Every tool path argument is chosen by an LLM, and the PR text under review is
attacker-controlled. Without a boundary, a prompt-injected agent could ask
``read_file("../../.env")`` and exfiltrate the API key through its own findings.

So all tool paths resolve against a *review root* and are rejected if they escape
it — symlinks included, since resolution happens before the containment check.
This is the second half of the security story in ``docs/SECURITY.md``: the agents
run static analysers over the PR, never code from it, and they can only see files
inside the review root.
"""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
from typing import Iterator

_review_root: ContextVar[Path | None] = ContextVar("codeguard_review_root", default=None)


class SandboxViolation(PermissionError):
    """Raised when a tool is asked for a path outside the review root."""


@contextmanager
def review_root(path: Path | str) -> Iterator[Path]:
    """Scope every tool call in this block to ``path``."""
    root = Path(path).resolve()
    if not root.is_dir():
        raise SandboxViolation(f"Review root does not exist or is not a directory: {root}")
    token = _review_root.set(root)
    try:
        yield root
    finally:
        _review_root.reset(token)


def get_review_root() -> Path:
    root = _review_root.get()
    if root is None:
        raise SandboxViolation(
            "No review root is active. Wrap tool calls in `with review_root(path):`."
        )
    return root


def safe_resolve(relative_path: str) -> Path:
    """Resolve a tool-supplied path inside the review root, or refuse.

    Rejects absolute paths, ``..`` traversal, and symlinks pointing outside the
    root. Resolution happens first so a symlink cannot smuggle a path past the
    containment check.
    """
    root = get_review_root()
    candidate = Path(relative_path)
    if candidate.is_absolute():
        # Absolute paths are allowed only if already inside the root.
        resolved = candidate.resolve()
    else:
        resolved = (root / candidate).resolve()

    if resolved != root and root not in resolved.parents:
        raise SandboxViolation(
            f"Path escapes the review root and was refused: {relative_path!r} "
            f"(resolved to {resolved}, root is {root})"
        )
    return resolved


def relative_to_root(path: Path | str) -> str:
    """Render a path relative to the review root for stable, portable reporting."""
    root = get_review_root()
    p = Path(path).resolve()
    try:
        return str(p.relative_to(root))
    except ValueError:
        return str(p)
