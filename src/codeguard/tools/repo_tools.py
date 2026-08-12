"""Repository access: loading a pull request, reading files, and producing the diff.

A fixture on disk looks like a real PR:

    fixtures/pr_with_secret/
        pr.json          metadata: id, title, description, changed_files
        files/           the actual tree the PR would produce

The tree is real because the analysers are real — ``bandit`` and ``pytest`` need
files to open. ``materialize`` copies that tree into ``workdir/`` so the
remediation loop can patch a working copy and leave the fixture pristine, which
is what makes the demo repeatable.
"""

from __future__ import annotations

import difflib
import json
import shutil
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

from codeguard.tools.sandbox import relative_to_root, safe_resolve

TEXT_SUFFIXES = {".py", ".txt", ".md", ".cfg", ".ini", ".toml", ".yaml", ".yml", ".json", ".env"}
MAX_READ_BYTES = 40_000


@dataclass
class PullRequest:
    pr_id: str
    title: str
    description: str
    changed_files: list[str]
    root: Path                    # directory holding the PR's file tree
    author: str = "unknown"
    notes: str = ""               # fixture author's note; never shown to agents
    _diff: str | None = field(default=None, repr=False)

    @property
    def diff(self) -> str:
        if self._diff is None:
            self._diff = build_diff(self.root, self.changed_files)
        return self._diff

    def to_dict(self) -> dict[str, Any]:
        return {
            "pr_id": self.pr_id,
            "title": self.title,
            "description": self.description,
            "changed_files": self.changed_files,
            "author": self.author,
            "root": str(self.root),
        }


_current_pr: ContextVar[PullRequest | None] = ContextVar("codeguard_current_pr", default=None)


@contextmanager
def pr_context(pr: PullRequest) -> Iterator[PullRequest]:
    token = _current_pr.set(pr)
    try:
        yield pr
    finally:
        _current_pr.reset(token)


def get_current_pr() -> PullRequest:
    pr = _current_pr.get()
    if pr is None:
        raise RuntimeError("No pull request in context. Use `with pr_context(pr):`.")
    return pr


def load_pull_request(fixture_dir: Path | str) -> PullRequest:
    """Load a PR fixture from disk."""
    d = Path(fixture_dir).resolve()
    meta_path = d / "pr.json"
    if not meta_path.exists():
        raise FileNotFoundError(f"fixture is missing pr.json: {d}")
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    root = d / "files"
    if not root.is_dir():
        raise FileNotFoundError(f"fixture is missing files/: {d}")

    changed = meta.get("changed_files")
    if not changed:  # default to every file in the tree
        changed = sorted(
            str(p.relative_to(root)) for p in root.rglob("*") if p.is_file()
        )

    return PullRequest(
        pr_id=meta["pr_id"],
        title=meta.get("title", ""),
        description=meta.get("description", ""),
        changed_files=changed,
        root=root,
        author=meta.get("author", "unknown"),
        notes=meta.get("notes", ""),
    )


def materialize(pr: PullRequest, dest: Path) -> PullRequest:
    """Copy the PR tree into ``dest`` and return a PR pointing at the copy.

    The remediation loop patches files; it must never touch the fixture, or the
    second run of the demo would start from the already-fixed state.
    """
    dest = Path(dest).resolve()
    if dest.exists():
        shutil.rmtree(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(pr.root, dest)
    return PullRequest(
        pr_id=pr.pr_id,
        title=pr.title,
        description=pr.description,
        changed_files=list(pr.changed_files),
        root=dest,
        author=pr.author,
        notes=pr.notes,
    )


def build_diff(root: Path, changed_files: list[str]) -> str:
    """Synthesise a unified diff. The fixtures add files, so every line is an addition."""
    chunks: list[str] = []
    for rel in changed_files:
        p = root / rel
        if not p.exists():
            continue
        try:
            content = p.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
        except OSError:
            continue
        chunks.extend(
            difflib.unified_diff(
                [], content, fromfile=f"a/{rel}", tofile=f"b/{rel}", lineterm="\n", n=0
            )
        )
    return "".join(chunks)


# --- tool implementations (plain functions; wrapped for the LLM in registry.py) ---

def read_file(path: str, max_bytes: int = MAX_READ_BYTES) -> dict[str, Any]:
    """Read a file from the PR under review.

    Args:
        path: Path relative to the repository root, e.g. ``src/config.py``.
        max_bytes: Truncation limit for very large files.
    """
    resolved = safe_resolve(path)          # refuses anything outside the review root
    if not resolved.exists():
        return {"tool": "read_file", "path": path, "error": "file not found"}
    if not resolved.is_file():
        return {"tool": "read_file", "path": path, "error": "not a regular file"}
    try:
        raw = resolved.read_bytes()[:max_bytes]
        text = raw.decode("utf-8", errors="replace")
    except OSError as e:
        return {"tool": "read_file", "path": path, "error": f"{type(e).__name__}: {e}"}

    numbered = "\n".join(
        f"{i:>4} | {line}" for i, line in enumerate(text.splitlines(), start=1)
    )
    return {
        "tool": "read_file",
        "path": relative_to_root(resolved),
        "line_count": len(text.splitlines()),
        "truncated": len(raw) >= max_bytes,
        "content": numbered,
    }


def list_changed_files() -> dict[str, Any]:
    """List the files changed by the pull request under review."""
    pr = get_current_pr()
    return {
        "tool": "list_changed_files",
        "pr_id": pr.pr_id,
        "count": len(pr.changed_files),
        "files": pr.changed_files,
    }


def get_diff(max_chars: int = 12_000) -> dict[str, Any]:
    """Return the unified diff of the pull request under review.

    Args:
        max_chars: Truncation limit, to keep the diff inside the model's context.
    """
    pr = get_current_pr()
    d = pr.diff
    return {
        "tool": "get_diff",
        "pr_id": pr.pr_id,
        "truncated": len(d) > max_chars,
        "diff": d[:max_chars],
    }
