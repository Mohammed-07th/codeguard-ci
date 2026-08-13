"""Every declared dependency must actually be importable and reported."""

from __future__ import annotations

import re
from pathlib import Path

from codeguard.config import PROJECT_ROOT
from codeguard.deps import DEPENDENCIES, dependency_report


def _declared() -> set[str]:
    text = (PROJECT_ROOT / "requirements.txt").read_text()
    return {
        re.split(r"[=<>\[]", line)[0].strip()
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }


def test_every_declared_dependency_is_imported_somewhere():
    """Declaring a library is a claim; importing it is a fact.

    A package listed in requirements.txt but never imported is dead weight at
    best and a misleading claim at worst.
    """
    missing = _declared() - {dist for dist, _, _ in DEPENDENCIES}
    assert not missing, f"declared but never imported: {sorted(missing)}"


def test_the_report_does_not_claim_undeclared_packages():
    extra = {dist for dist, _, _ in DEPENDENCIES} - _declared()
    assert not extra, f"reported but not declared in requirements.txt: {sorted(extra)}"


def test_all_dependencies_import_at_runtime():
    report = dependency_report(verbose=True)
    assert report["healthy"], f"failed to import: {report['missing']}"
    assert report["importable"] == report["declared"]


def test_report_records_the_real_module_path_not_the_distribution_name():
    """The distribution name and the import path differ for several packages."""
    by_dist = {d: m for d, m, _ in DEPENDENCIES}
    assert by_dist["langgraph-checkpoint-sqlite"] == "langgraph.checkpoint.sqlite"
    assert by_dist["openinference-instrumentation-langchain"].startswith("openinference.")
    assert by_dist["opentelemetry-sdk"].startswith("opentelemetry.")


def test_no_template_placeholders_remain_in_the_repo():
    """Scaffold text left in a submission looks like unfinished work."""
    patterns = re.compile(r"REPLACE_ME|FILL[ _-]?IN|your-key-here|TODO:", re.I)
    offenders = []
    for path in PROJECT_ROOT.rglob("*"):
        if not path.is_file() or path.suffix not in {".py", ".md", ".yml", ".toml", ".example"}:
            continue
        if any(part in {".venv", ".git", "workdir", "artifacts"} for part in path.parts):
            continue
        for i, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
            if patterns.search(line) and "patterns = re.compile" not in line:
                offenders.append(f"{path.relative_to(PROJECT_ROOT)}:{i}")
    assert not offenders, f"template placeholders left behind: {offenders}"
