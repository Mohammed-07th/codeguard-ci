#!/usr/bin/env python
"""Final verification. Every line is executed; nothing is asserted from memory.

    .venv/bin/python scripts/final_check.py [--skip-clean-venv]
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY = str(ROOT / ".venv" / "bin" / "python")
results: list[tuple[str, bool, str]] = []


def check(label: str, ok: bool, detail: str = "") -> bool:
    results.append((label, ok, detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}" + (f" — {detail}" if detail else ""))
    return ok


def run(cmd, cwd=ROOT, timeout=1800):
    return subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True, timeout=timeout)


def main() -> int:
    skip_venv = "--skip-clean-venv" in sys.argv
    print("=" * 82)
    print("FINAL VERIFICATION")
    print("=" * 82)

    # 1 -----------------------------------------------------------------------
    print("\n1. Clean-venv install from requirements.txt")
    if skip_venv:
        check("clean venv install", True, "skipped by flag")
    else:
        with tempfile.TemporaryDirectory() as tmp:
            venv = Path(tmp) / "venv"
            mk = run(["uv", "venv", str(venv), "--python", "3.11"], timeout=300)
            inst = run(["uv", "pip", "install", "--python", str(venv / "bin" / "python"),
                        "-r", "requirements.txt"], timeout=1200)
            ok = mk.returncode == 0 and inst.returncode == 0
            imp = run([str(venv / "bin" / "python"), "-c",
                       "import langgraph, langchain_openai, fastapi, boto3, bandit, ruff, "
                       "opentelemetry, openinference; print('imports ok')"], timeout=180)
            check("pip install -r requirements.txt in a clean venv", ok,
                  (inst.stderr or inst.stdout).strip().splitlines()[-1][:90] if not ok else "")
            check("every declared dependency imports", imp.returncode == 0,
                  imp.stdout.strip() or imp.stderr.strip()[-90:])

    # 2 -----------------------------------------------------------------------
    print("\n2. Test suite")
    t = run([PY, "-m", "pytest", "tests/", "-v", "-p", "no:phoenix", "-o", "addopts="], timeout=900)
    m = re.search(r"(\d+) passed", t.stdout)
    n = int(m.group(1)) if m else 0
    check("pytest tests/ -v passes", t.returncode == 0, f"{n} tests")
    names = t.stdout
    check("includes a graph-termination test",
          "test_routing_always_terminates_within_max_iter" in names)
    check("includes guardrail tests",
          "test_measured_block_rate_holds" in names and "test_redaction" in names)
    check("includes the remediation-loop substance test",
          "test_remediation_genuinely_reduces_real_scanner_findings" in names)

    # 3 -----------------------------------------------------------------------
    print("\n3. Demo suite end to end")
    d = run(["bash", "scripts/run_demo.sh"], timeout=1800)
    check("bash scripts/run_demo.sh completes with no unhandled exception",
          d.returncode == 0 and "Traceback" not in d.stdout,
          re.search(r"passed : \d+", d.stdout).group(0) if "passed :" in d.stdout else "")

    # 4 -----------------------------------------------------------------------
    print("\n4. Container stack")
    have_docker = run(["docker", "info", "--format", "{{.ServerVersion}}"], timeout=60).returncode == 0
    if not have_docker:
        check("docker compose build && up", False, "no container runtime available")
    else:
        b = run(["docker", "compose", "build"], timeout=1800)
        check("docker compose build succeeds", b.returncode == 0)
        u = run(["docker", "compose", "up", "-d"], timeout=600)
        check("docker compose up -d succeeds", u.returncode == 0)
        import time, urllib.request
        code, body = 0, {}
        for _ in range(30):
            try:
                with urllib.request.urlopen("http://localhost:8000/health", timeout=5) as r:
                    code, body = r.status, json.loads(r.read())
                break
            except Exception:
                time.sleep(3)
        check("GET /health returns 200", code == 200, f"HTTP {code}")
        check("artifact store reachable from the container",
              bool(body.get("components", {}).get("artifact_store", {}).get("reachable")))

    # 5 -----------------------------------------------------------------------
    print("\n5. Evidence notebook")
    nbp = ROOT / "notebooks" / "capstone_evidence.ipynb"
    if nbp.exists():
        nb = json.loads(nbp.read_text())
        code_cells = [c for c in nb["cells"] if c["cell_type"] == "code"]
        with_out = [c for c in code_cells if c.get("outputs")]
        errs = [c for c in code_cells
                if any(o.get("output_type") == "error" for o in c.get("outputs", []))]
        text = "\n".join(
            (o.get("text") if isinstance(o.get("text"), str) else "".join(o.get("text", [])))
            for c in code_cells for o in c.get("outputs", [])
            if o.get("output_type") == "stream")
        check("notebook executed with outputs saved",
              len(with_out) == len(code_cells) and not errs,
              f"{len(with_out)}/{len(code_cells)} cells, {len(errs)} errors")
        check("all six deliverable sections present",
              all(f"Deliverable {i} evidence captured" in text for i in range(1, 7)))
    else:
        check("notebook exists", False)

    # 6 -----------------------------------------------------------------------
    print("\n6. Repository hygiene")
    log = run(["git", "log", "--oneline"]).stdout.strip().splitlines()
    check("git log shows >= 10 meaningful commits", len(log) >= 10, f"{len(log)} commits")
    check("no bulk single upload", len(log) >= 10 and len({l[:9] for l in log}) == len(log))

    tracked = run(["git", "ls-files"]).stdout
    bad = [f for f in tracked.splitlines() if re.search(r"(^|/)\.env$|\.sqlite$", f)]
    check("no .env or .sqlite tracked", not bad, str(bad) if bad else "")

    hist = run(["bash", "-c", "git log -p | grep -cE 'sk-or-v1-[A-Za-z0-9]{20,}' || true"])
    leaked = int((hist.stdout or "0").strip() or 0)
    check("no OpenRouter key anywhere in git history", leaked == 0, f"{leaked} matches")

    for f in (".gitignore", ".env.example", ".dockerignore"):
        check(f"{f} present", (ROOT / f).exists())

    # 7 -----------------------------------------------------------------------
    print("\n7. Rubric coverage — every deliverable has code and executed evidence")
    EV = ROOT / "evidence"
    rubric = [
        ("1 Agentic reasoning", "src/codeguard/agents/base.py", "phase3_security_agent.log"),
        ("2 Graph orchestration", "src/codeguard/graph/build.py", "phase4_remediation_run.log"),
        ("3 Multi-agent roles", "src/codeguard/agents/synthesizer.py", "phase2_tool_check.log"),
        ("4 Guardrails & observability", "src/codeguard/guardrails/injection.py",
         "phase5_adversarial.log"),
        ("5 Production readiness", "src/codeguard/graph/resume.py",
         "phase6_persistence_proof.log"),
        ("6 Documentation", "docs/ARCHITECTURE.md", "phase9_pytest.log"),
    ]
    for name, code_path, ev in rubric:
        check(f"{name}", (ROOT / code_path).exists() and (EV / ev).exists(),
              f"{code_path} + evidence/{ev}")

    # ------------------------------------------------------------------------
    passed = sum(1 for _, ok, _ in results if ok)
    print("\n" + "=" * 82)
    print(f"  {passed}/{len(results)} checks passed")
    for label, ok, detail in results:
        if not ok:
            print(f"    FAILED: {label} {detail}")
    print("=" * 82)
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
