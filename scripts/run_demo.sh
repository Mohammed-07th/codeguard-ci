#!/usr/bin/env bash
# Run every demo end to end, tee-ing captured output into evidence/.
#
#   bash scripts/run_demo.sh          # everything that needs no model calls
#   bash scripts/run_demo.sh --live   # additionally drive the four fixtures with real models
#
# The split is deliberate. Most of the evidence — the tool layer, both
# guardrails, the adversarial set, the graph topology, loop termination, the
# HITL pause and both resume decisions, checkpoint durability, the trace
# waterfall — needs no LLM at all, so it runs anywhere, every time, for free.
# --live adds the four full reviews against real models, which on a free tier is
# rate-limited to roughly one and a half runs per day.

set -uo pipefail
cd "$(dirname "$0")/.."

PY=".venv/bin/python"
[ -x "$PY" ] || PY="python3"
LIVE=0
[ "${1:-}" = "--live" ] && LIVE=1

mkdir -p evidence
PASS=0; FAIL=0; SKIP=0

hr()   { printf '\n\033[1m%s\033[0m\n%s\n' "$1" "$(printf '=%.0s' {1..78})"; }
step() {
  local name="$1" log="$2"; shift 2
  printf '\n>>> %s\n    -> evidence/%s\n' "$name" "$(basename "$log")"
  if "$@" > "$log" 2>&1; then
    printf '    \033[32mPASS\033[0m (%s lines captured)\n' "$(wc -l < "$log" | tr -d ' ')"
    PASS=$((PASS+1))
  else
    printf '    \033[31mFAIL\033[0m (exit %s) — see %s\n' "$?" "$log"
    FAIL=$((FAIL+1))
  fi
}

hr "CodeGuard CI — full demo run  ($(date -u '+%Y-%m-%d %H:%M:%SZ'))"
echo "mode: $([ $LIVE -eq 1 ] && echo 'live models + offline' || echo 'offline only (no model calls)')"

# --------------------------------------------------------------- no LLM needed
hr "1. Tool layer and access controls"
step "seven real tools, path sandbox, per-agent allow-list" \
     evidence/phase2_tool_check.log "$PY" scripts/tool_check.py

hr "2. Input guardrail against an adversarial set"
step "block rate and false-positive rate" \
     evidence/phase5_adversarial.log "$PY" scripts/adversarial_check.py

hr "3. Injection attack blocked end to end through the graph"
step "pr_injection reaches 'blocked' with zero model calls" \
     evidence/phase5_injection_blocked.log "$PY" scripts/run_review.py pr_injection "demo-blocked-$$"

hr "4. Human-in-the-loop: pause, then BOTH decisions"
step "approve and reject from one identical checkpoint" \
     evidence/phase6_hitl_both_paths.log "$PY" scripts/hitl_demo.py

hr "5. Checkpoint durability across a process kill"
step "SIGKILL mid-review, resume in a fresh process" \
     evidence/phase6_persistence_proof.log "$PY" scripts/prove_persistence.py

hr "6. Tracing, metrics and provider failover"
step "trace waterfall, run summary, failover evidence" \
     evidence/phase7_observability.log "$PY" scripts/observability_demo.py

hr "7. Test suite"
step "unit and integration tests" \
     evidence/phase9_pytest.log "$PY" -m pytest tests/ -v

# ------------------------------------------------------------- needs the stack
hr "8. Deployed stack (docker compose)"
if docker compose ps --format '{{.Name}}' 2>/dev/null | grep -q codeguard-app; then
  step "health, webhook, MinIO artifact" evidence/phase8_docker_stack.log bash -c '
    set -e
    docker compose ps --format "table {{.Name}}\t{{.Service}}\t{{.Status}}"
    echo; echo "=== GET /health ==="
    curl -s -o /tmp/cg_h.json -w "HTTP %{http_code}\n" http://localhost:8000/health
    cat /tmp/cg_h.json
    echo; echo "=== POST /webhook/pr {\"fixture\":\"pr_injection\"} ==="
    curl -s -X POST "http://localhost:8000/webhook/pr?wait=true" \
         -H "Content-Type: application/json" -d "{\"fixture\":\"pr_injection\"}" \
         -w "\nHTTP %{http_code}\n"
    echo; echo "=== GET /reports (MinIO) ==="
    curl -s http://localhost:8000/reports -w "\nHTTP %{http_code}\n"
  '
else
  printf '\n>>> docker compose stack is not running — \033[33mSKIPPED\033[0m\n'
  printf '    start it with:  docker compose up -d --build\n'
  SKIP=$((SKIP+1))
fi

# -------------------------------------------------------------------- live LLM
if [ $LIVE -eq 1 ]; then
  hr "9. Full reviews against real models"
  step "SecurityAgent ReAct trace on pr_with_secret" \
       evidence/phase3_security_agent.log "$PY" scripts/agent_demo.py pr_with_secret
  for fx in pr_clean pr_with_secret pr_critical; do
    step "full graph review: $fx" \
         "evidence/live_review_${fx}.log" "$PY" scripts/run_review.py "$fx" "live-${fx}-$$"
  done
else
  printf '\n>>> live model reviews — \033[33mSKIPPED\033[0m (pass --live to include them)\n'
  SKIP=$((SKIP+1))
fi

hr "SUMMARY"
printf '  passed : %s\n  failed : %s\n  skipped: %s\n\n' "$PASS" "$FAIL" "$SKIP"
ls -la evidence/ | awk 'NR>3 {printf "  %-42s %8s bytes\n", $9, $5}'
echo
[ "$FAIL" -eq 0 ] && echo "  All executed steps passed." || echo "  $FAIL step(s) failed."
exit $([ "$FAIL" -eq 0 ] && echo 0 || echo 1)
