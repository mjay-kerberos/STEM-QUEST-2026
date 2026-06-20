#!/usr/bin/env bash
# test.sh — Verify that all workshop services are healthy.
# Run this after completing the setup steps in README.md.
#
# Usage:
#   bash scripts/test.sh

set -euo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0

pass() { echo -e "${GREEN}[PASS]${NC} $1"; ((PASS++)); }
fail() { echo -e "${RED}[FAIL]${NC} $1"; ((FAIL++)); }
info() { echo -e "${YELLOW}[INFO]${NC} $1"; }

echo ""
echo "=================================================="
echo "  AI Threat Detection Workshop — Health Check"
echo "=================================================="
echo ""

# ── 1. Docker is running ──────────────────────────────
if docker info >/dev/null 2>&1; then
  pass "Docker is running"
else
  fail "Docker is not running — open Docker Desktop and try again"
  exit 1
fi

# ── 2. Container count ────────────────────────────────
RUNNING=$(docker compose ps --status running 2>/dev/null | grep -c "Up" || true)
if [[ "$RUNNING" -ge 7 ]]; then
  pass "All 7 containers running ($RUNNING found)"
elif [[ "$RUNNING" -ge 4 ]]; then
  fail "Only $RUNNING containers running (expected 7 — did you run the Loki overlay?)"
  info "Run: docker compose -f docker-compose.yml -f docker-compose.loki.yml up -d"
else
  fail "Only $RUNNING containers running (expected 7)"
  info "Run: docker compose -f docker-compose.yml -f docker-compose.loki.yml up -d"
fi

# ── 3. DVWA ───────────────────────────────────────────
HTTP=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 http://localhost:8080/ 2>/dev/null || echo "000")
if [[ "$HTTP" == "200" || "$HTTP" == "302" ]]; then
  pass "DVWA is reachable at http://localhost:8080  (HTTP $HTTP)"
else
  fail "DVWA not reachable at http://localhost:8080 (got HTTP $HTTP)"
  info "Check: docker compose logs dvwa"
fi

# ── 4. AI Analyst ─────────────────────────────────────
AI=$(curl -s --max-time 5 http://localhost:8000/api/health 2>/dev/null || echo "")
if echo "$AI" | grep -qi "ok\|healthy\|status"; then
  pass "AI Analyst is reachable at http://localhost:8000"
elif curl -s -o /dev/null -w "%{http_code}" --max-time 5 http://localhost:8000/ 2>/dev/null | grep -q "200"; then
  pass "AI Analyst is reachable at http://localhost:8000"
else
  fail "AI Analyst not reachable at http://localhost:8000"
  info "Check: docker compose logs ai-analyst"
fi

# ── 5. Ollama ─────────────────────────────────────────
OLLAMA=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 http://localhost:11434/ 2>/dev/null || echo "000")
if [[ "$OLLAMA" == "200" ]]; then
  pass "Ollama is reachable at http://localhost:11434"
else
  fail "Ollama not reachable at http://localhost:11434 (got HTTP $OLLAMA)"
  info "Check: docker compose logs ollama"
fi

# ── 6. Mistral model is loaded ────────────────────────
MODELS=$(curl -s --max-time 10 http://localhost:11434/api/tags 2>/dev/null || echo "")
if echo "$MODELS" | grep -qi "mistral"; then
  pass "Mistral model is loaded in Ollama"
else
  fail "Mistral model not found in Ollama"
  info "Run: docker exec workshop-ollama ollama pull mistral:7b-instruct-q4_K_M"
fi

# ── 7. Loki ───────────────────────────────────────────
LOKI=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 http://localhost:3100/ready 2>/dev/null || echo "000")
if [[ "$LOKI" == "200" ]]; then
  pass "Loki is reachable at http://localhost:3100"
else
  fail "Loki not reachable at http://localhost:3100 (got HTTP $LOKI)"
  info "Run: docker compose -f docker-compose.yml -f docker-compose.loki.yml up -d"
fi

# ── 8. Grafana ────────────────────────────────────────
GRAFANA=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 http://localhost:3000/ 2>/dev/null || echo "000")
if [[ "$GRAFANA" == "200" || "$GRAFANA" == "302" ]]; then
  pass "Grafana is reachable at http://localhost:3000"
else
  fail "Grafana not reachable at http://localhost:3000 (got HTTP $GRAFANA)"
  info "Run: docker compose -f docker-compose.yml -f docker-compose.loki.yml up -d"
fi

# ── 9. Fire a quick test attack and check AI response ─
info "Firing a test SQL injection request..."
curl -s -o /dev/null -A "sqlmap/1.8" \
  "http://localhost:8080/vulnerabilities/sqli/?id=1%27%20UNION%20SELECT%20user%2Cpassword%20FROM%20users--%20-&Submit=Submit" \
  --max-time 5 2>/dev/null || true
sleep 2
ALERTS=$(curl -s --max-time 5 http://localhost:8000/api/alerts 2>/dev/null | python3 -c "import sys,json; a=json.load(sys.stdin); print(len(a))" 2>/dev/null || echo "0")
if [[ "$ALERTS" -gt 0 ]]; then
  pass "AI Analyst is detecting attacks ($ALERTS alert(s) in buffer)"
else
  fail "AI Analyst alert buffer is empty after test attack"
  info "Wait 10 seconds and check http://localhost:8000 manually"
fi

# ── Summary ───────────────────────────────────────────
echo ""
echo "=================================================="
if [[ "$FAIL" -eq 0 ]]; then
  echo -e "${GREEN}  All checks passed! ($PASS/$((PASS+FAIL)))${NC}"
  echo ""
  echo "  Open your dashboards:"
  echo "    DVWA         → http://localhost:8080  (admin/password)"
  echo "    AI Analyst   → http://localhost:8000"
  echo "    Grafana SIEM → http://localhost:3000  (admin/admin)"
else
  echo -e "${RED}  $FAIL check(s) failed, $PASS passed.${NC}"
  echo ""
  echo "  See the [INFO] hints above for how to fix each failure."
  echo "  Full logs: docker compose logs [container-name]"
fi
echo "=================================================="
echo ""
