"""
server/ingestor.py
──────────────────
DVWA Apache access-log tailer.

Watches /var/log/apache2/access.log (mounted from the DVWA container)
and converts every log line into a structured alert dict that
the rest of the AI analyst expects, applying lightweight rule-matching
so each alert carries a meaningful rule_id / rule_level. The model
then scores each event in real time.

Runs as an asyncio background task started from main.py's lifespan.
"""

from __future__ import annotations

import asyncio
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Awaitable


# Combined log format:
#   IP - - [date] "METHOD PATH HTTP/1.1" status bytes "referer" "user-agent"
APACHE_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) [^"]*" '
    r'(?P<status>\d+) (?P<bytes>\S+)'
)

# Rule matrix — maps attack patterns to rule IDs and severity levels.
#
# Rule ID convention (workshop-custom, 5-digit scheme):
#   100100-100109  SQL Injection  (OWASP A03:2021 / CWE-89)
#   100110-100119  Brute Force    (OWASP A07:2021 / CWE-307)
#   100120-100129  XSS            (OWASP A03:2021 / CWE-79)
#   100130-100139  Command Inject (OWASP A03:2021 / CWE-78)
#   100140-100149  File Inclusion (OWASP A05:2021 / CWE-22)
#   100000          Baseline / benign web request
#
# Severity levels (0–15):
#   3  = informational   10 = high   12 = critical   14 = max
#
RULES: list[tuple[int, int, re.Pattern, str]] = [
    (100101, 14,
     re.compile(r"vulnerabilities/sqli.*(union|select|1=1|sleep\(|--|%27\+or)", re.I),
     "SQL Injection (High) — Classic payload: UNION/SELECT or time-based blind detected"
     " [OWASP A03:2021 · CWE-89]"),
    (100100, 12,
     re.compile(r"vulnerabilities/sqli", re.I),
     "SQL Injection — Attempt on SQLi endpoint; payload signature pending analysis"
     " [OWASP A03:2021 · CWE-89]"),
    (100121, 12,
     re.compile(r"vulnerabilities/xss.*(<script|%3cscript|javascript:|onerror=|onload=|alert\()", re.I),
     "Cross-Site Scripting (High) — Script injection payload confirmed in request"
     " [OWASP A03:2021 · CWE-79]"),
    (100120, 10,
     re.compile(r"vulnerabilities/xss", re.I),
     "Cross-Site Scripting — Attempt on XSS endpoint; payload analysis pending"
     " [OWASP A03:2021 · CWE-79]"),
    (100130, 13,
     re.compile(r"vulnerabilities/exec", re.I),
     "OS Command Injection — Shell metacharacter or chained command detected in parameter"
     " [OWASP A03:2021 · CWE-78]"),
    (100140, 12,
     re.compile(r"vulnerabilities/fi", re.I),
     "File Inclusion — Path traversal, LFI, or RFI attempt detected"
     " [OWASP A05:2021 · CWE-22]"),
    (100110, 10,
     re.compile(r"vulnerabilities/brute", re.I),
     "Brute Force — Credential guessing attempt on login endpoint"
     " [OWASP A07:2021 · CWE-307]"),
]

# Sliding-window counter for brute-force escalation.
# Escalation: ≥50 hits from the same source IP within 60 s → rule 100111 (automated tool).
_BRUTE_HITS: dict[str, list[float]] = {}


def _match_rule(path: str, ip: str) -> tuple[int, int, str]:
    for rid, level, pat, desc in RULES:
        if pat.search(path):
            if rid == 100110:
                now = datetime.now().timestamp()
                hits = _BRUTE_HITS.setdefault(ip, [])
                hits.append(now)
                hits[:] = [t for t in hits if now - t <= 60]
                if len(hits) >= 50:
                    return 100111, 14, "Brute Force (High-Volume) — ≥50 auth attempts in 60 s; automated tool likely [OWASP A07:2021 · CWE-307]"
            return rid, level, desc
    return 100000, 3, "Web request — no known attack pattern matched (benign)"


def parse_line(line: str) -> dict | None:
    m = APACHE_RE.match(line)
    if not m:
        return None
    g = m.groupdict()
    try:
        bytes_sent = int(g["bytes"]) if g["bytes"].isdigit() else 0
    except ValueError:
        bytes_sent = 0

    rule_id, rule_level, desc = _match_rule(g["path"], g["ip"])

    return {
        "_source": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "rule": {
                "id":          str(rule_id),
                "level":       rule_level,
                "description": desc,
                "groups":      ["dvwa", "web", "workshop"],
            },
            "data": {
                "url":      g["path"],
                "srcip":    g["ip"],
                "protocol": g["method"],
                "id":       g["status"],
                "bytes":    bytes_sent,
            },
            "agent": {"id": "001", "name": "dvwa-monitor", "ip": "172.20.0.5"},
        }
    }


async def tail_apache_log(
    path: Path,
    on_event: Callable[[dict], Awaitable[None]],
    poll_interval: float = 1.0,
) -> None:
    """Tail an Apache access log forever, emitting parsed alerts."""
    print(f"[INGEST] watching {path}")
    # Wait until the log file exists.
    while not path.exists():
        await asyncio.sleep(poll_interval)

    with path.open("r", encoding="utf-8", errors="ignore") as fh:
        fh.seek(0, 2)  # seek to end — only watch NEW lines
        while True:
            line = fh.readline()
            if not line:
                await asyncio.sleep(poll_interval)
                continue
            alert = parse_line(line.rstrip())
            if alert:
                await on_event(alert)
