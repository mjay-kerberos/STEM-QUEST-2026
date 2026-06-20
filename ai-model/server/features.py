"""
server/features.py
──────────────────
Feature extraction from Apache log alert JSON.

This module extracts exactly the same 16 features that
generate_dataset.py used during training.
Any mismatch between these two files would cause silent
model degradation — keep them in sync.
"""

from __future__ import annotations
from typing import Any


# Feature names in training order — must match train_model.py FEATURE_COLS
FEATURE_NAMES = [
    "rule_id",
    "rule_level",
    "http_method_post",
    "status_code",
    "url_length",
    "bytes_sent",
    "has_sqli_token",
    "has_xss_token",
    "has_cmd_token",
    "has_traversal",
    "has_encoded_chars",
    "source_is_external",
    "requests_per_min",
    "failed_logins",
    "hour_of_day",
    "is_off_hours",
]

# IPs considered "internal" in the workshop network
_INTERNAL_SUBNETS = ("172.20.", "192.168.", "10.", "127.")


def _is_external(ip: str) -> int:
    return 0 if any(ip.startswith(s) for s in _INTERNAL_SUBNETS) else 1


def _has_token(text: str, tokens: list[str]) -> int:
    text_lower = text.lower()
    return int(any(t in text_lower for t in tokens))


def extract(alert: dict[str, Any]) -> list[float]:
    """
    Extract a feature vector from an alert dict.

    Parameters
    ----------
    alert : dict
        Raw alert JSON (as received from the ingestor or alerts.json).
        Expected keys (all optional — missing keys default safely):
          _source.rule.id, _source.rule.level,
          _source.data.protocol, _source.data.url,
          _source.data.srcip, _source.timestamp, etc.

    Returns
    -------
    list of float
        16-element feature vector in FEATURE_NAMES order.
    """
    src        = alert.get("_source", alert)   # handle both raw and wrapped
    rule       = src.get("rule", {})
    data       = src.get("data", {})
    timestamp  = src.get("timestamp", "2026-01-01T12:00:00Z")

    rule_id    = int(rule.get("id", 0))
    rule_level = int(rule.get("level", 0))

    # HTTP fields (populated by web decoder)
    method     = str(data.get("protocol", "GET")).upper()
    url        = str(data.get("url", ""))
    status     = int(data.get("id", 200))          # HTTP status code
    bytes_sent = int(data.get("bytes", 500))

    # Source IP
    src_ip     = str(src.get("agent", {}).get("ip", data.get("srcip", "172.20.0.1")))

    # Timestamp → hour
    try:
        hour = int(timestamp[11:13])
    except (IndexError, ValueError):
        hour = 12

    # SQLi tokens — only highly-specific SQL markers.
    # A bare %27 is a URL-encoded quote and appears in many benign URLs,
    # so we only fire when it is followed by an SQL keyword.
    sqli_tokens = [
        "union", "select", "or+1=1", "or '1'='1", "sleep(",
        "drop+table", "drop table", "insert+into", "insert into",
        "--", "1=1", "%27+or", "%27+union", "%27+and",
    ]
    # XSS tokens
    xss_tokens = [
        "<script", "%3cscript", "javascript:", "onerror=",
        "onload=", "alert(", "%3cimg", "svg/onload",
    ]
    # Command injection tokens
    cmd_tokens = [
        "%3b", "%7c", ";cat", "|whoami", "/etc/passwd",
        "cmd=", "exec(", "system(", "shell_exec",
    ]

    return [
        float(rule_id),
        float(rule_level),
        float(int(method == "POST")),
        float(status),
        float(len(url)),
        float(bytes_sent),
        float(_has_token(url, sqli_tokens)),
        float(_has_token(url, xss_tokens)),
        float(_has_token(url, cmd_tokens)),
        float(int("../" in url or "%2e%2e" in url.lower())),
        float(int("%" in url and len(url) > 50)),
        float(_is_external(src_ip)),
        1.0,    # requests_per_min: not available from single alert; default 1
        0.0,    # failed_logins: populated separately if brute-force context available
        float(hour),
        float(int(hour not in range(8, 19))),
    ]
