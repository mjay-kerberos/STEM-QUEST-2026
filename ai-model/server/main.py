"""
server/main.py
──────────────
AI Analyst FastAPI server.

Endpoints:
  GET  /              → HTML dashboard
  GET  /api/alerts    → latest 20 alerts with AI risk scores
  POST /api/analyze   → analyze a single alert JSON, return full brief
  GET  /api/health    → liveness check
  GET  /api/feature_importance → top model features (for the dashboard)

Falls back to a local fixture file (data/sample_alerts.json) when the
live log buffer is empty so the workshop demo can run standalone.
"""

from __future__ import annotations

import asyncio
import json
import os
import joblib
import httpx
from collections import deque
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from .features import extract, FEATURE_NAMES
from .ingestor import tail_apache_log

# ── Config from environment ───────────────────────────────
BASE_DIR        = Path(__file__).resolve().parent.parent
OLLAMA_HOST     = os.getenv("OLLAMA_HOST",     "http://ollama:11434")
OLLAMA_MODEL    = os.getenv("OLLAMA_MODEL",    "mistral:7b-instruct-q4_K_M")
MODEL_PATH      = os.getenv("MODEL_PATH",      str(BASE_DIR / "model" / "rf_classifier.pkl"))
FIXTURE_PATH    = os.getenv("FIXTURE_PATH",    str(BASE_DIR / "data" / "sample_alerts.json"))
APACHE_LOG_PATH = os.getenv("APACHE_LOG_PATH", "/var/log/apache2/access.log")
ENABLE_INGEST   = os.getenv("ENABLE_INGEST", "true").lower() in ("1", "true", "yes")
DISABLE_LLM     = os.getenv("DISABLE_LLM", "false").lower() in ("1", "true", "yes")
MAX_LIVE_ALERTS = int(os.getenv("MAX_LIVE_ALERTS", "100"))

# Rolling buffer of recent alerts produced by the ingestor.
_live_alerts: deque[dict] = deque(maxlen=MAX_LIVE_ALERTS)

# ── Load classifier ───────────────────────────────────────
_model_path = Path(MODEL_PATH)
if _model_path.exists():
    clf = joblib.load(_model_path)
    print(f"[AI] Classifier loaded from {_model_path}")
else:
    clf = None
    print(f"[AI] WARNING: model not found at {_model_path} — run train_model.py first")

async def _on_ingest_event(alert: dict) -> None:
    """Called for every parsed Apache log line. Stores in the live buffer."""
    _live_alerts.appendleft(alert)


@asynccontextmanager
async def lifespan(app: FastAPI):
    task = None
    if ENABLE_INGEST:
        task = asyncio.create_task(
            tail_apache_log(Path(APACHE_LOG_PATH), _on_ingest_event)
        )
        print(f"[AI] log ingestor started for {APACHE_LOG_PATH}")
    try:
        yield
    finally:
        if task:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass


app = FastAPI(title="AI Threat Analyst", version="1.0.0", lifespan=lifespan)


# ── Pydantic models ───────────────────────────────────────
class AlertIn(BaseModel):
    alert: dict[str, Any]


class AnalysisOut(BaseModel):
    rule_id:     int
    rule_level:  int
    risk_score:  int
    risk_label:  str
    attack_type: str
    brief:       str
    features:    dict[str, float]
    timestamp:   str


# ── Alert sources: live buffer + fixture fallback ─────────
def _load_fixture_alerts() -> list[dict]:
    fp = Path(FIXTURE_PATH)
    if not fp.exists():
        return []
    try:
        data = json.loads(fp.read_text())
        if isinstance(data, dict) and "alerts" in data:
            return data["alerts"]
        if isinstance(data, list):
            return data
    except json.JSONDecodeError as e:
        print(f"[AI] fixture parse error: {e}")
    return []


async def _get_recent_alerts(n: int = 20) -> list[dict]:
    # 1. Live buffer — populated by the Apache log ingestor in real time.
    if _live_alerts:
        return list(_live_alerts)[:n]

    # 2. Fixture file — guarantees the dashboard has something to show
    #    on first launch before any attacks have been fired.
    return _load_fixture_alerts()[:n]


# ── Risk scoring ──────────────────────────────────────────
def score_alert(alert: dict) -> tuple[int, str, str, dict[str, float]]:
    feat_vec  = extract(alert)
    feat_dict = dict(zip(FEATURE_NAMES, feat_vec))

    if clf is None:
        level = int(alert.get("_source", alert).get("rule", {}).get("level", 0))
        score = min(100, level * 7)
    else:
        proba = clf.predict_proba([feat_vec])[0][1]
        score = int(round(proba * 100))

    if score >= 85:
        label = "CRITICAL"
        atype = _infer_attack_type(alert, feat_dict)
    elif score >= 65:
        label = "HIGH"
        atype = _infer_attack_type(alert, feat_dict)
    elif score >= 40:
        label = "MEDIUM"
        atype = _infer_attack_type(alert, feat_dict) or "suspicious"
    else:
        label = "LOW"
        atype = "benign"

    return score, label, atype, feat_dict


def _infer_attack_type(alert: dict, feat: dict) -> str:
    # 1. Feature-flag signals (strongest — payload was observed)
    if feat.get("has_sqli_token"):       return "sql_injection"
    if feat.get("has_xss_token"):        return "xss"
    if feat.get("has_cmd_token"):        return "command_injection"
    if feat.get("has_traversal"):        return "path_traversal"
    if feat.get("failed_logins", 0) > 5: return "brute_force"

    # 2. Rule metadata (description, groups, URL) — used for events where
    #    the payload itself is not in the alert body (e.g. brute force
    #    correlated rules carry no URL payload of their own).
    src   = alert.get("_source", alert)
    rule  = src.get("rule", {})
    data  = src.get("data", {})
    text  = " ".join([
        str(rule.get("description", "")),
        " ".join(rule.get("groups", []) or []),
        str(data.get("url", "")),
    ]).lower()

    if "brute" in text or "auth" in text:        return "brute_force"
    if "sql"   in text or "sqli" in text:        return "sql_injection"
    if "xss"   in text or "script" in text:      return "xss"
    if "exec"  in text or "command" in text:     return "command_injection"
    if "/fi"   in text or "inclusion" in text:   return "path_traversal"
    if "scan"  in text or "recon" in text:       return "recon"
    return ""


# ── LLM brief generation ──────────────────────────────────
def _fallback_brief(
    alert: dict,
    risk_score: int,
    risk_label: str,
    attack_type: str,
    feat: dict,
    error: str | None = None,
) -> str:
    src   = alert.get("_source", alert)
    rule  = src.get("rule", {})
    data  = src.get("data", {})

    nice_attack = (attack_type or "unknown").replace("_", " ").title()
    confidence  = "HIGH" if risk_score >= 65 else ("MEDIUM" if risk_score >= 40 else "LOW")
    extra = f"\n[Note: LLM unavailable — {error}]" if error else ""
    return (
        f"INCIDENT BRIEF\n==============\n"
        f"Attack type  : {nice_attack}\n"
        f"Confidence   : {confidence} — rule level "
        f"{rule.get('level', '?')}/15, risk score {risk_score}/100\n"
        f"Impact       : Potential compromise of the DVWA application layer "
        f"and any data it can reach.\n"
        f"Evidence     : Rule {rule.get('id', '?')} fired. "
        f"Payload flags — SQLi:{int(feat.get('has_sqli_token', 0))} "
        f"XSS:{int(feat.get('has_xss_token', 0))} "
        f"CMD:{int(feat.get('has_cmd_token', 0))} "
        f"Traversal:{int(feat.get('has_traversal', 0))}. "
        f"Source IP {data.get('srcip', 'unknown')} "
        f"({'external' if feat.get('source_is_external') else 'internal'}).\n"
        f"Action items :\n"
        f"  1. Block source IP {data.get('srcip', 'unknown')} at the perimeter firewall.\n"
        f"  2. Review web-application input validation and add a WAF signature "
        f"for {nice_attack} patterns.\n"
        f"  3. Rotate credentials and audit access logs for the affected endpoint."
        f"{extra}"
    )


async def _generate_brief(
    alert: dict,
    risk_score: int,
    risk_label: str,
    attack_type: str,
    feat: dict,
) -> str:
    if DISABLE_LLM:
        return _fallback_brief(alert, risk_score, risk_label, attack_type, feat)

    src       = alert.get("_source", alert)
    rule      = src.get("rule", {})
    data      = src.get("data", {})
    timestamp = src.get("timestamp", datetime.now(timezone.utc).isoformat())

    prompt = f"""You are a senior security analyst writing a concise incident brief.
Analyze the following security alert and produce a structured report.

=== ALERT DATA ===
Timestamp  : {timestamp}
Rule ID    : {rule.get('id', 'N/A')}
Rule level : {rule.get('level', 'N/A')} / 15
Description: {rule.get('description', 'N/A')}
URL        : {data.get('url', 'N/A')}
Source IP  : {data.get('srcip', 'N/A')}
HTTP Method: {data.get('protocol', 'N/A')}
Status code: {data.get('id', 'N/A')}

=== AI RISK SCORE ===
Score      : {risk_score} / 100
Label      : {risk_label}
Attack type: {(attack_type or 'unknown').replace('_', ' ').title()}

=== FEATURE FLAGS ===
SQLi payload detected   : {'YES' if feat.get('has_sqli_token') else 'no'}
XSS payload detected    : {'YES' if feat.get('has_xss_token') else 'no'}
Command injection       : {'YES' if feat.get('has_cmd_token') else 'no'}
Path traversal          : {'YES' if feat.get('has_traversal') else 'no'}
External source IP      : {'YES' if feat.get('source_is_external') else 'no'}
Failed login attempts   : {int(feat.get('failed_logins', 0))}

Write your brief using EXACTLY this format — no extra commentary:

INCIDENT BRIEF
==============
Attack type  : [one line]
Confidence   : [HIGH / MEDIUM / LOW] — [one sentence why]
Impact       : [what is at risk if this succeeds, one sentence]
Evidence     : [specific log signals that led to this conclusion]
Action items :
  1. [immediate action]
  2. [short-term hardening]
  3. [long-term recommendation]
"""

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.post(
                f"{OLLAMA_HOST}/api/generate",
                json={
                    "model":  OLLAMA_MODEL,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": 0.2,
                        "num_predict": 350,
                    },
                },
            )
            r.raise_for_status()
            text = r.json().get("response", "").strip()
            return text or _fallback_brief(alert, risk_score, risk_label, attack_type, feat)
    except Exception as e:
        return _fallback_brief(alert, risk_score, risk_label, attack_type, feat, error=str(e))


# ── Routes ────────────────────────────────────────────────
@app.get("/api/health")
async def health():
    return {
        "status":       "ok",
        "model_loaded": clf is not None,
        "model_path":   str(MODEL_PATH),
        "fixture_path": str(FIXTURE_PATH),
        "ollama_host":  OLLAMA_HOST,
        "ollama_model": OLLAMA_MODEL,
        "disable_llm":  DISABLE_LLM,
        "timestamp":    datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/feature_importance")
async def feature_importance():
    if clf is None or not hasattr(clf, "feature_importances_"):
        return JSONResponse({"error": "model not loaded"}, status_code=503)
    pairs = sorted(
        zip(FEATURE_NAMES, clf.feature_importances_.tolist()),
        key=lambda p: p[1],
        reverse=True,
    )
    return [{"name": n, "importance": float(v)} for n, v in pairs]


@app.get("/api/alerts")
async def get_alerts():
    raw_alerts = await _get_recent_alerts(20)
    results = []
    for alert in raw_alerts:
        score, label, atype, feat = score_alert(alert)
        src = alert.get("_source", alert)
        results.append({
            "rule_id":     src.get("rule", {}).get("id"),
            "rule_level":  src.get("rule", {}).get("level"),
            "description": src.get("rule", {}).get("description"),
            "timestamp":   src.get("timestamp"),
            "source_ip":   src.get("data", {}).get("srcip"),
            "url":         src.get("data", {}).get("url"),
            "risk_score":  score,
            "risk_label":  label,
            "attack_type": atype,
        })
    return JSONResponse(results)


@app.post("/api/analyze", response_model=AnalysisOut)
async def analyze(body: AlertIn):
    alert = body.alert
    score, label, atype, feat = score_alert(alert)
    brief = await _generate_brief(alert, score, label, atype, feat)

    src = alert.get("_source", alert)
    return AnalysisOut(
        rule_id     = int(src.get("rule", {}).get("id", 0) or 0),
        rule_level  = int(src.get("rule", {}).get("level", 0) or 0),
        risk_score  = score,
        risk_label  = label,
        attack_type = atype or "unknown",
        brief       = brief,
        features    = feat,
        timestamp   = src.get("timestamp", datetime.now(timezone.utc).isoformat()),
    )


@app.get("/", response_class=HTMLResponse)
async def dashboard():
    html_path = Path(__file__).parent / "dashboard.html"
    if html_path.exists():
        return html_path.read_text()
    return HTMLResponse(
        "<h1>AI Analyst</h1><p>Dashboard file missing — see <code>server/dashboard.html</code>.</p>"
    )
