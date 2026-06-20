# Detection Engineering with AI — Workshop

**NYC STEM Quest 2026 · Columbia VP&S**  
**Presenter:** Juliet Meza

Explore the detection pipeline and how ai can be used to help analysts by building a live AI-powered security system from scratch. You will start containers, fire real attacks at a vulnerable web app, and watch a Random Forest model score every request in real time. A local language model (Mistral 7B) then writes a plain-English incident brief for each high-risk alert — exactly like a SOC analyst would.

> **Purpose:** Learn by doing. This README walks you through every step manually so you understand what is happening and why.

---

## What you are building

```
[ You, running curl ] ──▶ [ DVWA web app :8080 ]
                                 │
                         Apache access.log
                           │           │
                    [ Promtail ]   [ AI Analyst :8000 ]
                         │              │
                    [ Loki :3100 ]   [ Ollama + Mistral 7B ]
                         │
                   [ Grafana :3000 ]
                   (live dashboards)
```

**7 containers, all running locally on your machine.** No cloud. No API keys.

| Container | What it does |
|---|---|
| `workshop-dvwa` | (Damn Vulnerable Web App) Deliberately vulnerable web app — your attack target |
| `workshop-dvwa-db` | MariaDB database backing DVWA |
| `workshop-ai-analyst` | FastAPI server — runs the Random Forest + writes incident briefs |
| `workshop-ollama` | Local LLM runtime (Mistral 7B) |
| `workshop-loki` | Log storage (receives logs from Promtail) |
| `workshop-promtail` | Log collector (tails Apache logs → Loki) |
| `workshop-grafana` | Live SIEM dashboard |

---

## Prerequisites

- **Docker Desktop** — download at [docker.com/products/docker-desktop](https://www.docker.com/products/docker-desktop)
- After installing: open Docker Desktop → **Settings → Resources** → set **Memory to 8 GB** and **Disk to 25 GB**
- macOS, Windows 10/11, or Linux all work

---

## Step 1 — Get the repo

Open Terminal (macOS/Linux) or PowerShell (Windows) and run:

```bash
git clone https://github.com/mjay-kerberos/ai-threat-workshop
cd ai-threat-workshop
```

---

## Step 2 — Build the container images

This compiles the DVWA wrapper image and the AI Analyst image. You only do this once.

```bash
docker compose build dvwa ai-analyst
```

You should see output like `=> exporting layers` for each image. It takes 1–3 minutes.

---

## Step 3 — Pull the base images

This downloads the pre-built images for MariaDB and Ollama from Docker Hub.

```bash
docker compose pull dvwa-db ollama
```

---

## Step 4 — Start the main stack

```bash
docker compose up -d
```

This starts 4 containers: DVWA, MariaDB, AI Analyst, and Ollama. The `-d` flag runs them in the background.

**Verify they are running:**

```bash
docker compose ps
```

All four should show **Up** (or **healthy**). If one shows **Exit**, check its logs:

```bash
docker compose logs dvwa
docker compose logs ai-analyst
```

---

## Step 5 — Start the Grafana SIEM overlay

Grafana, Loki, and Promtail are in a separate compose file. Start them on top of the main stack:

```bash
docker compose -f docker-compose.yml -f docker-compose.loki.yml up -d
```

Verify with `docker compose ps` again — you should now see 7 containers total, all **Up**.

---

## Step 6 — Pull the Mistral 7B language model

Mistral 7B is the local LLM that writes the incident briefs. This downloads ~4 GB and only needs to happen once — the weights are saved in a Docker volume.

```bash
docker exec workshop-ollama ollama pull mistral:7b-instruct-q4_K_M
```

This takes 5–10 minutes on a typical connection. You will see a progress bar.

> **Why local?** Enterprise security teams cannot send customer log data to external APIs like ChatGPT. Running the LLM locally means no data leaves your machine — a real data sovereignty requirement.

---

## Step 7 — Open the dashboards

| Dashboard | URL | Login |
|---|---|---|
| DVWA (target app) | http://localhost:8080 | `admin` / `password` |
| AI Analyst | http://localhost:8000 | none |
| Grafana — Attack Pipeline | http://localhost:3000 | `admin` / `admin` |
| Ollama API | http://localhost:11434 | none |

**First-time DVWA setup:**
1. Go to http://localhost:8080/setup.php
2. Click **Create / Reset Database**
3. Log in with `admin` / `password`
4. Go to **DVWA Security** and set Security Level to **Low**

---

## Step 8 — Run the attacks

Each script below fires a different class of attack at DVWA. Run them from the `ai-threat-workshop` directory.

Make the scripts executable first (macOS/Linux):
```bash
chmod +x scripts/*.sh
```

### SQL Injection

SQL injection tricks the database into revealing data it should protect. The payload `1' UNION SELECT user,password FROM users-- -` asks the database to dump its entire user table.

```bash
./scripts/attack-sqli.sh
```

What it does step by step:
1. Sends HTTP GET requests to `http://localhost:8080/vulnerabilities/sqli/`
2. URL-encodes each SQL payload and passes it as the `id` parameter
3. Uses a `sqlmap/1.8` user-agent so the AI can fingerprint the tool
4. Fires 4 payloads: `OR 1=1`, `UNION SELECT`, `SLEEP(2)`, and a comment bypass

### Brute Force

Brute force login tries common passwords automatically. No lockout + no CAPTCHA = unlimited attempts.

```bash
./scripts/attack-brute.sh
```

What it does step by step:
1. Sends 60 HTTP GET requests to `http://localhost:8080/vulnerabilities/brute/`
2. Tries passwords from a list: `admin`, `password`, `123456`, `letmein`, etc.
3. Uses a `Hydra/9.5` user-agent — Hydra is a real penetration testing tool
4. Each request has `username=admin&password=<attempt>&Login=Login`

### Cross-Site Scripting (XSS)

XSS injects JavaScript into a web page. When another user visits, their browser runs your code.

```bash
./scripts/attack-xss.sh
```

What it does step by step:
1. Sends GET requests to `http://localhost:8080/vulnerabilities/xss_r/`
2. URL-encodes each JavaScript payload and passes it as the `name` parameter
3. Payloads include: `<script>alert('xss')</script>`, `<img src=x onerror=...>`, SVG onload
4. Uses `python-requests/2.31.0` as user-agent

### OS Command Injection

Command injection passes shell commands through a web form directly to the server's operating system.

```bash
./scripts/attack-cmdi.sh
```

What it does step by step:
1. Sends requests to `http://localhost:8080/vulnerabilities/exec/`
2. DVWA's ping form passes the input directly to `ping` without validation
3. Payloads chain commands with `;`, `&&`, `|`, subshells, backticks
4. Examples: `127.0.0.1; id`, `127.0.0.1 | cat /etc/passwd`, `\`whoami\``

---

## Step 9 — Watch what the AI does

After running the attacks, go to:

- **http://localhost:8000** — AI Analyst: see Risk Scores and click any alert for the Mistral 7B incident brief
- **http://localhost:3000** — Grafana: live attack pipeline, risk score distribution, incident briefs

### How the Random Forest scores each request

The AI model does not read sentences — it reads numbers. Every Apache log line is converted into ~15 features:

| Feature | Example value | What it captures |
|---|---|---|
| `has_union` | 1 or 0 | SQL UNION keyword present |
| `has_select` | 1 or 0 | SQL SELECT keyword |
| `has_script_tag` | 1 or 0 | `<script>` in URL |
| `url_length` | 89 | Longer URLs often carry payloads |
| `has_sleep` | 1 or 0 | Time-based blind SQLi |
| `user_agent_score` | 0–3 | Known attack tool fingerprint |
| `requests_per_min` | 60 | High rate = brute force or scanner |
| `status_code` | 200, 404 | Response code |

The Random Forest runs 100 decision trees, each examining a different combination of features. The **Risk Score** is the percentage of trees that voted "attack" — a score of 92 means 92 out of 100 trees agreed this was an attack.

### What the Mistral 7B brief looks like

When Risk Score > 70, the AI Analyst passes the raw log line to Mistral 7B and asks it to write an incident brief. You will see something like:

```
INCIDENT BRIEF — SQL Injection (High Confidence)
Source: 45.33.32.156  |  Target: /dvwa/vulnerabilities/sqli/  |  Risk: 92/100

A UNION SELECT payload was detected attempting to extract user credentials
from the database. Pattern is consistent with manual exploitation.
Recommendation: block source IP, rotate DB credentials, review WAF rules.
```

---

## Step 10 — Verify everything works

Run the included test script to check that all services are healthy:

```bash
bash scripts/test.sh
```

A passing run looks like:

```
[PASS] DVWA is reachable at http://localhost:8080
[PASS] AI Analyst is reachable at http://localhost:8000
[PASS] Ollama is reachable at http://localhost:11434
[PASS] Loki is reachable at http://localhost:3100
[PASS] Grafana is reachable at http://localhost:3000
[PASS] Mistral model is loaded
[PASS] All 7 containers running
```

---

## Understanding the detection rules

| Rule ID | Severity | Attack type | OWASP | CWE |
|---|---|---|---|---|
| 100100 | 12/15 | SQL Injection | A03:2021 | CWE-89 |
| 100101 | 14/15 | SQL Injection — High Confidence | A03:2021 | CWE-89 |
| 100110 | 10/15 | Brute Force | A07:2021 | CWE-307 |
| 100111 | 14/15 | Brute Force — High Volume (≥50/60s) | A07:2021 | CWE-307 |
| 100120 | 10/15 | Cross-Site Scripting (XSS) | A03:2021 | CWE-79 |
| 100121 | 12/15 | XSS — High Confidence | A03:2021 | CWE-79 |
| 100130 | 13/15 | OS Command Injection | A03:2021 | CWE-78 |
| 100000 | 3/15 | Benign (no pattern matched) | — | — |

Severity scale: 3 = informational, 10 = high, 12 = critical, 14 = max.

---

## Challenge exercises

Once the basics are working, try these:

**1. Evade the AI.** Can you craft a SQL injection payload that scores below 50? Try obfuscating `UNION` as `uNiOn` or `UNION/**/SELECT`. Check what features the model uses in `ai-model/server/features.py`.

**2. Slow attack.** The brute force runs 60 attempts in a few seconds. Modify `attack-brute.sh` to add a 2-second sleep between attempts (`sleep 2` in the loop). Does the AI still catch it? Why?

**3. Read the model.** Open `ai-model/server/ingestor.py`. Find the function that extracts features from a log line. What would you add to make detection better?

**4. Add a new rule.** Find where rules are defined in `ai-model/server/ingestor.py`. Add a rule for path traversal (`../etc/passwd`). What CWE and OWASP category does it belong to?

---

## Shut down

To stop all containers (model weights are preserved):

```bash
docker compose -f docker-compose.yml -f docker-compose.loki.yml down
```

To stop AND delete all data (model will re-download next time):

```bash
docker compose -f docker-compose.yml -f docker-compose.loki.yml down -v
```

---

## Repo layout

```
ai-threat-workshop/
├── docker-compose.yml          # Main 4-service stack
├── docker-compose.loki.yml     # Grafana + Loki + Promtail overlay
├── docker/
│   ├── dvwa/Dockerfile         # DVWA wrapper (enables Apache log files)
│   └── loki/                   # Loki config, Promtail config, Grafana dashboards
├── ai-model/
│   ├── server/                 # FastAPI app, log ingestor, rule engine, dashboard
│   ├── training/               # Dataset generator + Random Forest training script
│   ├── model/                  # Trained rf_classifier.pkl + metadata
│   └── data/                   # Training CSV + sample alert fixtures
└── scripts/
    ├── attack-sqli.sh          # SQL injection attacks
    ├── attack-xss.sh           # XSS attacks
    ├── attack-brute.sh         # Brute force login
    ├── attack-cmdi.sh          # OS command injection
    └── test.sh                 # Verify all services are healthy
```

---

