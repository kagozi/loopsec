# LoopSec

**Open-Source Closed-Loop AI Security Agent**

> Scan → Attack → Map → Fix → Verify → Repeat

LoopSec is an AI-powered security agent that finds vulnerabilities in your code and deployed applications, generates fixes, and verifies they work — all in one automated pipeline.

```
Code → Static Analysis → Deploy to Sandbox →
Pentest App → Map Vulns to Source → LLM Patches →
Re-deploy → Re-verify ✅
```

---

## Table of Contents

- [What Makes LoopSec Different](#what-makes-loopsec-different)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Security Tools Setup](#security-tools-setup)
- [Configuration](#configuration)
- [Running the CLI](#running-the-cli)
- [Running the API Server](#running-the-api-server)
- [Docker Compose (Full Stack)](#docker-compose-full-stack)
- [Testing Against the Included Vuln App](#testing-against-the-included-vuln-app)
- [GitHub Integration](#github-integration)
- [Architecture](#architecture)
- [Troubleshooting](#troubleshooting)
- [Roadmap](#roadmap)

---

## What Makes LoopSec Different

Most security tools do one thing: scan code OR pentest apps OR suggest fixes. LoopSec closes the loop — it runs all five stages automatically and verifies that generated patches actually eliminate the vulnerabilities.

---

## Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Python | 3.12+ | `python3 --version` |
| Docker | 24+ | Required for ZAP, sandbox, and test targets |
| Docker Compose | v2+ | `docker compose version` |
| OpenAI API key | — | Or any LiteLLM-compatible provider |

---

## Installation

### 1. Clone and install

```bash
git clone https://github.com/yourorg/loopsec.git
cd loopsec

# Recommended: use a virtual environment
python3 -m venv .venv
source .venv/bin/activate      # Linux / macOS
# .venv\Scripts\activate       # Windows

# Install LoopSec and all Python dependencies
pip install -e ".[dev]"

# Verify the CLI is available
loopsec version
```

---

## Security Tools Setup

LoopSec calls these tools as subprocesses. Install whichever you need for your use case.

### Semgrep — static analysis (required for SAST)

```bash
pip install semgrep

# Verify
semgrep --version
```

### Gitleaks — secrets detection (optional, recommended)

```bash
# macOS
brew install gitleaks

# Linux — download the pre-built binary
GITLEAKS_VERSION=8.21.2
curl -sSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
  | tar -xz gitleaks
sudo mv gitleaks /usr/local/bin/

# Verify
gitleaks version
```

### Nuclei — template-based scanning (optional, for DAST)

```bash
# macOS
brew install nuclei

# Linux
curl -sSL "https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_$(uname -s)_$(uname -m).zip" \
  -o nuclei.zip && unzip nuclei.zip && sudo mv nuclei /usr/local/bin/

# Pull the default template library (do this once)
nuclei -update-templates

# Verify
nuclei --version
```

### OWASP ZAP — active web scanner (optional, for DAST)

ZAP runs as a Docker container — no local install needed:

```bash
docker run -d --name zap \
  -p 8080:8080 \
  ghcr.io/zaproxy/zaproxy:stable \
  zap.sh -daemon \
  -host 0.0.0.0 -port 8080 \
  -config api.addrs.addr.name=.* \
  -config api.addrs.addr.regex=true \
  -config api.disablekey=true

# Wait ~15 seconds for ZAP to start, then verify
curl -s http://localhost:8080/JSON/core/view/version/ | python3 -m json.tool
```

---

## Configuration

### Environment variables

Copy the example file and fill in your values:

```bash
cp .env.example .env
```

```bash
# ── LLM (required) ──────────────────────────────────────
OPENAI_API_KEY=sk-...                       # or ANTHROPIC_API_KEY for Claude

# ── GitHub OAuth (required for API server + UI) ─────────
GITHUB_CLIENT_ID=your-client-id
GITHUB_CLIENT_SECRET=your-client-secret

# ── API server ───────────────────────────────────────────
LOOPSEC_JWT_SECRET=a-long-random-string     # signs session tokens

# ── Optional overrides ───────────────────────────────────
LOOPSEC_LLM_PROVIDER=openai                 # openai | anthropic | any LiteLLM provider
LOOPSEC_LLM_MODEL=gpt-4o
LOOPSEC_LOG_LEVEL=INFO
ZAP_HOST=http://localhost:8080
```

### Setting up GitHub OAuth

The API server uses GitHub as the identity provider — users log in with their GitHub account and LoopSec uses their GitHub token to list and clone their repositories.

1. Go to **GitHub → Settings → Developer settings → OAuth Apps → New OAuth App**
2. Fill in:
   - **Application name:** LoopSec (or anything)
   - **Homepage URL:** `http://localhost:8000`
   - **Authorization callback URL:** `http://localhost:8000/auth/github/callback`
3. Click **Register application**, then copy the **Client ID** and generate a **Client Secret**
4. Add both to your `.env`:

```bash
GITHUB_CLIENT_ID=Iv1.abc123...
GITHUB_CLIENT_SECRET=abc123...
```

5. Generate a secure JWT secret:

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
# → paste the output into LOOPSEC_JWT_SECRET
```

### Using Anthropic / Claude instead of OpenAI

```bash
export LOOPSEC_LLM_PROVIDER="anthropic"
export LOOPSEC_LLM_MODEL="claude-sonnet-4-6"
export ANTHROPIC_API_KEY="sk-ant-..."
```

LiteLLM handles the provider switch transparently — all other commands stay the same.

---

## Running the CLI

### Quick static analysis (no app needed)

```bash
loopsec analyze --repo ./your-app
```

### Full pipeline — SAST + LLM fixes (no running app needed)

```bash
loopsec scan --repo ./your-app --skip attacker verifier
```

### Full pipeline — SAST + DAST + fixes + verification

```bash
# Requires: ZAP running, app deployed at --url
loopsec scan --repo ./your-app --url http://localhost:8080
```

### Common options

```bash
loopsec scan --repo ./your-app \
  --url http://localhost:8080 \       # target app URL (enables DAST)
  --branch main \                    # git branch (default: main)
  --skip attacker verifier \         # skip specific agents
  --model gpt-4o-mini \              # override LLM model
  --output my-report.md \            # custom report path (default: loopsec-report-<id>.md)
  --no-deploy \                      # disable Docker auto-deploy
  --verbose                          # show debug logs
```

### All CLI commands

| Command | Description |
|---------|-------------|
| `loopsec analyze --repo ./path` | SAST + secrets scan only |
| `loopsec scan --repo ./path` | Full pipeline, SAST-only mode |
| `loopsec scan --repo ./path --url http://...` | Full pipeline with DAST |
| `loopsec scan --repo ./path --skip attacker verifier` | SAST + fix, skip DAST |
| `loopsec api --port 8000` | Start the REST API server |
| `loopsec webhook --port 9000 --github-token <tok>` | Start the GitHub webhook server |
| `loopsec github-scan owner/repo` | Clone from GitHub and scan |
| `loopsec github-scan owner/repo --create-pr` | Scan and open a fix PR |
| `loopsec version` | Print version |

---

## Running the API Server

The API server exposes all pipeline functionality over HTTP with SSE streaming for real-time progress. It uses a local SQLite database (`~/.loopsec/loopsec.db`) to persist scan history.

### Start the server

```bash
loopsec api --port 8000

# Development mode with auto-reload
loopsec api --port 8000 --host 0.0.0.0 --reload
```

Interactive API docs are available at `http://localhost:8000/docs`.

### API endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/scans` | Trigger a new scan (returns immediately) |
| `GET` | `/scans` | List all scans with pagination |
| `GET` | `/scans/{id}` | Get full scan details and summary |
| `DELETE` | `/scans/{id}` | Delete a scan and all its data |
| `GET` | `/scans/{id}/stream` | SSE stream — live progress while running, replay when done |
| `GET` | `/scans/{id}/findings` | List findings (filter by `severity`, `source`) |
| `GET` | `/findings/{id}` | Get a single finding |
| `GET` | `/scans/{id}/patches` | List patches (filter by `status`) |
| `GET` | `/patches/{id}` | Get a patch including full diff |
| `GET` | `/scans/{id}/exploits` | List generated exploits |
| `GET` | `/scans/{id}/report` | Download markdown report |
| `GET` | `/health` | Health check |

### Authentication flow

Every API endpoint (except `/health`) requires a `Bearer` token. Here's the full login flow:

```
1. Direct user to: GET /auth/github/login?redirect_uri=http://localhost:3000/callback
2. User authorizes on GitHub
3. GitHub redirects to /auth/github/callback — we issue a JWT
4. We redirect to: http://localhost:3000/callback?token=<jwt>
5. Frontend stores the JWT and sends it as: Authorization: Bearer <jwt>
```

Test it manually:
```bash
# Open this URL in a browser to start login
open "http://localhost:8000/auth/github/login?redirect_uri=http://localhost:3000/callback"

# After login, extract the token from the redirect URL and use it:
TOKEN="eyJ..."

# Get your profile
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/auth/me
```

### Browse GitHub repositories

```bash
# List your repos (paginated, sorted by last push)
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/github/repos?per_page=30&sort=pushed"

# Get a specific repo
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/github/repos/myorg/myapp

# List branches
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/github/repos/myorg/myapp/branches
```

### Trigger a scan via the API

```bash
# Scan a GitHub repo (cloned automatically using your GitHub token)
curl -X POST http://localhost:8000/scans \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "github_repo": "myorg/myapp",
    "branch": "main",
    "skip_agents": ["attacker", "verifier"]
  }'

# Or scan a local path
curl -X POST http://localhost:8000/scans \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "repo_path": "/absolute/path/to/your-app",
    "branch": "main",
    "skip_agents": ["attacker", "verifier"]
  }'

# Response:
# {
#   "scan_id": "a1b2c3d4e5f6",
#   "status": "queued",
#   "stream_url": "/scans/a1b2c3d4e5f6/stream"
# }
```

### Stream progress in real time

```bash
# In a second terminal — events arrive as the pipeline runs
curl -N -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/scans/a1b2c3d4e5f6/stream
```

Events look like:

```
event: progress
data: {"type": "status_change", "status": "analyzing"}

event: progress
data: {"type": "finding_added", "finding": {"id": "...", "severity": "high", "title": "SQL Injection", ...}}

event: progress
data: {"type": "patch_added", "patch": {"id": "...", "file_path": "app.py", "status": "verified"}}

event: progress
data: {"type": "complete", "summary": {"total_findings": 7, "verified_fixes": 3, ...}}
```

If you connect after the scan has finished, the server replays all events from the database and then closes the stream.

### Full pipeline scan via API (with DAST)

```bash
curl -X POST http://localhost:8000/scans \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "github_repo": "myorg/myapp",
    "app_url": "http://localhost:5001",
    "branch": "main"
  }'
```

### List scan history

```bash
curl -H "Authorization: Bearer $TOKEN" "http://localhost:8000/scans?limit=10"
```

### Get findings for a scan

```bash
H="Authorization: Bearer $TOKEN"

# All findings
curl -H "$H" http://localhost:8000/scans/a1b2c3d4e5f6/findings

# Only high severity
curl -H "$H" "http://localhost:8000/scans/a1b2c3d4e5f6/findings?severity=high"

# Only SAST findings
curl -H "$H" "http://localhost:8000/scans/a1b2c3d4e5f6/findings?source=sast"
```

### Download a report

```bash
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/scans/a1b2c3d4e5f6/report > report.md
```

---

## Docker Compose (Full Stack)

The included `docker-compose.yml` starts everything you need for full DAST testing:

| Service | Port | Description |
|---------|------|-------------|
| `zap` | 8080 | OWASP ZAP (active web scanner) |
| `redis` | 6379 | Cache / queue |
| `postgres` | 5432 | Database |
| `vuln-app` | 5003 | Included vulnerable Flask app |
| `juice-shop` | 3000 | OWASP Juice Shop (intentionally vulnerable) |
| `dvwa` | 8081 | DVWA (intentionally vulnerable) |

```bash
# Start everything
docker compose up -d

# Check all services are healthy
docker compose ps

# Tail logs
docker compose logs -f zap

# Stop and remove
docker compose down
```

### Scan Juice Shop end-to-end

```bash
# Clone Juice Shop source (for SAST)
git clone https://github.com/juice-shop/juice-shop.git /tmp/juice-shop

# Run the full pipeline against it
loopsec scan --repo /tmp/juice-shop --url http://localhost:3000
```

---

## Testing Against the Included Vuln App

`test-targets/vuln-app/` is a Flask app with 8 intentional vulnerabilities — good for verifying that LoopSec is working correctly.

**Vulnerabilities included:**
- SQL Injection (3 instances, CWE-89)
- Command Injection (2 instances, CWE-78)
- Hardcoded Secrets (CWE-798)
- Path Traversal (CWE-22)
- Insecure Deserialization via `pickle` (CWE-502)
- Cross-Site Scripting (CWE-79)
- Missing Authorization / IDOR
- Information Exposure (CWE-200)

### Option A: Run the app directly

```bash
pip install flask
cd test-targets/vuln-app
python app.py
# Listening on http://localhost:5001
```

### Option B: Run via Docker Compose

```bash
docker compose up -d vuln-app
# Listening on http://localhost:5003
```

### Test Case 1 — Static analysis only

```bash
loopsec analyze --repo ./test-targets/vuln-app
```

Expected: Semgrep finds SQLi, command injection, `pickle.loads`, `shell=True`. Gitleaks finds hardcoded credentials.

### Test Case 2 — SAST + LLM fixes (no running app)

```bash
loopsec scan \
  --repo ./test-targets/vuln-app \
  --skip attacker verifier
```

Expected: Analyzer finds vulnerabilities, Fixer generates patches, report saved to `loopsec-report-<id>.md`.

### Test Case 3 — Full pipeline with DAST

```bash
# Start the app and ZAP first
docker compose up -d vuln-app zap

# Wait for ZAP to be ready (~15 seconds)
curl -s http://localhost:8080/JSON/core/view/version/

# Run the complete pipeline
loopsec scan \
  --repo ./test-targets/vuln-app \
  --url http://localhost:5003
```

Expected: All five agents run. ZAP discovers runtime vulnerabilities. Mapper links them to source lines. Fixer patches them. Verifier re-scans.

### Test Case 4 — Full pipeline via API server

```bash
# Terminal 1: start the API server (ensure GITHUB_CLIENT_ID/SECRET + LOOPSEC_JWT_SECRET are set)
loopsec api --port 8000

# Terminal 2: login via browser, then grab the token from the redirect URL
open "http://localhost:8000/auth/github/login?redirect_uri=http://localhost:3000/callback"
# Copy the token= value from the redirect URL
TOKEN="eyJ..."

# Trigger a scan from a GitHub repo
SCAN=$(curl -s -X POST http://localhost:8000/scans \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "github_repo": "myorg/myapp",
    "branch": "main",
    "skip_agents": ["attacker", "verifier"]
  }' | python3 -c "import sys,json; print(json.load(sys.stdin)['scan_id'])")

echo "Scan ID: $SCAN"

# Terminal 3: watch live progress
curl -N -H "Authorization: Bearer $TOKEN" "http://localhost:8000/scans/$SCAN/stream"

# After it finishes, inspect results
curl -H "Authorization: Bearer $TOKEN" "http://localhost:8000/scans/$SCAN" | python3 -m json.tool
curl -H "Authorization: Bearer $TOKEN" "http://localhost:8000/scans/$SCAN/findings" | python3 -m json.tool
curl -H "Authorization: Bearer $TOKEN" "http://localhost:8000/scans/$SCAN/patches" | python3 -m json.tool
```

### Checking the report

```bash
# List generated reports
ls loopsec-report-*.md

# Read the report
cat loopsec-report-*.md

# Extract patch diffs from the JSON
python3 -c "
import json, glob
for f in glob.glob('loopsec-report-*.json'):
    data = json.load(open(f))
    for p in data.get('patches', []):
        print(f'=== {p[\"file_path\"]} ({p[\"status\"]}) ===')
        print(p['diff'])
        print()
"
```

---

## GitHub Integration

### Webhook server

Listens for GitHub push/PR events and automatically triggers scans:

```bash
loopsec webhook \
  --port 9000 \
  --github-token ghp_... \
  --webhook-secret your-secret \
  --app-url http://your-staging-app.example.com
```

Configure GitHub: **Repo → Settings → Webhooks → Add webhook**
- Payload URL: `http://your-server:9000/webhook`
- Content type: `application/json`
- Secret: same as `--webhook-secret`
- Events: `push`, `pull_request`

### Scan a GitHub repo directly

```bash
# Scan the default branch
loopsec github-scan owner/repo --github-token ghp_...

# Scan a specific PR
loopsec github-scan owner/repo --pr 42 --github-token ghp_...

# Scan and open a fix PR automatically
loopsec github-scan owner/repo --create-pr --github-token ghp_...
```

---

## Architecture

```
┌─────────────────────────────────────────────────┐
│                 ORCHESTRATOR                     │
│            Sequential state machine              │
└────┬──────┬──────┬──────┬──────┬────────────────┘
     │      │      │      │      │
  Analyze Attack  Map    Fix  Verify
     │      │      │      │      │
  Semgrep  ZAP    LLM    LLM  Re-run
  Gitleaks Nuclei Route  AST  attacks
           LLM   match   Diff
```

### The five agents

| Agent | What it does | Tools |
|-------|-------------|-------|
| **Analyzer** | SAST + secrets detection | Semgrep, Gitleaks |
| **Attacker** | Active pentesting of deployed app | ZAP, Nuclei, LLM-generated payloads |
| **Mapper** | Maps DAST findings → source code lines | Route matching, CWE correlation, LLM |
| **Fixer** | Generates minimal code patches | LLM + Semgrep re-validation |
| **Verifier** | Confirms patches eliminate the vuln | Re-runs Semgrep + Nuclei |

### API server

```
Browser / curl
     │
     ▼
FastAPI (loopsec/api/main.py)
     │
     ├── POST /scans ──► BackgroundTask ──► asyncio.to_thread(Orchestrator.run())
     │                                              │
     │                                              ▼
     │                                       SQLite (~/.loopsec/loopsec.db)
     │
     └── GET /scans/{id}/stream ──► SSE fan-out event bus (in-memory queues)
```

---

## Configuration Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENAI_API_KEY` | — | OpenAI API key |
| `ANTHROPIC_API_KEY` | — | Anthropic API key (if using Claude) |
| `LOOPSEC_LLM_PROVIDER` | `openai` | LiteLLM provider name |
| `LOOPSEC_LLM_MODEL` | `gpt-4o` | Model to use |
| `GITHUB_CLIENT_ID` | — | GitHub OAuth App client ID |
| `GITHUB_CLIENT_SECRET` | — | GitHub OAuth App client secret |
| `LOOPSEC_JWT_SECRET` | — | Secret for signing session JWTs (generate with `secrets.token_hex(32)`) |
| `LOOPSEC_JWT_EXPIRY_DAYS` | `30` | JWT token lifetime in days |
| `LOOPSEC_SEMGREP_RULES` | `auto` | `auto`, `p/security-audit`, or path to rules |
| `ZAP_HOST` | `http://localhost:8080` | ZAP daemon URL |
| `LOOPSEC_LOG_LEVEL` | `INFO` | `DEBUG` / `INFO` / `WARNING` / `ERROR` |

---

## Troubleshooting

**`loopsec: command not found`**
```bash
# Make sure the venv is activated and the package installed
source .venv/bin/activate
pip install -e ".[dev]"
```

**`semgrep: command not found`**
```bash
pip install semgrep
```

**`ZAP is not running` or connection refused on port 8080**
```bash
# Check the container
docker ps | grep zap
docker logs zap

# Restart if needed
docker restart zap

# Or start fresh
docker compose up -d zap
```

**LLM timeout or API error**
```bash
# Verify the key is set
echo $OPENAI_API_KEY

# Test it directly
curl https://api.openai.com/v1/models -H "Authorization: Bearer $OPENAI_API_KEY"

# Switch to a faster/cheaper model
loopsec scan --repo ./test-targets/vuln-app --model gpt-4o-mini --skip attacker verifier
```

**No findings detected**
```bash
# Run Semgrep directly to confirm it works
semgrep scan --config auto ./test-targets/vuln-app/

# Confirm the file exists
ls -la ./test-targets/vuln-app/app.py
```

**API server returns 400 on `POST /scans`**

`repo_path` must be an absolute path to a directory that exists on the machine running the API server.

```bash
# Use absolute path
curl -X POST http://localhost:8000/scans \
  -H "Content-Type: application/json" \
  -d '{"repo_path": "/absolute/path/to/repo"}'
```

**Port 8000 already in use**
```bash
loopsec api --port 8001
```

---

## Roadmap

- [x] Core pipeline (Analyze → Attack → Map → Fix → Verify)
- [x] Semgrep + Gitleaks integration
- [x] ZAP + Nuclei integration
- [x] LLM-powered patch generation (LiteLLM, multi-provider)
- [x] Docker sandbox auto-deploy
- [x] GitHub integration (webhooks, PR creation, commit status)
- [x] REST API server with SSE streaming
- [x] Persistent scan history (SQLite)
- [x] GitHub OAuth login
- [x] User-scoped scan history
- [x] GitHub repository browser (list, branches, languages)
- [x] Scan from GitHub repo (auto-clone)
- [ ] Web dashboard (separate repo: `loopsec-ui`)
- [ ] PyPI release (`pip install loopsec`)
- [ ] GitHub App (install on org, auto-trigger on push)
- [ ] Expanded test coverage

---

## License

Apache 2.0
