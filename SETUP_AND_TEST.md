# LoopSec — Setup, Run & Test Guide

## Step 0: Prerequisites

Make sure you have these installed:

```bash
# Check Python (need 3.12+)
python3 --version

# Check Docker
docker --version
docker compose version

# Check pip
pip --version
```

---

## Step 1: Install LoopSec

```bash
# Unzip if you haven't already
unzip loopsec.zip
cd loopsec

# Create a virtual environment (recommended)
python3 -m venv .venv
source .venv/bin/activate   # Linux/Mac
# .venv\Scripts\activate    # Windows

# Install LoopSec
pip install -e ".[dev]"
```

---

## Step 2: Install Security Tools

### Semgrep (SAST scanner — required)
```bash
pip install semgrep

# Verify
semgrep --version
```

### Gitleaks (secrets scanner — optional but recommended)
```bash
# macOS
brew install gitleaks

# Linux (download binary)
wget https://github.com/gitleaks/gitleaks/releases/download/v8.21.2/gitleaks_8.21.2_linux_x64.tar.gz
tar -xzf gitleaks_8.21.2_linux_x64.tar.gz
sudo mv gitleaks /usr/local/bin/

# Verify
gitleaks version
```

### Nuclei (template scanner — optional, for DAST)
```bash
# macOS
brew install nuclei

# Linux
curl -sL https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_$(uname -s)_$(uname -m).zip -o nuclei.zip
unzip nuclei.zip
sudo mv nuclei /usr/local/bin/

# Pull default templates
nuclei -update-templates

# Verify
nuclei --version
```

---

## Step 3: Configure Environment

```bash
# Copy the example env file
cp .env.example .env

# Edit with your OpenAI API key
# Option A: Edit the file
nano .env

# Option B: Or just export directly
export OPENAI_API_KEY="sk-your-key-here"
```

---

## Step 4: Start the Vulnerable Test App

We've included a simple Flask app with 8 intentional vulnerabilities.

```bash
# Install Flask for the test app
pip install flask

# Start the vulnerable app
cd test-targets/vuln-app
python app.py &
cd ../..

# Verify it's running
curl http://localhost:5001/
# Should show the VulnApp homepage
```

---

## Step 5: Run LoopSec — Test Cases

### Test Case 1: SAST Only (No deployed app needed)

This is the simplest test — just static analysis on the source code.

```bash
loopsec analyze --repo ./test-targets/vuln-app
```

**Expected output:**
- Semgrep findings for SQL injection, command injection, hardcoded secrets
- Gitleaks findings for the API key and database password
- A severity summary table

You should see findings like:
- HIGH: `subprocess` with `shell=True`
- HIGH: Formatted SQL queries
- HIGH: `pickle.loads` on user input
- HIGH: Hardcoded credentials

---

### Test Case 2: Full Pipeline — SAST Only (skip DAST agents)

Run the full pipeline but skip the network-dependent agents:

```bash
loopsec scan \
  --repo ./test-targets/vuln-app \
  --skip attacker verifier
```

**Expected output:**
- Analyzer finds vulnerabilities
- Mapper is skipped (no DAST findings to map)
- Fixer generates LLM-powered patches for each finding
- Outputs a markdown report + JSON file

**Check the report:**
```bash
ls loopsec-report-*.md
cat loopsec-report-*.md
```

---

### Test Case 3: Full Pipeline with DAST (requires ZAP)

Start ZAP first, then run the complete pipeline:

```bash
# Start ZAP via Docker
docker run -d --name zap \
  -p 8080:8080 \
  ghcr.io/zaproxy/zaproxy:stable \
  zap.sh -daemon \
  -host 0.0.0.0 -port 8080 \
  -config api.addrs.addr.name=.* \
  -config api.addrs.addr.regex=true \
  -config api.disablekey=true

# Wait for ZAP to start (~10 seconds)
sleep 10

# Verify ZAP is running
curl http://localhost:8080/JSON/core/view/version/

# Make sure the vuln app is running
curl http://localhost:5001/

# Run the FULL pipeline
loopsec scan \
  --repo ./test-targets/vuln-app \
  --url http://localhost:5001
```

**Expected output:**
- Analyzer: SAST findings (SQLi, CMDi, secrets, etc.)
- Attacker: DAST findings from ZAP active scan + LLM-suggested attacks
- Mapper: Links DAST findings back to source code lines
- Fixer: Generates patches for all mapped vulnerabilities
- Verifier: Re-scans to check if patches would fix the issues

---

### Test Case 4: Using a Different Model

```bash
# Use GPT-4o-mini (cheaper, faster)
loopsec scan \
  --repo ./test-targets/vuln-app \
  --skip attacker verifier \
  --model gpt-4o-mini

# Use GPT-4o (better reasoning for complex fixes)
loopsec scan \
  --repo ./test-targets/vuln-app \
  --skip attacker verifier \
  --model gpt-4o
```

---

### Test Case 5: Verbose Mode (Debug)

```bash
loopsec scan \
  --repo ./test-targets/vuln-app \
  --skip attacker verifier \
  --verbose
```

This shows detailed logs: LLM prompts/responses, tool command output, timing.

---

## Step 6: Verify the Results

### Check the Report
```bash
# List generated reports
ls -la loopsec-report-*

# View the markdown report
cat loopsec-report-*.md

# View raw JSON (machine-readable)
cat loopsec-report-*.json | python -m json.tool | head -50
```

### Check Generated Patches
The patches are in the JSON report under the `patches` array. Each patch has:
- `file_path`: Which file was patched
- `diff`: A unified diff showing the exact change
- `explanation`: Why the fix works
- `status`: `verified`, `pending`, or `failed`

```bash
# Extract just the diffs from the JSON report
python3 -c "
import json, glob

for f in glob.glob('loopsec-report-*.json'):
    data = json.load(open(f))
    for p in data.get('patches', []):
        print(f'=== {p[\"file_path\"]} ({p[\"status\"]}) ===')
        print(p['diff'])
        print(f'Explanation: {p[\"explanation\"]}')
        print()
"
```

---

## Step 7: Docker Compose (All-in-One)

For the full setup with ZAP + test targets:

```bash
# Start everything
docker compose up -d

# This starts:
#   - ZAP on port 8080
#   - Redis on port 6379
#   - Postgres on port 5432
#   - OWASP Juice Shop on port 3000
#   - DVWA on port 8081

# Scan Juice Shop (clone source first)
git clone https://github.com/juice-shop/juice-shop.git /tmp/juice-shop
loopsec scan --repo /tmp/juice-shop --url http://localhost:3000

# When done, stop everything
docker compose down
```

---

## Troubleshooting

### "Semgrep not found"
```bash
pip install semgrep
# Or on some systems:
pip3 install semgrep
```

### "ZAP is not running"
```bash
# Check if ZAP container is up
docker ps | grep zap

# Check ZAP logs
docker logs zap

# Restart ZAP
docker restart zap
```

### "LLM API error" / timeout
```bash
# Verify your API key is set
echo $OPENAI_API_KEY

# Test the key directly
curl https://api.openai.com/v1/models \
  -H "Authorization: Bearer $OPENAI_API_KEY"

# Use a cheaper/faster model if hitting rate limits
loopsec scan --repo ./test-targets/vuln-app --model gpt-4o-mini --skip attacker verifier
```

### "No findings detected"
```bash
# Run Semgrep directly to verify it works
semgrep scan --config auto ./test-targets/vuln-app/

# Check that the test app has actual code
ls -la ./test-targets/vuln-app/app.py
```

### Want to switch to Claude later?
```bash
export LOOPSEC_LLM_PROVIDER=anthropic
export LOOPSEC_LLM_MODEL=claude-sonnet-4-20250514
export ANTHROPIC_API_KEY=sk-ant-your-key
# Re-run any scan command — LiteLLM handles the provider switch
```

---

## Quick Reference

| Command | What It Does |
|---------|-------------|
| `loopsec analyze --repo ./path` | SAST scan only |
| `loopsec scan --repo ./path` | Full pipeline (SAST + fix) |
| `loopsec scan --repo ./path --url http://...` | Full pipeline with DAST |
| `loopsec scan --repo ./path --skip attacker verifier` | SAST + fix (no DAST) |
| `loopsec scan --repo ./path --model gpt-4o-mini` | Use a specific model |
| `loopsec scan --repo ./path -v` | Verbose / debug mode |
| `loopsec version` | Check version |
