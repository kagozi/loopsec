# 🔒 LoopSec

**Open-Source Closed-Loop AI Security Agent**

> Scan → Attack → Map → Fix → Verify → Repeat

LoopSec is an AI-powered security agent that finds vulnerabilities in your code and deployed applications, generates fixes, and verifies they work — all in one automated pipeline.

## What Makes LoopSec Different

Most security tools do one thing: scan code OR pentest apps OR suggest fixes. LoopSec closes the loop:

```
Code Push → Static Analysis → Deploy to Sandbox →
Pentest Deployed App → Map Vulns to Source Code →
Generate Fix Patches → Re-deploy → Re-verify → ✅
```

## Quick Start

### Prerequisites

- Python 3.12+
- Docker & Docker Compose
- An OpenAI API key (Anthropic support coming)

### Install

```bash
git clone https://github.com/yourorg/loopsec.git
cd loopsec
pip install -e ".[dev]"

# Install security tools
pip install semgrep
# Nuclei: https://github.com/projectdiscovery/nuclei#install
# Gitleaks: https://github.com/gitleaks/gitleaks#install
```

### Configure

```bash
cp .env.example .env
# Edit .env with your API keys
export OPENAI_API_KEY=sk-...
```

### Run Infrastructure

```bash
docker compose up -d  # Starts ZAP, Postgres, Redis, test targets
```

### Scan

```bash
# Full pipeline (SAST + DAST + Fix + Verify)
loopsec scan --repo ./your-app --url http://localhost:3000

# SAST only (no deployed app needed)
loopsec scan --repo ./your-app

# Skip specific agents
loopsec scan --repo ./your-app --url http://localhost:3000 --skip verifier

# Quick static analysis only
loopsec analyze --repo ./your-app

# Use a different model
loopsec scan --repo ./your-app --model gpt-4o-mini
```

### Test Against Juice Shop

```bash
# Start the vulnerable test app
docker compose up -d juice-shop

# Clone its source for SAST
git clone https://github.com/juice-shop/juice-shop.git /tmp/juice-shop

# Run LoopSec
loopsec scan --repo /tmp/juice-shop --url http://localhost:3000
```

## Architecture

```
┌─────────────────────────────────────────────┐
│              ORCHESTRATOR                    │
│        Pipeline state machine               │
└──────┬──────┬──────┬──────┬──────┬──────────┘
       │      │      │      │      │
    Analyze Attack  Map   Fix   Verify
       │      │      │      │      │
    Semgrep  ZAP    LLM   LLM   Re-run
    Gitleaks Nuclei Route  AST   attacks
             LLM   match  Diff
```

### The 5 Agents

| Agent | What It Does | Tools Used |
|-------|-------------|------------|
| **Analyzer** | Static code analysis + secrets detection | Semgrep, Gitleaks |
| **Attacker** | Dynamic pentesting of deployed apps | ZAP, Nuclei, LLM fuzzing |
| **Mapper** | Links runtime vulns → source code lines | Route matching, CWE correlation, LLM |
| **Fixer** | Generates minimal security patches | LLM + AST validation |
| **Verifier** | Confirms fixes by re-attacking | Re-runs Attacker tools |

## Configuration

| Env Variable | Default | Description |
|-------------|---------|-------------|
| `OPENAI_API_KEY` | — | OpenAI API key |
| `LOOPSEC_LLM_PROVIDER` | `openai` | LLM provider via LiteLLM |
| `LOOPSEC_LLM_MODEL` | `gpt-4o` | Model to use |
| `LOOPSEC_SEMGREP_RULES` | `auto` | Semgrep rule config |
| `ZAP_HOST` | `http://localhost:8080` | ZAP proxy URL |
| `LOOPSEC_LOG_LEVEL` | `INFO` | Logging level |

## Roadmap

- [x] Core pipeline (Analyze → Attack → Map → Fix → Verify)
- [x] Semgrep + Gitleaks integration
- [x] ZAP + Nuclei integration
- [x] LLM-powered patch generation
- [ ] GitHub App (auto-trigger on push, open PRs)
- [ ] Web dashboard with real-time progress
- [ ] Docker sandbox manager (auto-deploy target apps)
- [ ] CI/CD marketplace actions
- [ ] Multi-language framework support
- [ ] Persistent vulnerability database

## License

Apache 2.0
