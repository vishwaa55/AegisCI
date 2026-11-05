# AegisCI — Autonomous CI/CD Failure Diagnosis & Multi-Agent Security Remediation

AegisCI is a human-in-the-loop AI-assisted software repair and security remediation system integrated into CI/CD pipelines.

---

## Architecture Overview

```
                                      ┌─────────────────────────────────┐
                                      │   CI/CD Pipeline (GitHub Actions)│
                                      └────────────────┬────────────────┘
                                                       │
                      ┌────────────────────────────────┴────────────────────────────────┐
                      │                                                                 │
         [Functional Test / Build Failure]                             [Semgrep Security Findings]
                      │                                                                 │
                      ▼                                                                 ▼
         ┌─────────────────────────┐                                       ┌─────────────────────────┐
         │   Build-Monitor Agent   │                                       │     Attacker Agent      │
         │  (Triage Flaky Tests)   │                                       │ (Threat Model & Exploit)│
         └────────────┬────────────┘                                       └────────────┬────────────┘
                      │                                                                 │
                      ▼                                                                 ▼
         ┌─────────────────────────┐                                       ┌─────────────────────────┐
         │     Diagnosis Agent     │                                       │  Defender A & B Debate  │
         │ (Root Cause & Evidence) │                                       │ (Independent Strategies)│
         └────────────┬────────────┘                                       └────────────┬────────────┘
                      │                                                                 │
                      ▼                                                                 ▼
         ┌─────────────────────────┐◄── [ChromaDB Memory] ────────────────►┌─────────────────────────┐
         │   Fix-Proposer Agent    │    (Rejection RAG)                    │       Judge Agent       │
         │  (Unified Diff Patch)   │                                       │ (Patch Eval & Validation│
         └────────────┬────────────┘                                       └────────────┬────────────┘
                      │                                                                 │
                      ▼                                                                 ▼
         ┌─────────────────────────┐                                       ┌─────────────────────────┐
         │ Reviewer & Sandbox Exec │                                       │ Isolated Sandbox & Scan │
         │  (Up to 3 loop attempts)│                                       │   (Max 3 debate rounds) │
         └────────────┬────────────┘                                       └────────────┬────────────┘
                      │                                                                 │
                      ▼                                                                 ▼
         ┌──────────────────────────────────────────────────────────────────────────────┐
         │                        GitHub Pull Request Manager                           │
         │    • Opens Draft PR on dedicated branch (agent-fix/* or security-fix/*)      │
         │    • Never commits or pushes to main directly                                │
         │    • Mandatory human review and approval before merging                      │
         └──────────────────────────────────────────────────────────────────────────────┘
```

---

## Tech Stack

- **Backend Framework**: Python 3.12, FastAPI, Uvicorn, Pydantic v2
- **Agent Orchestration**: LangGraph, LangChain Core
- **Database**: SQLite (SQLAlchemy ORM)
- **Vector Memory**: ChromaDB rejection memory RAG (`all-MiniLM-L6-v2`)
- **Static Analysis**: Semgrep (`--config=auto` / custom rule packs)
- **Sandboxing**: Docker container execution (`python:3.12-slim`) with isolated process directory fallback
- **CI/CD Integration**: GitHub Actions, GitHub CLI (`gh`), PyGithub
- **LLM Providers**: Groq (`qwen/qwen3.8-27b`), OpenAI (`gpt-4o-mini`), Anthropic (`claude-3-5-haiku`)

---

## Getting Started

### 1. Prerequisites
- Python 3.12+
- Git
- (Optional but recommended) Docker Desktop (running)
- (Optional for remote PRs) GitHub CLI (`gh`) or a GitHub Personal Access Token

### 2. Environment Setup

```powershell
# 1. Clone repository
git clone <repo-url>
cd AegisCI

# 2. Create and activate Python virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# 3. Install dependencies
pip install -r backend/requirements.txt
```

### 3. Configure Environment Variables

Copy `.env.example` to `.env` and fill in your keys:

```ini
# LLM Provider Configuration
DEFAULT_LLM_PROVIDER=groq
GROQ_API_KEY=your_groq_api_key_here
GROQ_MODEL=qwen/qwen3.8-27b

# AegisCI Configuration
AEGIS_BACKEND_URL=http://localhost:8000
AEGIS_WEBHOOK_SECRET=your_optional_webhook_secret_here
DATABASE_URL=sqlite:///./aegis.db
CHROMA_PERSIST_DIR=./chroma_data
LOG_LEVEL=INFO

# Optional GitHub Integration (for live PR creation)
GITHUB_TOKEN=your_github_token_here
GITHUB_REPOSITORY=owner/repository_name
```

---

## Phase 3 — CI/CD Integration & Controlled Experimentation

### 1. Unified CI Results Webhook
The backend provides a unified intake endpoint:
- `POST /ci/results`: Securely receives test exit codes, failure logs, and Semgrep findings.
  - Authenticated via `X-Aegis-Secret` header when `AEGIS_WEBHOOK_SECRET` is set.
  - Automatically sanitizes raw logs using `scrub_secrets()` to ensure no tokens or keys are ever logged or sent to LLMs.
  - Enforces idempotency via `run_id` + `commit_sha` to prevent duplicate LLM agent invocations.

### 2. Local CI Artifact Ingestion CLI
When running AegisCI locally behind NAT and GitHub Actions runners cannot reach `localhost:8000`:
1. GitHub Actions automatically uploads `aegis-ci-artifacts.zip` containing `aegis-ci-run.json`, `test-output.log`, and `semgrep-results.json`.
2. Ingest the artifact locally using the CLI:
   ```powershell
   # Ingest from downloaded artifact zip
   python -m backend.ingest_ci_artifact --zip path/to/aegis-ci-artifacts.zip

   # Or ingest directly in-process without running the HTTP server
   python -m backend.ingest_ci_artifact --file aegis-ci-run.json --direct
   ```

### 3. Functional Experiment Harness
Isolated under `experiments/functional_fixtures/` with 4 reproducible failure modes:
```powershell
# Reset all fixture services to clean passing baseline
python -m experiments.functional_fixtures.reset_fixtures --reset --test

# Inject Failure Mode 1: Missing null check (AttributeError)
python -m experiments.functional_fixtures.reset_fixtures --scenario null_check --test

# Inject Failure Mode 2: Inverted logic / discount operator
python -m experiments.functional_fixtures.reset_fixtures --scenario logic_bug --test

# Inject Failure Mode 3: Syntax error
python -m experiments.functional_fixtures.reset_fixtures --scenario syntax_error --test

# Inject Failure Mode 4: Missing unresolvable dependency
python -m experiments.functional_fixtures.reset_fixtures --scenario missing_dep --test
```

### 4. OWASP Juice Shop Security Target
- Start local Juice Shop container (bound strictly to `127.0.0.1:3000`):
  ```powershell
  docker run -d --name aegis-juice-shop -p 127.0.0.1:3000:3000 --rm bkimminich/juice-shop:v17.1.1
  ```
- Stop local Juice Shop container:
  ```powershell
  docker stop aegis-juice-shop
  ```
- Run the Multi-Agent Security Debate against baseline Semgrep findings:
  ```powershell
  python -m experiments.juice_shop.run_security_experiment
  ```

---

## Running the Application

### Start the FastAPI Backend

```powershell
.\venv\Scripts\python.exe -m uvicorn backend.main:app --reload --port 8000
```

Interactive API documentation is available at: `http://localhost:8000/docs`

### Key Endpoints

- `GET /health` — System status and version health check
- `POST /ci/results` — Phase 3 unified CI result webhook (handles both test failures & Semgrep findings)
- `POST /incident` — Receive CI/CD functional failure logs directly
- `POST /security-incident` — Receive Semgrep JSON findings directly
- `GET /incidents` — List all registered incident records and their outcomes
- `GET /incidents/{incident_id}` — Inspect detailed incident log, patch diff, and validation notes
- `POST /known-failures` — Add known flaky test signatures to bypass false alarms

---

## Running Tests

Execute the full automated test suite:

```powershell
# Run all unit, security, memory, sandbox, integration, and fixture tests (46 tests)
$env:PYTHONPATH="."
.\venv\Scripts\python.exe -m pytest backend/tests/ experiments/functional_fixtures/tests/ -v

# Run the live bug evaluation scenarios
.\venv\Scripts\python.exe -m backend.tests.run_bug_evaluations
```

# Run the live bug evaluation scenarios
.\venv\Scripts\python.exe -m backend.tests.run_bug_evaluations
```

---

## Safety and Guardrails

1. **No Direct Pushes to Main**: All remediation proposals are created on isolated branches (`agent-fix/<run-id>` or `security-fix/<run-id>`).
2. **Mandatory Human Review**: Pull requests are created as drafts. Automatic merging or deploying is strictly disallowed.
3. **Guardrail Enforcements**:
   - Patches attempting to modify `.github/workflows/`, `.env`, secrets, or private keys are rejected immediately.
   - Patches modifying files outside diagnosed affected files are rejected.
4. **Execution Boundaries**:
   - Patch validation runs in an isolated workspace with strict timeouts (default 60s).
   - Docker sandboxes operate with network isolation (`network_mode="none"`) and memory limits (`512MB`).
5. **Rejection-Memory RAG**:
   - Failed or rejected patches are embedded and stored in ChromaDB.
   - Subsequent repair attempts query top-$k$ failure entries to prevent repeating known invalid fixes.
6. **Bounded Loops**:
   - Functional repair loop is capped at **3 attempts** before human escalation.
   - Security debate loop is capped at **3 rounds** before human escalation.

