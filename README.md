# AHVF — Autonomous Hybrid VAPT Framework

An autonomous security testing framework that crawls authenticated web applications, condenses endpoint schemas, and uses a local LLM (Ollama) to generate targeted attack payloads — all without sending any data off your machine.

> **⚠️ Authorized use only.** A signed Rules of Engagement (RoE) document must be on file before running against any target environment.

---

## Architecture

```
                        ┌─────────────────────────────────────────────────────────┐
                        │              AHVF Pipeline (v2.0)                       │
                        │                                                         │
  M1: Stateful Crawler  →  JS Scanner  →  M2: Schema Condenser                  │
       (Crawler.py)      (js_scanner.py)   (schema_condenser.py)                 │
            │                                      │                              │
            └────────── SQLite State DB ───────────┤                              │
                        (database.py)               │                              │
                                                    ▼                              │
  M3: Payload Orchestrator  →  Passive Analyzer  →  BAC Comparator               │
    (payload_orchestrator.py)  (passive_analyzer.py)  (bac_comparator.py)         │
            │                                                                      │
            └──────────────── Ollama (local LLM) ─────────────────────────────────│
                              (ollama_client.py)                                   │
                                        │                                          │
                                        ▼                                          │
            M4: Async Executor  →  M5: Triage & Reporting                         │
             (async_executor.py)    (triage_engine.py)                             │
                                         │                                         │
                                    HTML/JSON Report                               │
                                  (report_template.html)                           │
                        └─────────────────────────────────────────────────────────┘
```

**Pipeline runner:** `run_pipeline.py` orchestrates all modules.

**Modular login:** `login_agent.py` provides strategy-based authentication (heuristic → LLM → manual fallback) used by the crawler, BAC comparator, and async executor.

---

## Prerequisites

| Requirement | Version | Purpose |
|---|---|---|
| Python | 3.10+ | Runtime |
| Playwright | Latest | Headless browser for crawling |
| Ollama | Latest | Local LLM inference server |
| LLM Model | `goekdenizguelmez/JOSIEFIED-Qwen3:8b` (or any Ollama-compatible model) | Payload generation & triage |

---

## Setup Instructions

### 1. Clone & create virtual environment

```bash
git clone <repo-url>
cd Autonomous_security_tool

python -m venv .venv

# Windows
.venv\Scripts\activate

# Linux / macOS
source .venv/bin/activate
```

### 2. Install Python dependencies

```bash
pip install -r requirements.txt
```

This installs:
- `playwright` + `playwright-stealth` — headless browser for SPA crawling
- `requests` — HTTP client for Ollama REST API
- `aiosqlite` — async SQLite (used by future modules)
- `aiohttp` — async HTTP client for fuzzing, passive analysis, JS scanning
- `jinja2` — HTML report template rendering
- `PyJWT` — JWT token decoding and TTL monitoring
- `Flask` & `Flask-Cors` — Web UI backend and CORS support

### 3. Install Playwright browser

```bash
playwright install chromium
```

### 4. Install and start Ollama

Download from [ollama.com](https://ollama.com/) and install for your OS.

Start the Ollama server:
```bash
ollama serve
```

Pull the default model:
```bash
ollama pull goekdenizguelmez/JOSIEFIED-Qwen3:8b
```

> **Note:** You can use a different model by setting the `OLLAMA_MODEL` environment variable before running the pipeline.

---

## Configuration

### Ollama Settings (environment variables)

| Variable | Default | Description |
|---|---|---|
| `OLLAMA_HOST` | `http://localhost:11434` | Ollama API base URL |
| `OLLAMA_MODEL` | `goekdenizguelmez/JOSIEFIED-Qwen3:8b` | Model to use for payload generation |
| `OLLAMA_API_KEY` | `""` | Optional Bearer token for cloud setups |
| `OLLAMA_TIMEOUT` | `300` | Timeout per LLM request (seconds) |

Example (Windows PowerShell):
```powershell
$env:OLLAMA_MODEL = "goekdenizguelmez/JOSIEFIED-Qwen3:8b"
$env:OLLAMA_HOST = "http://localhost:11434"
$env:OLLAMA_API_KEY = "your-token-here"
```

Example (Linux / macOS):
```bash
export OLLAMA_MODEL="goekdenizguelmez/JOSIEFIED-Qwen3:8b"
export OLLAMA_HOST="http://localhost:11434"
export OLLAMA_API_KEY="your-token-here"
```

### Crawler Settings (interactive prompts at runtime)

When you run the crawler, it will interactively ask for:
- **Target Base URL** — the starting URL of the application (e.g., `http://example.com/`)
- **Login URL** — where the login form lives (defaults to the base URL)
- **Username Selector** — CSS selector for the username field (defaults to `input[name='username']`)
- **Password Selector** — CSS selector for the password field (defaults to `input[name='password']`)
- **Submit Selector** — CSS selector for the submit button (defaults to `button[type='submit']`)
- **Roles & Credentials** — one or more user roles with username/password pairs

The crawler also has dynamic login field detection (with LLM fallback), so the default selectors work for most applications.

### Crawler Hardcoded Defaults (in `Crawler.py`)

These can be adjusted in the source if needed:
- `EXCLUDED_PATHS` — paths the crawler will never follow (e.g., `/logout`, `/signout`, `/static/`)
- `MAX_PAGES_PER_ROLE` — max pages to visit per role (default: 500)
- `CRAWL_DEPTH` — max BFS link-follow depth (default: 10)

---

## How to Run

### Option A: Full Pipeline

```bash
python run_pipeline.py
```

This runs all modules in sequence:

```
crawl → js_scan → condense → generate → passive → bac → execute → triage
```

1. **M1 Crawler** — crawls the target, captures endpoints, collects JS files
2. **JS Scanner** — scans JavaScript for hardcoded secrets and logic flaws
3. **M2 Schema Condenser** — sanitises and deduplicates endpoint data
4. **M3 Payload Orchestrator** — sends schemas to Ollama, generates attack payloads
5. **Passive Analyzer** — checks security headers, CORS, cookies, info disclosure
6. **BAC Comparator** — cross-role endpoint replay, IDOR probes, verb tampering, path bypass (requires 2+ roles)
7. **M4 Async Executor** — fires payloads asynchronously against target
8. **M5 Triage & Reporting** — evaluates anomalous responses with heuristic pre-classification + LLM triage

### Option B: Skip Crawl (reuse existing crawl data)

If you've already crawled a target and want to re-generate payloads:

```bash
python run_pipeline.py --skip-crawl
```

### Option C: Run Individual Phases

```bash
# Crawl only
python run_pipeline.py --phase crawl

# JS secret/logic flaw scan (keyword-based)
python run_pipeline.py --phase js_scan

# JS scan with LLM deep analysis (slower, finds logic flaws)
python run_pipeline.py --phase js_scan --deep-scan

# Schema condensation only (requires crawl data in results/)
python run_pipeline.py --phase condense

# Payload generation only (requires condensed schemas)
python run_pipeline.py --phase generate

# Passive security analysis (headers, CORS, cookies)
python run_pipeline.py --phase passive

# BAC/IDOR cross-role comparison (requires 2+ crawled roles)
python run_pipeline.py --phase bac

# Fuzzing Execution only (requires generated payloads)
python run_pipeline.py --phase execute

# Triage & Reporting only (requires anomalies in DB)
python run_pipeline.py --phase triage
```

### Option D: Run Modules Standalone

Each module can be run independently for testing:

```bash
# Test database initialisation
python database.py

# Test Ollama connectivity + generation
python ollama_client.py

# Test schema condensation (reads from results/crawl_results.json)
python schema_condenser.py

# Test payload generation (reads condensed schemas + calls Ollama)
python payload_orchestrator.py

# Test async fuzzing executor directly
python async_executor.py

# Test triage and report generation directly
python triage_engine.py

# Run crawler directly (without the pipeline wrapper)
python Crawler.py
```

### Option E: Web UI

The framework includes a Web UI built with Flask that allows you to trigger scans and view real-time logs and results.

```bash
# Start the Web UI server
python ui/app.py
```
Open your browser and navigate to `http://localhost:5000`.

---

## Modules

### Core Pipeline

| Module | File | Description |
|---|---|---|
| M1: Stateful Crawler | `Crawler.py` | Playwright-based headless crawler with SPA support, multi-role authentication, DOM mutation observer, GraphQL introspection, API version detection |
| M2: Schema Condenser | `schema_condenser.py` | Strips PII, deduplicates endpoints by structural fingerprint, attaches security context hints |
| M3: Payload Orchestrator | `payload_orchestrator.py` | Batches schemas to Ollama for targeted payload generation (XSS, SQLi, SSTI, IDOR, SSRF, path traversal, polyglot) |
| M4: Async Executor | `async_executor.py` | High-speed async fuzzing (aiohttp), adaptive rate limiting, JWT expiry handling, baseline delta comparison |
| M5: Triage Engine | `triage_engine.py` | Heuristic pre-classification + LLM triage, CVSS scoring, CWE mapping, remediation, HTML report generation |

### New Analysis Modules

| Module | File | Description |
|---|---|---|
| JS Scanner | `js_scanner.py` | Two-tier JS analysis: fast regex keyword scan (~30 patterns) + optional LLM deep scan for logic flaws |
| Passive Analyzer | `passive_analyzer.py` | Security header audit, CORS misconfiguration, cookie security, information disclosure detection |
| BAC Comparator | `bac_comparator.py` | Cross-role endpoint replay (FR-03.1/2), IDOR probes (FR-03.3), HTTP verb tampering (FR-03.4), path normalization bypass (FR-03.5) |

### Infrastructure

| Module | File | Description |
|---|---|---|
| Login Agent | `login_agent.py` | Modular authentication with strategy chain: heuristic field detection → LLM-backed selector extraction → manual fallback. Designed for future agentic browser expansion |
| Ollama Client | `ollama_client.py` | REST API wrapper for all LLM communication (text + JSON generation, batch processing, health check) |
| Database | `database.py` | SQLite state management — `endpoints`, `payload_cache`, `anomalies`, `passive_findings` tables |
| Report Template | `report_template.html` | Jinja2 HTML template with executive summary, detailed findings, scan coverage matrix, passive findings |

---

## Output Files

All outputs are written to the `results/` directory:

| File | Written by | Description |
|---|---|---|
| `crawl_results.txt` | M1 Crawler | Human-readable crawl report |
| `crawl_results.csv` | M1 Crawler | Tabular report with payloads, JWTs, CSRF tokens |
| `crawl_results.json` | M1 Crawler | Full machine-readable crawl data (including JS file list) |
| `condensed_schemas.json` | M2 Condenser | Sanitised, deduplicated schemas (no PII) |
| `payload_cache.json` | M3 Orchestrator | Generated attack payloads (JSON) |
| `js_scan_results.json` | JS Scanner | Hardcoded secrets and logic flaws found in JS files |
| `passive_scan_results.json` | Passive Analyzer | Security header, CORS, cookie, info disclosure findings |
| `bac_scan_results.json` | BAC Comparator | BAC, IDOR, verb tampering, path bypass findings |
| `report.json` | M5 Triage | Full structured report (all findings merged) |
| `report.html` | M5 Triage | Rendered HTML report with executive summary |

The SQLite database (`ahvf_state.db`) is created in the project root and stores all state across tables: `endpoints`, `payload_cache`, `anomalies`, `passive_findings`.

---

## Project Structure

```
Autonomous_security_tool/
├── Crawler.py              # M1 — Stateful crawler (Playwright)
├── schema_condenser.py     # M2 — Schema sanitisation & deduplication
├── payload_orchestrator.py # M3 — AI payload generation via Ollama
├── async_executor.py       # M4 — Async fuzzing executor (aiohttp)
├── triage_engine.py        # M5 — Heuristic + LLM triage & reporting
├── js_scanner.py           # JS secret & logic flaw scanner
├── passive_analyzer.py     # Passive security analysis (headers/CORS/cookies)
├── bac_comparator.py       # BAC/IDOR cross-role comparator (FR-03)
├── login_agent.py          # Modular browser login agent (strategy pattern)
├── ollama_client.py        # Ollama REST API wrapper
├── database.py             # SQLite state database (SRS Section 6)
├── run_pipeline.py         # Pipeline orchestrator (CLI)
├── report_template.html    # Jinja2 HTML report template
├── requirements.txt        # Python dependencies
├── .gitignore              # Git exclusions
├── README.md               # This file
├── LICENSE
├── results/                # Output directory (generated at runtime)
│   ├── crawl_results.{txt,csv,json}
│   ├── condensed_schemas.json
│   ├── payload_cache.json
│   ├── js_scan_results.json
│   ├── passive_scan_results.json
│   ├── bac_scan_results.json
│   ├── report.json
│   └── report.html
└── ahvf_state.db           # SQLite database (generated at runtime)
```

---

## Vulnerability Coverage

### Active Testing (Fuzzing)

| Vulnerability Class | Detection Method |
|---|---|
| Cross-Site Scripting (XSS) | Reflected payload detection (case-insensitive) |
| SQL Injection (SQLi) | Error-based + blind (status code / body diff) |
| Server-Side Template Injection (SSTI) | Template expression evaluation in filenames |
| Path Traversal | Directory traversal payload + file content detection |
| SSRF | Internal URL probe via parameter injection |
| Command Injection | OS command payload + error response analysis |
| Second-Order Injection | Stored payload payloads for delayed execution |
| Polyglot | Combined SQL/XSS payloads for dual-context endpoints |

### Passive Analysis (No Injection)

| Check | Module | What It Catches |
|---|---|---|
| Security Headers | `passive_analyzer.py` | Missing HSTS, CSP, X-Frame-Options, X-Content-Type-Options |
| CORS Misconfig | `passive_analyzer.py` | Reflected origin, wildcard with credentials, null origin |
| Cookie Security | `passive_analyzer.py` | Missing HttpOnly, Secure, SameSite on auth cookies |
| Info Disclosure | `passive_analyzer.py` | Server version headers, debug headers, stack traces |
| JS Secrets | `js_scanner.py` | API keys, hardcoded passwords, JWT signing keys, internal URLs |
| JS Logic Flaws | `js_scanner.py` | Client-side auth, DOM XSS sinks, eval(), localStorage token storage |

### Access Control Testing

| Check | Module | SRS Reference |
|---|---|---|
| Cross-Role Replay | `bac_comparator.py` | FR-03.1, FR-03.2 |
| IDOR Probes | `bac_comparator.py` | FR-03.3 |
| HTTP Verb Tampering | `bac_comparator.py` | FR-03.4 |
| Path Normalization Bypass | `bac_comparator.py` | FR-03.5 |

---

## Fallback Mode (No Ollama)

If Ollama is not running or the model is unavailable, the pipeline will automatically fall back to built-in static wordlists covering:
- XSS (reflected + stored)
- SQL Injection
- Server-Side Template Injection (SSTI)
- Path Traversal
- SSRF
- Command Injection
- Polyglot payloads

The JS Scanner Tier 1 (keyword scan) and all passive analysis checks work without Ollama. Only the JS deep scan and LLM triage require an active Ollama instance.

---

## Troubleshooting

| Problem | Solution |
|---|---|
| `OllamaConnectionError: Cannot connect` | Make sure Ollama is running: `ollama serve` |
| `OllamaModelNotFoundError` | Pull the model: `ollama pull goekdenizguelmez/JOSIEFIED-Qwen3:8b` |
| Crawler login fails | Check selectors; the LLM fallback will try to auto-detect fields |
| No endpoints found | Verify the target is reachable and the scope hosts match |
| Empty payload cache | Check Ollama logs for errors; the tool will fall back to static payloads |
| BAC comparator skips | BAC requires 2+ crawled roles — crawl with both Admin and User |
| `ModuleNotFoundError: requests` | Run `pip install -r requirements.txt` |
| JS scan finds no files | Ensure crawl ran first and the app loads external JS files |
