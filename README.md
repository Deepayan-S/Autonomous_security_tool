# AHVF — Autonomous Hybrid VAPT Framework

An autonomous security testing framework that crawls authenticated web applications, condenses endpoint schemas, and uses a local LLM (Ollama) to generate targeted attack payloads — all without sending any data off your machine.

> **⚠️ Authorized use only.** A signed Rules of Engagement (RoE) document must be on file before running against any target environment.

---

## Architecture

```
M1: Stateful Crawler  →  M2: Schema Condenser  →  M3: AI Payload Orchestrator
     (Crawler.py)        (schema_condenser.py)     (payload_orchestrator.py)
         │                       │                          │
         └───── SQLite State DB (database.py) ──────────────┘
                                                            │
                                                   Ollama (local LLM)
                                                   (ollama_client.py)
```

**Pipeline runner:** `run_pipeline.py` orchestrates all three modules.

---

## Prerequisites

| Requirement | Version | Purpose |
|---|---|---|
| Python | 3.10+ | Runtime |
| Playwright | Latest | Headless browser for crawling |
| Ollama | Latest | Local LLM inference server |
| LLM Model | `goekdenizguelmez/JOSIEFIED-Qwen3:8b` (or any Ollama-compatible model) | Payload generation |

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

The crawler also has dynamic login field detection, so the default selectors work for most applications.

### Crawler Hardcoded Defaults (in `Crawler.py`)

These can be adjusted in the source if needed:
- `EXCLUDED_PATHS` — paths the crawler will never follow (e.g., `/logout`, `/signout`, `/static/`)
- `MAX_PAGES_PER_ROLE` — max pages to visit per role (default: 500)
- `CRAWL_DEPTH` — max BFS link-follow depth (default: 10)

---

## How to Run

### Option A: Full Pipeline (Crawl → Condense → Generate → Execute → Triage)

```bash
python run_pipeline.py
```

This runs all five modules in sequence from beginning to end:
1. **M1 Crawler** — crawls the target, captures endpoints, saves to `results/`
2. **M2 Schema Condenser** — sanitises and deduplicates endpoint data
3. **M3 Payload Orchestrator** — sends schemas to Ollama, generates attack payloads
4. **M4 Async Executor** — fires payloads asynchronously against target
5. **M5 Triage & Reporting** — evaluates anomalous responses with LLM and generates HTML report

### Option B: Skip Crawl (reuse existing crawl data)

If you've already crawled a target and want to re-generate payloads:

```bash
python run_pipeline.py --skip-crawl
```

### Option C: Run Individual Phases

```bash
# Crawl only
python run_pipeline.py --phase crawl

# Schema condensation only (requires crawl data in results/)
python run_pipeline.py --phase condense

# Payload generation only (requires condensed schemas)
python run_pipeline.py --phase generate

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

---

## Output Files

All outputs are written to the `results/` directory:

| File | Written by | Description |
|---|---|---|
| `crawl_results.txt` | M1 Crawler | Human-readable crawl report |
| `crawl_results.csv` | M1 Crawler | Tabular report with payloads, JWTs, CSRF tokens |
| `crawl_results.json` | M1 Crawler | Full machine-readable crawl data |
| `condensed_schemas.json` | M2 Condenser | Sanitised, deduplicated schemas (no PII) |
| `payload_cache.json` | M3 Orchestrator | Generated attack payloads (JSON) |

The SQLite database (`ahvf_state.db`) is created in the project root and stores all state across tables: `endpoints`, `payload_cache`, `anomalies`.

---

## Project Structure

```
Autonomous_security_tool/
├── Crawler.py              # M1 — Stateful crawler (Playwright)
├── schema_condenser.py     # M2 — Schema sanitisation & deduplication
├── payload_orchestrator.py # M3 — AI payload generation via Ollama
├── ollama_client.py        # Ollama REST API wrapper
├── database.py             # SQLite state database (SRS Section 6)
├── run_pipeline.py         # Pipeline orchestrator (CLI)
├── requirements.txt        # Python dependencies
├── .gitignore              # Git exclusions
├── README.md               # This file
├── LICENSE
├── results/                # Output directory (generated at runtime)
│   ├── crawl_results.txt
│   ├── crawl_results.csv
│   ├── crawl_results.json
│   ├── condensed_schemas.json
│   └── payload_cache.json
└── ahvf_state.db           # SQLite database (generated at runtime)
```

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

This ensures the tool always produces usable output, even without LLM access.

---

## Troubleshooting

| Problem | Solution |
|---|---|
| `OllamaConnectionError: Cannot connect` | Make sure Ollama is running: `ollama serve` |
| `OllamaModelNotFoundError` | Pull the model: `ollama pull goekdenizguelmez/JOSIEFIED-Qwen3:8b` |
| Crawler login fails | Check that the target URL is correct and the login selectors match the page |
| No endpoints found | Verify the target is reachable and the scope hosts match |
| Empty payload cache | Check Ollama logs for errors; the tool will fall back to static payloads |
| `ModuleNotFoundError: requests` | Run `pip install -r requirements.txt` |
