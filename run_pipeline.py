"""
AHVF — Pipeline Runner
========================
Orchestrates the AHVF pipeline: Crawl → JS Scan → Condense → Generate →
Passive Analysis → BAC Compare → Execute → Triage.

Can run the full pipeline or individual phases:
  --phase crawl      Run M1 Crawler only
  --phase js_scan    Run JS Secret Scanner only
  --phase condense   Run M2 Schema Condenser only (requires crawl output)
  --phase generate   Run M3 Payload Orchestrator only (requires condensed schemas)
  --phase passive    Run Passive Security Analyzer only
  --phase bac        Run BAC/IDOR Cross-Role Comparator only
  --phase execute    Run M4 Async Executor only
  --phase triage     Run M5 Triage & Reporting only
  --phase all        Run full pipeline (default)

Additional flags:
  --deep-scan        Enable LLM deep analysis of JS files (slower, more thorough)
  --skip-crawl       Skip crawl, use existing crawl_results.json

USAGE:
    python run_pipeline.py                        # Full pipeline
    python run_pipeline.py --phase condense       # M2 only
    python run_pipeline.py --phase js_scan --deep-scan  # JS scan with LLM
    python run_pipeline.py --skip-crawl            # Reuse crawl data
"""

import argparse
import sys
import time
from pathlib import Path

from database import AHVFDatabase
from ollama_client import OllamaClient, OllamaError


# ─────────────────────────────────────────────
#  PHASE RUNNERS
# ─────────────────────────────────────────────

def run_crawl(interactive: bool = False):
    """
    Phase 1: Run M1 Crawler.

    Imports and runs the existing Crawler.py main function.
    The Crawler handles its own user interaction (target URL,
    credentials, etc.) and writes output to results/.
    """
    print(f"\n{'='*60}")
    print(f"  PHASE 1: Stateful Crawler (M1)")
    print(f"{'='*60}\n")

    import subprocess
    import sys

    # Run Crawler.py as a subprocess to ensure clean event loop and global state
    try:
        cmd = [sys.executable, "Crawler.py"]
        if interactive:
            cmd.append("--interactive")
        result = subprocess.run(cmd)
        return result.returncode == 0
    except KeyboardInterrupt:
        print("\n[Pipeline] Crawl interrupted by user.")
        return False
    except Exception as e:
        print(f"[Pipeline] Crawl failed: {e}")
        return False


def run_condense(db: AHVFDatabase) -> bool:
    """
    Phase 2 (pre-synthesis): Run M2 Schema Condenser.

    Reads crawl output from SQLite (or JSON fallback) and produces
    condensed, sanitised schemas for M3.
    """
    print(f"\n{'='*60}")
    print(f"  PHASE 2a: Schema Condenser (M2)")
    print(f"{'='*60}\n")

    from schema_condenser import SchemaCondenser

    condenser = SchemaCondenser(db)
    schemas = condenser.condense_and_store()

    if not schemas:
        print("[Pipeline] No schemas produced. Check that crawl data exists.")
        return False

    print(f"[Pipeline] M2 complete: {len(schemas)} condensed schema(s)")
    return True


def run_generate(db: AHVFDatabase) -> bool:
    """
    Phase 2 (synthesis): Run M3 Payload Orchestrator.

    Connects to Ollama, generates payloads from condensed schemas,
    validates them, and writes to the payload cache.

    After completion, severs the AI connection (FR-05.7).
    """
    print(f"\n{'='*60}")
    print(f"  PHASE 2b: AI Payload Orchestrator (M3)")
    print(f"{'='*60}\n")

    from schema_condenser import SchemaCondenser
    from payload_orchestrator import PayloadOrchestrator

    # Step 1: Load condensed schemas
    condenser = SchemaCondenser(db)
    schemas = condenser.condense()

    if not schemas:
        # Try loading from JSON file
        schema_path = Path("results") / "condensed_schemas.json"
        if schema_path.exists():
            import json
            from schema_condenser import CondensedSchema
            from dataclasses import fields as dc_fields

            raw = json.loads(schema_path.read_text(encoding="utf-8"))
            schemas = []
            for item in raw:
                # Build CondensedSchema from dict
                valid_keys = {f.name for f in dc_fields(CondensedSchema)}
                filtered = {k: v for k, v in item.items() if k in valid_keys}
                schemas.append(CondensedSchema(**filtered))
            print(f"[Pipeline] Loaded {len(schemas)} schema(s) from {schema_path}")

    if not schemas:
        print("[Pipeline] No schemas available. Run the condenser first.")
        return False

    # Step 2: Initialize Ollama client
    client = None
    use_fallback_only = False

    try:
        client = OllamaClient()
        client.health_check()
        print("[Pipeline] Ollama connected successfully")
    except OllamaError as e:
        print(f"[Pipeline] WARNING: Ollama not available: {e}")
        print("[Pipeline] Proceeding with fallback wordlists only.")
        use_fallback_only = True

    # Step 3: Generate payloads
    try:
        if use_fallback_only:
            # Fallback-only mode — create orchestrator without client
            orchestrator = PayloadOrchestrator.__new__(PayloadOrchestrator)
            orchestrator.client = None
            orchestrator.db = db
            orchestrator.batch_size = 15
            orchestrator._total_generated = 0
            orchestrator._total_fallback = 0
            orchestrator._total_invalid = 0

            schema_lookup = {s.schema_hash: s for s in schemas}
            all_hashes = [s.schema_hash for s in schemas]
            payloads = orchestrator._generate_batch_fallback(all_hashes, schema_lookup)

            if db:
                db.insert_payloads(payloads)
            orchestrator._write_payload_json(payloads)
            orchestrator._print_summary(payloads, 0)
        else:
            orchestrator = PayloadOrchestrator(client, db)
            payloads = orchestrator.generate_payloads(schemas)
    except Exception as e:
        print(f"[Pipeline] Payload generation failed: {e}")
        return False
    finally:
        # FR-05.7: Sever AI connection after cache population
        if client:
            client.close()
            print("[Pipeline] AI connection severed (FR-05.7)")

    return True

def run_executor() -> bool:
    print(f"\n{'='*60}")
    print(f"  PHASE 3: Async Payload Executor (M4)")
    print(f"{'='*60}\n")
    import asyncio
    from async_executor import AsyncPayloadExecutor
    try:
        executor = AsyncPayloadExecutor(concurrency=20)
        asyncio.run(executor.run())
        return True
    except Exception as e:
        print(f"[Pipeline] Executor failed: {e}")
        return False

def run_triage() -> bool:
    print(f"\n{'='*60}")
    print(f"  PHASE 4: Triage & Reporting (M5)")
    print(f"{'='*60}\n")
    from triage_engine import TriageEngine
    try:
        engine = TriageEngine()
        engine.triage_anomalies()
        engine.generate_report()
        return True
    except Exception as e:
        print(f"[Pipeline] Triage failed: {e}")
        return False


def run_js_scan(db: AHVFDatabase, deep_scan: bool = False) -> bool:
    """
    Phase 1b: Run JS Secret Scanner.

    Scans JavaScript files collected during crawling for hardcoded
    secrets and logic flaws. Uses keyword matching by default,
    with optional LLM deep scan.
    """
    print(f"\n{'='*60}")
    print(f"  PHASE 1b: JavaScript Scanner")
    print(f"  Mode: {'Deep Scan (LLM)' if deep_scan else 'Keyword Scan'}")
    print(f"{'='*60}\n")

    import asyncio
    import json

    from js_scanner import JSScanner

    # Load JS file URLs from crawl results
    crawl_json = Path("results") / "crawl_results.json"
    if not crawl_json.exists():
        print("[Pipeline] No crawl_results.json found — cannot scan JS files")
        return False

    raw = json.loads(crawl_json.read_text(encoding="utf-8"))
    all_js_urls = []
    all_cookies = {}
    jwt_token = None
    role = "unknown"

    for role_result in raw.get("results", []):
        js_files = role_result.get("js_files", [])
        all_js_urls.extend(js_files)
        role = role_result.get("role", "unknown")

        # Extract cookies from first endpoint for auth
        for ep in role_result.get("endpoints", []):
            if ep.get("jwt"):
                jwt_token = ep["jwt"]
            cookies = ep.get("cookies", [])
            if isinstance(cookies, list):
                for c in cookies:
                    if isinstance(c, dict) and c.get("name"):
                        all_cookies[c["name"]] = c.get("value", "")
            if jwt_token:
                break

    if not all_js_urls:
        print("[Pipeline] No JS files found in crawl results — skipping JS scan")
        return True  # Not a failure, just nothing to scan

    # Deduplicate
    all_js_urls = list(set(all_js_urls))
    print(f"[Pipeline] Found {len(all_js_urls)} unique JS file(s) to scan")

    scanner = JSScanner(db=db, deep_scan=deep_scan)

    try:
        findings = asyncio.run(scanner.run(
            js_urls=all_js_urls,
            cookies=all_cookies,
            role=role,
            jwt_token=jwt_token,
        ))
        print(f"[Pipeline] JS scan complete: {len(findings)} finding(s)")
        return True
    except Exception as e:
        print(f"[Pipeline] JS scan failed: {e}")
        return False


def run_passive_analysis(db: AHVFDatabase) -> bool:
    """
    Phase 2c: Run Passive Security Analyzer.

    Checks security headers, CORS, cookies, and information disclosure
    on all crawled endpoints without injecting payloads.
    """
    print(f"\n{'='*60}")
    print(f"  PHASE 2c: Passive Security Analysis")
    print(f"{'='*60}\n")

    import asyncio
    import json

    from passive_analyzer import PassiveAnalyzer

    # Load endpoints from crawl results (richer data than DB)
    crawl_json = Path("results") / "crawl_results.json"
    endpoints = []

    if crawl_json.exists():
        raw = json.loads(crawl_json.read_text(encoding="utf-8"))
        for role_result in raw.get("results", []):
            for ep in role_result.get("endpoints", []):
                ep["role"] = role_result.get("role", "unknown")
                endpoints.append(ep)
    else:
        # Fallback to DB
        endpoints = db.get_all_endpoints()

    if not endpoints:
        print("[Pipeline] No endpoints found for passive analysis")
        return True

    analyzer = PassiveAnalyzer(db=db)

    try:
        findings = asyncio.run(analyzer.run(endpoints=endpoints))
        print(f"[Pipeline] Passive analysis complete: {len(findings)} finding(s)")
        return True
    except Exception as e:
        print(f"[Pipeline] Passive analysis failed: {e}")
        return False


def run_bac_compare(db: AHVFDatabase) -> bool:
    """
    Phase 2d: Run BAC/IDOR Cross-Role Comparator.

    Compares endpoints across roles to detect broken access control.
    Requires at least 2 crawled roles — skips gracefully if only 1.
    """
    print(f"\n{'='*60}")
    print(f"  PHASE 2d: BAC/IDOR Cross-Role Comparator")
    print(f"{'='*60}\n")

    import asyncio

    from bac_comparator import BACComparator

    comparator = BACComparator(db=db)

    try:
        findings = asyncio.run(comparator.run())
        print(f"[Pipeline] BAC comparison complete: {len(findings)} finding(s)")
        return True
    except Exception as e:
        print(f"[Pipeline] BAC comparison failed: {e}")
        return False

# ─────────────────────────────────────────────
#  PIPELINE ORCHESTRATOR
# ─────────────────────────────────────────────

def run_pipeline(phase: str = "all", skip_crawl: bool = False, deep_scan: bool = False, interactive: bool = False):
    """
    Run the AHVF pipeline.

    Args:
        phase: Which phase(s) to run
        skip_crawl: If True, skip crawl even in "all" mode (reuse existing data)
        deep_scan: If True, enable LLM deep analysis in JS scanner
        interactive: If True, prompt for crawler configuration
    """
    print(f"\n{'='*60}")
    print(f"  AHVF — Autonomous Hybrid VAPT Framework")
    print(f"  Pipeline Runner v2.0")
    print(f"  !! For authorized security testing only !!")
    print(f"{'='*60}\n")

    start_time = time.time()

    # Initialize database
    db = AHVFDatabase()
    db.initialize()

    try:
        # ── Phase 1: Crawl ───────────────────────────────────────
        if phase in ("all", "crawl"):
            if phase == "all":
                print("[Pipeline] Wiping database state for fresh pipeline run...")
                db.clear_all()
                
            if skip_crawl:
                crawl_json = Path("results") / "crawl_results.json"
                if crawl_json.exists():
                    print("[Pipeline] Skipping crawl — using existing crawl_results.json")
                    if phase == "all":
                        _import_crawl_to_db(db, skip_crawl)
                else:
                    print("[Pipeline] ERROR: --skip-crawl specified but no crawl_results.json found")
                    return
            else:
                ok = run_crawl(interactive=interactive)
                if not ok:
                    print("[Pipeline] Crawl failed. Stopping pipeline.")
                    return

            # Import crawl data into SQLite (for both "crawl" and "all" phases)
            _import_crawl_to_db(db, skip_crawl)

            if phase == "crawl":
                return

        # ── Phase 1b: JS Scan ────────────────────────────────────
        if phase in ("all", "js_scan"):
            ok = run_js_scan(db, deep_scan=deep_scan)
            if not ok and phase == "js_scan":
                print("[Pipeline] JS scan failed.")
                return
            if phase == "js_scan":
                return

        # ── Phase 2a: Condense ───────────────────────────────────
        if phase in ("all", "condense"):
            # Ensure crawl data is in the database
            stats = db.get_stats()
            if stats["endpoints"] == 0:
                _import_crawl_to_db(db)

            ok = run_condense(db)
            if not ok:
                print("[Pipeline] Condensation failed.")
                return
            if phase == "condense":
                return

        # ── Phase 2b: Generate Payloads ──────────────────────────
        if phase in ("all", "generate"):
            ok = run_generate(db)
            if not ok:
                print("[Pipeline] Payload generation failed.")
                return
            if phase == "generate":
                return

        # ── Phase 2c: Passive Security Analysis ──────────────────
        if phase in ("all", "passive"):
            ok = run_passive_analysis(db)
            if not ok and phase == "passive":
                print("[Pipeline] Passive analysis failed.")
                return
            if phase == "passive":
                return

        # ── Phase 2d: BAC/IDOR Cross-Role Comparison ─────────────
        if phase in ("all", "bac"):
            ok = run_bac_compare(db)
            if not ok and phase == "bac":
                print("[Pipeline] BAC comparison failed.")
                return
            if phase == "bac":
                return

        # ── Phase 3: Execute Fuzzing ──────────────────────────────
        if phase in ("all", "execute"):
            ok = run_executor()
            if not ok:
                print("[Pipeline] Executor failed.")
                return
            if phase == "execute":
                return

        # ── Phase 4: Triage & Reporting ──────────────────────────
        if phase in ("all", "triage"):
            ok = run_triage()
            if not ok:
                print("[Pipeline] Triage & Reporting failed.")
                return

        elapsed = time.time() - start_time
        print(f"\n{'='*60}")
        print(f"  Pipeline complete in {elapsed:.1f}s")
        print(f"  Database: {db.db_path}")
        stats = db.get_stats()
        print(f"  Stats: {stats}")
        print(f"{'='*60}\n")

    finally:
        db.close()


def _import_crawl_to_db(db: AHVFDatabase, skip_crawl: bool = False):
    """Import crawl_results.json into the SQLite endpoints table."""
    import json

    crawl_json = Path("results") / "crawl_results.json"
    if not crawl_json.exists():
        print("[Pipeline] No crawl_results.json found to import")
        return

    print(f"[Pipeline] Importing crawl data from {crawl_json}...")
    raw = json.loads(crawl_json.read_text(encoding="utf-8"))

    endpoints = []
    for role_result in raw.get("results", []):
        role = role_result.get("role", "unknown")
        for ep in role_result.get("endpoints", []):
            ep["role"] = role
            endpoints.append(ep)

    if endpoints:
        db.insert_endpoints(endpoints)
        print(f"[Pipeline] Imported {len(endpoints)} endpoint(s) into SQLite")
    else:
        print("[Pipeline] No endpoints found in crawl data")
        
    meta = raw.get("meta", {})
    if meta:
        db.insert_metadata("crawl_target", meta.get("target", ""))
        db.insert_metadata("crawl_generated", meta.get("generated", ""))
        db.insert_metadata("crawl_roles", ",".join(meta.get("roles", [])))
        db.insert_metadata("data_freshness", "reused" if skip_crawl else "fresh")


# ─────────────────────────────────────────────
#  CLI ENTRY POINT
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="AHVF Pipeline Runner — Full L1/L2 Security Testing Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Pipeline flow:
  crawl → js_scan → condense → generate → passive → bac → execute → triage

Examples:
  python run_pipeline.py                          Full pipeline
  python run_pipeline.py --phase js_scan          JS secret scan only
  python run_pipeline.py --phase js_scan --deep-scan  JS scan with LLM analysis
  python run_pipeline.py --phase passive           Passive security analysis only
  python run_pipeline.py --phase bac               BAC/IDOR comparison only
  python run_pipeline.py --skip-crawl              Skip crawl, use existing data
        """,
    )

    parser.add_argument(
        "--phase",
        choices=["all", "crawl", "js_scan", "condense", "generate", "passive", "bac", "execute", "triage"],
        default="all",
        help="Which phase to run (default: all)",
    )
    parser.add_argument(
        "--skip-crawl",
        action="store_true",
        help="Skip the crawl phase and use existing crawl_results.json",
    )
    parser.add_argument(
        "--deep-scan",
        action="store_true",
        help="Enable LLM deep analysis of JS files (slower, more thorough)",
    )
    parser.add_argument(
        "--interactive",
        action="store_true",
        help="Force CLI input for crawler configuration, ignoring config file",
    )

    args = parser.parse_args()
    run_pipeline(phase=args.phase, skip_crawl=args.skip_crawl, deep_scan=args.deep_scan, interactive=args.interactive)


if __name__ == "__main__":
    main()
