"""
AHVF — Pipeline Runner
========================
Orchestrates the AHVF pipeline: M1 (Crawl) → M2 (Condense) → M3 (Generate Payloads).

Can run the full pipeline or individual phases:
  --phase crawl      Run M1 Crawler only
  --phase condense   Run M2 Schema Condenser only (requires crawl output)
  --phase generate   Run M3 Payload Orchestrator only (requires condensed schemas)
  --phase all        Run full pipeline M1 → M2 → M3 (default)

Also supports skipping the crawl if crawl_results.json already exists.

USAGE:
    python run_pipeline.py                   # Full pipeline (M1 -> M5)
    python run_pipeline.py --phase condense  # M2 only (uses existing crawl data)
    python run_pipeline.py --phase generate  # M3 only (uses existing condensed schemas)
    python run_pipeline.py --skip-crawl      # M2 to M5 only (reuse crawl data)
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

def run_crawl():
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
        result = subprocess.run([sys.executable, "Crawler.py"])
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
        executor = AsyncPayloadExecutor(concurrency=500)
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

# ─────────────────────────────────────────────
#  PIPELINE ORCHESTRATOR
# ─────────────────────────────────────────────

def run_pipeline(phase: str = "all", skip_crawl: bool = False):
    """
    Run the AHVF pipeline.

    Args:
        phase: Which phase(s) to run — "all", "crawl", "condense", "generate"
        skip_crawl: If True, skip crawl even in "all" mode (reuse existing data)
    """
    print(f"\n{'='*60}")
    print(f"  AHVF — Autonomous Hybrid VAPT Framework")
    print(f"  Pipeline Runner v1.0")
    print(f"  !! For authorized security testing only !!")
    print(f"{'='*60}\n")

    start_time = time.time()

    # Initialize database
    db = AHVFDatabase()
    db.initialize()

    try:
        # ── Phase 1: Crawl ───────────────────────────────────────
        if phase in ("all", "crawl"):
            if skip_crawl:
                crawl_json = Path("results") / "crawl_results.json"
                if crawl_json.exists():
                    print("[Pipeline] Skipping crawl — using existing crawl_results.json")
                else:
                    print("[Pipeline] ERROR: --skip-crawl specified but no crawl_results.json found")
                    return
            else:
                ok = run_crawl()
                if not ok and phase == "crawl":
                    return

            if phase == "crawl":
                # Import crawl data into SQLite
                _import_crawl_to_db(db)
                return

        # ── Phase 2a: Condense ───────────────────────────────────
        if phase in ("all", "condense"):
            # Ensure crawl data is in the database
            stats = db.get_stats()
            if stats["endpoints"] == 0:
                _import_crawl_to_db(db)

            ok = run_condense(db)
            if not ok:
                print("[Pipeline] Condensation failed. Stopping.")
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


def _import_crawl_to_db(db: AHVFDatabase):
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


# ─────────────────────────────────────────────
#  CLI ENTRY POINT
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="AHVF Pipeline Runner — Orchestrates M1 → M2 → M3",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run_pipeline.py                     Full pipeline (crawl → condense → generate)
  python run_pipeline.py --phase condense    Schema condensation only
  python run_pipeline.py --phase generate    Payload generation only
  python run_pipeline.py --skip-crawl        Skip crawl, use existing data
        """,
    )

    parser.add_argument(
        "--phase",
        choices=["all", "crawl", "condense", "generate", "execute", "triage"],
        default="all",
        help="Which phase to run (default: all)",
    )
    parser.add_argument(
        "--skip-crawl",
        action="store_true",
        help="Skip the crawl phase and use existing crawl_results.json",
    )

    args = parser.parse_args()
    run_pipeline(phase=args.phase, skip_crawl=args.skip_crawl)


if __name__ == "__main__":
    main()
