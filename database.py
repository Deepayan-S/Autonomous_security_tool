"""
AHVF — SQLite State Database
==============================
Implements the data model from SRS Section 6.

Creates and manages the three core tables:
  - endpoints     : Crawled endpoint records (M1 output)
  - payload_cache : AI-generated payloads (M3 output)
  - anomalies     : Flagged responses from fuzzing (M4 output, M5 input)

All persistent state is stored in a single SQLite file (ahvf_state.db).
Foreign key constraints are enforced (PRAGMA foreign_keys = ON).

USAGE:
    from database import AHVFDatabase

    db = AHVFDatabase()           # uses default path
    db.initialize()               # creates tables if not exist
    db.insert_endpoints([...])    # bulk insert from Crawler
    db.close()
"""

import os
import sqlite3
from pathlib import Path
from typing import Optional


# ─────────────────────────────────────────────
#  CONFIGURATION
# ─────────────────────────────────────────────

DEFAULT_DB_PATH = Path(__file__).parent / "ahvf_state.db"


# ─────────────────────────────────────────────
#  SQL SCHEMA (SRS Section 6, line 144)
# ─────────────────────────────────────────────

CREATE_ENDPOINTS_TABLE = """
CREATE TABLE IF NOT EXISTS endpoints (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    url             TEXT    NOT NULL,
    method          TEXT    NOT NULL,
    role            TEXT    NOT NULL,
    schema_hash     TEXT    NOT NULL,
    baseline_hash   TEXT,
    baseline_status INTEGER,
    headers         TEXT,
    body            TEXT,
    response_status INTEGER,
    response_body   TEXT,
    jwt             TEXT,
    cookies         TEXT,
    csrf_token      TEXT,
    form_structure  TEXT,
    source          TEXT    DEFAULT 'network',
    discovered_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""

CREATE_PAYLOAD_CACHE_TABLE = """
CREATE TABLE IF NOT EXISTS payload_cache (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    schema_hash         TEXT    NOT NULL,
    vuln_class          TEXT    NOT NULL,
    payload             TEXT    NOT NULL,
    target_param        TEXT    NOT NULL,
    expected_indicator  TEXT
);
"""

CREATE_ANOMALIES_TABLE = """
CREATE TABLE IF NOT EXISTS anomalies (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    endpoint_id     INTEGER NOT NULL,
    payload_id      INTEGER NOT NULL,
    status_code     INTEGER,
    response_hash   TEXT,
    baseline_delta  TEXT,
    flagged_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    triage_status   TEXT    DEFAULT 'pending',
    cvss_score      REAL,
    cwe_id          TEXT,
    FOREIGN KEY (endpoint_id) REFERENCES endpoints(id),
    FOREIGN KEY (payload_id)  REFERENCES payload_cache(id)
);
"""

CREATE_METADATA_TABLE = """
CREATE TABLE IF NOT EXISTS metadata (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    key             TEXT    NOT NULL UNIQUE,
    value           TEXT
);
"""

CREATE_DROPPED_SCHEMAS_TABLE = """
CREATE TABLE IF NOT EXISTS dropped_schemas (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    url             TEXT    NOT NULL,
    method          TEXT    NOT NULL,
    role            TEXT    NOT NULL,
    reason          TEXT    NOT NULL,
    dropped_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""

# Index for fast lookup by schema_hash (used heavily by M2/M3/M4)
CREATE_SCHEMA_HASH_INDEX = """
CREATE INDEX IF NOT EXISTS idx_endpoints_schema_hash
ON endpoints(schema_hash);
"""

CREATE_PAYLOAD_SCHEMA_INDEX = """
CREATE INDEX IF NOT EXISTS idx_payload_cache_schema_hash
ON payload_cache(schema_hash);
"""

# Passive findings table for JS scanner, passive analyzer, BAC comparator
CREATE_PASSIVE_FINDINGS_TABLE = """
CREATE TABLE IF NOT EXISTS passive_findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    url             TEXT    NOT NULL,
    check_type      TEXT    NOT NULL,
    finding         TEXT    NOT NULL,
    severity        TEXT    NOT NULL,
    evidence        TEXT,
    cwe_id          TEXT,
    remediation     TEXT,
    role            TEXT,
    discovered_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""

CREATE_PASSIVE_FINDINGS_INDEX = """
CREATE INDEX IF NOT EXISTS idx_passive_findings_severity
ON passive_findings(severity);
"""


# ─────────────────────────────────────────────
#  DATABASE CLASS
# ─────────────────────────────────────────────

class AHVFDatabase:
    """
    Manages the AHVF SQLite state database.

    All CRUD operations for endpoints, payloads, and anomalies
    are centralised here. Uses synchronous sqlite3 for simplicity
    in the cold-phase pipeline (M2/M3). The async execution engine
    (M4) will use aiosqlite when it is built.
    """

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = Path(db_path) if db_path else DEFAULT_DB_PATH
        self._conn: Optional[sqlite3.Connection] = None

    # ── Connection management ────────────────────────────────────

    def connect(self) -> sqlite3.Connection:
        """Open a connection to the database."""
        if self._conn is None:
            self._conn = sqlite3.connect(str(self.db_path))
            self._conn.execute("PRAGMA foreign_keys = ON;")
            self._conn.execute("PRAGMA journal_mode = WAL;")  # better concurrency
            self._conn.row_factory = sqlite3.Row  # dict-like access
        return self._conn

    def close(self):
        """Close the database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None

    def initialize(self):
        """Create all tables and indices if they don't exist."""
        conn = self.connect()
        conn.execute(CREATE_ENDPOINTS_TABLE)
        conn.execute(CREATE_PAYLOAD_CACHE_TABLE)
        conn.execute(CREATE_ANOMALIES_TABLE)
        conn.execute(CREATE_PASSIVE_FINDINGS_TABLE)
        conn.execute(CREATE_METADATA_TABLE)
        conn.execute(CREATE_DROPPED_SCHEMAS_TABLE)
        conn.execute(CREATE_SCHEMA_HASH_INDEX)
        conn.execute(CREATE_PAYLOAD_SCHEMA_INDEX)
        conn.execute(CREATE_PASSIVE_FINDINGS_INDEX)
        conn.commit()
        print(f"[DB] Database initialized at {self.db_path}")

    # ── Endpoints (M1 → DB) ─────────────────────────────────────

    def insert_endpoints(self, endpoints: list[dict]) -> int:
        """
        Bulk insert endpoint records from Crawler output.

        Each dict should have keys matching the endpoints table columns.
        JSON-serialisable fields (headers, cookies, form_structure) are
        stored as JSON strings.

        Returns the number of rows inserted.
        """
        import json as _json

        conn = self.connect()
        inserted = 0

        for ep in endpoints:
            # Serialise complex fields to JSON strings
            headers_json = _json.dumps(ep.get("headers", {}))
            cookies_json = _json.dumps(ep.get("cookies", []))
            form_json = _json.dumps(ep.get("form_structure")) if ep.get("form_structure") else None

            conn.execute(
                """
                INSERT INTO endpoints
                    (url, method, role, schema_hash, headers, body,
                     response_status, response_body, jwt, cookies,
                     csrf_token, form_structure, source, discovered_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ep.get("url", ""),
                    ep.get("method", "GET"),
                    ep.get("role", "unknown"),
                    ep.get("schema_hash", ""),
                    headers_json,
                    ep.get("body"),
                    ep.get("response_status"),
                    ep.get("response_body"),
                    ep.get("jwt"),
                    cookies_json,
                    ep.get("csrf_token"),
                    form_json,
                    ep.get("source", "network"),
                    ep.get("discovered_at"),
                ),
            )
            inserted += 1

        conn.commit()
        print(f"[DB] Inserted {inserted} endpoint(s)")
        return inserted

    def get_all_endpoints(self) -> list[dict]:
        """Retrieve all endpoints from the database."""
        import json as _json

        conn = self.connect()
        cursor = conn.execute("SELECT * FROM endpoints ORDER BY id")
        rows = cursor.fetchall()

        results = []
        for row in rows:
            record = dict(row)
            # Deserialise JSON fields
            if record.get("headers"):
                record["headers"] = _json.loads(record["headers"])
            if record.get("cookies"):
                record["cookies"] = _json.loads(record["cookies"])
            if record.get("form_structure"):
                record["form_structure"] = _json.loads(record["form_structure"])
            results.append(record)

        return results

    def get_unique_schema_hashes(self) -> list[str]:
        """Get distinct schema hashes (for deduplication in M2)."""
        conn = self.connect()
        cursor = conn.execute("SELECT DISTINCT schema_hash FROM endpoints")
        return [row["schema_hash"] for row in cursor.fetchall()]

    def get_endpoints_by_schema_hash(self, schema_hash: str) -> list[dict]:
        """Get all endpoints sharing a given schema hash."""
        import json as _json

        conn = self.connect()
        cursor = conn.execute(
            "SELECT * FROM endpoints WHERE schema_hash = ?",
            (schema_hash,),
        )
        rows = cursor.fetchall()

        results = []
        for row in rows:
            record = dict(row)
            if record.get("headers"):
                record["headers"] = _json.loads(record["headers"])
            if record.get("cookies"):
                record["cookies"] = _json.loads(record["cookies"])
            if record.get("form_structure"):
                record["form_structure"] = _json.loads(record["form_structure"])
            results.append(record)

        return results

    # ── Payload Cache (M3 → DB) ──────────────────────────────────

    def insert_payloads(self, payloads: list[dict]) -> int:
        """
        Bulk insert generated payloads into the payload_cache table.

        Each dict should have: schema_hash, vuln_class, payload,
        target_param, expected_indicator.

        Returns the number of rows inserted.
        """
        conn = self.connect()
        inserted = 0

        for p in payloads:
            conn.execute(
                """
                INSERT INTO payload_cache
                    (schema_hash, vuln_class, payload, target_param, expected_indicator)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    p.get("schema_hash", ""),
                    p.get("vuln_class", "UNKNOWN"),
                    p.get("payload", ""),
                    p.get("target_param", ""),
                    p.get("expected_indicator"),
                ),
            )
            inserted += 1

        conn.commit()
        print(f"[DB] Inserted {inserted} payload(s) into cache")
        return inserted

    def get_payloads_by_schema_hash(self, schema_hash: str) -> list[dict]:
        """Get all payloads for a given schema hash."""
        conn = self.connect()
        cursor = conn.execute(
            "SELECT * FROM payload_cache WHERE schema_hash = ?",
            (schema_hash,),
        )
        return [dict(row) for row in cursor.fetchall()]

    def get_all_payloads(self) -> list[dict]:
        """Retrieve all payloads from the cache."""
        conn = self.connect()
        cursor = conn.execute("SELECT * FROM payload_cache ORDER BY id")
        return [dict(row) for row in cursor.fetchall()]

    def get_payload_count(self) -> int:
        """Get total number of payloads in cache."""
        conn = self.connect()
        cursor = conn.execute("SELECT COUNT(*) as cnt FROM payload_cache")
        return cursor.fetchone()["cnt"]

    # ── Anomalies (M4 → DB, M5 reads) ───────────────────────────
    # Stubbed for future use — M4 does not exist yet.

    def insert_anomaly(self, anomaly: dict) -> int:
        """Insert a single anomaly record. Returns the row ID."""
        conn = self.connect()
        cursor = conn.execute(
            """
            INSERT INTO anomalies
                (endpoint_id, payload_id, status_code, response_hash,
                 baseline_delta, triage_status)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                anomaly.get("endpoint_id"),
                anomaly.get("payload_id"),
                anomaly.get("status_code"),
                anomaly.get("response_hash"),
                anomaly.get("baseline_delta"),
                anomaly.get("triage_status", "pending"),
            ),
        )
        conn.commit()
        return cursor.lastrowid

    def get_pending_anomalies(self) -> list[dict]:
        """Get all anomalies pending triage (for M5)."""
        conn = self.connect()
        cursor = conn.execute(
            "SELECT * FROM anomalies WHERE triage_status = 'pending' ORDER BY id"
        )
        return [dict(row) for row in cursor.fetchall()]

    # ── Passive Findings (JS Scanner / Passive Analyzer / BAC Comparator → DB) ─

    def insert_passive_findings(self, findings: list[dict]) -> int:
        """
        Bulk insert passive findings from any analysis module.

        Each dict should have: url, check_type, finding, severity.
        Optional: evidence, cwe_id, remediation, role.

        check_type values: 'header', 'cors', 'cookie', 'info_disclosure',
            'js_secret', 'js_logic_flaw', 'bac', 'idor', 'verb_tampering', 'path_bypass'
        severity values: 'Critical', 'High', 'Medium', 'Low', 'Info'
        """
        conn = self.connect()
        inserted = 0

        for f in findings:
            conn.execute(
                """
                INSERT INTO passive_findings
                    (url, check_type, finding, severity, evidence,
                     cwe_id, remediation, role)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    f.get("url", ""),
                    f.get("check_type", "unknown"),
                    f.get("finding", ""),
                    f.get("severity", "Info"),
                    f.get("evidence"),
                    f.get("cwe_id"),
                    f.get("remediation"),
                    f.get("role"),
                ),
            )
            inserted += 1

        conn.commit()
        print(f"[DB] Inserted {inserted} passive finding(s)")
        return inserted

    def get_passive_findings(self, check_type: Optional[str] = None) -> list[dict]:
        """Retrieve passive findings, optionally filtered by check_type."""
        conn = self.connect()
        if check_type:
            cursor = conn.execute(
                "SELECT * FROM passive_findings WHERE check_type = ? ORDER BY id",
                (check_type,),
            )
        else:
            cursor = conn.execute("SELECT * FROM passive_findings ORDER BY id")
        return [dict(row) for row in cursor.fetchall()]

    def get_passive_findings_summary(self) -> dict:
        """Return counts grouped by severity and check_type."""
        conn = self.connect()
        summary = {"by_severity": {}, "by_check_type": {}}

        cursor = conn.execute(
            "SELECT severity, COUNT(*) as cnt FROM passive_findings GROUP BY severity"
        )
        for row in cursor.fetchall():
            summary["by_severity"][row["severity"]] = row["cnt"]

        cursor = conn.execute(
            "SELECT check_type, COUNT(*) as cnt FROM passive_findings GROUP BY check_type"
        )
        for row in cursor.fetchall():
            summary["by_check_type"][row["check_type"]] = row["cnt"]

        return summary

    def insert_metadata(self, key: str, value: str):
        conn = self.connect()
        conn.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
            (key, value)
        )
        conn.commit()

    def get_metadata(self) -> dict:
        conn = self.connect()
        cursor = conn.execute("SELECT key, value FROM metadata")
        return {row["key"]: row["value"] for row in cursor.fetchall()}

    def insert_dropped_schemas(self, schemas: list[dict]):
        conn = self.connect()
        for s in schemas:
            conn.execute(
                "INSERT INTO dropped_schemas (url, method, role, reason) VALUES (?, ?, ?, ?)",
                (s.get("url", ""), s.get("method", "GET"), s.get("role", "unknown"), s.get("reason", "unknown"))
            )
        conn.commit()

    def get_dropped_schemas(self) -> list[dict]:
        conn = self.connect()
        cursor = conn.execute("SELECT * FROM dropped_schemas ORDER BY id")
        return [dict(row) for row in cursor.fetchall()]

    # ── Utility ──────────────────────────────────────────────────

    def clear_all(self):
        """Drop all data (for testing / re-runs). Tables are preserved."""
        conn = self.connect()
        conn.execute("DELETE FROM anomalies")
        conn.execute("DELETE FROM payload_cache")
        conn.execute("DELETE FROM endpoints")
        conn.execute("DELETE FROM passive_findings")
        conn.execute("DELETE FROM metadata")
        conn.execute("DELETE FROM dropped_schemas")
        conn.commit()
        print("[DB] All tables cleared")

    def get_stats(self) -> dict:
        """Return row counts for all tables."""
        conn = self.connect()
        stats = {}
        for table in ("endpoints", "payload_cache", "anomalies", "passive_findings", "dropped_schemas"):
            cursor = conn.execute(f"SELECT COUNT(*) as cnt FROM {table}")
            stats[table] = cursor.fetchone()["cnt"]
        return stats


# ─────────────────────────────────────────────
#  STANDALONE TEST
# ─────────────────────────────────────────────

if __name__ == "__main__":
    db = AHVFDatabase()
    db.initialize()
    print(f"[DB] Stats: {db.get_stats()}")
    db.close()
