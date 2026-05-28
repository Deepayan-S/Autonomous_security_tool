import aiosqlite
import json
import logging
from pathlib import Path
from typing import Optional, List, Dict, Any

logger = logging.getLogger("ahvf_crawler.db")

async def init_db(db_path: str | Path):
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    
    async with aiosqlite.connect(str(path)) as db:
        await db.execute("PRAGMA journal_mode=WAL;")
        await db.execute("PRAGMA foreign_keys = ON;")
        
        # Pipeline State
        await db.execute("""
            CREATE TABLE IF NOT EXISTS pipeline_state (
                phase TEXT PRIMARY KEY,
                status TEXT,
                meta TEXT,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Sessions
        await db.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                role TEXT PRIMARY KEY,
                storage_state TEXT,
                jwt TEXT,
                jwt_exp INTEGER,
                csrf_token TEXT,
                cookies TEXT,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Crawl State (Queue)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS crawl_state (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                role TEXT,
                url TEXT,
                depth INTEGER,
                state TEXT, -- QUEUED, NAVIGATING, EXTRACTING, PERSISTED, FAILED, SKIPPED
                failure_reason TEXT,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(role, url)
            )
        """)
        
        # Endpoints
        await db.execute("""
            CREATE TABLE IF NOT EXISTS endpoints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                role TEXT,
                method TEXT,
                url TEXT,
                schema_hash TEXT,
                baseline_hash TEXT,
                baseline_status INTEGER,
                baseline_content_length INTEGER,
                headers TEXT,
                source TEXT,
                idor_candidate BOOLEAN DEFAULT 0,
                condense_status TEXT DEFAULT 'pending',
                discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(role, schema_hash)
            )
        """)
        
        # Payload Cache
        await db.execute("""
            CREATE TABLE IF NOT EXISTS payload_cache (
                endpoint_id INTEGER,
                payload_type TEXT,
                payload_data TEXT,
                FOREIGN KEY(endpoint_id) REFERENCES endpoints(id)
            )
        """)
        
        # Anomalies
        await db.execute("""
            CREATE TABLE IF NOT EXISTS anomalies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                endpoint_id INTEGER,
                anomaly_type TEXT,
                details TEXT,
                triage_status TEXT DEFAULT 'pending',
                detected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(endpoint_id) REFERENCES endpoints(id)
            )
        """)
        
        # Captcha Queue
        await db.execute("""
            CREATE TABLE IF NOT EXISTS captcha_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                role TEXT,
                url TEXT,
                captcha_type TEXT,
                raw_image_b64 TEXT,
                preprocessed_image_b64 TEXT,
                metadata TEXT,
                solve_status TEXT DEFAULT 'pending',
                llm_raw_response TEXT,
                llm_extracted_answer TEXT,
                solved_at DATETIME
            )
        """)
        
        await db.commit()
    logger.info(f"Database initialized at {path}")

# ==========================================
# Named DB Operations
# ==========================================

async def update_pipeline_state(db_path: str, phase: str, status: str, meta: dict = None):
    meta_str = json.dumps(meta) if meta else "{}"
    async with aiosqlite.connect(db_path) as db:
        await db.execute("""
            INSERT INTO pipeline_state (phase, status, meta, updated_at) 
            VALUES (?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(phase) DO UPDATE SET 
                status=excluded.status, 
                meta=excluded.meta, 
                updated_at=CURRENT_TIMESTAMP
        """, (phase, status, meta_str))
        await db.commit()

async def get_session(db_path: str, role: str) -> Optional[Dict]:
    async with aiosqlite.connect(db_path) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM sessions WHERE role = ?", (role,)) as cursor:
            row = await cursor.fetchone()
            if row:
                return dict(row)
    return None

async def save_session(db_path: str, role: str, storage_state: str, jwt: str, jwt_exp: int, csrf_token: str, cookies: str):
    async with aiosqlite.connect(db_path) as db:
        await db.execute("""
            INSERT INTO sessions (role, storage_state, jwt, jwt_exp, csrf_token, cookies, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(role) DO UPDATE SET
                storage_state=excluded.storage_state,
                jwt=excluded.jwt,
                jwt_exp=excluded.jwt_exp,
                csrf_token=excluded.csrf_token,
                cookies=excluded.cookies,
                updated_at=CURRENT_TIMESTAMP
        """, (role, storage_state, jwt, jwt_exp, csrf_token, cookies))
        await db.commit()

async def enqueue_url(db_path: str, role: str, url: str, depth: int):
    async with aiosqlite.connect(db_path) as db:
        await db.execute("""
            INSERT OR IGNORE INTO crawl_state (role, url, depth, state)
            VALUES (?, ?, ?, 'QUEUED')
        """, (role, url, depth))
        await db.commit()

async def update_crawl_state(db_path: str, role: str, url: str, state: str, failure_reason: str = None):
    async with aiosqlite.connect(db_path) as db:
        await db.execute("""
            UPDATE crawl_state SET state = ?, failure_reason = ?, updated_at = CURRENT_TIMESTAMP
            WHERE role = ? AND url = ?
        """, (state, failure_reason, role, url))
        await db.commit()

async def get_queued_urls(db_path: str, role: str, limit: int = 1) -> List[Dict]:
    async with aiosqlite.connect(db_path) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("""
            SELECT * FROM crawl_state 
            WHERE role = ? AND state IN ('QUEUED', 'NAVIGATING') 
            ORDER BY depth ASC LIMIT ?
        """, (role, limit)) as cursor:
            return [dict(r) for r in await cursor.fetchall()]

async def save_endpoint(db_path: str, ep: Dict):
    async with aiosqlite.connect(db_path) as db:
        await db.execute("""
            INSERT INTO endpoints (
                role, method, url, schema_hash, baseline_hash, baseline_status, 
                baseline_content_length, headers, source, idor_candidate
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(role, schema_hash) DO UPDATE SET
                baseline_hash = excluded.baseline_hash,
                baseline_status = excluded.baseline_status,
                baseline_content_length = excluded.baseline_content_length
        """, (
            ep['role'], ep['method'], ep['url'], ep['schema_hash'], ep.get('baseline_hash'),
            ep.get('baseline_status'), ep.get('baseline_content_length'), ep.get('headers'),
            ep.get('source'), ep.get('idor_candidate', False)
        ))
        await db.commit()

async def save_captcha(db_path: str, c: Dict) -> int:
    async with aiosqlite.connect(db_path) as db:
        cursor = await db.execute("""
            INSERT INTO captcha_queue (
                role, url, captcha_type, raw_image_b64, preprocessed_image_b64, metadata
            ) VALUES (?, ?, ?, ?, ?, ?)
        """, (
            c['role'], c['url'], c['captcha_type'], c['raw_image_b64'], 
            c['preprocessed_image_b64'], json.dumps(c.get('metadata', {}))
        ))
        await db.commit()
        return cursor.lastrowid

async def update_captcha_solve(db_path: str, captcha_id: int, status: str, raw_resp: str, answer: str):
    async with aiosqlite.connect(db_path) as db:
        await db.execute("""
            UPDATE captcha_queue SET 
                solve_status = ?, llm_raw_response = ?, llm_extracted_answer = ?, solved_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (status, raw_resp, answer, captcha_id))
        await db.commit()

async def get_endpoints_for_bac(db_path: str) -> List[Dict]:
    async with aiosqlite.connect(db_path) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM endpoints") as cursor:
            return [dict(r) for r in await cursor.fetchall()]

async def save_anomaly(db_path: str, anomaly: Dict):
    async with aiosqlite.connect(db_path) as db:
        await db.execute("""
            INSERT INTO anomalies (endpoint_id, anomaly_type, details)
            VALUES (?, ?, ?)
        """, (anomaly['endpoint_id'], anomaly['anomaly_type'], json.dumps(anomaly.get('details', {}))))
        await db.commit()
