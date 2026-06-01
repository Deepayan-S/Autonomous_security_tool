from __future__ import annotations
import sqlite3
import json
import logging
from typing import List, Dict, Any
from pathlib import Path
from ollama_client import OllamaClient
from jinja2 import Environment, FileSystemLoader

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("TriageEngine")

DB_PATH = Path("ahvf_state.db")
RESULTS_DIR = Path("results")
RESULTS_DIR.mkdir(exist_ok=True)

class TriageEngine:
    """Module 5: LLM-powered anomaly classification and reporting."""
    
    SYSTEM_PROMPT = """You are a Senior Application Security Engineer performing authorized penetration testing triage. You will receive a JSON array of anomalies detected during fuzzing. Each anomaly contains the payload, endpoint context, and baseline deltas.

Your job is to classify each anomaly and return a JSON array containing EXACTLY one object per input anomaly, in the exact same order.

For each anomaly, your output object MUST have:
1. "anomaly_id": The exact ID provided in the input.
2. "classification": One of ["Confirmed Vulnerability", "Likely False Positive", "Requires Manual Review"].
3. "confidence_score": A float between 0.0 and 1.0.
4. "cve_cwe_mapping": Provide a relevant CWE ID (e.g., "CWE-89") if it's a Confirmed Vulnerability, else "".
5. "cvss_score": Provide a CVSS v3.1 base score (float 0.0-10.0) if Confirmed Vulnerability, else null.
6. "cvss_justification": A brief explanation of the CVSS score, else "".
7. "remediation_snippet": A secure coding snippet or advice to fix the issue, else "".

EVIDENCE-BASED TRIAGE RULES (MUST FOLLOW):

CONFIRMED VULNERABILITY — classify as "Confirmed Vulnerability" ONLY when:
- baseline_delta contains "Injection payload reflected in response" AND the vuln_class is XSS/SECOND_ORDER_XSS → CWE-79
- baseline_delta contains SQL error keywords (e.g., "syntax error", "mysql", "ORA-", "UNION", "SQLite") → CWE-89
- baseline_delta shows template evaluation output (e.g., "49" for {{7*7}}) → CWE-1336 (SSTI)
- baseline_delta contains "Access control bypass" → CWE-284
- baseline_delta contains OS output (e.g., "uid=", "root:", "[extensions]") from command injection/path traversal → CWE-78 or CWE-22
- The response body contains data belonging to another user (IDOR evidence) → CWE-639

LIKELY FALSE POSITIVE — classify as "Likely False Positive" when:
- baseline_delta contains ONLY "Server Error (Status: 500)" with NO other evidence. A 500 error on malformed input is typically just an unhandled exception, NOT proof of exploitation. Most web applications will return 500 when receiving unexpected input formats, SQL injection strings, or special characters in parameters — this is poor error handling, not a vulnerability.
- baseline_delta is empty or contains ONLY "Response body differs from baseline" with no meaningful indicators.
- The response simply shows a generic error page or JSON error message.

REQUIRES MANUAL REVIEW — classify as "Requires Manual Review" when:
- There is partial evidence but not enough to confirm (e.g., 500 error WITH a SQL-like payload AND suspicious response content).
- The anomaly shows a timing difference that could indicate blind injection.
- The response contains unusual data that might indicate information disclosure.

Output MUST be a valid JSON array."""

    def __init__(self):
        self.db = sqlite3.connect(DB_PATH)
        self.db.row_factory = sqlite3.Row
        self.client = OllamaClient()
        try:
            self.db.execute("ALTER TABLE anomalies ADD COLUMN llm_details TEXT")
            self.db.commit()
        except sqlite3.OperationalError:
            pass

    def fetch_pending_anomalies(self) -> List[Dict]:
        """Fetches pending anomalies with endpoint and payload context."""
        cursor = self.db.execute("""
            SELECT a.id as anomaly_id, a.status_code as response_status_code, a.baseline_delta, 
                   e.url, e.method, e.role, e.schema_hash, e.response_status as baseline_status, e.body as baseline_body,
                   p.payload, p.target_param, p.expected_indicator, p.vuln_class
            FROM anomalies a
            JOIN endpoints e ON a.endpoint_id = e.id
            JOIN payload_cache p ON a.payload_id = p.id
            WHERE a.triage_status = 'pending'
        """)
        
        results = []
        for row in cursor.fetchall():
            d = dict(row)
            # Truncate baseline_delta or body to 500 chars to save context
            if d.get("baseline_delta") and len(d["baseline_delta"]) > 500:
                d["baseline_delta"] = d["baseline_delta"][:500] + "... [TRUNCATED]"
            results.append(d)
            
        return results

    def _pre_classify(self, anomaly: dict) -> Optional[dict]:
        """
        Deterministic heuristic pre-classification.
        
        Auto-classifies obvious cases to skip the LLM entirely.
        Returns a triage result dict, or None to fall through to LLM.
        """
        delta = anomaly.get("baseline_delta", "")
        vuln_class = anomaly.get("vuln_class", "")
        a_id = anomaly.get("anomaly_id")

        # Reflected XSS — payload with special chars reflected
        if "reflected in response" in delta.lower() and vuln_class in ("XSS", "SECOND_ORDER_XSS", "POLYGLOT"):
            return {
                "anomaly_id": a_id,
                "classification": "Confirmed Vulnerability",
                "confidence_score": 0.95,
                "cve_cwe_mapping": "CWE-79",
                "cvss_score": 6.1,
                "cvss_justification": "Reflected XSS — injection payload echoed in response with special characters intact",
                "remediation_snippet": "Encode all user input before rendering in HTML context. Use context-aware output encoding.",
            }

        # SQLi reflection
        if "reflected in response" in delta.lower() and vuln_class == "SQLI":
            return {
                "anomaly_id": a_id,
                "classification": "Confirmed Vulnerability",
                "confidence_score": 0.90,
                "cve_cwe_mapping": "CWE-89",
                "cvss_score": 8.6,
                "cvss_justification": "SQL injection payload reflected — likely unsanitized query parameter",
                "remediation_snippet": "Use parameterized queries / prepared statements. Never concatenate user input into SQL.",
            }

        # Auth bypass — 401/403 -> 200
        if "access control bypass" in delta.lower():
            return {
                "anomaly_id": a_id,
                "classification": "Confirmed Vulnerability",
                "confidence_score": 0.99,
                "cve_cwe_mapping": "CWE-284",
                "cvss_score": 9.1,
                "cvss_justification": "Broken access control — privileged endpoint accessible without proper authorization",
                "remediation_snippet": "Enforce server-side authorization checks on every request. Do not rely on client-side controls.",
            }

        # Removed: Server error triggered by injection payload block
        # Path traversal with indicator match
        if vuln_class == "PATH_TRAVERSAL" and "expected string found" in delta.lower():
            return {
                "anomaly_id": a_id,
                "classification": "Confirmed Vulnerability",
                "confidence_score": 0.95,
                "cve_cwe_mapping": "CWE-22",
                "cvss_score": 7.5,
                "cvss_justification": "Path traversal payload triggered expected file content in response",
                "remediation_snippet": "Validate file paths against an allowlist. Use canonical path resolution and reject any path containing '..'.",
            }

        return None  # Falls through to LLM triage

    def triage_anomalies(self):
        """Batch process anomalies via heuristic pre-classification + LLM."""
        anomalies = self.fetch_pending_anomalies()
        if not anomalies:
            logger.info("No pending anomalies to triage.")
            return

        logger.info(f"Triaging {len(anomalies)} anomalies...")

        # Phase 1: Heuristic pre-classification (deterministic, no LLM)
        llm_batch = []
        pre_classified = 0

        for anomaly in anomalies:
            result = self._pre_classify(anomaly)
            if result:
                # Auto-classified — write directly to DB
                a_id = result["anomaly_id"]
                self.db.execute("""
                    UPDATE anomalies
                    SET triage_status = ?, cvss_score = ?, cwe_id = ?, llm_details = ?
                    WHERE id = ?
                """, (
                    result.get("classification", "Requires Manual Review"),
                    result.get("cvss_score"),
                    result.get("cve_cwe_mapping"),
                    json.dumps(result),
                    a_id,
                ))
                pre_classified += 1
            else:
                llm_batch.append(anomaly)

        self.db.commit()
        logger.info(f"Pre-classified {pre_classified} anomalies heuristically. {len(llm_batch)} remaining for LLM.")

        if not llm_batch:
            return
        
        # Phase 2: LLM triage for remaining anomalies
        batch_size = 5
        total_batches = (len(llm_batch) + batch_size - 1) // batch_size

        for i in range(0, len(llm_batch), batch_size):
            batch = llm_batch[i:i+batch_size]
            
            try:
                user_prompt = json.dumps(batch, indent=2)
                logger.info(f"Sending batch {i//batch_size + 1}/{total_batches} to LLM...")
                response = self.client.generate_json(self.SYSTEM_PROMPT, user_prompt)
                
                if isinstance(response, dict):
                    # Sometimes model returns an object like {"results": [...]} instead of an array
                    if "results" in response:
                        response = response["results"]
                    else:
                        response = [response]
                
                # Update database
                for item in response:
                    a_id = item.get("anomaly_id")
                    if not a_id: continue
                    
                    self.db.execute("""
                        UPDATE anomalies 
                        SET triage_status = ?, cvss_score = ?, cwe_id = ?
                        WHERE id = ?
                    """, (
                        item.get("classification", "Requires Manual Review"),
                        item.get("cvss_score"),
                        item.get("cve_cwe_mapping"),
                        a_id
                    ))
                    
                    # Store remediation details
                    self.db.execute("""
                        UPDATE anomalies SET llm_details = ? WHERE id = ?
                    """, (json.dumps(item), a_id))
                    
                self.db.commit()
            except Exception as e:
                logger.error(f"Failed to triage batch: {e}")

    def generate_report(self):
        """Compiles the HTML and JSON reports."""
        logger.info("Generating reports...")
        
        # 1. Fetch all triaged anomalies
        cursor = self.db.execute("""
            SELECT a.id, a.status_code, a.baseline_delta, a.triage_status, a.cvss_score, a.cwe_id, a.llm_details,
                   e.url, e.method, e.role, p.payload, p.target_param, p.vuln_class
            FROM anomalies a
            JOIN endpoints e ON a.endpoint_id = e.id
            JOIN payload_cache p ON a.payload_id = p.id
            ORDER BY a.cvss_score DESC
        """)
        
        findings = []
        stats = {
            "Confirmed Vulnerability": 0,
            "Likely False Positive": 0,
            "Requires Manual Review": 0,
            "pending": 0,
        }
        
        for row in cursor.fetchall():
            d = dict(row)
            status = d.get("triage_status", "pending")
            stats[status] = stats.get(status, 0) + 1
            if d.get("llm_details"):
                try:
                    d["llm_details"] = json.loads(d["llm_details"])
                except (json.JSONDecodeError, TypeError):
                    pass
            findings.append(d)

        # 2. Compute Coverage Matrix
        cursor = self.db.execute("""
            SELECT e.url, e.role, p.vuln_class, count(*) as payload_count
            FROM endpoints e
            JOIN payload_cache p ON e.schema_hash = p.schema_hash
            GROUP BY e.url, e.role, p.vuln_class
        """)
        
        coverage = [dict(r) for r in cursor.fetchall()]

        # 3. Fetch passive findings (JS scanner, passive analyzer, BAC comparator)
        passive_findings = []
        try:
            passive_cursor = self.db.execute(
                "SELECT * FROM passive_findings ORDER BY "
                "CASE severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 "
                "WHEN 'Medium' THEN 3 WHEN 'Low' THEN 4 ELSE 5 END"
            )
            passive_findings = [dict(r) for r in passive_cursor.fetchall()]
        except sqlite3.OperationalError:
            # Table may not exist in older DBs
            pass

        # Group findings by vuln_class for the report
        grouped_findings = {}
        for f in findings:
            vclass = f.get("vuln_class", "UNKNOWN")
            if vclass not in grouped_findings:
                grouped_findings[vclass] = []
            grouped_findings[vclass].append(f)

        report_data = {
            "summary": stats,
            "findings": findings,
            "grouped_findings": grouped_findings,
            "coverage": coverage,
            "passive_findings": passive_findings,
        }

        # Dump JSON
        json_path = RESULTS_DIR / "report.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)
            
        # Render HTML
        from jinja2 import select_autoescape
        env = FileSystemLoader(searchpath="./")
        jinja_env = Environment(
            loader=env,
            autoescape=select_autoescape(['html', 'xml'])
        )
        try:
            template = jinja_env.get_template("report_template.html")
            html_out = template.render(report=report_data)
            
            html_path = RESULTS_DIR / "report.html"
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(html_out)
            logger.info(f"Reports generated: {json_path} and {html_path}")
        except Exception as e:
            logger.error(f"Failed to render HTML report: {e}")

if __name__ == "__main__":
    engine = TriageEngine()
    engine.triage_anomalies()
    engine.generate_report()
