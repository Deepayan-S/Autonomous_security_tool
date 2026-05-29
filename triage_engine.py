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
    
    SYSTEM_PROMPT = """You are a Senior Application Security Engineer. Your task is to triage anomalous responses detected during fuzzing.
You will be provided with a JSON array of anomalies. Each anomaly contains the payload, endpoint context, and baseline deltas.
Your job is to classify each anomaly and return a JSON array containing EXACTLY one object per input anomaly, in the exact same order.

For each anomaly, your output object MUST have:
1. "anomaly_id": The exact ID provided in the input.
2. "classification": One of ["Confirmed Vulnerability", "Likely False Positive", "Requires Manual Review"].
3. "confidence_score": A float between 0.0 and 1.0.
4. "cve_cwe_mapping": Provide a relevant CWE ID (e.g., "CWE-89") if it's a Confirmed Vulnerability, else "".
5. "cvss_score": Provide a CVSS v3.1 base score (float 0.0-10.0) if Confirmed Vulnerability, else null.
6. "cvss_justification": A brief explanation of the CVSS score, else "".
7. "remediation_snippet": A secure coding snippet or advice to fix the issue, else "".

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

    def triage_anomalies(self):
        """Batch process anomalies via LLM."""
        anomalies = self.fetch_pending_anomalies()
        if not anomalies:
            logger.info("No pending anomalies to triage.")
            return

        logger.info(f"Triaging {len(anomalies)} anomalies...")
        
        # Process in batches of 5
        batch_size = 5
        total_batches = (len(anomalies) + batch_size - 1) // batch_size
        
        for i in range(0, len(anomalies), batch_size):
            batch = anomalies[i:i+batch_size]
            user_prompt = json.dumps(batch, indent=2)
            
            logger.info(f"Sending batch {i//batch_size + 1}/{total_batches} to LLM...")
            
            try:
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
            "Requires Manual Review": 0
        }
        
        for row in cursor.fetchall():
            d = dict(row)
            stats[d["triage_status"]] = stats.get(d["triage_status"], 0) + 1
            if d.get("llm_details"):
                d["llm_details"] = json.loads(d["llm_details"])
            findings.append(d)

        # 2. Compute Coverage Matrix
        cursor = self.db.execute("""
            SELECT e.url, e.role, p.vuln_class, count(*) as payload_count
            FROM endpoints e
            JOIN payload_cache p ON e.schema_hash = p.schema_hash
            GROUP BY e.url, e.role, p.vuln_class
        """)
        
        coverage = [dict(r) for r in cursor.fetchall()]

        report_data = {
            "summary": stats,
            "findings": findings,
            "coverage": coverage
        }

        # Dump JSON
        json_path = RESULTS_DIR / "report.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)
            
        # Render HTML
        env = FileSystemLoader(searchpath="./")
        jinja_env = Environment(loader=env)
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
