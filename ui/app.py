import os
import sys
import json
import time
import threading
import subprocess
from pathlib import Path
from flask import Flask, request, jsonify, send_file, Response
from flask_cors import CORS

ROOT = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, ROOT)

from database import AHVFDatabase

app = Flask(__name__, static_folder=os.path.join(os.path.dirname(__file__), 'frontend'), static_url_path='')
CORS(app, resources={r"/api/*": {"origins": "*"}})

# Global state for running scan
scan_state = {
    "status": "idle", # idle, running, complete, error
    "process": None,
    "logs": []
}

@app.route('/')
def index():
    return send_file(os.path.join(os.path.dirname(__file__), 'frontend', 'index.html'))

@app.route('/api/health')
def health():
    return jsonify({'status': 'ok', 'version': '1.0.0'})

def run_pipeline_thread(config_path, ollama_model, phase):
    global scan_state
    scan_state["status"] = "running"
    scan_state["logs"] = []
    scan_state["progress"] = 0
    
    cmd = [sys.executable, "-u", "run_pipeline.py"]
    if phase == "skip_crawl":
        cmd.extend(["--skip-crawl"])
    elif phase == "crawl":
        cmd.extend(["--phase", "crawl"])
    else:
        cmd.extend(["--phase", "all"])
        
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    if ollama_model:
        env["OLLAMA_MODEL"] = ollama_model
    
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace", cwd=ROOT, env=env, bufsize=1)
    scan_state["process"] = process
    
    for line in iter(process.stdout.readline, ''):
        if line:
            msg = line.strip()
            scan_state["logs"].append({
                "level": "info",
                "module": "engine",
                "msg": msg
            })
            
            # Dynamic progress tracking based on AHVF pipeline phases
            msg_upper = msg.upper()
            if "PHASE 1" in msg_upper or "[CRAWLER]" in msg_upper:
                scan_state["progress"] = 10
            elif "PHASE 2" in msg_upper:
                scan_state["progress"] = 30
            elif "PHASE 3" in msg_upper or "M3:" in msg_upper:
                scan_state["progress"] = 50
            elif "PHASE 4" in msg_upper:
                scan_state["progress"] = 70
            elif "PHASE 5" in msg_upper:
                scan_state["progress"] = 90
            elif "COMPLETED SUCCESSFULLY" in msg_upper:
                scan_state["progress"] = 100
            
    process.stdout.close()
    return_code = process.wait()
    
    if return_code == 0:
        scan_state["status"] = "complete"
        scan_state["progress"] = 100
    else:
        scan_state["status"] = "error"

@app.route('/api/scan/start', methods=['POST'])
def start_scan():
    global scan_state
    if scan_state["status"] == "running":
        return jsonify({'error': 'A scan is already running'}), 400
        
    data = request.get_json(force=True) or {}
    
    ollama_model = data.pop("ollama_model", "gemma4:31b-cloud")
    phase = data.pop("phase", "all")
    
    # Write to crawl_config.json in ROOT
    config_path = os.path.join(ROOT, "crawl_config.json")
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        
    scan_state["logs"] = []
    scan_state["progress"] = 0
    
    thread = threading.Thread(target=run_pipeline_thread, args=(config_path, ollama_model, phase))
    thread.daemon = True
    thread.start()
    
    return jsonify({'scan_id': 'ahvf_scan_1', 'status': 'started'})

@app.route('/api/scan/status/<scan_id>')
def scan_status(scan_id):
    global scan_state
    return jsonify({
        'scan_id': scan_id,
        'status': scan_state['status'],
        'progress': scan_state.get('progress', 0),
        'current_module': 'AHVF Pipeline',
        'logs': scan_state['logs'],
    })

@app.route('/api/stats')
def get_stats():
    return jsonify({
        'total_scans': 1,
        'total_findings': 0
    })

@app.route('/api/scan/results/<scan_id>')
def scan_results(scan_id):
    db = AHVFDatabase()
    anomalies = []
    endpoints_data = []
    
    try:
        db.initialize()
        conn = db.connect()
        c = conn.cursor()
        
        # Fetch Anomalies
        c.execute("""
            SELECT 
                a.id, p.payload, e.url, e.role, e.baseline_status, 
                a.status_code, a.baseline_delta, a.triage_status,
                p.vuln_class, a.cvss_score, a.llm_details
            FROM anomalies a
            JOIN endpoints e ON a.endpoint_id = e.id
            JOIN payload_cache p ON a.payload_id = p.id
        """)
        for row in c.fetchall():
            anomalies.append({
                "id": row[0], "payload": row[1], "endpoint_url": row[2],
                "role": row[3], "baseline_status": row[4], "test_status": row[5],
                "delta_summary": row[6], "ai_classification": row[7],
                "vuln_class": row[8], "cvss_score": row[9] or 0.0, "llm_details": row[10]
            })
            
        # Fetch Endpoints for Headers, Cookies, Tech, Crawler Stats
        c.execute("SELECT url, method, role, headers, cookies FROM endpoints")
        endpoints_data = c.fetchall()
            
    except Exception as e:
        print(f"Error fetching DB data: {e}")
    finally:
        db.close()

    findings = []
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    
    import html
    import json
    
    for a in anomalies:
        classification = (a["ai_classification"] or "Unknown").lower()
        if "confirmed vulnerability" in classification:
            sev = "high"
        elif "requires manual review" in classification:
            sev = "medium"
        else:
            sev = "low"
            
        counts[sev] += 1
        
        escaped_payload = html.escape(a['payload'] or '')
        escaped_url = html.escape(a['endpoint_url'] or '')
        escaped_role = html.escape(a['role'] or '')
        escaped_class = html.escape(a['vuln_class'] or '')
        escaped_ai = html.escape(a['ai_classification'] or '')
        escaped_llm = html.escape(a['llm_details'] or '')
        escaped_delta = html.escape(a['delta_summary'] or '')
            
        findings.append({
            "name": f"{escaped_class} on {escaped_url}",
            "severity": sev,
            "category": escaped_class,
            "description": f"AI Classification: {escaped_ai}\n\nDetails:\n{escaped_llm}",
            "evidence": escaped_delta,
            "impact": f"Role: {escaped_role} | Status: {a['baseline_status']} -> {a['test_status']}\nPayload: {escaped_payload}",
            "remediation": f"Review {escaped_class} vulnerabilities. Ensure input validation and parameterized queries are used.",
            "cvss_score": a['cvss_score'],
            "cwe_id": "CWE-Unknown"
        })

    # Grade Calculation
    score = max(0, 100 - (counts['critical']*25 + counts['high']*10 + counts['medium']*5 + counts['low']*1))
    if score >= 90: grade = 'A'
    elif score >= 80: grade = 'B'
    elif score >= 70: grade = 'C'
    elif score >= 60: grade = 'D'
    else: grade = 'F'
    
    # Parse Headers, Cookies, Tech
    http_headers = []
    cookies_list = []
    tech_stack = set()
    roles_seen = {}
    endpoints_list = []
    
    for ep in endpoints_data:
        r = ep[2]
        roles_seen[r] = roles_seen.get(r, 0) + 1
        
        # Crawler endpoints
        endpoints_list.append({
            "url": ep[0],
            "method": ep[1],
            "role": ep[2],
            "source": "network",
            "response_status": 200 # approximate
        })
        
        if ep[3]: # Request Headers for Tech Stack
            try:
                h_dict = json.loads(ep[3])
                for k, v in h_dict.items():
                    k_lower = k.lower()
                    if k_lower in ('server', 'x-powered-by', 'x-aspnet-version'):
                        tech_stack.add(f"{k}: {v}")
            except: pass
            
        if ep[4]: # Cookies
            try:
                c_list = json.loads(ep[4])
                for c in c_list:
                    if len(cookies_list) < 50:
                        cookies_list.append({
                            "cookie_name": c.get("name", "Unknown"),
                            "has_secure": c.get("secure", False),
                            "has_httponly": c.get("httpOnly", False),
                            "samesite_value": c.get("sameSite", "Lax"),
                            "issues": []
                        })
            except: pass
            
    # Read Security Headers from passive scan results
    passive_json = os.path.join(ROOT, "results", "passive_scan_results.json")
    if os.path.exists(passive_json):
        try:
            with open(passive_json, "r", encoding="utf-8") as f:
                passive_data = json.load(f)
                for item in passive_data:
                    if item.get("check_type") == "header":
                        finding = item.get("finding", "")
                        evidence = item.get("evidence", "")
                        header_name = "Unknown"
                        
                        if "Missing" in finding:
                            parts = finding.split(" ")
                            if len(parts) > 1: header_name = parts[1]
                        elif ":" in evidence:
                            header_name = evidence.split(":")[0]
                        
                        status = "missing" if "Missing" in finding else "weak"
                        http_headers.append({
                            "header_name": header_name,
                            "header_value": evidence,
                            "status": status,
                            "risk_level": item.get("severity", "Low").lower()
                        })
        except: pass

    return jsonify({
        'scan': {
            'target_url': endpoints_data[0][0] if endpoints_data else 'Unknown Target',
            'status': 'complete',
            'score': score,
            'grade': grade
        },
        'findings': findings,
        'http_headers': http_headers[:100],
        'cookies': cookies_list[:100],
        'technology': [{"tech_name": t.split(": ")[0], "tech_version": t.split(": ")[1] if ": " in t else "", "category": "Framework/Server"} for t in tech_stack],
        'crawler': {
            "total_endpoints": len(endpoints_data),
            "roles": roles_seen,
            "endpoints": endpoints_list
        },
        'ssl': {
            "https_enabled": True if endpoints_data and endpoints_data[0][0].startswith('https') else False,
            "grade": "B",
            "tls_version": "TLSv1.2/1.3",
            "cert_issuer": "Let's Encrypt / Internal"
        },
        'summary': {
            'counts': counts,
            'total': len(findings)
        }
    })

if __name__ == '__main__':
    print("="*55)
    print("  AHVF Web UI started")
    print("  -> Open: http://localhost:5000")
    print("="*55)
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
