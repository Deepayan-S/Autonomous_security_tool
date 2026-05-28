import asyncio
import hashlib
import json
import logging
from typing import Dict, List
from playwright.async_api import async_playwright

import ahvf_crawler.db as db
from ahvf_crawler.config import CrawlConfig

logger = logging.getLogger("ahvf_crawler.bac")

async def test_endpoint(page, method: str, url: str, headers: dict) -> dict:
    """Send a request via Playwright fetch to inherit context (cookies)."""
    try:
        resp = await page.request.fetch(
            url, 
            method=method, 
            headers=headers,
            max_redirects=0 # Don't follow redirects for BAC, 302 usually means unauthorized
        )
        body = await resp.body()
        return {
            "status": resp.status,
            "content_length": len(body),
            "body_hash": hashlib.sha256(body).hexdigest()
        }
    except Exception as e:
        return {"error": str(e)}

async def run_bac_engine(config: CrawlConfig):
    """
    M1 Engine: Cross-pollinates discovered endpoints against missing roles.
    """
    logger.info("Starting BAC Cross-Pollination Engine...")
    await db.update_pipeline_state(config.db_path, "bac_engine", "in_progress")
    
    endpoints = await db.get_endpoints_for_bac(config.db_path)
    sessions = {}
    
    for role in config.roles.keys():
        s = await db.get_session(config.db_path, role)
        if s:
            sessions[role] = s

    # Map URLs to discovering roles to avoid testing against roles that already found it
    # Note: schema_hash deduplicates URL+Method
    url_role_map = {}
    for ep in endpoints:
        if ep['schema_hash'] not in url_role_map:
            url_role_map[ep['schema_hash']] = set()
        url_role_map[ep['schema_hash']].add(ep['role'])

    async with async_playwright() as pw:
        # Create a browser context for each role to perform tests
        contexts = {}
        pages = {}
        browser = await pw.chromium.launch(headless=True)
        
        for role, session in sessions.items():
            ctx = await browser.new_context(ignore_https_errors=True)
            if session.get("storage_state"):
                try:
                    await ctx.add_cookies(json.loads(session["storage_state"]).get("cookies", []))
                except:
                    pass
            contexts[role] = ctx
            pages[role] = await ctx.new_page()

        for ep in endpoints:
            discovering_roles = url_role_map[ep['schema_hash']]
            missing_roles = [r for r in config.roles.keys() if r not in discovering_roles]
            
            headers = {}
            try:
                if ep['headers']:
                    headers = json.loads(ep['headers'])
            except:
                pass
            
            # Cross-Pollination Tests
            for m_role in missing_roles:
                page = pages.get(m_role)
                if not page:
                    continue
                    
                # Reconstruct JWT/CSRF if present in session
                m_session = sessions[m_role]
                test_headers = dict(headers)
                if m_session.get("jwt"):
                    test_headers["Authorization"] = f"Bearer {m_session['jwt']}"
                if m_session.get("csrf_token"):
                    test_headers["X-CSRF-Token"] = m_session["csrf_token"]
                    
                result = await test_endpoint(page, ep['method'], ep['url'], test_headers)
                
                # Compare against baseline
                if result.get("status") == 200 and ep.get("baseline_status") == 200:
                    if result.get("content_length", 0) > 0:
                        anomaly = {
                            "endpoint_id": ep['id'],
                            "anomaly_type": "BAC_CANDIDATE",
                            "details": {
                                "tested_role": m_role,
                                "original_role": ep['role'],
                                "status_code": result.get("status"),
                                "baseline_hash": ep.get('baseline_hash'),
                                "test_hash": result.get("body_hash")
                            }
                        }
                        await db.save_anomaly(config.db_path, anomaly)
                        logger.warning(f"[BAC] Candidate found at {ep['url']} (Role: {m_role})")
            
            # HTTP Verb Tampering
            verbs = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]
            test_verbs = [v for v in verbs if v != ep['method']]
            for m_role in config.roles.keys():
                page = pages.get(m_role)
                if not page:
                    continue
                    
                for verb in test_verbs:
                    result = await test_endpoint(page, verb, ep['url'], headers)
                    if result.get("status") == 200 and result.get("content_length", 0) > 0:
                        anomaly = {
                            "endpoint_id": ep['id'],
                            "anomaly_type": "VERB_TAMPERING",
                            "details": {
                                "tested_role": m_role,
                                "original_method": ep['method'],
                                "tested_method": verb,
                                "status_code": result.get("status")
                            }
                        }
                        await db.save_anomaly(config.db_path, anomaly)

            # IDOR Probes
            if ep.get('idor_candidate'):
                # Basic sequential test if path has INT
                # E.g., /users/5 -> /users/6
                import re
                url = ep['url']
                int_match = re.search(r'/(\d+)(/|$|\?)', url)
                if int_match:
                    orig_val = int_match.group(1)
                    new_val = str(int(orig_val) + 1)
                    idor_url = url.replace(f"/{orig_val}", f"/{new_val}")
                    
                    for m_role in config.roles.keys():
                        page = pages.get(m_role)
                        if not page:
                            continue
                        result = await test_endpoint(page, ep['method'], idor_url, headers)
                        if result.get("status") == 200:
                            anomaly = {
                                "endpoint_id": ep['id'],
                                "anomaly_type": "IDOR_CANDIDATE",
                                "details": {
                                    "tested_role": m_role,
                                    "original_url": url,
                                    "tested_url": idor_url,
                                    "status_code": result.get("status")
                                }
                            }
                            await db.save_anomaly(config.db_path, anomaly)

        await browser.close()
    
    await db.update_pipeline_state(config.db_path, "bac_engine", "completed")
    logger.info("BAC Cross-Pollination Engine complete.")
