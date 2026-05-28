import base64
import hashlib
import json
import logging
import re
import urllib.parse
from typing import Set, Dict, List
from playwright.async_api import Request, Response

import ahvf_crawler.db as db
from ahvf_crawler.config import CrawlConfig

logger = logging.getLogger("ahvf_crawler.network")

def _fingerprint(url: str, method: str) -> str:
    parsed = urllib.parse.urlparse(url)
    params = sorted(urllib.parse.parse_qs(parsed.query).keys())
    
    # Typed placeholders for integers and UUIDs
    path_segments = parsed.path.split('/')
    for i, seg in enumerate(path_segments):
        if seg.isdigit():
            path_segments[i] = "{INT}"
        elif re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', seg, re.I):
            path_segments[i] = "{UUID}"
            
    canon_path = "/".join(path_segments)
    canonical = f"{method.upper()}:{parsed.scheme}://{parsed.netloc}{canon_path}?{','.join(params)}"
    return hashlib.sha256(canonical.encode()).hexdigest()[:16]

def _extract_jwt(value: str) -> str | None:
    jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
    m = re.search(jwt_pattern, value)
    return m.group(0) if m else None

def parse_jwt_exp(jwt_token: str) -> int:
    try:
        payload_b64 = jwt_token.split('.')[1]
        payload_b64 += '=' * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64).decode())
        return payload.get("exp", 0)
    except:
        return 0

def make_request_handler(
    role: str,
    config: CrawlConfig,
    seen_hashes: Set[str],
    current_jwt: List[str],  # mutable ref
    current_csrf: List[str], # mutable ref
    context_cookies: List[Dict]
):
    async def on_request(request: Request):
        url = request.url
        method = request.method
        
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname or ""
        in_scope = any(host == s or host.endswith(f".{s}") for s in config.scope_hosts)
        
        # Scope Whitelist enforcement at HTTP layer
        if not in_scope:
            return
            
        excluded = any(parsed.path.startswith(ex) for ex in config.excluded_paths)
        if excluded or url.endswith((".css", ".png", ".jpg", ".gif", ".ico", ".woff", ".svg", ".woff2")):
            return

        fp = _fingerprint(url, method)
        if fp in seen_hashes:
            return
        seen_hashes.add(fp)

        headers = dict(request.headers)
        
        # Extract JWT
        jwt = None
        auth_header = headers.get("authorization", "")
        if auth_header.lower().startswith("bearer "):
            jwt = auth_header[7:]
        elif current_jwt[0]:
            jwt = current_jwt[0]
        else:
            for c in context_cookies:
                found = _extract_jwt(c.get("value", ""))
                if found:
                    jwt = found
                    break
        
        if jwt and not current_jwt[0]:
            current_jwt[0] = jwt

        # Extract CSRF
        csrf = None
        for hname in ("x-csrf-token", "x-xsrf-token", "csrf-token", "_csrf"):
            if hname in headers:
                csrf = headers[hname]
                break
        
        if csrf and not current_csrf[0]:
            current_csrf[0] = csrf

        # Strip headers down to safe set
        safe_headers = {
            k: v for k, v in headers.items() 
            if k.lower() in ("accept", "content-type", "user-agent", "origin", "referer", "host")
        }

        # Write to DB initially (status & hash will be updated on response)
        ep = {
            "role": role,
            "method": method,
            "url": url,
            "schema_hash": fp,
            "headers": json.dumps(safe_headers),
            "source": f"network ({request.resource_type})"
        }
        await db.save_endpoint(config.db_path, ep)

    return on_request


def make_response_handler(role: str, config: CrawlConfig):
    async def on_response(response: Response):
        url = response.url
        method = response.request.method
        
        # Skip binary / non-scope quickly
        if url.endswith((".css", ".png", ".jpg", ".gif", ".ico", ".woff", ".svg", ".woff2")):
            return

        fp = _fingerprint(url, method)
        
        baseline_hash = ""
        baseline_len = 0
        status = response.status
        
        try:
            # We discard binary bodies immediately after hashing
            if response.request.resource_type in ("fetch", "xhr", "document"):
                body_bytes = await response.body()
                baseline_len = len(body_bytes)
                baseline_hash = hashlib.sha256(body_bytes).hexdigest()
        except Exception:
            pass
            
        # Update endpoint in DB
        ep = {
            "role": role,
            "method": method,
            "url": url,
            "schema_hash": fp,
            "baseline_hash": baseline_hash,
            "baseline_status": status,
            "baseline_content_length": baseline_len
        }
        await db.save_endpoint(config.db_path, ep)

    return on_response
