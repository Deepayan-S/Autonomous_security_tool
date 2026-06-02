"""
AHVF — BAC/IDOR Cross-Role Comparator
=========================================
Implements FR-03.1 through FR-03.5: Broken Access Control detection
by comparing endpoints across crawled roles.

Checks:
  - FR-03.1/2: Cross-role endpoint replay (Admin endpoints via User session)
  - FR-03.3: IDOR probes on numeric/UUID path segments
  - FR-03.4: HTTP verb tampering (all methods × all roles)
  - FR-03.5: Path normalization bypass tests

Precondition: Requires at least 2 roles crawled. Skips if only 1 role.

Sessions are obtained fresh via LoginAgent (not reused from crawler)
because apps expire sessions and stale tokens will 401.

USAGE:
    from bac_comparator import BACComparator
    comparator = BACComparator(db, login_agent=agent, credentials=creds)
    findings = asyncio.run(comparator.run())
"""

from __future__ import annotations
import asyncio
import json
import logging
import re
import urllib.parse
from pathlib import Path
from typing import Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("BACComparator")

RESULTS_DIR = Path("results")
RESULTS_DIR.mkdir(exist_ok=True)

# HTTP methods for verb tampering (FR-03.4)
ALL_HTTP_VERBS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]

# Path normalization bypass patterns (FR-03.5)
PATH_BYPASS_PATTERNS = [
    ("dot-dot", lambda path: path.replace("/", "/../") + "/"),
    ("case-variation", lambda path: path.upper()),
    ("url-encode", lambda path: path.replace("/", "%2f")),
    ("hex-encode", lambda path: re.sub(r"[a-zA-Z]", lambda m: f"%{ord(m.group()):02x}", path[:20]) + path[20:]),
    ("semicolon", lambda path: path.replace("/", ";/")),
    ("dot-segment", lambda path: path.replace("/", "/./")),
]

# Common public endpoints that should NOT be flagged as BAC.
# These are pages/routes accessible to all roles by design.
COMMON_PUBLIC_PATHS = {
    "home", "login", "logout", "signin", "signup", "register",
    "dashboard", "about", "contact", "index", "main",
    "forgot-password", "reset-password", "change-password",
    "terms", "privacy", "help", "faq", "error", "404", "500",
    "health", "ping", "status", "favicon.ico",
}


def _is_common_public_endpoint(url: str) -> bool:
    """Check if a URL path ends with a common public route segment."""
    parsed = urllib.parse.urlparse(url)
    path = parsed.path.rstrip("/").lower()
    # Check the last segment of the path
    last_segment = path.split("/")[-1] if path else ""
    if last_segment in COMMON_PUBLIC_PATHS:
        return True
    # Also check the full path against common patterns
    for common in COMMON_PUBLIC_PATHS:
        if path.endswith(f"/{common}") or path.endswith(f"/{common}/"):
            return True
    return False


def _extract_ids_from_json(data) -> set:
    ids = set()
    if isinstance(data, dict):
        for v in data.values():
            ids.update(_extract_ids_from_json(v))
    elif isinstance(data, list):
        for item in data:
            ids.update(_extract_ids_from_json(item))
    elif isinstance(data, (str, int)):
        val = str(data)
        if val.isdigit() and len(val) <= 10:
            ids.add(val)
        elif re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', val, re.IGNORECASE):
            ids.add(val)
    return ids

def _substitute_id_in_json(data, old_id: str, new_id: str):
    if isinstance(data, dict):
        return {k: _substitute_id_in_json(v, old_id, new_id) for k, v in data.items()}
    elif isinstance(data, list):
        return [_substitute_id_in_json(item, old_id, new_id) for item in data]
    elif isinstance(data, (str, int)):
        val = str(data)
        if val == old_id:
            return int(new_id) if isinstance(data, int) and new_id.isdigit() else new_id
        return data
    return data

def _normalize_endpoint_key(ep: dict) -> tuple:
    """Normalize an endpoint to (path, method) for comparison across roles.
    
    Uses the URL path (without query params) to match endpoints.
    This prevents false mismatches when the same API was crawled
    with different query parameters for different roles.
    """
    parsed = urllib.parse.urlparse(ep["url"])
    return (parsed.path.rstrip("/").lower(), ep["method"].upper())

# Privilege hierarchy (higher index = more privileged)
DEFAULT_PRIVILEGE_ORDER = [
    "guest", "unauthenticated", "public",
    "user", "member", "employee", "standard",
    "manager", "moderator", "editor",
    "admin", "administrator", "superadmin", "root",
]


# ─────────────────────────────────────────────
#  BAC COMPARATOR CLASS
# ─────────────────────────────────────────────

class BACComparator:
    """
    Compares endpoints across crawled roles to detect
    Broken Access Control and IDOR vulnerabilities.
    """

    def __init__(
        self,
        db=None,
        login_agent=None,
        credentials: dict = None,
    ):
        """
        Args:
            db: AHVFDatabase instance
            login_agent: LoginAgent instance for session management
            credentials: Dict of {role: (username, password)} for re-auth
        """
        self.db = db
        self.login_agent = login_agent
        self.credentials = credentials or {}
        self.findings: list[dict] = []
        self.ollama_client = None

    async def _verify_bac_with_ai(self, method: str, url: str, role_low: str, role_high: str, replay_status: int, replay_body: str) -> bool:
        """Use LLM to verify if a 200 OK response is a genuine BAC leak or a soft error."""
        if replay_status != 200:
            return False

        if not self.ollama_client:
            try:
                from ollama_client import OllamaClient
                self.ollama_client = OllamaClient()
                self.ollama_client.health_check()
            except Exception as e:
                logger.error(f"Failed to initialize OllamaClient for BAC triage: {e}")
                return True  # Fallback to True if AI is unavailable

        system_prompt = '''You are an expert API security analyst. A lower privileged user attempted to access an endpoint reserved for a higher privileged user.
The server returned HTTP 200. However, many APIs return HTTP 200 even for errors (e.g. {"success": false, "message": "Unauthorized"}).
Analyze the response body and determine if the access was ACTUALLY successful (sensitive data leaked, state changed, or action confirmed) or if it's just a soft error.
Respond with a JSON object containing exactly one boolean key "is_vulnerable".
Example 1: {"success": false, "message": "Access denied"} -> {"is_vulnerable": false}
Example 2: {"success": true, "data": {"user": "admin"}} -> {"is_vulnerable": true}
Example 3: <html><body>Login required</body></html> -> {"is_vulnerable": false}'''
        
        user_prompt = f"Endpoint: {method} {url}\nResponse Body:\n{replay_body[:1500]}"
        
        try:
            result = await asyncio.to_thread(
                self.ollama_client.generate_json,
                system_prompt,
                user_prompt,
                temperature=0.1
            )
            return bool(result.get("is_vulnerable", True))
        except Exception as e:
            logger.warning(f"AI BAC verification failed: {e}. Defaulting to True.")
            return True

    def _get_privilege_rank(self, role: str) -> int:
        """Get numeric privilege rank for a role. Higher = more privileged."""
        role_lower = role.lower().strip()
        for i, level in enumerate(DEFAULT_PRIVILEGE_ORDER):
            if level in role_lower or role_lower in level:
                return i
        return len(DEFAULT_PRIVILEGE_ORDER) // 2  # Default: mid-level

    async def run(self) -> list[dict]:
        """
        Main entry point. Runs all BAC/IDOR checks.

        Returns list of finding dicts.
        """
        if not self.db:
            logger.error("No database provided.")
            return []

        # Load all endpoints grouped by role
        all_endpoints = self.db.get_all_endpoints()
        if not all_endpoints:
            logger.info("No endpoints in database.")
            return []

        # Group by role
        role_endpoints: dict[str, list[dict]] = {}
        for ep in all_endpoints:
            role = ep.get("role", "unknown")
            role_endpoints.setdefault(role, []).append(ep)

        roles = list(role_endpoints.keys())
        if len(roles) < 2:
            logger.info(f"Only {len(roles)} role(s) crawled — BAC comparison requires at least 2. Skipping.")
            return []

        logger.info(f"BAC Comparator: {len(roles)} roles detected: {roles}")

        # Sort roles by privilege (ascending)
        roles_sorted = sorted(roles, key=lambda r: self._get_privilege_rank(r))
        logger.info(f"Privilege order (low→high): {roles_sorted}")

        import aiohttp
        connector = aiohttp.TCPConnector(ssl=False, limit=5)

        async with aiohttp.ClientSession(connector=connector) as session:
            # FR-03.1/2: Cross-role endpoint replay
            await self._cross_role_replay(session, role_endpoints, roles_sorted)

            # FR-03.3: IDOR probes
            await self._idor_probes(session, role_endpoints, roles_sorted)

            # FR-03.4: HTTP verb tampering
            await self._verb_tampering(session, role_endpoints, roles_sorted)

            # FR-03.5: Path normalization bypass
            await self._path_normalization_bypass(session, role_endpoints, roles_sorted)

        logger.info(f"BAC Comparator complete: {len(self.findings)} findings")

        # Write results
        self._write_results()

        # Store in DB
        if self.db:
            try:
                self.db.insert_passive_findings(self.findings)
            except Exception as e:
                logger.error(f"Failed to store BAC findings in DB: {e}")

        return self.findings

    async def _get_session_headers(self, role: str) -> dict:
        """Get fresh auth headers for a role using LoginAgent or cached credentials."""
        headers = {"User-Agent": "AHVF-SecurityScanner/1.0 (authorized-testing)"}
        
        cookies = {}

        # Load from storage_state if available (Pass 3 requirement)
        import os
        state_path = f"results/state_{role}.json"
        if os.path.exists(state_path):
            try:
                with open(state_path, 'r', encoding='utf-8') as f:
                    state_data = json.load(f)
                    for c in state_data.get("cookies", []):
                        cookies[c["name"]] = c["value"]
            except Exception as e:
                logger.warning(f"Failed to load storage state for role {role}: {e}")

        # Try LoginAgent first
        if self.login_agent:
            creds = self.credentials.get(role, ("", ""))
            if creds[0]:  # Has username
                try:
                    session_data = await self.login_agent.get_session(
                        role, username=creds[0], password=creds[1]
                    )
                    if session_data:
                        headers.update(session_data.headers)
                        # Also set cookies via Cookie header
                        if session_data.cookies:
                            for c in session_data.cookies:
                                cookies[c["name"]] = c["value"]
                except Exception as e:
                    logger.warning(f"LoginAgent failed for role '{role}': {e}")

        # Fallback: use JWT/cookies from DB endpoints
        if self.db:
            endpoints = [ep for ep in self.db.get_all_endpoints() if ep.get("role") == role]
            for ep in endpoints:
                jwt = ep.get("jwt")
                if jwt:
                    headers["Authorization"] = f"Bearer {jwt}"
                ep_cookies = ep.get("cookies")
                if ep_cookies:
                    try:
                        import json as local_json
                        ep_cookies = local_json.loads(ep_cookies)
                        if isinstance(ep_cookies, list):
                            for c in ep_cookies:
                                cookies[c["name"]] = c["value"]
                        elif isinstance(ep_cookies, dict):
                            cookies.update(ep_cookies)
                    except Exception:
                        pass
                if jwt or cookies:
                    break
                    
        if cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
            headers["Cookie"] = cookie_str

        return headers

    async def _make_request(self, session, method: str, url: str, headers: dict, data: Optional[str] = None) -> Optional[dict]:
        """Make an HTTP request and return status + response info."""
        try:
            import aiohttp
            
            # If the request is a POST/PUT/PATCH and we have data, we should include the Content-Type
            # But the original headers are usually already there.
            kwargs = {
                "headers": headers,
                "timeout": aiohttp.ClientTimeout(total=10),
                "allow_redirects": False,
                "ssl": False,
            }
            if data and method.upper() in ["POST", "PUT", "PATCH"]:
                kwargs["data"] = data

            async with session.request(method, url, **kwargs) as resp:
                body = ""
                try:
                    body = await resp.text(errors="replace")
                except Exception:
                    pass

                return {
                    "status": resp.status,
                    "body_length": len(body),
                    "body_preview": body[:200] if body else "",
                }
        except Exception as e:
            logger.debug(f"Request failed: {method} {url}: {e}")
            return None

    # ── FR-03.1/2: Cross-Role Endpoint Replay ────────────────

    async def _cross_role_replay(
        self, session, role_endpoints: dict, roles_sorted: list
    ) -> None:
        """
        For each high-privilege endpoint NOT found in low-privilege crawl,
        replay the request using the low-privilege session.
        """
        logger.info("  [FR-03.1/2] Cross-role endpoint replay...")

        for i, low_role in enumerate(roles_sorted[:-1]):
            for high_role in roles_sorted[i + 1:]:
                # Normalize low-privilege endpoints by (path, method)
                low_keys = {
                    _normalize_endpoint_key(ep)
                    for ep in role_endpoints.get(low_role, [])
                }
                high_eps = role_endpoints.get(high_role, [])

                # Find API endpoints exclusive to the higher-privilege role,
                # excluding common public pages (home, login, dashboard, etc.)
                admin_only = [
                    ep for ep in high_eps
                    if _normalize_endpoint_key(ep) not in low_keys
                    and not _is_common_public_endpoint(ep["url"])
                ]

                if not admin_only:
                    logger.info(f"    No exclusive endpoints for '{high_role}' vs '{low_role}'")
                    continue

                logger.info(f"    Testing {len(admin_only)} '{high_role}'-only endpoints with '{low_role}' session...")

                # Get fresh session for low-privilege role
                low_headers = await self._get_session_headers(low_role)

                for ep in admin_only[:50]:  # Cap at 50 to prevent overload
                    url = ep["url"]
                    method = ep["method"]
                    # Get original headers and inject auth
                    req_headers = dict(ep.get("headers", {}))
                    req_headers.update(low_headers)
                    body_data = ep.get("body", "")

                    result = await self._make_request(session, method, url, req_headers, data=body_data)
                    if not result:
                        continue

                    if result["status"] == 200:
                        is_vuln = await self._verify_bac_with_ai(method, url, low_role, high_role, result["status"], result.get("body_preview", ""))
                        if is_vuln:
                            self.findings.append({
                                "url": url,
                                "check_type": "bac",
                                "finding": f"BAC: '{high_role}'-only endpoint accessible by '{low_role}' ({method})",
                                "severity": "Critical",
                                "evidence": f"{method} {url} → HTTP {result['status']} (body: {result['body_length']} bytes)",
                                "cwe_id": "CWE-284",
                                "remediation": "Enforce server-side authorization. Verify user role/permissions on every request.",
                                "role": low_role,
                            })
                    elif result["status"] in (401, 403):
                        logger.debug(f"    Access correctly denied: {method} {url} → {result['status']}")

    # ── FR-03.3: IDOR Probes ─────────────────────────────────

    async def _idor_probes(
        self, session, role_endpoints: dict, roles_sorted: list
    ) -> None:
        """
        For endpoints with numeric/UUID path segments, substitute IDs
        from one role's endpoints into another role's session.
        """
        logger.info("  [FR-03.3] IDOR probes...")

        # Extract numeric path segments from each role's endpoints
        role_ids: dict[str, set] = {}
        id_endpoints: list[dict] = []

        for role, eps in role_endpoints.items():
            ids = set()
            for ep in eps:
                has_id = False
                # Extract numeric segments from URL path
                parsed = urllib.parse.urlparse(ep["url"])
                segments = parsed.path.split("/")
                for seg in segments:
                    if seg.isdigit() and len(seg) <= 10:
                        ids.add(seg)
                        has_id = True
                    # UUID detection
                    elif re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', seg, re.IGNORECASE):
                        ids.add(seg)
                        has_id = True

                # Extract IDs from query parameters
                query_params = urllib.parse.parse_qs(parsed.query)
                for values in query_params.values():
                    for val in values:
                        if val.isdigit() and len(val) <= 10:
                            ids.add(val)
                            has_id = True
                        elif re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', val, re.IGNORECASE):
                            ids.add(val)
                            has_id = True

                # Extract IDs from JSON body
                body_data = ep.get("body")
                if body_data:
                    try:
                        import json as local_json
                        body_json = local_json.loads(body_data)
                        body_ids = _extract_ids_from_json(body_json)
                        if body_ids:
                            ids.update(body_ids)
                            has_id = True
                            ep["_parsed_body"] = body_json  # cache for later substitution
                    except Exception:
                        pass

                # Tag endpoints with numeric/UUID segments
                if has_id:
                    id_endpoints.append(ep)

            role_ids[role] = ids

        if not id_endpoints:
            logger.info("    No endpoints with numeric/UUID path segments found")
            return

        # For each pair of roles, try swapping IDs
        for i, role_a in enumerate(roles_sorted):
            for role_b in roles_sorted[i + 1:]:
                ids_a = role_ids.get(role_a, set())
                ids_b = role_ids.get(role_b, set())

                # Find IDs that belong to role_b but not role_a
                foreign_ids = ids_b - ids_a
                if not foreign_ids:
                    continue

                logger.info(f"    Testing {len(foreign_ids)} '{role_b}' IDs in '{role_a}' session...")
                headers_a = await self._get_session_headers(role_a)

                for ep in id_endpoints[:20]:  # Cap
                    if ep["role"] != role_a:
                        continue

                    parsed = urllib.parse.urlparse(ep["url"])
                    segments = parsed.path.split("/")
                    
                    # 1. Substitute in path segments
                    for seg_idx, seg in enumerate(segments):
                        if not seg.isdigit() and not re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', seg, re.IGNORECASE):
                            continue

                        # Substitute with a foreign ID
                        for foreign_id in list(foreign_ids)[:3]:  # Test up to 3 foreign IDs
                            new_segments = segments.copy()
                            new_segments[seg_idx] = foreign_id
                            new_path = "/".join(new_segments)
                            new_url = urllib.parse.urlunparse(parsed._replace(path=new_path))
                            
                            body_data = ep.get("body", "")

                            result = await self._make_request(session, ep["method"], new_url, headers_a, data=body_data)
                            if not result:
                                continue

                            if result["status"] == 200 and result["body_length"] > 50:
                                is_vuln = await self._verify_bac_with_ai(ep["method"], new_url, role_a, role_b, result["status"], result.get("body_preview", ""))
                                if is_vuln:
                                    self.findings.append({
                                        "url": new_url,
                                        "check_type": "idor",
                                        "finding": f"IDOR (Path): '{role_a}' accessed '{role_b}' data by substituting ID {seg} → {foreign_id}",
                                        "severity": "Critical",
                                        "evidence": f"{ep['method']} {new_url} → HTTP {result['status']}",
                                        "cwe_id": "CWE-639",
                                        "remediation": "Validate object ownership server-side.",
                                        "role": role_a,
                                    })

                    # 2. Substitute in JSON body
                    body_json = ep.get("_parsed_body")
                    if body_json:
                        body_ids = _extract_ids_from_json(body_json)
                        for b_id in body_ids:
                            for foreign_id in list(foreign_ids)[:3]:
                                new_body_json = _substitute_id_in_json(body_json, b_id, foreign_id)
                                import json as local_json
                                new_body_str = local_json.dumps(new_body_json)
                                
                                result = await self._make_request(session, ep["method"], ep["url"], headers_a, data=new_body_str)
                                if not result:
                                    continue

                                if result["status"] == 200 and result["body_length"] > 50:
                                    is_vuln = await self._verify_bac_with_ai(ep["method"], ep["url"], role_a, role_b, result["status"], result.get("body_preview", ""))
                                    if is_vuln:
                                        self.findings.append({
                                            "url": ep["url"],
                                            "check_type": "idor",
                                            "finding": f"IDOR (Body): '{role_a}' accessed '{role_b}' data by substituting ID {b_id} → {foreign_id} in JSON body",
                                            "severity": "Critical",
                                            "evidence": f"{ep['method']} {ep['url']} with body ID {b_id} → HTTP {result['status']}",
                                            "cwe_id": "CWE-639",
                                            "remediation": "Validate object ownership server-side based on session, do not trust client-provided IDs.",
                                            "role": role_a,
                                        })

    # ── FR-03.4: HTTP Verb Tampering ─────────────────────────

    async def _verb_tampering(
        self, session, role_endpoints: dict, roles_sorted: list
    ) -> None:
        """
        For each endpoint, test all HTTP methods with each role's token.
        Flags if a destructive verb (PUT, DELETE, PATCH) gets 200.
        """
        logger.info("  [FR-03.4] HTTP verb tampering...")

        # Only test low-privilege roles for verb tampering
        for low_role in roles_sorted[:len(roles_sorted) // 2 + 1]:
            eps = role_endpoints.get(low_role, [])
            if not eps:
                continue

            headers = await self._get_session_headers(low_role)

            # Sample endpoints (cap at 30 to avoid overload)
            sampled = eps[:30]
            logger.info(f"    Testing {len(sampled)} endpoints for '{low_role}' with all HTTP verbs...")

            for ep in sampled:
                url = ep["url"]
                original_method = ep["method"]
                body_data = ep.get("body", "")

                for verb in ALL_HTTP_VERBS:
                    if verb == original_method:
                        continue
                    if verb in ("HEAD", "OPTIONS"):
                        continue  # These are usually benign

                    result = await self._make_request(session, verb, url, headers, data=body_data)
                    if not result:
                        continue

                    # Flag if a destructive verb gets 200 on what was originally a safe method
                    if result["status"] == 200 and verb in ("DELETE", "PUT", "PATCH"):
                        self.findings.append({
                            "url": url,
                            "check_type": "verb_tampering",
                            "finding": f"Verb tampering: {verb} accepted on {original_method}-only endpoint",
                            "severity": "High",
                            "evidence": f"{verb} {url} → HTTP {result['status']} (original method: {original_method})",
                            "cwe_id": "CWE-650",
                            "remediation": "Explicitly restrict allowed HTTP methods per endpoint. Return 405 Method Not Allowed for unsupported verbs.",
                            "role": low_role,
                        })

    # ── FR-03.5: Path Normalization Bypass ───────────────────

    async def _path_normalization_bypass(
        self, session, role_endpoints: dict, roles_sorted: list
    ) -> None:
        """
        Test alternate path encodings to bypass authorization
        that uses raw string comparison instead of resolved paths.
        """
        logger.info("  [FR-03.5] Path normalization bypass...")

        # Identify admin/privileged paths
        admin_keywords = ["admin", "manage", "config", "settings", "internal", "dashboard"]

        privileged_urls = set()
        for high_role in roles_sorted[len(roles_sorted) // 2:]:
            for ep in role_endpoints.get(high_role, []):
                url_lower = ep["url"].lower()
                if any(kw in url_lower for kw in admin_keywords):
                    privileged_urls.add((ep["url"], ep["method"]))

        if not privileged_urls:
            logger.info("    No privileged paths detected for bypass testing")
            return

        # Test with lowest-privilege role
        low_role = roles_sorted[0]
        headers = await self._get_session_headers(low_role)

        logger.info(f"    Testing {len(privileged_urls)} privileged paths with {len(PATH_BYPASS_PATTERNS)} bypass patterns...")

        for url, method in list(privileged_urls)[:20]:  # Cap
            parsed = urllib.parse.urlparse(url)

            for pattern_name, transform in PATH_BYPASS_PATTERNS:
                try:
                    bypassed_path = transform(parsed.path)
                    bypassed_url = urllib.parse.urlunparse(
                        parsed._replace(path=bypassed_path)
                    )

                    result = await self._make_request(session, method, bypassed_url, headers)
                    if not result:
                        continue

                    if result["status"] == 200:
                        self.findings.append({
                            "url": bypassed_url,
                            "check_type": "path_bypass",
                            "finding": f"Path normalization bypass ({pattern_name}): accessed privileged endpoint",
                            "severity": "Critical",
                            "evidence": f"{method} {bypassed_url} → HTTP {result['status']} (original: {url})",
                            "cwe_id": "CWE-22",
                            "remediation": "Normalize/resolve request paths before authorization checks. Do not compare raw path strings.",
                            "role": low_role,
                        })
                except Exception:
                    pass

    def _write_results(self) -> None:
        """Write findings to JSON file."""
        # Deduplicate findings by (url, check_type, finding) (Pass 4 requirement)
        seen = set()
        unique = []
        for f in self.findings:
            key = (f.get("url", ""), f.get("check_type", ""), f.get("finding", ""))
            if key not in seen:
                seen.add(key)
                unique.append(f)
        self.findings = unique
        
        output_path = RESULTS_DIR / "bac_scan_results.json"
        with open(output_path, "w", encoding="utf-8") as fp:
            json.dump(self.findings, fp, indent=2)
        logger.info(f"BAC scan results written to {output_path}")

        # Summary
        by_type = {}
        for f in self.findings:
            t = f.get("check_type", "unknown")
            by_type[t] = by_type.get(t, 0) + 1

        if by_type:
            logger.info("BAC Scan Summary: " + ", ".join(
                f"{t}: {cnt}" for t, cnt in sorted(by_type.items())
            ))


# ─────────────────────────────────────────────
#  STANDALONE TEST
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("\n=== AHVF BAC/IDOR Comparator (standalone) ===\n")
    print("This module requires database endpoints from multiple roles.")
    print("Use: python run_pipeline.py --phase bac")
