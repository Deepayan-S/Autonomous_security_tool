import asyncio
# pyrefly: ignore [missing-import]
import aiohttp
# pyrefly: ignore [missing-import]
import aiosqlite
# pyrefly: ignore [missing-import]
import jwt
import json
import hashlib
import random
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
import copy

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("AsyncExecutor")

DB_PATH = "ahvf_state.db"

class TokenManager:
    """Monitors JWT TTL and handles re-authentication (FR-06.5)"""
    def __init__(self, credential_matrix: Dict[str, Dict[str, str]] = None):
        self.credential_matrix = credential_matrix or {}
        # Stores role -> token
        self.active_tokens: Dict[str, str] = {}
        # Stores role -> Asyncio lock to prevent concurrent re-auths
        self.locks: Dict[str, asyncio.Lock] = {}

    async def get_valid_token(self, role: str, current_token: Optional[str]) -> Optional[str]:
        if not current_token:
            return None
        
        if role not in self.locks:
            self.locks[role] = asyncio.Lock()
        
        async with self.locks[role]:
            # Always favor the updated token if we just re-authenticated
            token_to_check = self.active_tokens.get(role, current_token)
            
            try:
                # Decode without verification to check exp
                decoded = jwt.decode(token_to_check, options={"verify_signature": False})
                exp = decoded.get("exp")
                if exp:
                    time_left = exp - datetime.now(timezone.utc).timestamp()
                    if time_left < 60:  # Less than 60s left, need re-auth
                        logger.warning(f"Token for role '{role}' is expiring soon (TTL: {time_left:.1f}s). Triggering re-auth...")
                        token_to_check = await self._reauthenticate(role)
            except jwt.DecodeError:
                # Not a valid JWT, just return it as is (might be a random opaque token)
                pass
            
            self.active_tokens[role] = token_to_check
            return token_to_check

    async def _reauthenticate(self, role: str) -> str:
        """
        Placeholder for re-authentication logic.
        In a full implementation, this would use self.credential_matrix to log in and get a new token.
        For now, we warn and fail silently if not implemented.
        """
        logger.error(f"Re-authentication for role '{role}' not fully implemented! Returning old token.")
        # Long scans fail silently if this is not handled, per FR-06.5.
        # We would ideally make a login request here.
        return self.active_tokens.get(role, "")


class AdaptiveRateLimiter:
    """Handles 429s and connection resets with exponential backoff + jitter (FR-06.4)"""
    def __init__(self, initial_backoff=1.0, max_backoff=60.0, max_retries=3):
        self.initial_backoff = initial_backoff
        self.max_backoff = max_backoff
        self.max_retries = max_retries
        self.global_pause = asyncio.Event()
        self.global_pause.set()  # Set means "allowed to proceed"

    async def request(self, session: aiohttp.ClientSession, method: str, url: str, **kwargs) -> aiohttp.ClientResponse:
        backoff = self.initial_backoff
        retries = 0
        while True:
            await self.global_pause.wait()
            try:
                resp = await session.request(method, url, **kwargs)
                if resp.status == 429:  
                    if retries >= self.max_retries:
                        logger.error(f"Max retries ({self.max_retries}) reached for 429 Too Many Requests on {url}.")
                        return resp  # Return the 429 response to be handled by the executor
                        
                    logger.warning(f"429 Too Many Requests from {url}. Backing off for {backoff:.2f}s")
                    await self._trigger_backoff(backoff)
                    backoff = min(backoff * 2, self.max_backoff)
                    retries += 1
                    # Don't return resp here, we need to retry
                    # Need to read and discard the body to release the connection
                    await resp.read()
                    continue
                return resp
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                if retries >= self.max_retries:
                    logger.error(f"Max retries ({self.max_retries}) reached for connection error on {url}. Giving up.")
                    raise  # Re-raise the exception so it gets caught by execute_task's try-except block
                    
                logger.warning(f"Connection error ({e}) to {url}. Backing off for {backoff:.2f}s")
                await self._trigger_backoff(backoff)
                backoff = min(backoff * 2, self.max_backoff)
                retries += 1

    async def _trigger_backoff(self, duration: float):
        self.global_pause.clear()
        jitter = random.uniform(0, 0.1 * duration)
        await asyncio.sleep(duration + jitter)
        self.global_pause.set()


class BaselineDeltaChecker:
    """Compares responses to baselines to reduce false positives (FR-06.6)"""
    @staticmethod
    def get_body_hash(body: str) -> str:
        if not body:
            return ""
        return hashlib.sha256(body.encode('utf-8')).hexdigest()

    @staticmethod
    def is_anomalous(
        baseline_status,
        baseline_hash,
        resp_status: int,
        resp_body: str,
        payload: str,
        expected_indicator: str,
        vuln_class: str = "",
    ) -> dict:
        delta = {}
        is_anomaly = False
        has_baseline = baseline_status is not None and baseline_hash is not None
        vuln_class = (vuln_class or "").upper()
        body_lower = (resp_body or "").lower()
        
        # 1. Expected Indicator match (STRONGEST SIGNAL)
        if expected_indicator:
            if expected_indicator.isdigit() and str(resp_status) == expected_indicator:
                # If we expect 200, make sure the response isn't just an empty success or soft error
                if resp_status == 200:
                    if len(resp_body.strip()) <= 15 or "error" in body_lower or "not found" in body_lower or "invalid" in body_lower or "unauthorized" in body_lower:
                        pass # False positive 200 OK
                    else:
                        delta["indicator"] = f"Matched expected status code: {expected_indicator}"
                        is_anomaly = True
                else:
                    delta["indicator"] = f"Matched expected status code: {expected_indicator}"
                    is_anomaly = True
            elif not expected_indicator.isdigit() and expected_indicator.lower() in resp_body.lower():
                delta["indicator"] = f"Expected string '{expected_indicator}' found in response body"
                is_anomaly = True

        # 1b. Class-specific proof markers. These catch real evidence even when
        # the LLM/fallback expected_indicator was too narrow.
        sql_markers = [
            "sql syntax", "syntax error", "sqlstate", "mysql", "mariadb",
            "postgresql", "sqlite", "ora-", "odbc", "jdbc", "unterminated quoted",
            "you have an error in your sql",
        ]
        if vuln_class in ("SQLI", "SECOND_ORDER_SQLI", "POLYGLOT") and any(m in body_lower for m in sql_markers):
            delta["sql_error"] = "Database error indicator found in response"
            is_anomaly = True

        traversal_markers = ["root:x:", "[extensions]", "[fonts]", "boot loader", "daemon:x:"]
        if vuln_class == "PATH_TRAVERSAL" and any(m in body_lower for m in traversal_markers):
            delta["path_traversal"] = "File content marker found in response"
            is_anomaly = True

        command_markers = ["uid=", "gid=", " groups=", "www-data", "nt authority", "volume serial number"]
        if vuln_class == "COMMAND_INJECTION" and any(m in body_lower for m in command_markers):
            delta["command_output"] = "Command output marker found in response"
            is_anomaly = True
                
        # 2. Payload Reflection (XSS/SQLi — flag if special chars reflected)
        if not is_anomaly and payload:
            payload_lower = payload.lower()
            body_lower = resp_body.lower()
            try:
                import urllib.parse
                decoded_body = urllib.parse.unquote(resp_body).lower()
            except Exception:
                decoded_body = body_lower

            if payload_lower in body_lower or payload_lower in decoded_body:
                if any(c in payload for c in ["<", ">", "'", "\"", "(", ")"]):
                    # Don't flag empty bodies or generic errors
                    if resp_status == 200 and len(resp_body) > 20: 
                        delta["reflection"] = "Injection payload reflected in response"
                        is_anomaly = True

        # 3. Auth Bypass Check (BAC/IDOR)
        if not is_anomaly and has_baseline:
            # Baseline was restricted, but payload got a 200 OK
            if baseline_status in (401, 403, 404) and resp_status == 200:
                # To prevent false positives on empty bodies, ensure it has some real content
                if len(resp_body.strip()) > 15 and "error" not in body_lower and "invalid" not in body_lower and "unauthorized" not in body_lower:
                    # Also ensure the body isn't identical to the baseline if baseline was soft error
                    if BaselineDeltaChecker.get_body_hash(resp_body) != baseline_hash:
                        delta["auth_bypass"] = f"Access control bypass ({baseline_status} -> {resp_status})"
                        is_anomaly = True

        return {
            "is_anomaly": is_anomaly,
            "delta_summary": json.dumps(delta) if delta else ""
        }


class AsyncPayloadExecutor:
    """High-throughput asyncio payload dispatcher (FR-06.1 - FR-06.8)"""
    def __init__(self, concurrency: int = 500):
        self.concurrency = concurrency
        self.semaphore = asyncio.Semaphore(concurrency)
        self.token_manager = TokenManager()
        self.rate_limiter = AdaptiveRateLimiter()

    async def _fetch_tasks(self) -> List[Dict]:
        """Loads payloads and joins with endpoints (FR-06.2)"""
        tasks = []
        async with aiosqlite.connect(DB_PATH) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("""
                SELECT 
                    e.id as endpoint_id, e.url, e.method, e.role, e.headers, e.body as base_body, 
                    e.baseline_hash, e.baseline_status, e.jwt, e.cookies, e.form_structure,
                    p.id as payload_id, p.payload, p.target_param, p.expected_indicator, p.vuln_class
                FROM payload_cache p
                JOIN endpoints e ON p.schema_hash = e.schema_hash
            """)
            async for row in cursor:
                tasks.append(dict(row))
        return tasks

    # Fields from schema metadata that are NOT real HTTP parameters
    INVALID_TARGET_PARAMS = {
        "schema_hash", "content_type", "context_hints", "params.context_hints",
        "params.filename", "endpoint_count", "roles", "method", "path",
        "is_file_upload", "upload_mime_types", "has_graphql", "form_fields",
    }

    def _is_valid_target(self, task: dict) -> bool:
        """Check that target_param is a real injectable HTTP parameter, not schema metadata."""
        target = task.get("target_param", "")
        if not target:
            return False
        # Reject known schema metadata fields
        if target in self.INVALID_TARGET_PARAMS:
            return False
        # Path segment injection is always valid
        if target.startswith("path_seg_"):
            return True
        # For POST/PUT/PATCH, check if target exists in body or accept any param name
        if task["method"].upper() in ["POST", "PUT", "PATCH"]:
            base_body = task.get("base_body") or "{}"
            try:
                body_json = json.loads(base_body)
                # Check if target exists as a flat key or nested path
                if isinstance(body_json, dict):
                    if target in body_json:
                        return True
                    # Check nested path
                    parts = target.split('.')
                    curr = body_json
                    for part in parts:
                        if isinstance(curr, dict) and part in curr:
                            curr = curr[part]
                        elif isinstance(curr, list) and part.isdigit() and int(part) < len(curr):
                            curr = curr[int(part)]
                        else:
                            curr = None
                            break
                    if curr is not None:
                        return True
            except (json.JSONDecodeError, TypeError):
                pass
            # If no body match, still allow (could be form param or multipart)
            return True
        # For GET, any param name is valid (appended as query string)
        return True

    async def _collect_baselines(self, session: aiohttp.ClientSession, tasks: List[Dict]):
        """Make clean requests (no payload) to establish baseline responses for each endpoint."""
        # Deduplicate by endpoint_id
        unique_endpoints = {}
        for t in tasks:
            eid = t["endpoint_id"]
            if eid not in unique_endpoints:
                unique_endpoints[eid] = t

        logger.info(f"Collecting baselines for {len(unique_endpoints)} unique endpoint(s)...")
        
        for eid, task in unique_endpoints.items():
            # Skip if baseline already collected
            if task.get("baseline_status") is not None and task.get("baseline_hash") is not None:
                continue
            
            try:
                headers = json.loads(task["headers"]) if task["headers"] else {}
                valid_jwt = await self.token_manager.get_valid_token(task["role"], task["jwt"])
                if valid_jwt:
                    headers["Authorization"] = f"Bearer {valid_jwt}"
                
                cookies = json.loads(task["cookies"]) if task["cookies"] else {}
                if isinstance(cookies, list):
                    cookies = {c["name"]: c["value"] for c in cookies if "name" in c}
                    
                # Merge with storage_state cookies if available
                state_cookies = self._load_storage_state_cookies(task["role"])
                if state_cookies:
                    cookies.update(state_cookies)

                # Make clean request (no injection)
                request_kwargs = {}
                if task["method"].upper() in ["POST", "PUT", "PATCH"]:
                    base_body = task.get("base_body")
                    if base_body:
                        try:
                            request_kwargs["json"] = json.loads(base_body)
                        except json.JSONDecodeError:
                            request_kwargs["data"] = base_body

                resp = await self.rate_limiter.request(
                    session,
                    method=task["method"],
                    url=task["url"],
                    headers=headers,
                    cookies=cookies,
                    allow_redirects=False,
                    **request_kwargs
                )
                raw_body = await resp.read()
                resp_body = raw_body.decode('utf-8', errors='replace')
                resp_hash = BaselineDeltaChecker.get_body_hash(resp_body)

                # Store baseline in DB
                async with aiosqlite.connect(DB_PATH) as db:
                    await db.execute(
                        "UPDATE endpoints SET baseline_status = ?, baseline_hash = ? WHERE id = ?",
                        (resp.status, resp_hash, eid)
                    )
                    await db.commit()

                # Update in-memory tasks with the baseline
                for t in tasks:
                    if t["endpoint_id"] == eid:
                        t["baseline_status"] = resp.status
                        t["baseline_hash"] = resp_hash

                logger.info(f"[BASELINE] {task['method']} {task['url']} -> {resp.status}")
            except Exception as e:
                logger.warning(f"[BASELINE] Failed for {task['url']}: {e}")

    async def _log_anomaly(self, endpoint_id: int, payload_id: int, status_code: int, response_body: str, delta: str, req_details: str = "", resp_details: str = ""):
        """Logs anomalous responses to SQLite (FR-06.8)"""
        resp_hash = BaselineDeltaChecker.get_body_hash(response_body)
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute("""
                INSERT INTO anomalies (endpoint_id, payload_id, status_code, response_hash, baseline_delta, request_details, response_details)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (endpoint_id, payload_id, status_code, resp_hash, delta, req_details, resp_details))
            await db.commit()

    def _set_nested_value(self, obj, target: str, value):
        """Set a value in a nested dictionary/list using dot notation or list index."""
        parts = target.split('.')
        current = obj
        for part in parts[:-1]:
            if isinstance(current, dict):
                current = current.setdefault(part, {})
            elif isinstance(current, list):
                if part.isdigit():
                    idx = int(part)
                    if idx < len(current):
                        current = current[idx]
                    else:
                        break # Cannot easily extend here
                else:
                    break
        last = parts[-1]
        if isinstance(current, dict):
            current[last] = value
        elif isinstance(current, list):
            if last.isdigit():
                idx = int(last)
                if idx < len(current):
                    current[idx] = value

    def _inject_payload(self, task: dict) -> tuple[bool, dict]:
        """Injects the payload into the target parameter. Returns (success, injected_kwargs)."""
        target = task["target_param"]
        payload = task["payload"]
        injected_kwargs = {}
        
        # 1. Path segment injection (e.g., path_seg_2)
        if target.startswith("path_seg_"):
            try:
                import urllib.parse
                seg_index = int(target.split("_")[2])
                parsed = urllib.parse.urlparse(task["url"])
                # Handle leading slash carefully
                path_str = parsed.path
                if path_str.startswith('/'):
                    path_parts = path_str[1:].split('/')
                else:
                    path_parts = path_str.split('/')
                    
                if seg_index < len(path_parts):
                    path_parts[seg_index] = str(payload)
                    new_path = "/" + "/".join(path_parts)
                    task["url"] = urllib.parse.urlunparse(parsed._replace(path=new_path))
                    return True, injected_kwargs
                else:
                    # Out of bounds injection fails
                    return False, injected_kwargs
            except (ValueError, IndexError):
                return False, injected_kwargs

        # 2. Body / Query injection
        if task["method"].upper() in ["POST", "PUT", "PATCH"]:
            base_body = task["base_body"] or "{}"
            try:
                body_json = json.loads(base_body)
                if isinstance(body_json, dict) or isinstance(body_json, list):
                    self._set_nested_value(body_json, target, payload)
                injected_kwargs["json"] = body_json
            except json.JSONDecodeError:
                # If form data or multipart
                injected_kwargs["data"] = {target: payload}
        else:
            injected_kwargs["params"] = {target: payload}
            
        return True, injected_kwargs

    async def execute_task(self, session: aiohttp.ClientSession, task: dict):
        async with self.semaphore:
            try:
                # Token management (FR-06.5)
                valid_jwt = await self.token_manager.get_valid_token(task["role"], task["jwt"])
                
                headers = json.loads(task["headers"]) if task["headers"] else {}
                if valid_jwt:
                    headers["Authorization"] = f"Bearer {valid_jwt}"
                
                cookies = json.loads(task["cookies"]) if task["cookies"] else {}
                # Flatten cookies if they are a list of dicts from playwright
                if isinstance(cookies, list):
                    cookies = {c["name"]: c["value"] for c in cookies if "name" in c}
                    
                # Merge with storage_state cookies if available
                state_cookies = self._load_storage_state_cookies(task["role"])
                if state_cookies:
                    cookies.update(state_cookies)

                # Injection (FR-06.2)
                success, inject_kwargs = self._inject_payload(task)
                if not success:
                    # Injection failed (e.g. out of bounds path segment), skip execution
                    return

                # Execution (FR-06.1 & FR-06.4 & FR-06.7)
                # Note: aiohttp does not natively support HTTP/2. We proceed with HTTP/1.1 
                # while acknowledging the FR-06.7 requirement constraint.
                resp = await self.rate_limiter.request(
                    session, 
                    method=task["method"], 
                    url=task["url"], 
                    headers=headers,
                    cookies=cookies,
                    allow_redirects=False,
                    **inject_kwargs
                )
                
                raw_body = await resp.read()
                resp_body = raw_body.decode('utf-8', errors='replace')
                
                # Baseline Checking (FR-06.6)
                checker_result = BaselineDeltaChecker.is_anomalous(
                    task["baseline_status"], 
                    task["baseline_hash"], 
                    resp.status, 
                    resp_body,
                    task["payload"],
                    task.get("expected_indicator", ""),
                    task.get("vuln_class", ""),
                )
                
                if checker_result["is_anomaly"]:
                    logger.info(f"[ANOMALY] Detected on {task['url']} (Status: {resp.status})")
                    
                    req_details_lines = [f"{task['method']} {resp.request_info.url} HTTP/1.1"]
                    for k, v in resp.request_info.headers.items():
                        req_details_lines.append(f"{k}: {v}")
                    req_details_lines.append("")
                    req_body = inject_kwargs.get("data") or inject_kwargs.get("json")
                    if req_body:
                        if isinstance(req_body, (dict, list)):
                            req_details_lines.append(json.dumps(req_body, indent=2))
                        else:
                            req_details_lines.append(str(req_body))
                    request_details_str = "\n".join(req_details_lines)

                    resp_details_lines = [f"HTTP/1.1 {resp.status} {resp.reason}"]
                    for k, v in resp.headers.items():
                        resp_details_lines.append(f"{k}: {v}")
                    resp_details_lines.append("")
                    resp_details_lines.append(resp_body[:10000])
                    if len(resp_body) > 10000:
                        resp_details_lines.append("\n...[TRUNCATED]")
                    response_details_str = "\n".join(resp_details_lines)

                    await self._log_anomaly(
                        task["endpoint_id"], 
                        task["payload_id"], 
                        resp.status, 
                        resp_body, 
                        checker_result["delta_summary"],
                        request_details_str,
                        response_details_str
                    )
            except Exception as e:
                logger.error(f"Task failed for {task['url']}: {e}")

    def _load_storage_state_cookies(self, role: str) -> dict:
        """Load cookies from Playwright's storage state JSON file."""
        import os
        state_path = f"results/state_{role}.json"
        if not os.path.exists(state_path):
            return {}
        try:
            with open(state_path, 'r', encoding='utf-8') as f:
                state_data = json.load(f)
                return {c["name"]: c["value"] for c in state_data.get("cookies", []) if "name" in c}
        except Exception as e:
            logger.warning(f"Failed to load storage state for role {role}: {e}")
            return {}

    async def run(self):
        tasks = await self._fetch_tasks()
        logger.info(f"Loaded {len(tasks)} payload injection tasks from database.")

        # Filter out tasks with invalid target_params (schema metadata fields)
        valid_tasks = [t for t in tasks if self._is_valid_target(t)]
        skipped = len(tasks) - len(valid_tasks)
        if skipped:
            logger.info(f"Skipped {skipped} task(s) with invalid target_param (schema metadata fields)")
        tasks = valid_tasks

        if not tasks:
            logger.info("No valid tasks to execute.")
            return
        
        # We use a single session for connection pooling with a 15-second timeout
        timeout = aiohttp.ClientTimeout(total=15)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            # Phase 1: Collect baselines for all unique endpoints
            await self._collect_baselines(session, tasks)

            # Phase 2: Execute payload injection
            coros = [self.execute_task(session, task) for task in tasks]
            await asyncio.gather(*coros)
            
        logger.info("Fuzzing run complete.")

if __name__ == "__main__":
    executor = AsyncPayloadExecutor(concurrency=500)
    asyncio.run(executor.run())
