"""
AHVF — JavaScript Secret & Logic Flaw Scanner
=================================================
Two-tier analysis of client-side JavaScript files:

Tier 1 (default): Regex-based keyword scan for hardcoded secrets,
    internal URLs, debug paths, insecure DOM sinks, and source maps.

Tier 2 (--deep-scan): Sends suspicious JS chunks to Ollama for
    semantic analysis of logic flaws, client-side auth checks,
    and complex vulnerability patterns.

Input: JS file URLs collected by the Crawler (CrawlResult.js_files)
Output: results/js_scan_results.json + passive_findings DB table

USAGE:
    from js_scanner import JSScanner
    scanner = JSScanner(db, deep_scan=False)
    findings = asyncio.run(scanner.run(js_urls, cookies, role))
"""

from __future__ import annotations
import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("JSScanner")

RESULTS_DIR = Path("results")
RESULTS_DIR.mkdir(exist_ok=True)


# ─────────────────────────────────────────────
#  KEYWORD PATTERNS (Tier 1)
# ─────────────────────────────────────────────

@dataclass
class ScanPattern:
    name: str
    regex: str
    severity: str           # Critical, High, Medium, Low
    cwe_id: str
    remediation: str
    category: str           # 'js_secret' or 'js_logic_flaw'
    compiled: re.Pattern = field(init=False, repr=False)

    def __post_init__(self):
        self.compiled = re.compile(self.regex, re.IGNORECASE)


PATTERNS: list[ScanPattern] = [
    # ── Cloud API Keys ──────────────────────────────────────
    ScanPattern(
        name="AWS Access Key",
        regex=r"AKIA[0-9A-Z]{16}",
        severity="Critical", cwe_id="CWE-798", category="js_secret",
        remediation="Remove AWS keys from client-side code. Use backend proxy with IAM roles.",
    ),
    ScanPattern(
        name="Google API Key",
        regex=r"AIzaSy[0-9A-Za-z_-]{33}",
        severity="High", cwe_id="CWE-798", category="js_secret",
        remediation="Restrict API key to specific referrers/IPs. Use backend proxy.",
    ),
    ScanPattern(
        name="Stripe Secret Key",
        regex=r"sk_live_[0-9a-zA-Z]{24,}",
        severity="Critical", cwe_id="CWE-798", category="js_secret",
        remediation="Never expose Stripe secret keys in client code. Use publishable key only.",
    ),
    ScanPattern(
        name="Firebase Config",
        regex=r"firebaseConfig\s*=\s*\{[^}]*apiKey\s*:",
        severity="Medium", cwe_id="CWE-798", category="js_secret",
        remediation="Firebase API keys are semi-public, but ensure Firestore/RTDB rules restrict access.",
    ),
    ScanPattern(
        name="Generic API Key Assignment",
        regex=r"""(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*["'][a-zA-Z0-9_\-]{16,}["']""",
        severity="High", cwe_id="CWE-798", category="js_secret",
        remediation="Move API keys to environment variables on the server. Never embed in client JS.",
    ),

    # ── Hardcoded Credentials ────────────────────────────────
    ScanPattern(
        name="Hardcoded Password",
        regex=r"""(?:password|passwd|pwd)\s*[:=]\s*["'][^"']{4,}["']""",
        severity="Critical", cwe_id="CWE-798", category="js_secret",
        remediation="Remove hardcoded passwords. Use secure credential storage.",
    ),
    ScanPattern(
        name="Hardcoded Secret/Token",
        regex=r"""(?:secret|token|private[_-]?key|signing[_-]?key)\s*[:=]\s*["'][a-zA-Z0-9_\-/+=]{8,}["']""",
        severity="High", cwe_id="CWE-798", category="js_secret",
        remediation="Secrets must be stored server-side. Use environment variables or vault services.",
    ),

    # ── JWT Secrets ──────────────────────────────────────────
    ScanPattern(
        name="JWT Signing in Client Code",
        regex=r"""jwt\.sign\s*\([^)]*,\s*["'][^"']+["']""",
        severity="Critical", cwe_id="CWE-345", category="js_secret",
        remediation="JWT signing must be done server-side. Client code should never have signing secrets.",
    ),
    ScanPattern(
        name="Hardcoded JWT",
        regex=r"""["']eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+["']""",
        severity="High", cwe_id="CWE-798", category="js_secret",
        remediation="Remove hardcoded JWTs from source code. Tokens should be obtained dynamically.",
    ),

    # ── Internal/Private URLs ────────────────────────────────
    ScanPattern(
        name="Private/Internal URL",
        regex=r"""https?://(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)(?::\d+)?[/\w.-]*""",
        severity="Medium", cwe_id="CWE-200", category="js_secret",
        remediation="Remove internal URLs from client JS. Use relative paths or environment-based config.",
    ),
    ScanPattern(
        name="Staging/Dev Hostname",
        regex=r"""https?://[\w.-]*(?:staging|dev|test|internal|local|debug)[\w.-]*\.\w+""",
        severity="Medium", cwe_id="CWE-200", category="js_secret",
        remediation="Remove references to non-production environments from client-side code.",
    ),

    # ── Admin/Debug Paths ────────────────────────────────────
    ScanPattern(
        name="Admin/Debug Route",
        regex=r"""["'](/(?:admin|debug|internal|_dev|_debug|backdoor|test|phpinfo|phpmyadmin)[/\w.-]*)["']""",
        severity="Medium", cwe_id="CWE-200", category="js_secret",
        remediation="Remove admin/debug path references from client JS. These should not be discoverable.",
    ),

    # ── Insecure DOM Sinks ───────────────────────────────────
    ScanPattern(
        name="innerHTML Assignment",
        regex=r"""\.innerHTML\s*=\s*[^"']""",
        severity="High", cwe_id="CWE-79", category="js_logic_flaw",
        remediation="Use textContent or a DOM sanitizer (e.g. DOMPurify) instead of innerHTML.",
    ),
    ScanPattern(
        name="document.write Usage",
        regex=r"""document\.write\s*\(""",
        severity="High", cwe_id="CWE-79", category="js_logic_flaw",
        remediation="Avoid document.write(). Use DOM APIs (createElement, appendChild) instead.",
    ),
    ScanPattern(
        name="eval() Usage",
        regex=r"""\beval\s*\(""",
        severity="High", cwe_id="CWE-95", category="js_logic_flaw",
        remediation="Never use eval() with user-controlled input. Use JSON.parse() for data parsing.",
    ),
    ScanPattern(
        name="setTimeout/setInterval with String",
        regex=r"""(?:setTimeout|setInterval)\s*\(\s*["']""",
        severity="Medium", cwe_id="CWE-95", category="js_logic_flaw",
        remediation="Pass function references to setTimeout/setInterval, not strings (which use eval internally).",
    ),

    # ── Source Maps ──────────────────────────────────────────
    ScanPattern(
        name="Source Map Reference",
        regex=r"""//[#@]\s*sourceMappingURL\s*=""",
        severity="Low", cwe_id="CWE-200", category="js_secret",
        remediation="Remove sourceMappingURL references in production builds to prevent source code exposure.",
    ),

    # ── Client-Side Auth Patterns ────────────────────────────
    ScanPattern(
        name="Client-Side Role Check",
        regex=r"""(?:isAdmin|is_admin|role\s*===?\s*["']admin["']|userRole\s*===?\s*["'])""",
        severity="Medium", cwe_id="CWE-602", category="js_logic_flaw",
        remediation="Role checks must be enforced server-side. Client-side checks are trivially bypassable.",
    ),
    ScanPattern(
        name="localStorage Token Storage",
        regex=r"""localStorage\.(?:setItem|getItem)\s*\(\s*["'](?:token|jwt|session|auth|access_token)["']""",
        severity="Medium", cwe_id="CWE-922", category="js_logic_flaw",
        remediation="Use HttpOnly cookies for auth tokens instead of localStorage (vulnerable to XSS).",
    ),

    # ── Sensitive Data Patterns ──────────────────────────────
    ScanPattern(
        name="SSN Pattern in Code",
        regex=r"""\b\d{3}-\d{2}-\d{4}\b""",
        severity="Medium", cwe_id="CWE-200", category="js_secret",
        remediation="Remove hardcoded PII (SSNs) from client-side code.",
    ),
    ScanPattern(
        name="Database Connection String",
        regex=r"""(?:mongodb|mysql|postgres|redis)://[^\s"']+""",
        severity="Critical", cwe_id="CWE-798", category="js_secret",
        remediation="Database connection strings must never appear in client-side code.",
    ),

    # ── Miscellaneous ────────────────────────────────────────
    ScanPattern(
        name="Disabled Security Check (TODO/FIXME)",
        regex=r"""(?://|/\*)\s*(?:TODO|FIXME|HACK|XXX)\s*.*(?:auth|secur|token|password|bypass)""",
        severity="Low", cwe_id="CWE-489", category="js_logic_flaw",
        remediation="Review and resolve security-related TODO/FIXME comments before deployment.",
    ),
    ScanPattern(
        name="Console.log Sensitive Data",
        regex=r"""console\.log\s*\([^)]*(?:password|token|secret|key|credential)[^)]*\)""",
        severity="Low", cwe_id="CWE-532", category="js_logic_flaw",
        remediation="Remove console.log statements that output sensitive data in production builds.",
    ),
]

# Subset of pattern names that indicate "suspicious" chunks for LLM deep scan
SUSPICIOUS_KEYWORDS = {
    "password", "secret", "token", "admin", "auth", "login", "role",
    "isAdmin", "eval(", "innerHTML", "localStorage", "jwt", "api_key",
    "private", "credential", "bypass", "debug",
}


# ─────────────────────────────────────────────
#  LLM DEEP SCAN PROMPT (Tier 2)
# ─────────────────────────────────────────────

LLM_DEEP_SCAN_SYSTEM = """You are a JavaScript security auditor. Analyze the following code snippet from a web application's client-side JavaScript. Identify:
1. Hardcoded secrets, API keys, or credentials
2. Logic flaws that could be exploited (e.g., client-side auth checks, role checking in JS, price calculations in client code)
3. Insecure data handling (PII in localStorage, tokens in URL params)
4. Hidden admin routes or feature flags
5. Dangerous function usage (eval, innerHTML, document.write with user input)

Return ONLY a JSON array. Each finding must have:
- "finding": description of the issue
- "severity": "Critical" | "High" | "Medium" | "Low"
- "evidence": the exact code line(s)
- "cwe_id": relevant CWE ID
- "remediation": fix suggestion

If NO issues are found, return an empty array: []"""


# ─────────────────────────────────────────────
#  JS SCANNER CLASS
# ─────────────────────────────────────────────

class JSScanner:
    """
    Scans JavaScript files for secrets and logic flaws.

    Tier 1: Fast regex keyword scan (always runs)
    Tier 2: LLM deep scan (only with --deep-scan flag)
    """

    def __init__(self, db=None, deep_scan: bool = False, ollama_client=None):
        self.db = db
        self.deep_scan = deep_scan
        self._client = ollama_client

    def _get_client(self):
        """Lazy-init Ollama client for deep scan."""
        if self._client is None:
            try:
                from ollama_client import OllamaClient
                self._client = OllamaClient()
                self._client.health_check()
            except Exception as e:
                logger.warning(f"Ollama not available for deep scan: {e}")
                return None
        return self._client

    async def run(
        self,
        js_urls: list[str],
        cookies: dict | None = None,
        role: str = "unknown",
        jwt_token: str | None = None,
    ) -> list[dict]:
        """
        Main entry point. Downloads and scans all JS files.

        Args:
            js_urls: List of JS file URLs from the crawler
            cookies: Dict of cookies for authenticated download
            role: The crawl role these JS files belong to
            jwt_token: Optional JWT for Authorization header

        Returns:
            List of finding dicts
        """
        if not js_urls:
            logger.info("No JS files to scan.")
            return []

        logger.info(f"Scanning {len(js_urls)} JavaScript files (deep_scan={self.deep_scan})...")

        # Download all JS files
        js_contents = await self._download_all(js_urls, cookies, jwt_token)
        logger.info(f"Downloaded {len(js_contents)} JS files successfully")

        # Tier 1: Keyword scan
        all_findings = []
        for url, content in js_contents.items():
            findings = self._keyword_scan(url, content, role)
            all_findings.extend(findings)

        logger.info(f"Tier 1 (Keyword): Found {len(all_findings)} issues across {len(js_contents)} files")

        # Tier 2: LLM deep scan (optional)
        if self.deep_scan:
            deep_findings = await self._llm_deep_scan(js_contents, role)
            all_findings.extend(deep_findings)
            logger.info(f"Tier 2 (LLM Deep): Found {len(deep_findings)} additional issues")

        # Deduplicate
        all_findings = self._deduplicate(all_findings)
        logger.info(f"Total unique findings: {len(all_findings)}")

        # Write results
        self._write_results(all_findings)

        # Store in DB
        if self.db:
            try:
                self.db.insert_passive_findings(all_findings)
            except Exception as e:
                logger.error(f"Failed to store findings in DB: {e}")

        return all_findings

    async def _download_all(
        self,
        urls: list[str],
        cookies: dict | None,
        jwt_token: str | None,
    ) -> dict[str, str]:
        """Download all JS files concurrently using aiohttp."""
        import aiohttp

        headers = {"User-Agent": "AHVF-SecurityScanner/1.0 (authorized-testing)"}
        if jwt_token:
            headers["Authorization"] = f"Bearer {jwt_token}"

        cookie_jar = None
        if cookies:
            cookie_jar = aiohttp.CookieJar(unsafe=True)

        results = {}
        connector = aiohttp.TCPConnector(ssl=False)

        async with aiohttp.ClientSession(
            connector=connector, headers=headers, cookie_jar=cookie_jar
        ) as session:
            # Set cookies manually
            if cookies:
                for name, value in cookies.items():
                    session.cookie_jar.update_cookies({name: value})

            tasks = [self._download_one(session, url) for url in urls]
            responses = await asyncio.gather(*tasks, return_exceptions=True)

            for url, resp in zip(urls, responses):
                if isinstance(resp, Exception):
                    logger.debug(f"Failed to download {url}: {resp}")
                elif resp:
                    results[url] = resp

        return results

    async def _download_one(self, session, url: str) -> Optional[str]:
        """Download a single JS file."""
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status == 200:
                    content = await resp.text(errors="replace")
                    # Skip very large files (likely bundled libraries)
                    if len(content) > 5_000_000:  # 5MB
                        logger.debug(f"Skipping {url} — too large ({len(content)} bytes)")
                        return None
                    return content
                else:
                    return None
        except Exception:
            return None

    def _keyword_scan(self, url: str, content: str, role: str) -> list[dict]:
        """Tier 1: Regex-based keyword scan against the pattern list."""
        findings = []

        for pattern in PATTERNS:
            matches = pattern.compiled.finditer(content)
            for match in matches:
                # Get surrounding context (the line containing the match)
                start = content.rfind("\n", 0, match.start()) + 1
                end = content.find("\n", match.end())
                if end == -1:
                    end = min(match.end() + 100, len(content))
                evidence_line = content[start:end].strip()

                # Skip minified library noise — if the line is > 500 chars,
                # it's likely a minified bundle and the match is in library code
                if len(evidence_line) > 500:
                    # Check if the actual match is meaningful or just noise
                    matched_text = match.group(0)
                    if len(matched_text) < 10:
                        continue  # Too short to be meaningful in minified code
                    evidence_line = f"...{content[max(0, match.start()-50):match.end()+50].strip()}..."

                findings.append({
                    "url": url,
                    "check_type": pattern.category,
                    "finding": f"{pattern.name}: {match.group(0)[:100]}",
                    "severity": pattern.severity,
                    "evidence": evidence_line[:500],
                    "cwe_id": pattern.cwe_id,
                    "remediation": pattern.remediation,
                    "role": role,
                })

        return findings

    async def _llm_deep_scan(self, js_contents: dict[str, str], role: str) -> list[dict]:
        """Tier 2: Send suspicious code chunks to Ollama for analysis."""
        client = self._get_client()
        if not client:
            logger.warning("Skipping LLM deep scan — Ollama not available")
            return []

        findings = []
        chunks_analyzed = 0

        for url, content in js_contents.items():
            # Split into chunks and filter for suspicious ones
            suspicious_chunks = self._extract_suspicious_chunks(content)
            if not suspicious_chunks:
                continue

            logger.info(f"  [Deep Scan] {url}: {len(suspicious_chunks)} suspicious chunk(s)")

            for chunk in suspicious_chunks:
                try:
                    user_prompt = f"Analyze this JavaScript code from {url}:\n\n```javascript\n{chunk}\n```"
                    response = client.generate_json(
                        system_prompt=LLM_DEEP_SCAN_SYSTEM,
                        user_prompt=user_prompt,
                        temperature=0.2,
                    )

                    if isinstance(response, list):
                        for item in response:
                            findings.append({
                                "url": url,
                                "check_type": "js_logic_flaw",
                                "finding": item.get("finding", "LLM-detected issue"),
                                "severity": item.get("severity", "Medium"),
                                "evidence": item.get("evidence", "")[:500],
                                "cwe_id": item.get("cwe_id", ""),
                                "remediation": item.get("remediation", ""),
                                "role": role,
                            })

                    chunks_analyzed += 1

                except Exception as e:
                    logger.debug(f"  [Deep Scan] LLM analysis failed for chunk: {e}")

        logger.info(f"  [Deep Scan] Analyzed {chunks_analyzed} chunks via LLM")
        return findings

    def _extract_suspicious_chunks(self, content: str, chunk_size: int = 2000, overlap: int = 200) -> list[str]:
        """
        Split JS content into chunks and return only those containing
        suspicious keywords (saves LLM calls on library code).
        """
        chunks = []
        content_lower = content.lower()

        # Quick check: does this file contain any suspicious content at all?
        has_suspicious = any(kw in content_lower for kw in SUSPICIOUS_KEYWORDS)
        if not has_suspicious:
            return []

        # Split into overlapping chunks
        for i in range(0, len(content), chunk_size - overlap):
            chunk = content[i:i + chunk_size]
            chunk_lower = chunk.lower()

            # Only include chunks that have suspicious keywords
            if any(kw in chunk_lower for kw in SUSPICIOUS_KEYWORDS):
                chunks.append(chunk)

        # Limit to max 10 chunks per file to control LLM cost
        return chunks[:10]

    def _deduplicate(self, findings: list[dict]) -> list[dict]:
        """Deduplicate findings by (finding_text, cwe_id) across files."""
        seen = set()
        unique = []
        for f in findings:
            key = (f.get("finding", ""), f.get("cwe_id", ""))
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    def _write_results(self, findings: list[dict]):
        """Write findings to JSON file."""
        output_path = RESULTS_DIR / "js_scan_results.json"
        with open(output_path, "w", encoding="utf-8") as fp:
            json.dump(findings, fp, indent=2)
        logger.info(f"JS scan results written to {output_path}")

        # Print summary by severity
        severity_counts = {}
        for f in findings:
            sev = f.get("severity", "Unknown")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        if severity_counts:
            logger.info("JS Scan Summary: " + ", ".join(
                f"{sev}: {cnt}" for sev, cnt in
                sorted(severity_counts.items(), key=lambda x: ["Critical", "High", "Medium", "Low"].index(x[0]) if x[0] in ["Critical", "High", "Medium", "Low"] else 99)
            ))


# ─────────────────────────────────────────────
#  STANDALONE TEST
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    print("\n=== AHVF JS Scanner (standalone test) ===\n")

    if len(sys.argv) < 2:
        print("Usage: python js_scanner.py <js_url_1> [js_url_2 ...]")
        print("  Add --deep-scan for LLM analysis")
        sys.exit(1)

    deep = "--deep-scan" in sys.argv
    urls = [u for u in sys.argv[1:] if not u.startswith("--")]

    scanner = JSScanner(deep_scan=deep)
    results = asyncio.run(scanner.run(urls))

    print(f"\nTotal findings: {len(results)}")
    for r in results:
        print(f"  [{r['severity']}] {r['finding']} ({r['url']})")
