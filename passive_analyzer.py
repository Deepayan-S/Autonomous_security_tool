"""
AHVF — Passive Security Analyzer
===================================
Non-fuzzing L1/L2 security checks that inspect response headers,
CORS behavior, cookie flags, and information disclosure patterns.

These checks catch entire categories of vulnerabilities that
payload-based fuzzing cannot detect.

Checks:
  - Security Header Audit (HSTS, CSP, X-Content-Type-Options, etc.)
  - CORS Misconfiguration Detection
  - Cookie Security Audit (HttpOnly, Secure, SameSite)
  - Information Disclosure (server version, debug headers, stack traces)

Input: Endpoint data from the database
Output: results/passive_scan_results.json + passive_findings DB table

USAGE:
    from passive_analyzer import PassiveAnalyzer
    analyzer = PassiveAnalyzer(db)
    findings = asyncio.run(analyzer.run())
"""

from __future__ import annotations
import asyncio
import json
import logging
import re
from pathlib import Path
from typing import Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("PassiveAnalyzer")

RESULTS_DIR = Path("results")
RESULTS_DIR.mkdir(exist_ok=True)


# ─────────────────────────────────────────────
#  SECURITY HEADER DEFINITIONS
# ─────────────────────────────────────────────

REQUIRED_HEADERS = [
    {
        "header": "strict-transport-security",
        "check": lambda v: v and "max-age" in v.lower() and int(re.search(r"max-age=(\d+)", v).group(1)) >= 31536000 if v and re.search(r"max-age=(\d+)", v) else False,
        "severity": "Medium",
        "cwe_id": "CWE-319",
        "finding_missing": "Missing Strict-Transport-Security header",
        "finding_weak": "Weak HSTS: max-age should be >= 31536000 (1 year)",
        "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to all responses.",
    },
    {
        "header": "content-security-policy",
        "check": lambda v: v and "unsafe-inline" not in v.lower() and "unsafe-eval" not in v.lower() if v else False,
        "severity": "High",
        "cwe_id": "CWE-693",
        "finding_missing": "Missing Content-Security-Policy header",
        "finding_weak": "CSP contains 'unsafe-inline' or 'unsafe-eval' — weakens XSS protection",
        "remediation": "Implement a strict CSP. Remove 'unsafe-inline' and 'unsafe-eval'. Use nonce-based script loading.",
    },
    {
        "header": "x-content-type-options",
        "check": lambda v: v and v.strip().lower() == "nosniff" if v else False,
        "severity": "Low",
        "cwe_id": "CWE-16",
        "finding_missing": "Missing X-Content-Type-Options header",
        "finding_weak": "X-Content-Type-Options should be 'nosniff'",
        "remediation": "Add 'X-Content-Type-Options: nosniff' to prevent MIME-type sniffing attacks.",
    },
    {
        "header": "x-frame-options",
        "check": lambda v: v and v.strip().upper() in ("DENY", "SAMEORIGIN") if v else False,
        "severity": "Medium",
        "cwe_id": "CWE-1021",
        "finding_missing": "Missing X-Frame-Options header — vulnerable to clickjacking",
        "finding_weak": "X-Frame-Options should be 'DENY' or 'SAMEORIGIN'",
        "remediation": "Add 'X-Frame-Options: DENY' or use CSP frame-ancestors directive.",
    },
    {
        "header": "referrer-policy",
        "check": lambda v: v and v.strip().lower() in (
            "no-referrer", "same-origin", "strict-origin",
            "strict-origin-when-cross-origin", "no-referrer-when-downgrade"
        ) if v else False,
        "severity": "Low",
        "cwe_id": "CWE-200",
        "finding_missing": "Missing Referrer-Policy header — may leak sensitive URLs to third parties",
        "finding_weak": "Referrer-Policy value is not restrictive enough",
        "remediation": "Add 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'.",
    },
    {
        "header": "permissions-policy",
        "check": lambda v: bool(v),
        "severity": "Low",
        "cwe_id": "CWE-16",
        "finding_missing": "Missing Permissions-Policy header",
        "finding_weak": "",
        "remediation": "Add Permissions-Policy to restrict browser features (camera, microphone, geolocation).",
    },
]

# Headers that indicate information disclosure
INFO_DISCLOSURE_HEADERS = [
    "server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
    "x-debug-token", "x-debug-token-link", "x-runtime", "x-request-id",
]


# ─────────────────────────────────────────────
#  PASSIVE ANALYZER CLASS
# ─────────────────────────────────────────────

class PassiveAnalyzer:
    """
    Performs non-fuzzing security checks against crawled endpoints.

    Makes clean (non-injected) HTTP requests and inspects response
    headers, cookies, and CORS behavior.
    """

    def __init__(self, db=None):
        self.db = db
        self.findings: list[dict] = []

    async def run(self, endpoints: list[dict] | None = None) -> list[dict]:
        """
        Main entry point.

        Args:
            endpoints: List of endpoint dicts with 'url', 'method', 'role', 'jwt', 'cookies'.
                       If None, loads from DB.

        Returns:
            List of finding dicts
        """
        if endpoints is None and self.db:
            endpoints = self.db.get_endpoints()

        if not endpoints:
            logger.info("No endpoints to analyze.")
            return []

        # Deduplicate by URL (we only need to check headers once per URL)
        unique_urls = {}
        for ep in endpoints:
            url = ep.get("url", "") if isinstance(ep, dict) else ep
            if url and url not in unique_urls:
                unique_urls[url] = ep

        logger.info(f"Passive analysis on {len(unique_urls)} unique URLs...")

        import aiohttp
        connector = aiohttp.TCPConnector(ssl=False, limit=10)

        # Extract auth info from first endpoint
        first_ep = next(iter(unique_urls.values()))
        headers = {"User-Agent": "AHVF-SecurityScanner/1.0 (authorized-testing)"}

        jwt_token = None
        cookies_dict = {}
        if isinstance(first_ep, dict):
            jwt_token = first_ep.get("jwt")
            raw_cookies = first_ep.get("cookies", [])
            if isinstance(raw_cookies, list):
                cookies_dict = {c.get("name", ""): c.get("value", "") for c in raw_cookies if isinstance(c, dict)}
            elif isinstance(raw_cookies, str):
                # Handle cookie string format
                try:
                    cookies_dict = dict(pair.split("=", 1) for pair in raw_cookies.split("; ") if "=" in pair)
                except Exception:
                    pass

        if jwt_token:
            headers["Authorization"] = f"Bearer {jwt_token}"

        async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
            # Set cookies
            if cookies_dict:
                for name, value in cookies_dict.items():
                    session.cookie_jar.update_cookies({name: value})

            # Run all checks concurrently
            tasks = []
            for url, ep in unique_urls.items():
                tasks.append(self._analyze_endpoint(session, url, ep))

            await asyncio.gather(*tasks, return_exceptions=True)

        # Cookie audit from crawl data (doesn't need live requests)
        self._cookie_audit(endpoints)

        logger.info(f"Passive analysis complete: {len(self.findings)} findings")

        # Write results
        self._write_results()

        # Store in DB
        if self.db:
            try:
                self.db.insert_passive_findings(self.findings)
            except Exception as e:
                logger.error(f"Failed to store passive findings in DB: {e}")

        return self.findings

    async def _analyze_endpoint(self, session, url: str, ep) -> None:
        """Run all passive checks against a single endpoint."""
        role = ep.get("role", "unknown") if isinstance(ep, dict) else "unknown"

        try:
            import aiohttp
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10), allow_redirects=False) as resp:
                resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                status = resp.status
                
                req_lines = [f"{resp.request_info.method} {resp.request_info.url} HTTP/1.1"]
                for k, v in resp.request_info.headers.items():
                    req_lines.append(f"{k}: {v}")
                req_lines.append("")
                req_details = "\n".join(req_lines)
                
                body = ""
                try:
                    body = await resp.text(errors="replace")
                except:
                    pass
                
                resp_lines = [f"HTTP/1.1 {status} {resp.reason}"]
                for k, v in resp.headers.items():
                    resp_lines.append(f"{k}: {v}")
                resp_lines.append("")
                resp_lines.append(body[:2000])
                if len(body) > 2000:
                    resp_lines.append("\n...[TRUNCATED]")
                resp_details = "\n".join(resp_lines)

                # 1. Security header audit
                self._check_security_headers(url, resp_headers, role, req_details, resp_details)

                # 2. Information disclosure
                self._check_info_disclosure(url, resp_headers, role, req_details, resp_details)

                # 3. Cache control on auth endpoints
                self._check_cache_control(url, resp_headers, role, req_details, resp_details)

                # 4. Check response body for stack traces (only on error pages)
                if status >= 400 and body:
                    self._check_error_disclosure(url, body, status, role, req_details, resp_details)

        except Exception as e:
            logger.debug(f"Failed to analyze {url}: {e}")
            return

        # 5. CORS check (separate request with Origin header)
        await self._check_cors(session, url, role)

    def _check_security_headers(self, url: str, headers: dict, role: str, req_details: str = "", resp_details: str = "") -> None:
        """Check for missing or misconfigured security headers."""
        for hdef in REQUIRED_HEADERS:
            header_name = hdef["header"]
            value = headers.get(header_name)

            if not value:
                self.findings.append({
                    "url": url,
                    "check_type": "header",
                    "finding": hdef["finding_missing"],
                    "severity": hdef["severity"],
                    "evidence": f"Header '{header_name}' not present in response",
                    "cwe_id": hdef["cwe_id"],
                    "remediation": hdef["remediation"],
                    "role": role,
                    "request_details": req_details,
                    "response_details": resp_details,
                })
            elif not hdef["check"](value) and hdef.get("finding_weak"):
                self.findings.append({
                    "url": url,
                    "check_type": "header",
                    "finding": hdef["finding_weak"],
                    "severity": hdef["severity"],
                    "evidence": f"{header_name}: {value}",
                    "cwe_id": hdef["cwe_id"],
                    "remediation": hdef["remediation"],
                    "role": role,
                    "request_details": req_details,
                    "response_details": resp_details,
                })

    def _check_info_disclosure(self, url: str, headers: dict, role: str, req_details: str = "", resp_details: str = "") -> None:
        """Check for server version strings and debug headers."""
        for header_name in INFO_DISCLOSURE_HEADERS:
            value = headers.get(header_name)
            if not value:
                continue

            # Only flag if it contains version info or is a debug header
            is_version = bool(re.search(r"\d+\.\d+", value))
            is_debug = header_name.startswith("x-debug")

            if is_version or is_debug:
                severity = "Medium" if is_debug else "Low"
                self.findings.append({
                    "url": url,
                    "check_type": "info_disclosure",
                    "finding": f"Information disclosure via '{header_name}' header",
                    "severity": severity,
                    "evidence": f"{header_name}: {value}",
                    "cwe_id": "CWE-200",
                    "remediation": f"Remove or suppress the '{header_name}' header in production.",
                    "role": role,
                    "request_details": req_details,
                    "response_details": resp_details,
                })

    def _check_cache_control(self, url: str, headers: dict, role: str, req_details: str = "", resp_details: str = "") -> None:
        """Check that sensitive endpoints have no-store cache control."""
        # Only check auth-related endpoints
        sensitive_keywords = ["auth", "login", "user", "account", "profile", "token", "session", "password"]
        url_lower = url.lower()

        if not any(kw in url_lower for kw in sensitive_keywords):
            return

        cache_control = headers.get("cache-control", "")
        if "no-store" not in cache_control.lower():
            self.findings.append({
                "url": url,
                "check_type": "header",
                "finding": "Sensitive endpoint missing 'Cache-Control: no-store'",
                "severity": "Medium",
                "evidence": f"Cache-Control: {cache_control or '(not set)'}",
                "cwe_id": "CWE-525",
                "remediation": "Add 'Cache-Control: no-store, no-cache, must-revalidate' to sensitive endpoints.",
                "role": role,
                "request_details": req_details,
                "response_details": resp_details,
            })

    def _check_error_disclosure(self, url: str, body: str, status: int, role: str, req_details: str = "", resp_details: str = "") -> None:
        """Check error responses for stack traces and verbose errors."""
        stack_trace_patterns = [
            r"Traceback \(most recent call last\)",  # Python
            r"at\s+\w+\.\w+\s*\([\w/\\:.]+:\d+:\d+\)",  # Node.js
            r"(?:java|javax)\.\w+\.\w+Exception",  # Java
            r"System\.(?:NullReferenceException|Exception)",  # .NET
            r"<b>Fatal error</b>.*on line\s+\d+",  # PHP
            r"(?:SQL|ORA-\d+|mysql_|pg_query)",  # Database errors
        ]

        for pattern in stack_trace_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                # Truncate evidence
                match = re.search(pattern, body, re.IGNORECASE)
                start = max(0, match.start() - 100)
                end = min(len(body), match.end() + 200)
                evidence = body[start:end].strip()

                self.findings.append({
                    "url": url,
                    "check_type": "info_disclosure",
                    "finding": f"Stack trace / verbose error exposed (HTTP {status})",
                    "severity": "High",
                    "evidence": evidence[:500],
                    "cwe_id": "CWE-209",
                    "remediation": "Implement custom error pages. Never expose stack traces in production.",
                    "role": role,
                    "request_details": req_details,
                    "response_details": resp_details,
                })
                break  # One finding per URL is enough

    async def _check_cors(self, session, url: str, role: str) -> None:
        """Check for CORS misconfigurations."""
        test_origins = [
            ("https://evil.com", "Arbitrary origin reflection"),
            ("null", "Null origin accepted"),
        ]

        for origin, description in test_origins:
            try:
                import aiohttp
                async with session.get(
                    url,
                    headers={"Origin": origin},
                    timeout=aiohttp.ClientTimeout(total=10),
                    allow_redirects=False,
                ) as resp:
                    acao = resp.headers.get("Access-Control-Allow-Origin", "")
                    acac = resp.headers.get("Access-Control-Allow-Credentials", "")

                    if not acao:
                        continue  # No CORS headers = not vulnerable
                        
                    req_lines = [f"{resp.request_info.method} {resp.request_info.url} HTTP/1.1"]
                    for k, v in resp.request_info.headers.items():
                        req_lines.append(f"{k}: {v}")
                    req_lines.append("")
                    req_details = "\n".join(req_lines)
                    
                    resp_lines = [f"HTTP/1.1 {resp.status} {resp.reason}"]
                    for k, v in resp.headers.items():
                        resp_lines.append(f"{k}: {v}")
                    resp_lines.append("")
                    resp_details = "\n".join(resp_lines)

                    # Check if origin is reflected
                    is_reflected = (acao == origin) or (acao == "*")

                    if is_reflected:
                        # Credentials + reflected origin = critical
                        if acac.lower() == "true" and acao != "*":
                            self.findings.append({
                                "url": url,
                                "check_type": "cors",
                                "finding": f"Critical CORS misconfiguration: {description} with credentials",
                                "severity": "Critical",
                                "evidence": f"Origin: {origin} → ACAO: {acao}, ACAC: {acac}",
                                "cwe_id": "CWE-942",
                                "remediation": "Never reflect arbitrary origins with Allow-Credentials. Use a strict allowlist.",
                                "role": role,
                                "request_details": req_details,
                                "response_details": resp_details,
                            })
                        elif acao == "*":
                            self.findings.append({
                                "url": url,
                                "check_type": "cors",
                                "finding": "CORS wildcard (*) allows any origin",
                                "severity": "Medium",
                                "evidence": f"Access-Control-Allow-Origin: *",
                                "cwe_id": "CWE-942",
                                "remediation": "Replace wildcard with a specific origin allowlist.",
                                "role": role,
                                "request_details": req_details,
                                "response_details": resp_details,
                            })
                        else:
                            self.findings.append({
                                "url": url,
                                "check_type": "cors",
                                "finding": f"CORS misconfiguration: {description}",
                                "severity": "High",
                                "evidence": f"Origin: {origin} → ACAO: {acao}",
                                "cwe_id": "CWE-942",
                                "remediation": "Do not reflect arbitrary Origin values. Use a strict allowlist.",
                                "role": role,
                                "request_details": req_details,
                                "response_details": resp_details,
                            })

            except Exception:
                pass

    def _cookie_audit(self, endpoints: list) -> None:
        """Audit cookie security flags from crawl data."""
        seen_cookies = set()

        for ep in endpoints:
            if isinstance(ep, dict):
                cookies = ep.get("cookies", [])
            else:
                continue

            if not isinstance(cookies, list):
                continue

            url = ep.get("url", "unknown")
            role = ep.get("role", "unknown")

            for cookie in cookies:
                if not isinstance(cookie, dict):
                    continue

                name = cookie.get("name", "")
                if name in seen_cookies:
                    continue
                seen_cookies.add(name)

                # Check for auth-related cookies
                auth_keywords = ["session", "token", "jwt", "auth", "sid", "connect.sid", "JSESSIONID"]
                is_auth_cookie = any(kw.lower() in name.lower() for kw in auth_keywords)

                if not is_auth_cookie:
                    continue  # Only audit auth-related cookies

                # HttpOnly flag
                if not cookie.get("httpOnly", False):
                    self.findings.append({
                        "url": url,
                        "check_type": "cookie",
                        "finding": f"Auth cookie '{name}' missing HttpOnly flag",
                        "severity": "Medium",
                        "evidence": f"Cookie: {name} (HttpOnly=false)",
                        "cwe_id": "CWE-1004",
                        "remediation": "Set HttpOnly flag on authentication cookies to prevent XSS-based theft.",
                        "role": role,
                    })

                # Secure flag
                if not cookie.get("secure", False):
                    self.findings.append({
                        "url": url,
                        "check_type": "cookie",
                        "finding": f"Auth cookie '{name}' missing Secure flag",
                        "severity": "Medium",
                        "evidence": f"Cookie: {name} (Secure=false)",
                        "cwe_id": "CWE-614",
                        "remediation": "Set Secure flag on cookies to prevent transmission over HTTP.",
                        "role": role,
                    })

                # SameSite attribute
                same_site = cookie.get("sameSite", "")
                if not same_site or same_site.lower() == "none":
                    self.findings.append({
                        "url": url,
                        "check_type": "cookie",
                        "finding": f"Auth cookie '{name}' missing or weak SameSite attribute",
                        "severity": "Medium",
                        "evidence": f"Cookie: {name} (SameSite={same_site or 'not set'})",
                        "cwe_id": "CWE-352",
                        "remediation": "Set SameSite=Strict or SameSite=Lax on authentication cookies.",
                        "role": role,
                    })

    def _write_results(self) -> None:
        """Write findings to JSON file."""
        output_path = RESULTS_DIR / "passive_scan_results.json"
        with open(output_path, "w", encoding="utf-8") as fp:
            json.dump(self.findings, fp, indent=2)
        logger.info(f"Passive scan results written to {output_path}")

        # Summary
        by_type = {}
        for f in self.findings:
            t = f.get("check_type", "unknown")
            by_type[t] = by_type.get(t, 0) + 1

        if by_type:
            logger.info("Passive Scan Summary: " + ", ".join(
                f"{t}: {cnt}" for t, cnt in sorted(by_type.items())
            ))


# ─────────────────────────────────────────────
#  STANDALONE TEST
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("\n=== AHVF Passive Security Analyzer (standalone) ===\n")
    print("This module requires database endpoints to run.")
    print("Use: python run_pipeline.py --phase passive")
