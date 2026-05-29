"""
AHVF — Modular Browser Login Agent
=====================================
Provides a strategy-based authentication module used by:
  - Crawler.py (initial login per role)
  - bac_comparator.py (fresh session for cross-role testing)
  - async_executor.py (re-authentication when tokens expire)

Strategy chain (tried in order):
  1. HeuristicLoginStrategy — JS-based dynamic field detection
  2. LLMLoginStrategy — Sends sanitized login HTML to Ollama
  3. ManualFallback — Prompts operator for selectors (interactive only)

Designed for future expansion: any new strategy (agentic browser,
CAPTCHA solver, MFA handler) implements the LoginStrategy ABC.

USAGE:
    from login_agent import LoginAgent
    agent = LoginAgent(login_url, playwright_instance)
    session = await agent.login("Admin", "admin@example.com", "password123")
    session = await agent.get_session("Admin")  # cached + TTL check
"""

from __future__ import annotations
import asyncio
import re
import urllib.parse
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, UTC
from typing import Optional

# pyrefly: ignore [missing-import]
from playwright.async_api import async_playwright, Page, BrowserContext


# ─────────────────────────────────────────────
#  DATA STRUCTURES
# ─────────────────────────────────────────────

@dataclass
class SessionData:
    """Stores authentication state for a single role."""
    role: str
    cookies: list[dict] = field(default_factory=list)
    jwt: Optional[str] = None
    headers: dict = field(default_factory=dict)
    authenticated_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    ttl_seconds: int = 300  # Default 5 min, configurable

    @property
    def is_expired(self) -> bool:
        elapsed = (datetime.now(UTC) - self.authenticated_at).total_seconds()
        return elapsed > (self.ttl_seconds - 60)  # Refresh 60s before expiry

    @property
    def aiohttp_cookies(self) -> dict:
        """Return cookies as a flat dict for aiohttp session use."""
        return {c["name"]: c["value"] for c in self.cookies if "name" in c}


# ─────────────────────────────────────────────
#  STRATEGY ABC
# ─────────────────────────────────────────────

class LoginStrategy(ABC):
    """
    Base class for login strategies.
    
    Future strategies (agentic browser, CAPTCHA solver, MFA handler)
    implement this interface and are plugged into LoginAgent.
    """
    @abstractmethod
    async def attempt_login(
        self, page: Page, login_url: str, username: str, password: str
    ) -> Optional[dict]:
        """
        Attempt to log in on the given page.

        Returns a dict with keys:
            {"username_sel": str, "password_sel": str, "submit_sel": str}
        if selectors were found, or None if this strategy cannot handle the page.
        
        The caller (LoginAgent) handles the actual fill-and-submit using
        the returned selectors, so strategies only need to detect fields.
        """
        ...


# ─────────────────────────────────────────────
#  STRATEGY 1: HEURISTIC (existing JS-based)
# ─────────────────────────────────────────────

HEURISTIC_DETECT_JS = """
() => {
    const inputs = Array.from(document.querySelectorAll('input'));
    let pwd = inputs.find(i => i.type === 'password') || 
              inputs.find(i => (i.name || '').toLowerCase().includes('pass') || (i.id || '').toLowerCase().includes('pass'));
    
    const candidates = inputs.filter(i => 
        ['text', 'email', 'tel', 'number', ''].includes((i.type || '').toLowerCase()) && i !== pwd
    );
    
    let user = null;
    const keywords = ['user', 'email', 'login', 'id', 'name', 'phone', 'account'];
    for (const kw of keywords) {
        user = candidates.find(i => {
            const name = (i.getAttribute('name') || '').toLowerCase();
            const id = (i.getAttribute('id') || '').toLowerCase();
            const placeholder = (i.getAttribute('placeholder') || '').toLowerCase();
            return name.includes(kw) || id.includes(kw) || placeholder.includes(kw);
        });
        if (user) break;
    }
    if (!user && pwd) {
        const before = candidates.filter(i => i.compareDocumentPosition(pwd) & Node.DOCUMENT_POSITION_FOLLOWING);
        if (before.length > 0) user = before[before.length - 1];
    }
    if (!user) user = candidates[0];
    
    const buttons = Array.from(document.querySelectorAll('button, input[type="submit"], input[type="button"]'));
    let submit = buttons.find(b => (b.getAttribute('type') || '').toLowerCase() === 'submit');
    if (!submit) {
        const btnKw = ['login', 'signin', 'submit', 'enter', 'log in', 'sign in'];
        for (const kw of btnKw) {
            submit = buttons.find(b => {
                const txt = (b.textContent || b.value || '').toLowerCase();
                const id = (b.getAttribute('id') || '').toLowerCase();
                return txt.includes(kw) || id.includes(kw);
            });
            if (submit) break;
        }
    }
    if (!submit && pwd) {
        const form = pwd.closest('form');
        if (form) {
            const formBtns = form.querySelectorAll('button, input[type="submit"]');
            if (formBtns.length > 0) submit = formBtns[formBtns.length - 1];
        }
    }
    
    const getSel = (el) => {
        if (!el) return null;
        if (el.id) return `#${CSS.escape(el.id)}`;
        if (el.getAttribute('name')) return `${el.tagName.toLowerCase()}[name="${CSS.escape(el.getAttribute('name'))}"]`;
        if (el.getAttribute('placeholder')) return `${el.tagName.toLowerCase()}[placeholder="${CSS.escape(el.getAttribute('placeholder'))}"]`;
        if (el.type) return `${el.tagName.toLowerCase()}[type="${CSS.escape(el.type)}"]`;
        return el.tagName.toLowerCase();
    };
    
    return {
        username_sel: getSel(user),
        password_sel: getSel(pwd),
        submit_sel: getSel(submit)
    };
}
"""


class HeuristicLoginStrategy(LoginStrategy):
    """Uses in-page JavaScript to detect login form fields heuristically."""

    async def attempt_login(
        self, page: Page, login_url: str, username: str, password: str
    ) -> Optional[dict]:
        try:
            await page.wait_for_timeout(2000)
            selectors = await page.evaluate(HEURISTIC_DETECT_JS)

            if selectors and selectors.get("username_sel") and selectors.get("password_sel"):
                print(f"    [LoginAgent/Heuristic] Detected fields -> "
                      f"User: '{selectors['username_sel']}', "
                      f"Pass: '{selectors['password_sel']}', "
                      f"Submit: '{selectors.get('submit_sel', 'N/A')}'")
                return selectors
            else:
                print("    [LoginAgent/Heuristic] Could not detect login fields")
                return None
        except Exception as e:
            print(f"    [LoginAgent/Heuristic] Detection failed: {e}")
            return None


# ─────────────────────────────────────────────
#  STRATEGY 2: LLM-BACKED (Ollama fallback)
# ─────────────────────────────────────────────

def _sanitize_html_for_llm(raw_html: str) -> str:
    """
    Strip noisy HTML elements, keep only form-relevant tags.
    Reduces token cost and improves LLM accuracy.
    """
    # Remove script, style, link, meta, svg, noscript tags and their contents
    cleaned = re.sub(r'<(script|style|link|meta|svg|noscript|iframe)[^>]*>.*?</\1>', '', raw_html, flags=re.DOTALL | re.IGNORECASE)
    cleaned = re.sub(r'<(script|style|link|meta|svg|noscript|iframe)[^>]*/>', '', cleaned, flags=re.IGNORECASE)
    # Remove HTML comments
    cleaned = re.sub(r'<!--.*?-->', '', cleaned, flags=re.DOTALL)
    # Remove data URIs (base64 images etc.)
    cleaned = re.sub(r'data:[^"\']+', 'data:...', cleaned)
    # Collapse whitespace
    cleaned = re.sub(r'\s+', ' ', cleaned).strip()
    # Truncate to ~4000 chars to stay within LLM context budget
    if len(cleaned) > 4000:
        cleaned = cleaned[:4000] + "... [TRUNCATED]"
    return cleaned


LLM_LOGIN_SYSTEM_PROMPT = """You are a web form analyzer. Given the HTML of a login page, identify the CSS selectors for the login form fields.

Return ONLY a valid JSON object with these exact keys:
- "username_sel": CSS selector for the username/email input field
- "password_sel": CSS selector for the password input field
- "submit_sel": CSS selector for the submit/login button

Rules:
- Use #id selectors when available (most reliable)
- Use input[name="..."] as fallback
- Use input[type="..."] as last resort
- For the submit button, prefer button[type="submit"] or the button containing text like "Login", "Sign In"
- If you cannot find a field, set its value to null

Example: {"username_sel": "#email", "password_sel": "#password", "submit_sel": "button[type=\\"submit\\"]"}"""


class LLMLoginStrategy(LoginStrategy):
    """Sends sanitized login page HTML to Ollama for selector extraction."""

    def __init__(self, ollama_client=None):
        self._client = ollama_client

    def _get_client(self):
        """Lazy-initialize Ollama client."""
        if self._client is None:
            try:
                from ollama_client import OllamaClient
                self._client = OllamaClient()
                self._client.health_check()
            except Exception as e:
                print(f"    [LoginAgent/LLM] Ollama not available: {e}")
                return None
        return self._client

    async def attempt_login(
        self, page: Page, login_url: str, username: str, password: str
    ) -> Optional[dict]:
        client = self._get_client()
        if not client:
            return None

        try:
            # Capture and sanitize page HTML
            raw_html = await page.content()
            cleaned_html = _sanitize_html_for_llm(raw_html)

            print("    [LoginAgent/LLM] Sending login page HTML to Ollama for analysis...")

            user_prompt = f"Analyze this login page HTML and extract the CSS selectors:\n\n{cleaned_html}"

            response = client.generate_json(
                system_prompt=LLM_LOGIN_SYSTEM_PROMPT,
                user_prompt=user_prompt,
                temperature=0.1,
            )

            if isinstance(response, dict):
                username_sel = response.get("username_sel")
                password_sel = response.get("password_sel")
                submit_sel = response.get("submit_sel")

                if username_sel and password_sel:
                    print(f"    [LoginAgent/LLM] Detected fields -> "
                          f"User: '{username_sel}', "
                          f"Pass: '{password_sel}', "
                          f"Submit: '{submit_sel or 'N/A'}'")
                    return {
                        "username_sel": username_sel,
                        "password_sel": password_sel,
                        "submit_sel": submit_sel,
                    }
                else:
                    print("    [LoginAgent/LLM] LLM could not identify login fields")
                    return None
            else:
                print(f"    [LoginAgent/LLM] Unexpected response type: {type(response)}")
                return None

        except Exception as e:
            print(f"    [LoginAgent/LLM] Analysis failed: {e}")
            return None


# ─────────────────────────────────────────────
#  STRATEGY 3: MANUAL FALLBACK
# ─────────────────────────────────────────────

class ManualFallbackStrategy(LoginStrategy):
    """Prompts the operator for CSS selectors. Only works in interactive mode."""

    def __init__(self, interactive: bool = True):
        self.interactive = interactive

    async def attempt_login(
        self, page: Page, login_url: str, username: str, password: str
    ) -> Optional[dict]:
        if not self.interactive:
            print("    [LoginAgent/Manual] Non-interactive mode — skipping manual fallback")
            return None

        print("\n    [LoginAgent/Manual] Automatic login field detection failed.")
        print("    Please provide CSS selectors for the login form:")

        username_sel = input("      Username field selector (e.g. #email): ").strip()
        password_sel = input("      Password field selector (e.g. #password): ").strip()
        submit_sel = input("      Submit button selector (e.g. button[type='submit']): ").strip()

        if username_sel and password_sel:
            return {
                "username_sel": username_sel,
                "password_sel": password_sel,
                "submit_sel": submit_sel or None,
            }

        print("    [LoginAgent/Manual] Insufficient selectors provided")
        return None


# ─────────────────────────────────────────────
#  JWT EXTRACTION HELPER
# ─────────────────────────────────────────────

def _extract_jwt(value: str) -> Optional[str]:
    """Detect a JWT pattern (3 base64url segments separated by dots)."""
    jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
    m = re.search(jwt_pattern, value)
    return m.group(0) if m else None


# ─────────────────────────────────────────────
#  LOGIN AGENT (main class)
# ─────────────────────────────────────────────

class LoginAgent:
    """
    Modular authentication agent.

    Tries login strategies in order until one succeeds.
    Caches sessions per role with TTL-based expiry.
    
    Usage:
        agent = LoginAgent(login_url="https://app.example.com/login")
        session = await agent.login("Admin", "admin@test.com", "pass123")
        # Later, get a cached or fresh session:
        session = await agent.get_session("Admin", "admin@test.com", "pass123")
    """

    def __init__(
        self,
        login_url: str,
        strategies: Optional[list[LoginStrategy]] = None,
        session_ttl: int = 300,
        ollama_client=None,
        interactive: bool = True,
    ):
        self.login_url = login_url
        self.session_ttl = session_ttl
        self._sessions: dict[str, SessionData] = {}
        self._locks: dict[str, asyncio.Lock] = {}

        # Default strategy chain
        if strategies is None:
            self.strategies = [
                HeuristicLoginStrategy(),
                LLMLoginStrategy(ollama_client=ollama_client),
                ManualFallbackStrategy(interactive=interactive),
            ]
        else:
            self.strategies = strategies

    async def login(
        self,
        role: str,
        username: str,
        password: str,
        playwright_instance=None,
    ) -> Optional[SessionData]:
        """
        Perform a fresh login for the given role.

        Creates a new browser context, navigates to login_url,
        tries each strategy in order, fills credentials, and
        captures the resulting session cookies/JWT.

        Returns SessionData on success, None on failure.
        """
        if role not in self._locks:
            self._locks[role] = asyncio.Lock()

        async with self._locks[role]:
            print(f"\n    [LoginAgent] Authenticating role '{role}' (user: {username})...")

            # If no playwright instance provided, create one
            own_pw = False
            pw = playwright_instance
            if pw is None:
                pw_cm = async_playwright()
                pw = await pw_cm.start()
                own_pw = True

            try:
                browser = await pw.chromium.launch(headless=True)
                context: BrowserContext = await browser.new_context(
                    ignore_https_errors=True,
                    user_agent="AHVF-SecurityScanner/1.0 (authorized-testing)",
                )
                page: Page = await context.new_page()

                # Navigate to login page
                try:
                    await page.goto(self.login_url, wait_until="networkidle", timeout=30000)
                except Exception as e:
                    print(f"    [LoginAgent] Could not load login page: {e}")
                    await browser.close()
                    return None

                # Try each strategy in order
                selectors = None
                for strategy in self.strategies:
                    strategy_name = type(strategy).__name__
                    selectors = await strategy.attempt_login(page, self.login_url, username, password)
                    if selectors:
                        print(f"    [LoginAgent] Strategy '{strategy_name}' succeeded")
                        break
                    else:
                        print(f"    [LoginAgent] Strategy '{strategy_name}' failed, trying next...")

                if not selectors:
                    print(f"    [LoginAgent] All strategies exhausted for role '{role}'")
                    await browser.close()
                    return None

                # Fill and submit the login form using detected selectors
                session = await self._fill_and_submit(
                    page, context, role, username, password, selectors
                )

                await browser.close()

                if session:
                    self._sessions[role] = session
                    print(f"    [LoginAgent] Session cached for role '{role}' (TTL: {self.session_ttl}s)")

                return session

            finally:
                if own_pw:
                    await pw.stop()

    async def _fill_and_submit(
        self,
        page: Page,
        context: BrowserContext,
        role: str,
        username: str,
        password: str,
        selectors: dict,
    ) -> Optional[SessionData]:
        """Fill in the login form and submit, then capture the resulting session."""
        user_sel = selectors.get("username_sel")
        pwd_sel = selectors.get("password_sel")
        submit_sel = selectors.get("submit_sel")

        try:
            # Wait for elements
            if user_sel:
                await page.wait_for_selector(user_sel, timeout=10000)
            if pwd_sel:
                await page.wait_for_selector(pwd_sel, timeout=10000)

            # Fill credentials
            await page.fill(user_sel, username)
            await page.fill(pwd_sel, password)

            # Submit
            if submit_sel:
                await page.click(submit_sel)
            else:
                await page.press(pwd_sel, "Enter")

            # Wait for navigation/redirect
            await page.wait_for_timeout(5000)

            # Check if login succeeded (heuristic: no longer on login page)
            parsed = urllib.parse.urlparse(page.url)
            current_fragment = parsed.fragment.lower()

            if "login" in current_fragment or "login" in parsed.path.lower():
                print(f"    [LoginAgent] Still on login page — login likely failed")
                return None

            print(f"    [LoginAgent] Login success -> redirected to {page.url}")

            # Capture session data
            raw_cookies = await context.cookies()
            cookies = [
                {"name": c["name"], "value": c["value"], "domain": c["domain"]}
                for c in raw_cookies
            ]

            # Extract JWT from cookies
            jwt_token = None
            for c in cookies:
                found = _extract_jwt(c.get("value", ""))
                if found:
                    jwt_token = found
                    break

            # Build headers
            headers = {}
            if jwt_token:
                headers["Authorization"] = f"Bearer {jwt_token}"

            return SessionData(
                role=role,
                cookies=cookies,
                jwt=jwt_token,
                headers=headers,
                authenticated_at=datetime.now(UTC),
                ttl_seconds=self.session_ttl,
            )

        except Exception as e:
            print(f"    [LoginAgent] Form interaction failed: {e}")
            return None

    async def get_session(
        self,
        role: str,
        username: str = "",
        password: str = "",
        playwright_instance=None,
    ) -> Optional[SessionData]:
        """
        Get a valid session for the given role.
        
        Returns cached session if still valid, otherwise re-authenticates.
        Requires username/password if re-auth might be needed.
        """
        cached = self._sessions.get(role)
        if cached and not cached.is_expired:
            return cached

        if not username or not password:
            print(f"    [LoginAgent] Session for '{role}' expired but no credentials for re-auth")
            return cached  # Return stale session as last resort

        print(f"    [LoginAgent] Session for '{role}' expired, re-authenticating...")
        return await self.login(role, username, password, playwright_instance)

    def invalidate(self, role: str):
        """Force invalidate a cached session."""
        self._sessions.pop(role, None)

    def invalidate_all(self):
        """Force invalidate all cached sessions."""
        self._sessions.clear()
