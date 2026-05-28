"""
AHVF — Module 1: Stateful Crawler (FR-02)
==========================================
Implements FR-02.1 through FR-02.7:
  FR-02.1  Playwright headless DOM-flow capture per role
  FR-02.2  Captures endpoints, JWTs, cookies, CSRF tokens, form structures
  FR-02.3  Link-following, form submission, AJAX interception
  FR-02.4  DOM-Mutation Observer for SPA/lazy-loaded routes  [NEW - CRITICAL]
  FR-02.5  GraphQL introspection harvesting                  [NEW - CRITICAL]
  FR-02.6  API versioning pattern detection (BAC candidates) [NEW]
  FR-02.7  Crawl deduplication via canonicalized fingerprint [NEW]

Output: results/crawl_results.txt  (human-readable)
        results/crawl_results.json (machine-readable, for downstream modules)

USAGE:
    pip install playwright aiofiles
    playwright install chromium
    python ahvf_crawler.py

NOTE: This script is for authorized security testing only.
      A signed Rules of Engagement (RoE) document must be on file
      before running against any target environment.
"""

import asyncio
import csv
import hashlib
import json
import re
import time
import urllib.parse
from dataclasses import dataclass, field, asdict
from datetime import datetime, UTC
from pathlib import Path
from typing import Optional

# pyrefly: ignore [missing-import]
from playwright.async_api import async_playwright, Page, BrowserContext, Request, Response

# ─────────────────────────────────────────────
#  CONFIGURATION  (hardcoded — refactor later)
# ─────────────────────────────────────────────

TARGET_BASE_URL = ""

# Form-based login: selector for the username/password fields and submit button.
# Adjust selectors to match your target's login page.
LOGIN_URL       = ""
USERNAME_SELECTOR = ""
PASSWORD_SELECTOR = ""
SUBMIT_SELECTOR   = ""

# ─────────────────────────────────────────────
#  CAPTCHA / LLM CONFIG
# ─────────────────────────────────────────────
OLLAMA_BASE_URL   = "http://localhost:11434"   # Local Ollama instance
OLLAMA_TEXT_MODEL = "qwen2.5:7b"              # For DOM analysis (no vision needed)
OLLAMA_VIS_MODEL  = "llama3.2-vision"         # For CAPTCHA image reading
CAPTCHA_MAX_RETRIES = 2                        # Re-solve attempts before giving up

# Credentials are now collected interactively from the terminal at run time.

# Scope: only URLs whose host matches this list will be crawled.
TARGET_HOST = ""
SCOPE_HOSTS = []

# Excluded path prefixes (never follow or submit forms here)
EXCLUDED_PATHS = [
    "/logout",
    "/signout",
    "/sign-out",
    "/__webpack",
    "/static/",
    "/assets/",
    "/favicon",
]

MAX_PAGES_PER_ROLE = 500     # Safety cap — prevent infinite crawl
CRAWL_DEPTH        = 10      # Max link-follow depth from root
FORM_SUBMIT_TIMEOUT = 5000   # ms to wait after form submission
OUTPUT_DIR         = Path("results")

# GraphQL common paths to probe
GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/query"]

# OpenAPI / Swagger common paths to probe
OPENAPI_PATHS = [
    "/swagger.json", "/api-docs", "/v1/api-docs", "/v2/api-docs", 
    "/api/swagger.json", "/openapi.json", "/docs", "/swagger/v1/swagger.json"
]

# ─────────────────────────────────────────────
#  DATA STRUCTURES
# ─────────────────────────────────────────────

@dataclass
class EndpointRecord:
    url:            str
    method:         str
    role:           str
    headers:        dict        = field(default_factory=dict)
    body:           Optional[str] = None
    response_status: Optional[int] = None
    response_body:  Optional[str] = None
    jwt:            Optional[str] = None
    cookies:        list        = field(default_factory=list)
    csrf_token:     Optional[str] = None
    form_structure: Optional[dict] = None
    source:         str         = "network"   # network | form | graphql | mutation_observer
    schema_hash:    str         = ""
    discovered_at:  str         = ""

    def __post_init__(self):
        if not self.discovered_at:
            self.discovered_at = datetime.now(UTC).isoformat()
        if not self.schema_hash:
            self.schema_hash = _fingerprint(self.url, self.method)


@dataclass
class GraphQLSchema:
    endpoint:   str
    role:       str
    schema:     dict            = field(default_factory=dict)
    types:      list            = field(default_factory=list)
    queries:    list            = field(default_factory=list)
    mutations:  list            = field(default_factory=list)


@dataclass
class CrawlResult:
    role:               str
    endpoints:          list[EndpointRecord]    = field(default_factory=list)
    graphql_schemas:    list[GraphQLSchema]     = field(default_factory=list)
    api_version_flags:  list[dict]              = field(default_factory=list)  # FR-02.6
    spa_routes:         list[str]               = field(default_factory=list)  # FR-02.4


# ─────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────

def _fingerprint(url: str, method: str) -> str:
    """Canonicalized URL fingerprint for deduplication (FR-02.7)."""
    parsed = urllib.parse.urlparse(url)
    # Normalize query params: sort them, strip values (keep keys only for dedup)
    params = sorted(urllib.parse.parse_qs(parsed.query).keys())
    canonical = f"{method.upper()}:{parsed.scheme}://{parsed.netloc}{parsed.path}?{','.join(params)}"
    return hashlib.sha256(canonical.encode()).hexdigest()[:16]


def _in_scope(url: str) -> bool:
    try:
        host = urllib.parse.urlparse(url).hostname or ""

        allowed = any(
            host == s or host.endswith(f".{s}")
            for s in SCOPE_HOSTS
        )

        return allowed

    except Exception:
        return False


def _is_excluded(url: str) -> bool:
    path = urllib.parse.urlparse(url).path
    return any(path.startswith(ex) for ex in EXCLUDED_PATHS)


def _extract_jwt(value: str) -> Optional[str]:
    """Detect a JWT pattern (3 base64url segments separated by dots)."""
    jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
    m = re.search(jwt_pattern, value)
    return m.group(0) if m else None


def _detect_api_version(url: str) -> Optional[str]:
    """Extract version string from URL if present."""
    m = re.search(r'/v(\d+)/', url)
    return m.group(1) if m else None


def _format_endpoint_txt(ep: EndpointRecord, idx: int) -> str:
    lines = [
        f"  [{idx}] {ep.method:6s} {ep.url}",
        f"       Role      : {ep.role}",
        f"       Source    : {ep.source}",
        f"       Hash      : {ep.schema_hash}",
        f"       Status    : {ep.response_status or 'N/A'}",
    ]
    if ep.jwt:
        lines.append(f"       JWT       : {ep.jwt[:40]}…")
    if ep.csrf_token:
        lines.append(f"       CSRF      : {ep.csrf_token[:40]}")
    if ep.cookies:
        names = ", ".join(c.get("name", "?") for c in ep.cookies[:5])
        lines.append(f"       Cookies   : {names}")
    if ep.form_structure:
        fields = list(ep.form_structure.get("fields", {}).keys())
        lines.append(f"       Form flds : {', '.join(fields)}")
    return "\n".join(lines)


# ─────────────────────────────────────────────
#  DOM MUTATION OBSERVER JS  (FR-02.4)
# ─────────────────────────────────────────────

DOM_MUTATION_OBSERVER_JS = """
(() => {
    if (window.__ahvf_routes) return;
    window.__ahvf_routes = new Set();

    // Capture pushState / replaceState (SPA navigation)
    const _pushState    = history.pushState.bind(history);
    const _replaceState = history.replaceState.bind(history);

    history.pushState = function(state, title, url) {
        if (url) window.__ahvf_routes.add(String(url));
        return _pushState(state, title, url);
    };
    history.replaceState = function(state, title, url) {
        if (url) window.__ahvf_routes.add(String(url));
        return _replaceState(state, title, url);
    };

    // Capture hash-router navigation
    window.addEventListener('hashchange', () => {
        window.__ahvf_routes.add(location.href);
    });

    // MutationObserver: watch for new <a href> and data-* route attrs injected by React/Vue/Angular
    const observer = new MutationObserver((mutations) => {
        for (const m of mutations) {
            for (const node of m.addedNodes) {
                if (node.nodeType !== 1) continue;  // Element nodes only
                // Collect all anchors within added subtree
                const anchors = node.querySelectorAll
                    ? node.querySelectorAll('a[href]')
                    : [];
                for (const a of anchors) {
                    try {
                        const abs = new URL(a.href, location.origin).href;
                        window.__ahvf_routes.add(abs);
                    } catch(e) {}
                }
                // Also check router-link, data-href patterns (Vue / Angular)
                const routerLinks = node.querySelectorAll
                    ? node.querySelectorAll('[to],[data-href],[routerlink]')
                    : [];
                for (const el of routerLinks) {
                    const val = el.getAttribute('to') || el.getAttribute('data-href') || el.getAttribute('routerlink');
                    if (val) {
                        try {
                            const abs = new URL(val, location.origin).href;
                            window.__ahvf_routes.add(abs);
                        } catch(e) {
                            if (val.startsWith('/')) window.__ahvf_routes.add(location.origin + val);
                        }
                    }
                }
            }
        }
    });
    observer.observe(document.documentElement, { childList: true, subtree: true });
    console.debug('[AHVF] MutationObserver + history hooks installed');
})();
"""

COLLECT_SPA_ROUTES_JS = """
() => window.__ahvf_routes ? Array.from(window.__ahvf_routes) : []
"""


# ─────────────────────────────────────────────
#  GRAPHQL INTROSPECTION  (FR-02.5)
# ─────────────────────────────────────────────

GRAPHQL_INTROSPECTION_QUERY = """
{
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields {
        name
        args { name type { name kind ofType { name kind } } }
        type { name kind ofType { name kind } }
      }
    }
  }
}
"""

async def _graphql_introspect(page: Page, role: str, gql_url: str) -> Optional[GraphQLSchema]:
    """Send an introspection query and parse the schema (FR-02.5)."""
    try:
        result = await page.evaluate(f"""
        async () => {{
            const resp = await fetch('{gql_url}', {{
                method: 'POST',
                headers: {{ 'Content-Type': 'application/json' }},
                body: JSON.stringify({{ query: `{GRAPHQL_INTROSPECTION_QUERY}` }})
            }});
            return resp.json();
        }}
        """)

        if not result or "data" not in result:
            return None

        schema_data = result["data"].get("__schema", {})
        types_raw   = schema_data.get("types", [])
        queries     = []
        mutations   = []

        for t in types_raw:
            if t.get("name") == schema_data.get("queryType", {}).get("name"):
                queries = [f.get("name") for f in (t.get("fields") or [])]
            if schema_data.get("mutationType") and \
               t.get("name") == schema_data.get("mutationType", {}).get("name"):
                mutations = [f.get("name") for f in (t.get("fields") or [])]

        # Filter out built-in types
        user_types = [t for t in types_raw if t.get("name") and not t["name"].startswith("__")]

        return GraphQLSchema(
            endpoint=gql_url,
            role=role,
            schema=schema_data,
            types=[t.get("name") for t in user_types],
            queries=queries,
            mutations=mutations,
        )
    except Exception as e:
        print(f"    [GraphQL] Introspection failed at {gql_url}: {e}")
        return None


async def _openapi_probe(page: Page, role: str, url: str) -> Optional[list[EndpointRecord]]:
    """Fetch OpenAPI/Swagger definitions and extract endpoints."""
    try:
        result = await page.evaluate(f"""
        async () => {{
            const resp = await fetch('{url}');
            if (!resp.ok) return null;
            return resp.json();
        }}
        """)
        
        if not result or "paths" not in result:
            return None
            
        endpoints = []
        for path, methods in result["paths"].items():
            for method in methods.keys():
                full_url = urllib.parse.urljoin(TARGET_BASE_URL, path)
                fp = _fingerprint(full_url, method.upper())
                endpoints.append(EndpointRecord(
                    url=full_url,
                    method=method.upper(),
                    role=role,
                    source="openapi",
                    schema_hash=fp,
                ))
        return endpoints
    except Exception:
        return None

async def _probe_sitemap_and_robots(page: Page, role: str) -> list[EndpointRecord]:
    endpoints = []
    # Robots.txt
    try:
        robots_url = urllib.parse.urljoin(TARGET_BASE_URL, "/robots.txt")
        result = await page.evaluate(f"""
        async () => {{
            const resp = await fetch('{robots_url}');
            if (!resp.ok) return null;
            return resp.text();
        }}
        """)
        if result:
            for line in result.splitlines():
                if line.lower().startswith("allow:") or line.lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path.startswith("/"):
                        full_url = urllib.parse.urljoin(TARGET_BASE_URL, path)
                        fp = _fingerprint(full_url, "GET")
                        endpoints.append(EndpointRecord(
                            url=full_url,
                            method="GET",
                            role=role,
                            source="robots.txt",
                            schema_hash=fp
                        ))
    except Exception:
        pass
    return endpoints


async def _extract_dom_snapshot(page: Page) -> str:
    snapshot = await page.evaluate("""
    () => {
        const lines = [];

        lines.push('PAGE: ' + document.title);

        document.querySelectorAll('h1, h2, h3').forEach(h => {
            const t = h.textContent.trim().replace(/\\s+/g, ' ');
            if (t) lines.push('HEADING: ' + t.slice(0, 80));
        });

        document.querySelectorAll('input, textarea, select').forEach(el => {
            const attrs = {
                tag:          el.tagName.toLowerCase(),
                type:         el.getAttribute('type') || '',
                name:         el.getAttribute('name') || '',
                id:           el.getAttribute('id') || '',
                placeholder:  el.getAttribute('placeholder') || '',
                autocomplete: el.getAttribute('autocomplete') || '',
                ariaLabel:    el.getAttribute('aria-label') || '',
                testid:       el.getAttribute('data-testid') || '',
                visible:      window.getComputedStyle(el).display !== 'none'
            };
            lines.push('INPUT: ' + JSON.stringify(attrs));
        });

        document.querySelectorAll('label').forEach(el => {
            lines.push('LABEL: for=' + (el.getAttribute('for') || '') +
                       ' text=' + el.textContent.trim().replace(/\\s+/g, ' ').slice(0, 60));
        });

        document.querySelectorAll('button, input[type="submit"], input[type="button"]').forEach(el => {
            const attrs = {
                tag:    el.tagName.toLowerCase(),
                type:   el.getAttribute('type') || '',
                id:     el.getAttribute('id') || '',
                name:   el.getAttribute('name') || '',
                text:   el.textContent.trim().replace(/\\s+/g, ' ').slice(0, 40),
                testid: el.getAttribute('data-testid') || ''
            };
            lines.push('BUTTON: ' + JSON.stringify(attrs));
        });

        const captchaSelectors = [
            'img[id*="captcha" i]',
            'img[src*="captcha" i]',
            'img[class*="captcha" i]',
            'img[alt*="captcha" i]',
            'canvas[id*="captcha" i]',
            'canvas[class*="captcha" i]',
            'div[class*="captcha" i]',
            'input[name*="captcha" i]',
            'input[id*="captcha" i]'
        ];
        captchaSelectors.forEach(sel => {
            const el = document.querySelector(sel);
            if (el) {
                lines.push(
                    'CAPTCHA_SIGNAL: selector=' + sel +
                    ' tag=' + el.tagName.toLowerCase() +
                    ' id=' + (el.id || '') +
                    ' src=' + (el.getAttribute('src') || '').slice(0, 80)
                );
            }
        });

        return lines.join('\\n');
    }
    """)
    return snapshot or ""

async def _solve_captcha_with_llm(page: Page, captcha_signal: str) -> Optional[str]:
    import base64
    import io
    import urllib.request as ureq
    try:
        from PIL import Image, ImageEnhance
        import numpy as np
        import cv2
    except ImportError:
        print("    [CAPTCHA] Missing libraries. Run: pip install pillow opencv-python-headless numpy")
        return None

    sel_match = re.search(r'selector=([^\s]+)', captcha_signal)
    if not sel_match:
        return None
    selector = sel_match.group(1)

    raw_bytes = None

    try:
        element = await page.query_selector(selector)
        if element:
            raw_bytes = await element.screenshot(type="png", scale="device")
    except Exception:
        pass

    if not raw_bytes:
        try:
            data_url = await page.evaluate(f"""
            () => {{
                const el = document.querySelector('{selector}');
                if (el && el.tagName.toLowerCase() === 'canvas') {{
                    return el.toDataURL('image/png', 1.0);
                }}
                return null;
            }}
            """)
            if data_url and ',' in data_url:
                raw_bytes = base64.b64decode(data_url.split(',', 1)[1])
        except Exception:
            pass

    if not raw_bytes:
        print(f"    [CAPTCHA] Could not capture image for selector: {selector}")
        return None

    try:
        img = Image.open(io.BytesIO(raw_bytes)).convert("RGBA")
        bg  = Image.new("RGBA", img.size, (255, 255, 255, 255))
        bg.paste(img, mask=img.split()[3])
        img = bg.convert("RGB")

        w, h = img.size
        if w < 300:
            scale = 300 / w
            img = img.resize((int(w * scale), int(h * scale)), Image.LANCZOS)

        arr      = np.array(img)
        gray     = cv2.cvtColor(arr, cv2.COLOR_RGB2GRAY)
        denoised = cv2.fastNlMeansDenoising(gray, h=10, templateWindowSize=7, searchWindowSize=21)
        binary   = cv2.adaptiveThreshold(
            denoised, 255,
            cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
            cv2.THRESH_BINARY,
            blockSize=11, C=2
        )
        kernel  = np.ones((2, 2), np.uint8)
        cleaned = cv2.morphologyEx(binary, cv2.MORPH_CLOSE, kernel)
        img     = Image.fromarray(cleaned).convert("RGB")
        img     = ImageEnhance.Contrast(img).enhance(3.0)

        out = io.BytesIO()
        img.save(out, format="PNG")
        processed_b64 = base64.b64encode(out.getvalue()).decode("utf-8")

    except Exception as e:
        print(f"    [CAPTCHA] Preprocessing failed ({e}), using raw image")
        processed_b64 = base64.b64encode(raw_bytes).decode("utf-8")

    prompt = (
        "This image contains a CAPTCHA. "
        "Read every character carefully. "
        "Reply with ONLY the characters you see — no spaces, no explanation, nothing else. "
        "If it is a math problem, reply with only the numeric answer."
    )

    payload = json.dumps({
        "model":  OLLAMA_VIS_MODEL,
        "prompt": prompt,
        "images": [processed_b64],
        "stream": False,
        "options": {"temperature": 0.0, "num_predict": 32}
    }).encode("utf-8")

    try:
        req = ureq.Request(
            f"{OLLAMA_BASE_URL}/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with ureq.urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read().decode("utf-8"))

        raw_answer = result.get("response", "").strip()
        clean      = re.sub(r"[^A-Za-z0-9@#\-]", "", raw_answer).strip()
        print(f"    [CAPTCHA] LLM answer: '{clean}' (raw: '{raw_answer[:60]}')")
        return clean if clean else None

    except Exception as e:
        print(f"    [CAPTCHA] Ollama call failed: {e}")
        return None


# ─────────────────────────────────────────────
#  LOGIN HANDLER
# ─────────────────────────────────────────────

async def _login(page: Page, username: str, password: str) -> bool:
    """Perform form-based login. Returns True on apparent success."""
    try:
        await page.goto(LOGIN_URL, wait_until="networkidle", timeout=30000)
    except Exception as e:
        print(f"    [Login] Could not load login page: {e}")
        return False

    # ── CAPTCHA DETECTION & SOLVE ─────────────────────────────────────
    dom_snapshot   = await _extract_dom_snapshot(page)
    captcha_lines  = [l for l in dom_snapshot.splitlines() if l.startswith("CAPTCHA_SIGNAL:")]

    if captcha_lines:
        print(f"    [CAPTCHA] {len(captcha_lines)} CAPTCHA signal(s) detected")

        captcha_input_sel = await page.evaluate("""
        () => {
            const candidates = [
                'input[name*="captcha" i]',
                'input[id*="captcha" i]',
                'input[placeholder*="captcha" i]',
                'input[name*="code" i]',
                'input[name*="verify" i]'
            ];
            for (const sel of candidates) {
                const el = document.querySelector(sel);
                if (el) {
                    if (el.id)   return '#' + CSS.escape(el.id);
                    if (el.name) return 'input[name="' + CSS.escape(el.name) + '"]';
                    return sel;
                }
            }
            return null;
        }
        """)

        solved = False
        for attempt in range(1, CAPTCHA_MAX_RETRIES + 1):
            print(f"    [CAPTCHA] Solve attempt {attempt}/{CAPTCHA_MAX_RETRIES}...")
            answer = await _solve_captcha_with_llm(page, captcha_lines[0])

            if answer and captcha_input_sel:
                try:
                    await page.fill(captcha_input_sel, answer)
                    print(f"    [CAPTCHA] Filled '{captcha_input_sel}' with '{answer}'")
                    solved = True
                    break
                except Exception as e:
                    print(f"    [CAPTCHA] Could not fill input: {e}")

            elif answer and not captcha_input_sel:
                print(f"    [CAPTCHA] Answer '{answer}' obtained but no input field found")
                solved = True
                break

            else:
                print(f"    [CAPTCHA] Attempt {attempt} returned no answer")
                if attempt < CAPTCHA_MAX_RETRIES:
                    try:
                        await page.reload(wait_until="networkidle", timeout=15000)
                    except Exception:
                        pass

        if not solved:
            print(f"    [CAPTCHA] All attempts failed — proceeding anyway (CAPTCHA might be optional)")

    else:
        print("    [CAPTCHA] No CAPTCHA detected on login page")
    # ── END CAPTCHA BLOCK ─────────────────────────────────────────────

    # Inject MutationObserver immediately after page load
    await page.add_init_script(DOM_MUTATION_OBSERVER_JS)
    try:
        await page.evaluate(DOM_MUTATION_OBSERVER_JS)
    except Exception:
        pass

    # Heuristic dynamic form field detection
    print("    [Login] Performing dynamic login field discovery...")
    selectors = None
    try:
        # Give page brief moment to execute scripts/components
        await page.wait_for_timeout(2000)
        
        selectors = await page.evaluate("""
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
                username: getSel(user),
                password: getSel(pwd),
                submit: getSel(submit)
            };
        }
        """)
    except Exception as e:
        print(f"    [Login] Dynamic detection failed: {e}")

    # Determine final selectors to use (falling back to configured selectors)
    user_sel = (selectors and selectors.get("username")) or USERNAME_SELECTOR
    pwd_sel = (selectors and selectors.get("password")) or PASSWORD_SELECTOR
    submit_sel = (selectors and selectors.get("submit")) or SUBMIT_SELECTOR

    print(f"    [Login] Resolved selectors -> Username: '{user_sel}', Password: '{pwd_sel}', Submit: '{submit_sel}'")

    try:
        # Wait for elements to become visible
        if user_sel:
            await page.wait_for_selector(user_sel, timeout=10000)
        if pwd_sel:
            await page.wait_for_selector(pwd_sel, timeout=10000)

        # Fill values using typing which triggers React/Vue synthetic events reliably
        await page.fill(user_sel, "") # Clear first
        await page.type(user_sel, username, delay=30)
        await page.wait_for_timeout(500)
        
        await page.fill(pwd_sel, "")
        await page.type(pwd_sel, password, delay=30)
        await page.wait_for_timeout(500)

        # Force a Javascript click to bypass any transparent overlays/banners
        if submit_sel:
            try:
                await page.evaluate(f"document.querySelector('{submit_sel}').click()")
            except Exception:
                pass
        
        # Always press Enter on password field as fallback
        try:
            await page.press(pwd_sel, "Enter")
        except Exception:
            pass

        try:
            # Wait for network idle or timeout, catching exception
            await page.wait_for_load_state("networkidle", timeout=8000)
        except Exception:
            pass

        parsed = urllib.parse.urlparse(page.url)
        current_fragment = parsed.fragment.lower()

        print("\n===== LOGIN DEBUG =====")
        print("Current URL:", page.url)
        print("Parsed Path:", parsed.path)
        print("Parsed Fragment:", current_fragment)
        print("=======================\n")

        # Heuristic to check if we are still on a login screen
        login_form_visible = False
        try:
            login_form_visible = await page.is_visible(user_sel)
        except Exception:
            pass

        if login_form_visible and ("login" in current_fragment or "login" in parsed.path.lower()):
            print("    [Login] Still on login page and form is visible.")
            # Extract potential error messages
            error_msg = await page.evaluate('''() => {
                const el = document.querySelector('.alert, .error, .text-danger, [role="alert"], .toast-message, .error-message');
                return el ? el.innerText.trim() : "";
            }''')
            if error_msg:
                print(f"    [Login] Error on page: {error_msg}")
            return False

        print(f"    [Login] Success -> redirected to {page.url}")
        return True
    except Exception as e:
        print(f"    [Login] Form interaction failed: {e}")
        return False


# ─────────────────────────────────────────────
#  NETWORK INTERCEPTOR
# ─────────────────────────────────────────────

def _make_request_handler(
    role: str,
    seen_hashes: set,
    records: list[EndpointRecord],
    current_cookies: list,
    current_jwt: list,  # mutable 1-element list used as a reference
):
    async def on_request(request: Request):
        url = request.url
        method = request.method

        if not _in_scope(url) or _is_excluded(url):
            return
        if url.endswith((".css", ".png", ".jpg", ".gif", ".ico", ".woff", ".svg")):
            return

        fp = _fingerprint(url, method)
        if fp in seen_hashes:
            return  # FR-02.7 dedup
        seen_hashes.add(fp)

        headers = dict(request.headers)

        # Extract JWT from Authorization header or cookies
        jwt = None
        auth_header = headers.get("authorization", "")
        if auth_header.lower().startswith("bearer "):
            jwt = auth_header[7:]
        elif current_jwt and current_jwt[0]:
            jwt = current_jwt[0]
        else:
            # Scan cookies for JWT-like values
            for c in current_cookies:
                val = c.get("value", "")
                found = _extract_jwt(val)
                if found:
                    jwt = found
                    break

        # Extract CSRF token
        csrf = None
        for hname in ("x-csrf-token", "x-xsrf-token", "csrf-token", "_csrf"):
            if hname in headers:
                csrf = headers[hname]
                break

        body = None
        try:
            body = request.post_data
        except Exception:
            pass

        rec = EndpointRecord(
            url=url,
            method=method,
            role=role,
            headers={k: v for k, v in headers.items()
                     if k.lower() not in ("cookie", "authorization")},  # strip sensitive
            body=body,
            jwt=jwt,
            cookies=list(current_cookies),
            csrf_token=csrf,
            source=f"network ({request.resource_type})",
            schema_hash=fp,
        )
        records.append(rec)

    return on_request


def _make_response_handler(records: list[EndpointRecord], role: str):
    async def on_response(response: Response):
        url = response.url
        status = response.status
        
        response_body = None
        try:
            if response.request.resource_type in ("fetch", "xhr"):
                response_body = await response.text()
        except Exception:
            pass

        # Update the last-seen record for this URL with the response status
        for rec in reversed(records):
            if rec.url == url:
                rec.response_status = status
                rec.response_body = response_body
                break


    return on_response

def _normalize_spa_url(url: str) -> str:
    if "#" in url:
        return url
    return url


# ─────────────────────────────────────────────
#  FORM DISCOVERY & SUBMISSION  (FR-02.3)
# ─────────────────────────────────────────────

async def _discover_and_submit_forms(page: Page, role: str, records: list[EndpointRecord]):
    """Find all forms on current page, record their structure, submit with safe values."""
    forms = await page.query_selector_all("form")
    for form in forms:
        try:
            action = await form.get_attribute("action") or page.url
            method = (await form.get_attribute("method") or "GET").upper()
            action_url = urllib.parse.urljoin(page.url, action)

            if not _in_scope(action_url) or _is_excluded(action_url):
                continue

            inputs = await form.query_selector_all("input, select, textarea")
            form_fields = {}
            for inp in inputs:
                name  = await inp.get_attribute("name")  or await inp.get_attribute("id") or "unnamed"
                itype = (await inp.get_attribute("type") or "text").lower()
                form_fields[name] = itype

            # Fill with safe default values (won't trigger destructive actions)
            for inp in inputs:
                itype = (await inp.get_attribute("type") or "text").lower()
                name  = await inp.get_attribute("name") or ""
                if itype in ("text", "search", "url"):
                    await inp.fill("test_value")
                elif itype == "email":
                    await inp.fill("test@example.com")
                elif itype == "number":
                    await inp.fill("1")
                elif itype == "checkbox":
                    await inp.check()
                # Intentionally skip file inputs, submit, reset, hidden

            # Record form structure before submitting
            fp = _fingerprint(action_url, method)
            rec = EndpointRecord(
                url=action_url,
                method=method,
                role=role,
                form_structure={"fields": form_fields, "action": action_url},
                source="form",
                schema_hash=fp,
            )
            records.append(rec)

        except Exception as e:
            print(f"    [Form] Error processing form: {e}")


# ─────────────────────────────────────────────
#  SINGLE-ROLE CRAWLER
# ─────────────────────────────────────────────

async def crawl_role(
    role: str,
    username: str,
    password: str,
    playwright_instance,
    all_role_results: dict,  # shared across roles for FR-02.6 comparison
) -> CrawlResult:

    print(f"\n{'='*60}")
    print(f"  Crawling role: [{role}]  user={username}")
    print(f"{'='*60}")

    result       = CrawlResult(role=role)
    seen_hashes  = set()
    current_cookies: list = []
    current_jwt: list     = [None]

    browser = await playwright_instance.chromium.launch(headless=True)
    context: BrowserContext = await browser.new_context(
        ignore_https_errors=True,
        user_agent="AHVF-SecurityScanner/1.0 (authorized-testing)",
    )
    page: Page = await context.new_page()

    # Install MutationObserver on every new page navigation
    await page.add_init_script(DOM_MUTATION_OBSERVER_JS)

    # Attach network interceptors
    page.on("request",  _make_request_handler(role, seen_hashes, result.endpoints, current_cookies, current_jwt))
    page.on("response", _make_response_handler(result.endpoints, role))

    # ── Step 1: Login (Only if username is provided) ─────────────────
    if username:
        login_ok = await _login(page, username, password)
        if not login_ok:
            print(f"  [!] Skipping role '{role}' — login failed.")
            await browser.close()
            return result

        # Refresh cookies after login
        raw_cookies = await context.cookies()
        print("\n===== LOGIN COOKIES =====")

        for cookie in raw_cookies:
            print(
                f"{cookie['name']} | "
                f"{cookie['domain']}"
            )

        print("=========================\n")
        current_cookies.clear()
        current_cookies.extend([{"name": c["name"], "value": c["value"], "domain": c["domain"]} for c in raw_cookies])

        # Extract JWT from cookies post-login
        for c in current_cookies:
            found = _extract_jwt(c.get("value", ""))
            if found:
                current_jwt[0] = found
                break
    else:
        print("  [Crawl] No username provided. Crawling unauthenticated (Guest mode)...")
        try:
            await page.goto(TARGET_BASE_URL, wait_until="domcontentloaded", timeout=30000)
        except Exception as e:
            print(f"  [!] Failed to load target URL: {e}")
            await browser.close()
            return result

    # ── Step 2: BFS link crawl ──────────────────────────────────────
    visited_urls  = set()
    queue = [(page.url, 0)]
    pages_visited = 0

    while queue and pages_visited < MAX_PAGES_PER_ROLE:
        url, depth = queue.pop(0)

        if url in visited_urls:
            continue
        if not _in_scope(url) or _is_excluded(url):
            continue
        if depth > CRAWL_DEPTH:
            continue

        visited_urls.add(url)
        pages_visited += 1
        print(f"  [Crawl] [{pages_visited:03d}] depth={depth} {url[:80]}")

        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=15000)
        except Exception as e:
            print(f"    [!] Navigation failed: {e}")
            continue

        # Collect SPA routes captured by MutationObserver (FR-02.4)
        try:
            spa_routes = await page.evaluate(COLLECT_SPA_ROUTES_JS)
            for r in spa_routes:
                if _in_scope(r) and r not in visited_urls:
                    result.spa_routes.append(r)
                    if r not in [u for u, _ in queue]:
                        queue.append((r, depth + 1))
        except Exception:
            pass

        # Collect standard <a href> links
        try:
            links = await page.eval_on_selector_all(
                "a[href]",
                "els => els.map(e => e.href)"
            )
            for link in links:
                abs_link = urllib.parse.urljoin(url, link)
                # Do not strip the fragment because this is a hash-routed SPA
                if abs_link and _in_scope(abs_link) and not _is_excluded(abs_link):
                    if abs_link not in visited_urls:
                        queue.append((abs_link, depth + 1))
        except Exception:
            pass

        # Discover forms (FR-02.3)
        await _discover_and_submit_forms(page, role, result.endpoints)

        # Wait briefly for any AJAX triggered by form discovery
        await asyncio.sleep(0.5)

    # ── Step 3: GraphQL introspection (FR-02.5) ────────────────────
    for gql_path in GRAPHQL_PATHS:
        gql_url = f"{TARGET_BASE_URL}{gql_path}"
        print(f"  [GraphQL] Probing {gql_url}…")
        gql_schema = await _graphql_introspect(page, role, gql_url)
        if gql_schema:
            result.graphql_schemas.append(gql_schema)
            print(f"    [+] GraphQL schema found: {len(gql_schema.types)} types, "
                  f"{len(gql_schema.queries)} queries, {len(gql_schema.mutations)} mutations")

    # ── Step 4: OpenAPI / Sitemap probing (NEW) ────────────────────
    for openapi_path in OPENAPI_PATHS:
        openapi_url = urllib.parse.urljoin(TARGET_BASE_URL, openapi_path)
        print(f"  [OpenAPI] Probing {openapi_url}…")
        eps = await _openapi_probe(page, role, openapi_url)
        if eps:
            result.endpoints.extend(eps)
            print(f"    [+] OpenAPI definition found: {len(eps)} endpoints")

    print(f"  [Discovery] Probing robots.txt…")
    extra_eps = await _probe_sitemap_and_robots(page, role)
    if extra_eps:
        result.endpoints.extend(extra_eps)
        print(f"    [+] Found {len(extra_eps)} endpoints from robots.txt")

    await browser.close()
    print(f"\n  Role '{role}' done: {len(result.endpoints)} endpoints, "
          f"{len(result.spa_routes)} SPA routes, {len(result.graphql_schemas)} GraphQL schemas")
    return result


# ─────────────────────────────────────────────
#  API VERSION COMPARISON  (FR-02.6)
# ─────────────────────────────────────────────

def _detect_version_bac_candidates(all_results: list[CrawlResult]) -> list[dict]:
    """
    Compare endpoints across API versions.
    Flag any endpoint path that appears in /api/vN/ but NOT in /api/vN+1/
    as a potential BAC candidate (old version may lack auth enforcement).
    """
    version_map: dict[str, dict[str, set]] = {}  # version -> method:path -> set of roles

    for result in all_results:
        for ep in result.endpoints:
            ver = _detect_api_version(ep.url)
            if ver is None:
                continue
            parsed = urllib.parse.urlparse(ep.url)
            # Normalize: strip the version segment so we can compare across versions
            norm_path = re.sub(r'/v\d+/', '/vX/', parsed.path)
            key = f"{ep.method}:{norm_path}"
            version_map.setdefault(ver, {})
            version_map[ver].setdefault(key, set()).add(result.role)

    flags = []
    versions = sorted(version_map.keys(), key=lambda v: int(v))
    for i, ver in enumerate(versions[:-1]):
        next_ver = versions[i + 1]
        for key in version_map[ver]:
            if key not in version_map.get(next_ver, {}):
                flags.append({
                    "endpoint_key":  key,
                    "present_in":    f"v{ver}",
                    "absent_in":     f"v{next_ver}",
                    "roles_seen":    list(version_map[ver][key]),
                    "bac_risk":      "HIGH — endpoint may exist without auth enforcement in older version",
                })
    return flags


# ─────────────────────────────────────────────
#  OUTPUT WRITER
# ─────────────────────────────────────────────

def _write_txt_report(all_results: list[CrawlResult], version_flags: list[dict], output_path: Path):
    lines = [
        "=" * 70,
        "AHVF — Crawl Results",
        f"Generated : {datetime.utcnow().isoformat()} UTC",
        f"Target    : {TARGET_BASE_URL}",
        f"Roles     : {', '.join(r.role for r in all_results)}",
        "=" * 70,
        "",
    ]

    total_eps = sum(len(r.endpoints) for r in all_results)
    total_spa = sum(len(r.spa_routes) for r in all_results)
    total_gql = sum(len(r.graphql_schemas) for r in all_results)

    lines += [
        "SUMMARY",
        "─" * 40,
        f"  Total endpoints captured : {total_eps}",
        f"  SPA routes (FR-02.4)     : {total_spa}",
        f"  GraphQL schemas (FR-02.5): {total_gql}",
        f"  Version BAC flags (FR-02.6): {len(version_flags)}",
        "",
    ]

    for result in all_results:
        lines += [
            "",
            f"{'─'*70}",
            f"ROLE: {result.role.upper()}",
            f"{'─'*70}",
            f"  Endpoints ({len(result.endpoints)}):",
        ]
        
        # Group endpoints by source
        from collections import defaultdict
        source_map = defaultdict(list)
        for ep in result.endpoints:
            source_map[ep.source].append(ep)
            
        ep_idx = 1
        for source_name, eps in sorted(source_map.items()):
            lines += [f"\n  --- SOURCE: {source_name.upper()} ({len(eps)}) ---"]
            for ep in eps:
                lines.append(_format_endpoint_txt(ep, ep_idx))
                ep_idx += 1

        if result.spa_routes:
            lines += ["", f"  SPA / Lazy-loaded Routes (FR-02.4) [{len(result.spa_routes)}]:"]
            for r in sorted(set(result.spa_routes)):
                lines.append(f"    {r}")

        if result.graphql_schemas:
            lines += ["", f"  GraphQL Schemas (FR-02.5) [{len(result.graphql_schemas)}]:"]
            for gql in result.graphql_schemas:
                lines += [
                    f"    Endpoint : {gql.endpoint}",
                    f"    Types    : {', '.join(gql.types[:15])}{'…' if len(gql.types) > 15 else ''}",
                    f"    Queries  : {', '.join(gql.queries[:10])}{'…' if len(gql.queries) > 10 else ''}",
                    f"    Mutations: {', '.join(gql.mutations[:10])}{'…' if len(gql.mutations) > 10 else ''}",
                ]

    if version_flags:
        lines += [
            "",
            "=" * 70,
            "API VERSION BAC CANDIDATES (FR-02.6)",
            "=" * 70,
        ]
        for f in version_flags:
            lines += [
                f"  Endpoint  : {f['endpoint_key']}",
                f"  Present in: {f['present_in']}   Absent in: {f['absent_in']}",
                f"  Roles seen: {', '.join(f['roles_seen'])}",
                f"  Risk      : {f['bac_risk']}",
                "",
            ]

    lines += ["", "=" * 70, "END OF CRAWL REPORT", "=" * 70]
    output_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"\n[+] Text report  -> {output_path}")


def _write_json_report(all_results: list[CrawlResult], version_flags: list[dict], output_path: Path):
    """Machine-readable JSON for downstream modules (M2 Schema Condenser etc.)."""

    def _serialise(obj):
        if hasattr(obj, "__dataclass_fields__"):
            return asdict(obj)
        return str(obj)

    payload = {
        "meta": {
            "target":    TARGET_BASE_URL,
            "generated": datetime.utcnow().isoformat(),
            "roles":     [r.role for r in all_results],
        },
        "results": [asdict(r) for r in all_results],
        "version_bac_candidates": version_flags,
    }
    output_path.write_text(json.dumps(payload, indent=2, default=_serialise), encoding="utf-8")
    print(f"[+] JSON report  -> {output_path}")

def _write_csv_report(all_results: list[CrawlResult], output_path: Path):
    def format_for_csv(text):
        if not text: return ""
        # Truncate to prevent massive files and replace newlines to maintain single-line CSV format
        return text[:10000].replace('\n', '\\n').replace('\r', '')

    try:
        with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['Role', 'Source', 'Method', 'URL', 'Status', 'Hash', 'JWT', 'CSRF_Token', 'Payload', 'Response']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for result in all_results:
                for ep in result.endpoints:
                    writer.writerow({
                        'Role': ep.role,
                        'Source': ep.source,
                        'Method': ep.method,
                        'URL': ep.url,
                        'Status': ep.response_status,
                        'Hash': ep.schema_hash,
                        'JWT': ep.jwt,
                        'CSRF_Token': ep.csrf_token,
                        'Payload': format_for_csv(ep.body),
                        'Response': format_for_csv(ep.response_body),
                    })
        print(f"[+] CSV report   -> {output_path}")
    except PermissionError:
        print(f"[-] ERROR: Permission denied when writing to {output_path}.")
        print("    Please ensure the file is not open in Excel or another program and try again.")


# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────

async def main():
    global TARGET_BASE_URL, LOGIN_URL, USERNAME_SELECTOR, PASSWORD_SELECTOR, SUBMIT_SELECTOR, TARGET_HOST, SCOPE_HOSTS

    print("\n" + "=" * 70)
    print("  AHVF — Module 1: Stateful Crawler")
    print("  !! For authorized security testing only !!")
    print("=" * 70)

    print("\n--- Target Configuration ---")
    TARGET_BASE_URL = input("Enter Target Base URL (e.g., http://example.com/): ").strip()
    if not TARGET_BASE_URL.endswith('/'):
        TARGET_BASE_URL += '/'
        
    LOGIN_URL = input(f"Enter Login URL [default: {TARGET_BASE_URL}]: ").strip()
    if not LOGIN_URL:
        LOGIN_URL = TARGET_BASE_URL
        
    USERNAME_SELECTOR = input("Enter Username Selector [default: input[name='username']]: ").strip()
    if not USERNAME_SELECTOR:
        USERNAME_SELECTOR = "input[name='username']"
        
    PASSWORD_SELECTOR = input("Enter Password Selector [default: input[name='password']]: ").strip()
    if not PASSWORD_SELECTOR:
        PASSWORD_SELECTOR = "input[name='password']"
        
    SUBMIT_SELECTOR = input("Enter Submit Selector [default: button[type='submit']]: ").strip()
    if not SUBMIT_SELECTOR:
        SUBMIT_SELECTOR = "button[type='submit']"

    TARGET_HOST = urllib.parse.urlparse(TARGET_BASE_URL).hostname or ""
    SCOPE_HOSTS = [ TARGET_HOST ] if TARGET_HOST else []

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    all_results: list[CrawlResult] = []

    import getpass
    print("\n--- Crawler Authentication Settings ---")
    print("Please configure credentials for each crawl role.")
    print("If you want to perform a Guest/Unauthenticated crawl, leave the inputs empty.\n")
    
    credentials = {}
    while True:
        role = input("Enter crawl role (e.g., 'User', 'Admin') [Press Enter to finish setting up roles]: ").strip()
        if not role:
            break
        username = input(f"Enter username for '{role}': ").strip()
        if not username:
            print(f"Skipping credentials configuration for '{role}' (will crawl unauthenticated as '{role}').")
            credentials[role] = ("", "")
            continue
        password = getpass.getpass(f"Enter password for '{role}': ")
        credentials[role] = (username, password)
        print(f"Role '{role}' configured successfully.\n")

    # Fallback to guest crawl if no roles were input
    if not credentials:
        print("No roles configured. Proceeding with Unauthenticated guest crawl.")
        credentials["Guest"] = ("", "")

    async with async_playwright() as pw:
        all_role_results: dict = {}

        for role, (username, password) in credentials.items():
            result = await crawl_role(role, username, password, pw, all_role_results)
            all_results.append(result)
            all_role_results[role] = result

    # FR-02.6: cross-version BAC analysis
    version_flags = _detect_version_bac_candidates(all_results)
    if version_flags:
        print(f"\n[!] FR-02.6: {len(version_flags)} API version BAC candidate(s) flagged.")

    # Write outputs
    _write_txt_report(all_results,  version_flags, OUTPUT_DIR / "crawl_results.txt")
    _write_json_report(all_results, version_flags, OUTPUT_DIR / "crawl_results.json")
    _write_csv_report(all_results, OUTPUT_DIR / "crawl_results.csv")

    # Quick stats
    total = sum(len(r.endpoints) for r in all_results)
    print(f"\n{'='*70}")
    print(f"  Crawl complete. {total} total endpoint records written.")
    print(f"  Output dir: {OUTPUT_DIR.resolve()}")
    print(f"{'='*70}\n")


if __name__ == "__main__":
    asyncio.run(main())