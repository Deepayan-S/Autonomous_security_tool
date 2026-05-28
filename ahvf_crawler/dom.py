import asyncio
import json
import logging
import re
import urllib.parse
from typing import Optional, List, Dict
from playwright.async_api import BrowserContext, Page

from ahvf_crawler.config import CrawlConfig, RoleConfig
import ahvf_crawler.db as db
from ahvf_crawler.captcha import handle_captcha
from ahvf_crawler.llm import distill_dom, analyze_login_page

logger = logging.getLogger("ahvf_crawler.dom")

DOM_MUTATION_OBSERVER_JS = """
(() => {
    if (window.__ahvf_routes) return;
    window.__ahvf_routes = new Set();
    window.__ahvf_last_mutation = Date.now();

    const _pushState    = history.pushState.bind(history);
    const _replaceState = history.replaceState.bind(history);

    history.pushState = function(state, title, url) {
        if (url) window.__ahvf_routes.add(String(url));
        window.__ahvf_last_mutation = Date.now();
        return _pushState(state, title, url);
    };
    history.replaceState = function(state, title, url) {
        if (url) window.__ahvf_routes.add(String(url));
        window.__ahvf_last_mutation = Date.now();
        return _replaceState(state, title, url);
    };

    window.addEventListener('hashchange', () => {
        window.__ahvf_routes.add(location.href);
        window.__ahvf_last_mutation = Date.now();
    });

    const observer = new MutationObserver((mutations) => {
        if (mutations.length > 0) window.__ahvf_last_mutation = Date.now();
        for (const m of mutations) {
            for (const node of m.addedNodes) {
                if (node.nodeType !== 1) continue;
                const anchors = node.querySelectorAll ? node.querySelectorAll('a[href]') : [];
                for (const a of anchors) {
                    try { window.__ahvf_routes.add(new URL(a.href, location.origin).href); } catch(e) {}
                }
                const routerLinks = node.querySelectorAll ? node.querySelectorAll('[to],[data-href],[routerlink]') : [];
                for (const el of routerLinks) {
                    const val = el.getAttribute('to') || el.getAttribute('data-href') || el.getAttribute('routerlink');
                    if (val) {
                        try { window.__ahvf_routes.add(new URL(val, location.origin).href); } 
                        catch(e) { if (val.startsWith('/')) window.__ahvf_routes.add(location.origin + val); }
                    }
                }
            }
        }
    });
    observer.observe(document.documentElement, { childList: true, subtree: true });
})();
"""

DANGER_KEYWORDS = ['delete', 'destroy', 'remove', 'payment', 'confirm', 'billing', 'checkout', 'pay']

async def wait_for_quiescence(page: Page, networkidle_timeout: int = 15000):
    """Wait for networkidle + 500ms of no DOM mutations."""
    try:
        await page.wait_for_load_state("networkidle", timeout=networkidle_timeout)
    except Exception:
        pass # Ignore networkidle timeout, still wait for DOM
        
    for _ in range(10): # Max 5 seconds waiting for DOM to settle
        try:
            last_mut = await page.evaluate("() => window.__ahvf_last_mutation || Date.now()")
            now = await page.evaluate("Date.now()")
            if now - last_mut > 500:
                break
        except Exception:
            break
        await asyncio.sleep(0.5)

async def bootstrap_session(context: BrowserContext, config: CrawlConfig, role_name: str, role_conf: RoleConfig, current_jwt: list) -> bool:
    """Check DB for unexpired session. Return True if valid session loaded."""
    session = await db.get_session(config.db_path, role_name)
    if session and session.get("jwt_exp"):
        import time
        if session["jwt_exp"] > time.time() + 60:
            logger.info(f"[{role_name}] Found valid session in DB, restoring...")
            if session.get("storage_state"):
                try:
                    state_dict = json.loads(session["storage_state"])
                    await context.add_cookies(state_dict.get("cookies", []))
                    current_jwt[0] = session.get("jwt")
                    return True
                except Exception as e:
                    logger.warning(f"[{role_name}] Failed to parse storage_state: {e}")
    return False

async def extract_links_and_forms(page: Page, config: CrawlConfig, role: str) -> List[Dict]:
    """Single synchronous pass extraction in the browser context."""
    results = await page.evaluate("""() => {
        const endpoints = [];
        
        // 1. Anchors
        document.querySelectorAll('a[href]').forEach(a => {
            endpoints.push({url: a.href, method: 'GET', source: 'a_href'});
        });
        
        // 2. Forms
        document.querySelectorAll('form').forEach(f => {
            const action = f.getAttribute('action') || location.href;
            const method = (f.getAttribute('method') || 'GET').toUpperCase();
            
            const fields = {};
            f.querySelectorAll('input, select, textarea').forEach(inp => {
                const name = inp.getAttribute('name') || inp.getAttribute('id') || 'unnamed';
                fields[name] = (inp.getAttribute('type') || 'text').toLowerCase();
            });
            
            try {
                const absAction = new URL(action, location.origin).href;
                endpoints.push({
                    url: absAction, 
                    method: method, 
                    source: 'form', 
                    form_structure: {action: absAction, fields: fields}
                });
            } catch(e) {}
        });
        
        // 3. SPA Routes (MutationObserver)
        if (window.__ahvf_routes) {
            window.__ahvf_routes.forEach(r => {
                endpoints.push({url: r, method: 'GET', source: 'spa_route'});
            });
        }
        
        return endpoints;
    }""")
    
    # Process and flag special patterns
    valid_endpoints = []
    for ep in results:
        url = ep['url']
        parsed = urllib.parse.urlparse(url)
        path = parsed.path.lower()
        
        # Scope check (enforced here and at queue time)
        host = parsed.hostname or ""
        in_scope = any(host == s or host.endswith(f".{s}") for s in config.scope_hosts)
        
        # Path exclusions
        excluded = any(path.startswith(ex) for ex in config.excluded_paths)
        
        if in_scope and not excluded:
            # Flag GraphQL
            if any(path.endswith(gql) for gql in ["/graphql", "/query", "graphql"]):
                logger.info(f"[{role}] Flagged GraphQL endpoint: {url}")
                ep['source'] += ' [graphql]'
            
            # API Versioning pattern check
            v_match = re.search(r'/v(\d+)/', path)
            if v_match:
                ver = v_match.group(1)
                logger.info(f"[{role}] API version flag (v{ver}) at {url}")
                # Enqueue the older version as a BAC candidate implicitly
                downgraded_url = url.replace(f"/v{ver}/", f"/v{max(1, int(ver)-1)}/")
                await db.enqueue_url(config.db_path, role, downgraded_url, 99) # High depth to deprioritize
                
            # Numeric/UUID check (IDOR candidate)
            segments = path.split('/')
            idor_candidate = False
            for seg in segments:
                if seg.isdigit() or re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', seg, re.I):
                    idor_candidate = True
                    break
            ep['idor_candidate'] = idor_candidate
            
            valid_endpoints.append(ep)
            
    return valid_endpoints

def is_dangerous_form(form_structure: dict) -> bool:
    action = form_structure.get("action", "").lower()
    fields = form_structure.get("fields", {})
    
    if any(k in action for k in DANGER_KEYWORDS):
        return True
    
    for fname in fields.keys():
        if any(k in fname.lower() for k in DANGER_KEYWORDS):
            return True
            
    return False

async def execute_login(context: BrowserContext, page: Page, config: CrawlConfig, role_name: str, role_conf: RoleConfig) -> bool:
    """Perform login, handle CAPTCHA, and save session."""
    logger.info(f"[{role_name}] Performing form-based login at {config.login_url}...")
    try:
        await page.goto(config.login_url, wait_until="networkidle", timeout=30000)
    except Exception as e:
        logger.error(f"[{role_name}] Login page failed to load: {e}")
        return False
        
    await page.add_init_script(DOM_MUTATION_OBSERVER_JS)
    try:
        await page.evaluate(DOM_MUTATION_OBSERVER_JS)
    except Exception:
        pass
        
    # Handle Captcha before credential fill
    captcha_ok = await handle_captcha(page, config.captcha, role_name, config.db_path)
    if not captcha_ok:
        return False
        
    # Resolve Form Selectors
    user_sel = config.username_selector
    pwd_sel = config.password_selector
    submit_sel = config.submit_selector
    
    if hasattr(config, 'llm') and config.llm.enabled:
        logger.info(f"[{role_name}] LLM DOM Analysis enabled. Distilling DOM...")
        try:
            # Wait a moment for dynamic forms to render
            await page.wait_for_timeout(2000)
            distilled_html = await distill_dom(page)
            
            llm_result = analyze_login_page(config.llm, distilled_html)
            if llm_result:
                logger.info(f"[{role_name}] LLM Analysis Result: {json.dumps(llm_result, indent=2)}")
                
                # Extract selectors from LLM output
                for field in llm_result.get("fields", []):
                    purpose = field.get("purpose")
                    sel = field.get("selector")
                    if sel:
                        if purpose == "username":
                            user_sel = sel
                        elif purpose == "password":
                            pwd_sel = sel
                            
                submit_node = llm_result.get("submit", {})
                if submit_node and submit_node.get("selector"):
                    submit_sel = submit_node.get("selector")
                    
                logger.info(f"[{role_name}] LLM resolved selectors -> User: {user_sel}, Pass: {pwd_sel}, Submit: {submit_sel}")
            else:
                logger.warning(f"[{role_name}] LLM Analysis returned empty. Falling back to configured selectors.")
                
        except Exception as e:
            logger.error(f"[{role_name}] LLM Analysis failed: {e}. Falling back to configured selectors.")

    # Fill credentials
    try:
        if user_sel:
            await page.wait_for_selector(user_sel, timeout=10000)
            await page.fill(user_sel, role_conf.username)
        if pwd_sel:
            await page.fill(pwd_sel, role_conf.password)
        
        # Click submit and wait for URL to CHANGE from login URL (negative wait)
        login_url_pattern = re.compile(rf"^{re.escape(config.login_url)}", re.IGNORECASE)
        
        if submit_sel:
            await page.click(submit_sel)
        
        # Negative pattern: Wait until URL does NOT match login URL
        try:
            await page.wait_for_url(lambda u: not login_url_pattern.match(u), timeout=15000)
            logger.info(f"[{role_name}] Login URL changed -> {page.url}")
        except Exception:
            # Fallback: check DOM for authenticated UI indicators
            logger.info(f"[{role_name}] URL didn't change, checking DOM fallback...")
            auth_indicators = ["nav", ".avatar", "#dashboard", "text=Logout", "text=Sign Out", ".profile"]
            found = False
            for sel in auth_indicators:
                try:
                    if await page.locator(sel).first.is_visible(timeout=2000):
                        found = True
                        break
                except:
                    pass
            
            if not found:
                # We will also check JWT presence at the network layer separately (in engine.py orchestrator)
                logger.warning(f"[{role_name}] Login success fallback inconclusive via DOM.")
                return False
                
    except Exception as e:
        logger.error(f"[{role_name}] Login form interaction failed: {e}")
        return False
        
    # Export state to save session
    storage_state = await context.storage_state()
    # Note: we save the session AFTER the network layer has extracted JWT, 
    # so we will call save_session from engine.py once we collect cookies/JWT.
    return True
