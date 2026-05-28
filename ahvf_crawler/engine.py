import asyncio
import json
import logging
import time
from typing import List, Dict
from tenacity import retry, wait_exponential_jitter, stop_after_attempt, retry_if_exception_type
from playwright.async_api import async_playwright, BrowserContext, Page, Error as PlaywrightError

import ahvf_crawler.db as db
from ahvf_crawler.config import CrawlConfig, RoleConfig
from ahvf_crawler.dom import execute_login, bootstrap_session, extract_links_and_forms, wait_for_quiescence
from ahvf_crawler.network import make_request_handler, make_response_handler, parse_jwt_exp

logger = logging.getLogger("ahvf_crawler.engine")

class EngineContext:
    def __init__(self, role: str, config: CrawlConfig):
        self.role = role
        self.config = config
        self.current_jwt = [None]
        self.current_csrf = [None]
        self.seen_hashes = set()
        self.context_cookies = []
        self.context: BrowserContext = None
        self.page: Page = None
        self.auth_failed = False

async def monitor_jwt_ttl(engine_ctx: EngineContext, pw_instance):
    """Background task to monitor JWT TTL and trigger re-auth if needed."""
    while not engine_ctx.auth_failed:
        await asyncio.sleep(10)
        
        jwt = engine_ctx.current_jwt[0]
        if not jwt:
            continue
            
        exp = parse_jwt_exp(jwt)
        if exp == 0:
            continue
            
        remaining = exp - time.time()
        if remaining < 60: # Threshold
            logger.warning(f"[{engine_ctx.role}] JWT TTL low ({int(remaining)}s). Re-authenticating...")
            # Re-auth mechanism
            role_conf = engine_ctx.config.roles.get(engine_ctx.role)
            if not role_conf or not role_conf.username:
                engine_ctx.auth_failed = True
                break
                
            # Perform re-login on a new page to avoid disrupting current flow
            temp_page = await engine_ctx.context.new_page()
            success = await execute_login(engine_ctx.context, temp_page, engine_ctx.config, engine_ctx.role, role_conf)
            await temp_page.close()
            
            if success:
                logger.info(f"[{engine_ctx.role}] Re-authentication successful.")
                # The network interceptor will pick up the new cookies/JWT automatically.
                # Update DB
                state = await engine_ctx.context.storage_state()
                await db.save_session(
                    engine_ctx.config.db_path, engine_ctx.role, json.dumps(state), 
                    engine_ctx.current_jwt[0], parse_jwt_exp(engine_ctx.current_jwt[0]),
                    engine_ctx.current_csrf[0], json.dumps(state.get("cookies", []))
                )
            else:
                logger.error(f"[{engine_ctx.role}] Re-authentication failed. Terminating role queue.")
                engine_ctx.auth_failed = True
                break


@retry(
    wait=wait_exponential_jitter(initial=1, max=10),
    stop=stop_after_attempt(5),
    retry=retry_if_exception_type((PlaywrightError, TimeoutError))
)
async def visit_url_with_rate_limit(page: Page, url: str):
    """Navigate to URL with exponential backoff on failure (simulating rate limit handling)."""
    await page.goto(url, wait_until="networkidle", timeout=15000)
    await wait_for_quiescence(page, 15000)


async def crawl_role(role: str, config: CrawlConfig, pw_instance) -> None:
    logger.info(f"[{role}] Starting role execution.")
    
    engine_ctx = EngineContext(role, config)
    role_conf = config.roles.get(role, RoleConfig())

    browser = await pw_instance.chromium.launch(headless=True)
    engine_ctx.context = await browser.new_context(
        ignore_https_errors=True,
        user_agent="AHVF-SecurityScanner/1.0 (authorized-testing)"
    )
    engine_ctx.page = await engine_ctx.context.new_page()

    # Network Handlers
    engine_ctx.page.on("request", make_request_handler(
        role, config, engine_ctx.seen_hashes, 
        engine_ctx.current_jwt, engine_ctx.current_csrf, engine_ctx.context_cookies
    ))
    engine_ctx.page.on("response", make_response_handler(role, config))

    # Authentication
    if role_conf.username:
        valid_session = await bootstrap_session(engine_ctx.context, config, role, role_conf, engine_ctx.current_jwt)
        if not valid_session:
            login_ok = await execute_login(engine_ctx.context, engine_ctx.page, config, role, role_conf)
            if not login_ok:
                logger.error(f"[{role}] Initial login failed. Aborting role.")
                await browser.close()
                return
                
            # Post-login session save
            state = await engine_ctx.context.storage_state()
            await db.save_session(
                config.db_path, role, json.dumps(state), 
                engine_ctx.current_jwt[0] or "", parse_jwt_exp(engine_ctx.current_jwt[0] or ""),
                engine_ctx.current_csrf[0] or "", json.dumps(state.get("cookies", []))
            )

    # JWT Monitor Task
    ttl_task = asyncio.create_task(monitor_jwt_ttl(engine_ctx, pw_instance))

    # Queue Initialization (if empty)
    queued = await db.get_queued_urls(config.db_path, role, limit=1)
    if not queued:
        await db.enqueue_url(config.db_path, role, config.target_base_url, 0)

    pages_visited = 0

    while pages_visited < config.max_pages_per_role and not engine_ctx.auth_failed:
        # Fetch next url
        queued = await db.get_queued_urls(config.db_path, role, limit=1)
        if not queued:
            break
            
        entry = queued[0]
        url = entry['url']
        depth = entry['depth']
        
        if depth > config.crawl_depth:
            await db.update_crawl_state(config.db_path, role, url, "SKIPPED", "depth_limit")
            continue

        await db.update_crawl_state(config.db_path, role, url, "NAVIGATING")
        
        try:
            logger.info(f"[{role}] Navigating: {url}")
            await visit_url_with_rate_limit(engine_ctx.page, url)
            
            await db.update_crawl_state(config.db_path, role, url, "EXTRACTING")
            
            # DOM Extraction
            new_endpoints = await extract_links_and_forms(engine_ctx.page, config, role)
            
            for ep in new_endpoints:
                # Deduplicate and queue newly found URLs
                await db.enqueue_url(config.db_path, role, ep['url'], depth + 1)
                
            await db.update_crawl_state(config.db_path, role, url, "PERSISTED")
            pages_visited += 1

        except Exception as e:
            logger.error(f"[{role}] Navigation failed for {url}: {e}")
            await db.update_crawl_state(config.db_path, role, url, "FAILED", str(e))

    # Cleanup
    ttl_task.cancel()
    if engine_ctx.auth_failed:
        logger.error(f"[{role}] Role aborted due to auth failure. Failing remaining queued items.")
        queued_all = await db.get_queued_urls(config.db_path, role, limit=9999)
        for q in queued_all:
            await db.update_crawl_state(config.db_path, role, q['url'], "FAILED", "jwt_reauth_failed")

    await browser.close()
    logger.info(f"[{role}] Role execution complete. Visited {pages_visited} pages.")


async def run_engine(config: CrawlConfig):
    """Main orchestration entry point for crawling."""
    await db.update_pipeline_state(config.db_path, "crawl", "in_progress")
    
    async with async_playwright() as pw:
        tasks = []
        for role in config.roles.keys():
            tasks.append(crawl_role(role, config, pw))
            
        await asyncio.gather(*tasks)
        
    await db.update_pipeline_state(config.db_path, "crawl", "completed", {"status": "all_roles_finished"})
