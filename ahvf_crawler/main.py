import argparse
import asyncio
import logging
import sys

from ahvf_crawler.config import load_config
from ahvf_crawler.db import init_db
from ahvf_crawler.engine import run_engine
from ahvf_crawler.bac import run_bac_engine

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("ahvf_crawler.main")

async def main():
    parser = argparse.ArgumentParser(description="AHVF Stateful Crawler")
    parser.add_argument("-c", "--config", required=True, help="Path to YAML configuration file")
    parser.add_argument("--resume", action="store_true", help="Resume previous crawl state if found")
    args = parser.parse_args()

    # Load Configuration
    config = load_config(args.config)
    
    # Initialize SQLite Database
    await init_db(config.db_path)
    
    logger.info("=" * 60)
    logger.info(" AHVF Stateful Crawler - Execution Started")
    logger.info("=" * 60)
    
    # Note: State machine persistence handles the --resume logic seamlessly.
    # If --resume is NOT passed, we could optionally clear the DB or specific tables.
    if not args.resume:
        logger.info("Fresh start requested. Clearing previous queue and session states...")
        import aiosqlite
        async with aiosqlite.connect(config.db_path) as db:
            await db.execute("DELETE FROM crawl_state")
            await db.execute("DELETE FROM sessions")
            await db.commit()
    else:
        logger.info("Resume requested. Continuing from existing crawl_state...")

    # Phase 1: Engine Execution (Crawling)
    await run_engine(config)
    
    # Phase 2: BAC Cross-Pollination
    await run_bac_engine(config)
    
    logger.info("=" * 60)
    logger.info(" AHVF Stateful Crawler - Execution Completed")
    logger.info("=" * 60)

if __name__ == "__main__":
    asyncio.run(main())
