"""
Headless browser screenshot capture via Playwright.
"""

from __future__ import annotations

import logging
import uuid
import asyncio
from pathlib import Path

from app.config import settings
from app.schemas import ScreenshotResult

logger = logging.getLogger(__name__)


def _capture_screenshot_sync(url: str, timeout: float, dest_dir: str) -> ScreenshotResult:
    """Synchronous implementation of screenshot capture to be run in a separate thread."""
    import sys
    
    # Force ProactorEventLoop in the new thread on Windows for Playwright subprocess compatibility
    if sys.platform == "win32":
        import asyncio
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
        
    from playwright.sync_api import sync_playwright
    
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(
                viewport={"width": 1280, "height": 720},
                ignore_https_errors=True,
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/122.0.0.0 Safari/537.36"
                ),
            )
            page = context.new_page()
            
            page.goto(
                url,
                wait_until="domcontentloaded",
                timeout=timeout,
            )

            filename = f"{uuid.uuid4().hex}.png"
            filepath = Path(dest_dir) / filename
            page.screenshot(path=str(filepath), full_page=False)
            
            context.close()
            browser.close()
            
            logger.info("Screenshot saved: %s", filepath)
            return ScreenshotResult(
                success=True, 
                file_path=str(filepath),
                url=f"/screenshots/{filename}"
            )
            
    except Exception as exc:
        logger.exception("Screenshot capture failed for %s", url)
        return ScreenshotResult(error=str(exc))


async def capture_screenshot(url: str) -> ScreenshotResult:
    """Navigate to *url* in a headless browser and capture a viewport screenshot."""
    # Run the synchronous Playwright implementation in a dedicated thread
    return await asyncio.to_thread(
        _capture_screenshot_sync,
        url,
        settings.SCREENSHOT_TIMEOUT,
        settings.SCREENSHOT_DIR,
    )
