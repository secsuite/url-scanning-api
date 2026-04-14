"""
Headless browser screenshot capture via Playwright.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
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
                wait_until="load",
                timeout=timeout,
            )

            # Best-effort: wait for network to go idle so JS-rendered content
            # is visible. Cap at 5 s so heavy sites don't stall indefinitely.
            try:
                page.wait_for_load_state("networkidle", timeout=5000)
            except Exception:
                pass  # proceed with whatever is rendered so far

            filename = f"{uuid.uuid4().hex}.png"
            filepath = Path(dest_dir) / filename
            page.screenshot(path=str(filepath), full_page=False)

            context.close()
            browser.close()

            logger.info("Screenshot saved: %s", filepath)
            return ScreenshotResult(
                success=True, file_path=str(filepath), url=f"/screenshots/{filename}"
            )

    except Exception as exc:
        logger.exception("Screenshot capture failed for %s", url)
        return ScreenshotResult(error=str(exc))


async def capture_screenshot(url: str, *, max_attempts: int = 3) -> ScreenshotResult:
    """Navigate to *url* in a headless browser and capture a viewport screenshot.

    Retries up to *max_attempts* times so that transient browser or network
    failures don't silently skip phishing detection.
    """
    last_result: ScreenshotResult | None = None
    for attempt in range(1, max_attempts + 1):
        result = await asyncio.to_thread(
            _capture_screenshot_sync,
            url,
            settings.SCREENSHOT_TIMEOUT,
            settings.SCREENSHOT_DIR,
        )
        if result.success:
            return result
        last_result = result
        if attempt < max_attempts:
            logger.warning(
                "Screenshot attempt %d/%d failed for %s: %s — retrying",
                attempt,
                max_attempts,
                url,
                result.error,
            )
            await asyncio.sleep(1)
    logger.error("All %d screenshot attempts failed for %s", max_attempts, url)
    return last_result or ScreenshotResult(error="Screenshot failed without details")
