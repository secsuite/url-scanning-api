"""
FastAPI application entry-point.
"""

import asyncio
import logging
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime, timezone

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app.config import settings
from app.dependencies import close_http_client
from app.ml.registry import preload_all
from app.routers import scan

logger = logging.getLogger(__name__)

# ── Lifespan ──────────────────────────────────────────────────────────────────


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Startup / shutdown lifecycle."""
    settings.ensure_directories()
    if settings.PRELOAD_MODELS_ON_STARTUP:
        await preload_all()
    else:
        logger.info("Skipping startup model preload (PRELOAD_MODELS_ON_STARTUP=false).")
    yield
    await close_http_client()


# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="Malicious URL Scanner API",
    description=(
        "Multi-stage URL analysis pipeline: malware scanning, reputation "
        "checking, SSL validation, screenshot capture, and ML-based threat "
        "detection."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/screenshots", StaticFiles(directory=settings.SCREENSHOT_DIR), name="screenshots")

app.include_router(scan.router)


@app.get("/health", tags=["System"])
async def health() -> dict[str, str]:
    """Liveness / readiness check."""
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
