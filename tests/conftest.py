"""
Shared fixtures for the URL Scanner integration test suite.

Every test in this suite hits real external services (Google Safe Browsing,
VirusTotal, WHOIS, DNS, Playwright).  Requirements:

  - GOOGLE_SAFE_BROWSING_API_KEY env var set
  - VIRUSTOTAL_API_KEY env var set
  - Playwright Chromium installed  (playwright install chromium)
  - ML model files present under app/ml/models/
  - Outbound internet access

Individual tests are skipped automatically when their prerequisite is absent.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from dotenv import load_dotenv
from fastapi.testclient import TestClient

# Load .env from the project root (api/) before any env-var checks or app imports.
# This mirrors what pydantic-settings does at runtime, so API keys and paths
# are available to both the skip guards below and to app.config.settings.
_env_path = Path(__file__).parent.parent / ".env"
load_dotenv(_env_path, override=False)  # override=False: real env vars win over .env


# ── Markers ───────────────────────────────────────────────────────────────────


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "requires_safe_browsing_key: skip if GOOGLE_SAFE_BROWSING_API_KEY is not set",
    )
    config.addinivalue_line(
        "markers",
        "requires_virustotal_key: skip if VIRUSTOTAL_API_KEY is not set",
    )


# ── Session-scoped live client ────────────────────────────────────────────────


@pytest.fixture(scope="session")
def live_client():
    """
    Start the real FastAPI app once per test session.

    This triggers the full lifespan:
      - settings.ensure_directories()  — creates screenshots/ and downloads/
      - preload_all()                  — loads LightGBM, LongFormer, Faster-RCNN

    Model loading can take 30-60 s on first run.  Subsequent tests in the
    same session reuse the loaded models.
    """
    try:
        from app.main import app

        with TestClient(app, raise_server_exceptions=True) as client:
            yield client
    except Exception as exc:
        pytest.skip(f"App failed to start (missing model files or config?): {exc}")


# ── Per-test key guards ───────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _skip_if_missing_safe_browsing_key(request):
    """Auto-skip any test marked requires_safe_browsing_key."""
    if request.node.get_closest_marker("requires_safe_browsing_key"):
        if not os.getenv("GOOGLE_SAFE_BROWSING_API_KEY"):
            pytest.skip("GOOGLE_SAFE_BROWSING_API_KEY not set")


@pytest.fixture(autouse=True)
def _skip_if_missing_virustotal_key(request):
    """Auto-skip any test marked requires_virustotal_key."""
    if request.node.get_closest_marker("requires_virustotal_key"):
        if not os.getenv("VIRUSTOTAL_API_KEY"):
            pytest.skip("VIRUSTOTAL_API_KEY not set")
