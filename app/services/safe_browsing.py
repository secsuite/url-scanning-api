"""
Google Safe Browsing Lookup API v4 integration.
"""

from __future__ import annotations

import logging

import httpx

from app.config import settings
from app.schemas import SafeBrowsingResult

logger = logging.getLogger(__name__)

SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
]

PLATFORM_TYPES = ["ANY_PLATFORM"]
THREAT_ENTRY_TYPES = ["URL"]


async def check_safe_browsing(url: str, client: httpx.AsyncClient) -> SafeBrowsingResult:
    """Query Google Safe Browsing Lookup API v4 for the given URL."""
    if not settings.GOOGLE_SAFE_BROWSING_API_KEY:
        return SafeBrowsingResult(error="Google Safe Browsing API key not configured")

    payload = {
        "client": {
            "clientId": "malicious-url-scanner",
            "clientVersion": "1.0.0",
        },
        "threatInfo": {
            "threatTypes": THREAT_TYPES,
            "platformTypes": PLATFORM_TYPES,
            "threatEntryTypes": THREAT_ENTRY_TYPES,
            "threatEntries": [{"url": url}],
        },
    }

    try:
        resp = await client.post(
            SAFE_BROWSING_URL,
            params={"key": settings.GOOGLE_SAFE_BROWSING_API_KEY},
            json=payload,
        )
        resp.raise_for_status()
        data = resp.json()

        matches = data.get("matches", [])
        return SafeBrowsingResult(
            is_threat=len(matches) > 0,
            threats=[
                {
                    "threat_type": m.get("threatType"),
                    "platform_type": m.get("platformType"),
                    "threat_entry": m.get("threat", {}).get("url"),
                }
                for m in matches
            ],
        )
    except httpx.HTTPStatusError as exc:
        logger.error("Safe Browsing API HTTP error: %s", exc)
        return SafeBrowsingResult(error=f"HTTP {exc.response.status_code}")
    except Exception as exc:
        logger.exception("Safe Browsing API error")
        return SafeBrowsingResult(error=str(exc))
