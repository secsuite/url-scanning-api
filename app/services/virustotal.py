"""
VirusTotal API v3 integration — URL scanning.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import time

import httpx

from app.config import settings
from app.schemas import VirusTotalResult

logger = logging.getLogger(__name__)

VT_URL_SCAN = "https://www.virustotal.com/api/v3/urls"
VT_URL_REPORT = "https://www.virustotal.com/api/v3/urls/{id}"
VT_URL_ANALYSIS = "https://www.virustotal.com/api/v3/analyses/{id}"


def _vt_headers() -> dict[str, str]:
    return {"x-apikey": settings.VIRUSTOTAL_API_KEY}


def _parse_analysis_data(data: dict) -> VirusTotalResult:
    stats = data["attributes"]["stats"]
    total = sum(stats.values())
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    vendor_results = {
        vendor: info.get("category", "unknown")
        for vendor, info in data["attributes"].get("results", {}).items()
    }
    return VirusTotalResult(
        is_malicious=(malicious + suspicious) > 0,
        detection_ratio=f"{malicious}/{total}",
        scan_id=data.get("id", ""),
        vendor_results=vendor_results,
    )


async def check_virustotal(
    url: str, client: httpx.AsyncClient
) -> VirusTotalResult:
    """Submit a URL to VirusTotal and retrieve the analysis results.

    Cached reports are returned immediately.  For fresh scans the function
    polls until the analysis completes or until VIRUSTOTAL_POLL_TIMEOUT seconds
    have elapsed — whichever comes first.  When the deadline is reached the
    scan_id is included in the result so callers can fetch the completed report
    later without re-submitting.
    """
    if not settings.VIRUSTOTAL_API_KEY:
        return VirusTotalResult(error="VirusTotal API key not configured")

    try:
        # ── Step 1: check for a cached report ────────────────────────────
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        cached_resp = await client.get(
            VT_URL_REPORT.format(id=url_id),
            headers=_vt_headers(),
        )
        if cached_resp.status_code == 200:
            cached_data = cached_resp.json().get("data", {})
            if cached_data.get("attributes", {}).get("last_analysis_stats"):
                logger.info("VirusTotal: returning cached report for %s", url)
                stats = cached_data["attributes"]["last_analysis_stats"]
                total = sum(stats.values())
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                vendor_results = {
                    vendor: info.get("category", "unknown")
                    for vendor, info in cached_data["attributes"]
                    .get("last_analysis_results", {})
                    .items()
                }
                return VirusTotalResult(
                    is_malicious=(malicious + suspicious) > 0,
                    detection_ratio=f"{malicious}/{total}",
                    scan_id=url_id,
                    vendor_results=vendor_results,
                )

        # ── Step 2: submit URL for a fresh scan ───────────────────────────
        submit_resp = await client.post(
            VT_URL_SCAN,
            headers=_vt_headers(),
            data={"url": url},
        )
        submit_resp.raise_for_status()
        analysis_id = submit_resp.json()["data"]["id"]

        # ── Step 3: poll until complete or deadline ───────────────────────
        deadline = time.monotonic() + settings.VIRUSTOTAL_POLL_TIMEOUT
        for delay in [2, 3, 3, 4, 4]:
            await asyncio.sleep(delay)

            if time.monotonic() >= deadline:
                logger.warning(
                    "VirusTotal poll timeout for %s after %.0fs — "
                    "returning scan_id for deferred retrieval",
                    url,
                    settings.VIRUSTOTAL_POLL_TIMEOUT,
                )
                return VirusTotalResult(
                    scan_id=analysis_id,
                    error=(
                        f"Scan submitted but not completed within "
                        f"{settings.VIRUSTOTAL_POLL_TIMEOUT:.0f}s. "
                        f"Retrieve results using scan_id: {analysis_id}"
                    ),
                )

            result_resp = await client.get(
                VT_URL_ANALYSIS.format(id=analysis_id),
                headers=_vt_headers(),
            )
            result_resp.raise_for_status()
            data = result_resp.json()["data"]

            if data["attributes"]["status"] == "completed":
                return _parse_analysis_data(data)

        return VirusTotalResult(
            scan_id=analysis_id,
            error="Analysis timed out — check VT dashboard",
        )

    except httpx.HTTPStatusError as exc:
        logger.error("VirusTotal HTTP error: %s", exc)
        return VirusTotalResult(error=f"HTTP {exc.response.status_code}")
    except Exception as exc:
        logger.exception("VirusTotal error")
        return VirusTotalResult(error=str(exc))


async def check_virustotal_file_hash(
    sha256: str, client: httpx.AsyncClient
) -> dict:
    """Look up a file hash on VirusTotal and return raw results."""
    if not settings.VIRUSTOTAL_API_KEY:
        return {"error": "VirusTotal API key not configured"}

    try:
        resp = await client.get(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers=_vt_headers(),
        )
        if resp.status_code == 404:
            return {"found": False}
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        logger.exception("VirusTotal file hash lookup error")
        return {"error": str(exc)}
