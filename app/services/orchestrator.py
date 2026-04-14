"""
Analysis orchestrator — fans out to all pipeline stages and aggregates results.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx

from app.dependencies import get_http_client
from app.ml.registry import get_phishing_detector
from app.schemas import (
    FileAnalysisResult,
    PhishingMLResult,
    ReputationResult,
    SafeBrowsingResult,
    ScanResponse,
    ScreenshotResult,
    SSLResult,
    VirusTotalResult,
)
from app.services.file_analyzer import analyze_file
from app.services.reputation import check_reputation
from app.services.safe_browsing import check_safe_browsing
from app.services.screenshot import capture_screenshot
from app.services.ssl_validator import validate_ssl
from app.services.virustotal import check_virustotal

logger = logging.getLogger(__name__)


def _extract_domain(url: str) -> str:
    parsed = urlparse(url)
    return parsed.hostname or parsed.path


async def _resolve_redirects(url: str, client: httpx.AsyncClient) -> tuple[str, list[str]]:
    """
    Follow the redirect chain for *url* and return (final_url, chain).

    *chain* contains every URL visited in order (including the final
    destination), and is empty when the URL does not redirect.

    A HEAD request is used to avoid downloading response bodies.
    Falls back to the original URL on any network error so the rest of
    the pipeline is never blocked by redirect resolution.
    """
    try:
        response = await client.head(url, follow_redirects=True)
        # response.history contains one entry per redirect response;
        # each entry's .url is the URL that was redirected FROM.
        if not response.history:
            return str(response.url), []

        chain = [str(r.url) for r in response.history] + [str(response.url)]
        final_url = str(response.url)
        logger.info("Redirect chain for %s: %d hop(s) → %s", url, len(response.history), final_url)
        return final_url, chain
    except Exception as exc:
        logger.warning("Redirect resolution failed for %s: %s", url, exc)
        return url, []


def _compute_risk_score(
    sb: SafeBrowsingResult,
    vt: VirusTotalResult,
    rep: ReputationResult,
    ssl_res: SSLResult,
    file_res: FileAnalysisResult,
    phishing: PhishingMLResult,
) -> tuple[float, list[str]]:
    """
    Compute an overall 0–100 risk score and a list of contributing risk factors.
    Higher score = more dangerous.
    """
    score = 0.0
    factors: list[str] = []

    # ── Safe Browsing ─────────────────────────────────────────────────────
    if sb.is_threat:
        score += 30
        threat_types = [t.get("threat_type", "unknown") for t in sb.threats]
        factors.append(f"Google Safe Browsing: flagged as {', '.join(threat_types)}")

    # ── VirusTotal ────────────────────────────────────────────────────────
    if vt.is_malicious:
        score += 25
        factors.append(f"VirusTotal: {vt.detection_ratio} detections")

    # ── Domain age ────────────────────────────────────────────────────────
    if rep.whois.domain_age_days is not None:
        if rep.whois.domain_age_days < 30:
            score += 10
            factors.append(f"Domain is only {rep.whois.domain_age_days} days old")
        elif rep.whois.domain_age_days < 90:
            score += 5
            factors.append(f"Domain is {rep.whois.domain_age_days} days old (relatively new)")

    # ── DNS configuration ─────────────────────────────────────────────────
    if not rep.dns.has_spf:
        score += 3
        factors.append("Missing SPF record")
    if not rep.dns.has_dmarc:
        score += 3
        factors.append("Missing DMARC record")

    # ── Tranco ranking ────────────────────────────────────────────────────
    if rep.tranco_rank is None:
        score += 5
        factors.append("Domain not in Tranco top-1M list")

    # ── SSL issues ────────────────────────────────────────────────────────
    if ssl_res.error and "No certificate" not in (ssl_res.error or ""):
        score += 5
        factors.append(f"SSL issue: {ssl_res.error}")
    if ssl_res.is_self_signed:
        score += 10
        factors.append("Self-signed SSL certificate")
    if ssl_res.days_until_expiry is not None and ssl_res.days_until_expiry < 7:
        score += 5
        factors.append(f"SSL certificate expires in {ssl_res.days_until_expiry} days")
    if ssl_res.san_list and not ssl_res.san_matches_domain:
        score += 5
        factors.append("SSL SAN does not match domain")

    # ── File analysis ─────────────────────────────────────────────────────
    if file_res.was_downloaded:
        if file_res.malware_detection.is_malicious:
            score += 20
            factors.append(
                f"Downloaded file flagged as malware "
                f"(confidence: {file_res.malware_detection.confidence:.2f})"
            )
        if file_res.script_detection.is_malicious:
            score += 15
            factors.append(
                f"Downloaded script flagged as malicious "
                f"(confidence: {file_res.script_detection.confidence:.2f})"
            )

    # ── Phishing ──────────────────────────────────────────────────────────
    if phishing.is_phishing:
        score += 20
        detail = f"confidence: {phishing.confidence:.2f}"
        if phishing.matched_brand:
            detail += f", impersonating '{phishing.matched_brand}'"
        factors.append(f"Phishing detected ({detail})")

    return min(score, 100.0), factors


async def analyze_url(url: str) -> ScanResponse:
    """
    Run the full analysis pipeline for *url*.

    Redirect resolution runs first so that Safe Browsing and VirusTotal
    evaluate the *final destination* rather than an opaque shortener URL.
    All other stages then run concurrently.
    """
    client = await get_http_client()

    # ── Redirect resolution ───────────────────────────────────────────────
    # Resolves the full redirect chain so threat-intel services receive the
    # actual destination URL instead of e.g. a bit.ly shortener.
    final_url, redirect_chain = await _resolve_redirects(url, client)
    domain = _extract_domain(final_url)

    # ── Stage 1: run independent checks in parallel ───────────────────────
    # Safe Browsing and VirusTotal use final_url (the resolved destination).
    # Reputation, SSL, screenshot and file analysis also use final_url so
    # that WHOIS, cert and page content all reflect the actual target.
    sb_task = asyncio.create_task(check_safe_browsing(final_url, client))
    vt_task = asyncio.create_task(check_virustotal(final_url, client))
    rep_task = asyncio.create_task(check_reputation(final_url))
    ssl_task = asyncio.create_task(validate_ssl(final_url))
    screenshot_task = asyncio.create_task(capture_screenshot(final_url))
    file_task = asyncio.create_task(analyze_file(final_url))

    sb_result, vt_result, rep_result, ssl_result, screenshot_result, file_result = (
        await asyncio.gather(
            sb_task,
            vt_task,
            rep_task,
            ssl_task,
            screenshot_task,
            file_task,
            return_exceptions=False,
        )
    )

    if isinstance(sb_result, Exception):
        sb_result = SafeBrowsingResult(error=str(sb_result))
    if isinstance(vt_result, Exception):
        vt_result = VirusTotalResult(error=str(vt_result))
    if isinstance(rep_result, Exception):
        rep_result = ReputationResult(error=str(rep_result))
    if isinstance(ssl_result, Exception):
        ssl_result = SSLResult(error=str(ssl_result))
    if isinstance(screenshot_result, Exception):
        screenshot_result = ScreenshotResult(error=str(screenshot_result))
    if isinstance(file_result, Exception):
        file_result = FileAnalysisResult(error=str(file_result))

    # ── Stage 2: phishing detection (needs screenshot) ────────────────────
    phishing_result = PhishingMLResult()
    if screenshot_result.success and screenshot_result.file_path:
        try:
            detector = get_phishing_detector()
            if detector is None:
                raise RuntimeError("Phishing detector not loaded")
            phishing_result = await asyncio.to_thread(
                detector.predict, screenshot_result.file_path, domain
            )
        except Exception as exc:
            logger.warning("Phishing detection error: %s", exc)
            phishing_result = PhishingMLResult(error=str(exc))

    # ── Stage 3: risk scoring ─────────────────────────────────────────────
    risk_score, risk_factors = _compute_risk_score(
        sb_result, vt_result, rep_result, ssl_result, file_result, phishing_result
    )

    return ScanResponse(
        url=url,
        final_url=final_url if final_url != url else None,
        redirect_chain=redirect_chain,
        scanned_at=datetime.now(timezone.utc),
        safe_browsing=sb_result,
        virustotal=vt_result,
        reputation=rep_result,
        ssl=ssl_result,
        screenshot=screenshot_result,
        file_analysis=file_result,
        phishing_detection=phishing_result,
        risk_score=risk_score,
        risk_factors=risk_factors,
    )
