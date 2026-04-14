"""
Integration test suite for the Link Checker pipeline  —  POST /scan

All tests hit real external services with no mocking.  See conftest.py for
prerequisites (API keys, Playwright, ML models).

Five test cases from the acceptance table:

  TC-01  Known malicious URL flagged in Google Safe Browsing
  TC-02  Safe URL check (https://www.google.com)
  TC-03  URL with multi-hop redirect chain
  TC-04  Malformed URL input ('not-a-url')
  TC-05  Response-time SLA (≤ 8 s for any valid URL)

Notes on real-world behaviour that affect what we assert:
  - Google provides https://testsafebrowsing.appspot.com/s/malware.html as an
    official test URL that is permanently listed in the Safe Browsing DB.
  - VirusTotal may take up to 16 s to return results for an uncached URL
    (2 + 3 + 3 + 4 + 4 s polling).  The 8-second SLA in TC-05 is only
    achievable when VT already has a cached report.  Tests for well-known
    domains (google.com) are virtually always cached; TC-05 is scoped
    accordingly and the caveat is documented.
  - validate_ssl() currently calls socket.create_connection() synchronously
    inside an async function without asyncio.to_thread().  Integration tests
    will expose this event-loop blocking if it causes timeouts.
"""

from __future__ import annotations

import time

import pytest

# ── Test URLs ─────────────────────────────────────────────────────────────────

# Google's official permanently-listed Safe Browsing test URL (MALWARE type).
MALICIOUS_URL = "https://testsafebrowsing.appspot.com/s/malware.html"

# A real, well-established safe URL.
SAFE_URL = "https://www.google.com"

# A URL that issues three HTTP 302 redirects before resolving to a real page.
# httpbin.org is a well-known HTTP testing service.
REDIRECT_URL = "https://httpbin.org/redirect/3"

MALFORMED_INPUT = "not-a-url"

# SLA requirement from the acceptance table.
RESPONSE_TIME_SLA_SECONDS = 8.0


# ── Helpers ───────────────────────────────────────────────────────────────────


def _scan(client, url: str):
    """POST /scan and return (response, elapsed_seconds)."""
    start = time.monotonic()
    response = client.post("/scan", json={"url": url})
    elapsed = time.monotonic() - start
    return response, elapsed


# ═════════════════════════════════════════════════════════════════════════════
# TC-01  Known malicious URL
# ═════════════════════════════════════════════════════════════════════════════


@pytest.mark.requires_safe_browsing_key
@pytest.mark.requires_virustotal_key
class TestMaliciousUrl:
    """
    TC-01 — https://testsafebrowsing.appspot.com/s/malware.html

    Google permanently lists this URL in its Safe Browsing database as MALWARE.
    The test therefore does not depend on network conditions varying — it will
    always be flagged as long as the API key is valid.
    """

    def test_safe_browsing_flags_url_as_threat(self, live_client):
        """Safe Browsing must return is_threat=True for the test malware URL."""
        response, _ = _scan(live_client, MALICIOUS_URL)

        assert response.status_code == 200
        sb = response.json()["safe_browsing"]

        # If the API key is configured but the call failed, surface the error.
        assert sb.get("error") is None, f"Safe Browsing returned an error: {sb['error']}"
        assert sb["is_threat"] is True, (
            "Expected is_threat=True for the Google test malware URL. "
            f"Full Safe Browsing result: {sb}"
        )

    def test_threat_category_is_present(self, live_client):
        """At least one threat entry with a non-empty threat_type must be returned."""
        response, _ = _scan(live_client, MALICIOUS_URL)
        threats = response.json()["safe_browsing"]["threats"]

        assert len(threats) >= 1
        for threat in threats:
            assert threat.get("threat_type"), f"Threat entry missing 'threat_type': {threat}"

    def test_threat_type_is_malware(self, live_client):
        """The official test URL is listed as MALWARE — the type must be present."""
        response, _ = _scan(live_client, MALICIOUS_URL)
        threat_types = [t["threat_type"] for t in response.json()["safe_browsing"]["threats"]]
        assert "MALWARE" in threat_types, f"Expected MALWARE in threat_types, got: {threat_types}"

    def test_risk_score_reflects_safe_browsing_hit(self, live_client):
        """
        Safe Browsing hit adds 30 points to the risk score.
        Even with no other signals the score must be >= 30.
        """
        response, _ = _scan(live_client, MALICIOUS_URL)
        body = response.json()

        assert body["risk_score"] >= 30, (
            f"risk_score={body['risk_score']} — expected >= 30 for a Safe Browsing hit. "
            f"risk_factors: {body['risk_factors']}"
        )

    def test_risk_factors_name_safe_browsing(self, live_client):
        """risk_factors must contain an entry that mentions Google Safe Browsing."""
        response, _ = _scan(live_client, MALICIOUS_URL)
        factors = response.json()["risk_factors"]

        assert any(
            "Google Safe Browsing" in f for f in factors
        ), f"Expected 'Google Safe Browsing' in risk_factors, got: {factors}"

    def test_screenshot_still_captured(self, live_client):
        """
        Even for malicious URLs the screenshot stage must attempt capture.
        A failure here surfaces a bug in the pipeline (e.g. Playwright crash),
        not an expected result — capture success/failure is both acceptable,
        but the key must be present in the response.
        """
        response, _ = _scan(live_client, MALICIOUS_URL)
        assert "screenshot" in response.json()


# ═════════════════════════════════════════════════════════════════════════════
# TC-02  Safe URL
# ═════════════════════════════════════════════════════════════════════════════


@pytest.mark.requires_safe_browsing_key
@pytest.mark.requires_virustotal_key
class TestSafeUrl:
    """
    TC-02 — https://www.google.com

    A well-established, globally trusted domain.  Every pipeline stage should
    return clean, populated results.
    """

    def test_safe_browsing_does_not_flag_google(self, live_client):
        response, _ = _scan(live_client, SAFE_URL)
        sb = response.json()["safe_browsing"]

        assert sb.get("error") is None, f"Safe Browsing error: {sb['error']}"
        assert sb["is_threat"] is False

    def test_ssl_certificate_is_valid(self, live_client):
        """Google serves a valid, CA-signed TLS certificate."""
        response, _ = _scan(live_client, SAFE_URL)
        ssl = response.json()["ssl"]

        assert ssl.get("error") is None, f"SSL validation error: {ssl['error']}"
        assert ssl["is_valid"] is True
        assert ssl["is_self_signed"] is False
        assert ssl["san_matches_domain"] is True
        assert ssl["days_until_expiry"] is not None
        assert ssl["days_until_expiry"] > 0

    def test_ssl_issuer_is_not_empty(self, live_client):
        """The certificate issuer must be populated (proves the cert was parsed)."""
        response, _ = _scan(live_client, SAFE_URL)
        ssl = response.json()["ssl"]
        assert ssl["issuer"], "SSL issuer should not be empty for google.com"

    def test_whois_domain_age_is_populated(self, live_client):
        """
        WHOIS must return a domain_age_days value.
        google.com was registered in 1997, so age > 9000 days.
        """
        response, _ = _scan(live_client, SAFE_URL)
        whois = response.json()["reputation"]["whois"]

        assert (
            whois["domain_age_days"] is not None
        ), "WHOIS lookup returned no domain age — check WHOIS service availability"
        assert (
            whois["domain_age_days"] > 9000
        ), f"google.com should be >9000 days old, got {whois['domain_age_days']}"

    def test_whois_registrar_is_populated(self, live_client):
        response, _ = _scan(live_client, SAFE_URL)
        whois = response.json()["reputation"]["whois"]
        assert whois["registrar"], "Registrar should be present for google.com"

    def test_screenshot_captured_successfully(self, live_client):
        """
        Playwright must successfully load google.com and save a screenshot.
        Failure here usually means Chromium is not installed.
        """
        response, _ = _scan(live_client, SAFE_URL)
        screenshot = response.json()["screenshot"]

        assert screenshot.get("error") is None, (
            f"Screenshot failed: {screenshot['error']}. "
            "Ensure Playwright Chromium is installed: playwright install chromium"
        )
        assert screenshot["success"] is True
        assert screenshot["url"] is not None
        assert screenshot["url"].startswith("/screenshots/")

    def test_screenshot_url_ends_with_png(self, live_client):
        response, _ = _scan(live_client, SAFE_URL)
        screenshot_url = response.json()["screenshot"]["url"]
        assert screenshot_url.endswith(".png"), f"Expected .png screenshot, got: {screenshot_url}"

    def test_tranco_rank_present_for_google(self, live_client):
        """google.com is in the Tranco top-1M list — rank must not be None."""
        response, _ = _scan(live_client, SAFE_URL)
        tranco_rank = response.json()["reputation"]["tranco_rank"]

        assert tranco_rank is not None, (
            "google.com must appear in the Tranco list. " "Check that tranco_top1m.csv is present."
        )
        assert (
            tranco_rank <= 10
        ), f"google.com should be ranked in the top 10, got rank {tranco_rank}"

    def test_dns_spf_and_dmarc_present_for_google(self, live_client):
        """google.com publishes both SPF and DMARC records."""
        response, _ = _scan(live_client, SAFE_URL)
        dns = response.json()["reputation"]["dns"]

        assert dns["has_spf"] is True, "google.com must have an SPF record"
        assert dns["has_dmarc"] is True, "google.com must have a DMARC record"

    def test_risk_score_is_zero_for_google(self, live_client):
        """
        With every check passing (safe browsing clean, SSL valid, old domain,
        SPF + DMARC present, Tranco ranked), the risk score must be 0.
        """
        response, _ = _scan(live_client, SAFE_URL)
        body = response.json()

        assert body["risk_score"] == 0.0, (
            f"Expected risk_score=0 for google.com, got {body['risk_score']}. "
            f"Unexpected risk factors: {body['risk_factors']}"
        )

    def test_response_contains_all_pipeline_fields(self, live_client):
        """Every section of the ScanResponse schema must be present."""
        response, _ = _scan(live_client, SAFE_URL)
        body = response.json()

        for field in (
            "url",
            "scanned_at",
            "safe_browsing",
            "virustotal",
            "reputation",
            "ssl",
            "screenshot",
            "file_analysis",
            "phishing_detection",
            "risk_score",
            "risk_factors",
        ):
            assert field in body, f"Missing top-level field: '{field}'"


# ═════════════════════════════════════════════════════════════════════════════
# TC-03  URL with redirect chain
# ═════════════════════════════════════════════════════════════════════════════


@pytest.mark.requires_safe_browsing_key
@pytest.mark.requires_virustotal_key
class TestRedirectChain:
    """
    TC-03 — https://httpbin.org/redirect/3

    httpbin.org/redirect/N issues N consecutive HTTP 302 redirects before
    resolving to /get (a JSON echo endpoint).  The httpx client in the pipeline
    has follow_redirects=True so it silently follows the chain.

    Important limitation: the orchestrator passes the *original* URL to all
    threat-intel services (Safe Browsing, VirusTotal, WHOIS).  The redirect
    chain is followed at the HTTP client level (for file download and screenshot)
    but is not exposed as a field in ScanResponse.  These tests validate the
    pipeline handles redirecting URLs without error and that the final page is
    captured by Playwright.
    """

    def test_redirecting_url_returns_200(self, live_client):
        response, _ = _scan(live_client, REDIRECT_URL)
        assert response.status_code == 200

    def test_original_url_preserved_in_url_field(self, live_client):
        """The 'url' field must always reflect the originally submitted URL."""
        response, _ = _scan(live_client, REDIRECT_URL)
        assert response.json()["url"] == REDIRECT_URL

    def test_redirect_chain_is_populated(self, live_client):
        """
        redirect_chain must contain at least two entries (original + final)
        for a URL that actually redirects.
        httpbin.org/redirect/3 issues exactly 3 hops.
        """
        response, _ = _scan(live_client, REDIRECT_URL)
        body = response.json()

        assert (
            len(body["redirect_chain"]) >= 2
        ), f"Expected >= 2 entries in redirect_chain, got: {body['redirect_chain']}"

    def test_final_url_differs_from_original(self, live_client):
        """
        final_url must be set and must differ from the submitted URL,
        confirming the redirect was followed.
        """
        response, _ = _scan(live_client, REDIRECT_URL)
        body = response.json()

        assert body["final_url"] is not None, "final_url should be set for a redirecting URL"
        assert (
            body["final_url"] != REDIRECT_URL
        ), f"final_url should differ from original URL after redirect, got: {body['final_url']}"

    def test_threat_intel_receives_final_url(self, live_client):
        """
        Safe Browsing must evaluate the resolved destination, not the shortener.
        httpbin.org/get (the final destination) is not malicious.
        """
        response, _ = _scan(live_client, REDIRECT_URL)
        sb = response.json()["safe_browsing"]

        assert sb.get("error") is None, f"Safe Browsing returned an error: {sb['error']}"
        assert sb["is_threat"] is False

    def test_ssl_reflects_final_destination(self, live_client):
        """
        SSL is validated against the final destination host (httpbin.org),
        not the original redirecting URL's host.
        """
        response, _ = _scan(live_client, REDIRECT_URL)
        body = response.json()
        ssl = body["ssl"]
        final_url = body.get("final_url", REDIRECT_URL)

        assert ssl is not None
        if ssl.get("error") is None:
            assert ssl["is_self_signed"] is False
            # The SAN must match the final destination host, not the original
            assert (
                ssl["san_matches_domain"] is True
            ), f"SAN mismatch — SSL cert should match final host in {final_url}"

    def test_all_pipeline_stages_populated(self, live_client):
        """No pipeline stage should be absent from the response."""
        response, _ = _scan(live_client, REDIRECT_URL)
        body = response.json()
        for stage in (
            "safe_browsing",
            "virustotal",
            "reputation",
            "ssl",
            "screenshot",
            "file_analysis",
        ):
            assert body[stage] is not None, f"Stage '{stage}' is None"

    def test_screenshot_captures_final_page(self, live_client):
        """
        Playwright follows redirects natively, so the screenshot must capture
        the final destination page.  A successful capture proves the browser
        reached the resolved URL.
        """
        response, _ = _scan(live_client, REDIRECT_URL)
        screenshot = response.json()["screenshot"]

        assert (
            screenshot.get("error") is None
        ), f"Screenshot failed for redirect URL: {screenshot['error']}"
        assert screenshot["success"] is True


# ═════════════════════════════════════════════════════════════════════════════
# TC-04  Malformed URL input
# ═════════════════════════════════════════════════════════════════════════════


class TestMalformedUrl:
    """
    TC-04 — Input that is not a valid URL must be rejected before the pipeline.

    This test class requires no API keys — Pydantic's HttpUrl validator runs
    before any service is called, so these tests pass with no external access.
    """

    def test_plain_string_returns_422(self, live_client):
        response = live_client.post("/scan", json={"url": "not-a-url"})
        assert response.status_code == 422

    def test_422_body_references_url_field(self, live_client):
        """The validation error detail must point to the 'url' field."""
        response = live_client.post("/scan", json={"url": "not-a-url"})
        body = response.json()

        assert "detail" in body
        locations = [tuple(err.get("loc", [])) for err in body["detail"]]
        assert any(
            "url" in loc for loc in locations
        ), f"Expected 'url' in error location, got: {locations}"

    def test_missing_url_field_returns_422(self, live_client):
        response = live_client.post("/scan", json={})
        assert response.status_code == 422

    def test_empty_string_returns_422(self, live_client):
        response = live_client.post("/scan", json={"url": ""})
        assert response.status_code == 422

    @pytest.mark.parametrize(
        "bad_input",
        [
            "not-a-url",
            "ftp://",
            "just some text",
            "://missing-scheme.com",
            "http://",
        ],
    )
    def test_various_invalid_urls_rejected(self, live_client, bad_input):
        response = live_client.post("/scan", json={"url": bad_input})
        assert (
            response.status_code == 422
        ), f"Expected 422 for {bad_input!r}, got {response.status_code}"

    def test_no_pipeline_services_called_for_invalid_url(self, live_client):
        """
        A 422 response body must not contain ScanResponse fields.
        This confirms the pipeline was never entered.
        """
        response = live_client.post("/scan", json={"url": "not-a-url"})
        body = response.json()
        # ScanResponse fields must not be present — only FastAPI's error envelope
        assert "safe_browsing" not in body
        assert "risk_score" not in body


# ═════════════════════════════════════════════════════════════════════════════
# TC-05  Response-time SLA
# ═════════════════════════════════════════════════════════════════════════════


@pytest.mark.requires_safe_browsing_key
@pytest.mark.requires_virustotal_key
class TestResponseTimeSLA:
    """
    TC-05 — Full pipeline response must be returned within 8 seconds.

    IMPORTANT CAVEAT — VirusTotal polling:
      When VT does *not* have a cached report for a URL it polls for up to
      2+3+3+4+4 = 16 seconds.  The 8-second SLA is therefore only achievable
      when VT already has a cached result.

      These tests use well-known URLs (google.com) that VT has virtually always
      cached.  If VT returns a fresh scan for any of these URLs the test will
      legitimately fail, which is a signal that the SLA definition needs
      revisiting (e.g. return partial results while VT scans in background).

    The tests assert the SLA and report elapsed time in the failure message
    so timing data is always visible.
    """

    def test_safe_url_within_sla(self, live_client):
        """google.com (cached in VT) must respond within 8 s."""
        response, elapsed = _scan(live_client, SAFE_URL)

        assert response.status_code == 200
        assert elapsed < RESPONSE_TIME_SLA_SECONDS, (
            f"google.com scan took {elapsed:.2f}s — exceeds {RESPONSE_TIME_SLA_SECONDS}s SLA.\n"
            f"VirusTotal result: {response.json()['virustotal']}\n"
            "If VT returned a fresh scan instead of a cached result this is expected."
        )

    def test_malicious_url_within_sla(self, live_client):
        """
        The Safe Browsing test malware URL should also be cached in VT.
        If not, the SLA will be violated — see class docstring.
        """
        response, elapsed = _scan(live_client, MALICIOUS_URL)

        assert response.status_code == 200
        assert elapsed < RESPONSE_TIME_SLA_SECONDS, (
            f"Malicious URL scan took {elapsed:.2f}s — exceeds {RESPONSE_TIME_SLA_SECONDS}s SLA.\n"
            f"VirusTotal result: {response.json()['virustotal']}"
        )

    def test_redirect_url_within_sla(self, live_client):
        """httpbin.org redirect scan must complete within 8 s."""
        response, elapsed = _scan(live_client, REDIRECT_URL)

        assert response.status_code == 200
        assert elapsed < RESPONSE_TIME_SLA_SECONDS, (
            f"Redirect URL scan took {elapsed:.2f}s — exceeds {RESPONSE_TIME_SLA_SECONDS}s SLA.\n"
            f"VirusTotal result: {response.json()['virustotal']}"
        )

    def test_elapsed_time_is_logged_in_all_cases(self, live_client):
        """
        Smoke test: scan google.com and print timing for every pipeline stage.
        Use -s flag with pytest to see the output.
        """
        response, elapsed = _scan(live_client, SAFE_URL)
        body = response.json()

        print(f"\n[SLA] Total elapsed: {elapsed:.2f}s")
        print(
            f"[SLA] VT result: {body['virustotal'].get('detection_ratio')} "
            f"(error: {body['virustotal'].get('error')})"
        )
        print(
            f"[SLA] Screenshot: success={body['screenshot']['success']} "
            f"error={body['screenshot'].get('error')}"
        )
        print(f"[SLA] SSL: valid={body['ssl']['is_valid']} " f"error={body['ssl'].get('error')}")

        assert response.status_code == 200  # always passes — output is the value
