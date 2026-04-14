"""
Pydantic schemas for API request / response models.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, HttpUrl

# ═══════════════════════════════════════════════════════════════════════════════
# Request
# ═══════════════════════════════════════════════════════════════════════════════


class ScanRequest(BaseModel):
    """Incoming scan request."""

    url: HttpUrl = Field(..., description="The URL to analyse")


# ═══════════════════════════════════════════════════════════════════════════════
# Sub-schemas — one per pipeline stage
# ═══════════════════════════════════════════════════════════════════════════════


class SafeBrowsingResult(BaseModel):
    """Google Safe Browsing Lookup API v4 result."""

    is_threat: bool = False
    threats: list[dict[str, Any]] = Field(default_factory=list)
    error: str | None = None


class VirusTotalResult(BaseModel):
    """VirusTotal URL analysis result."""

    is_malicious: bool = False
    detection_ratio: str | None = None
    scan_id: str | None = None
    vendor_results: dict[str, str] = Field(default_factory=dict)
    error: str | None = None


class WHOISInfo(BaseModel):
    domain_name: str | None = None
    creation_date: datetime | None = None
    expiration_date: datetime | None = None
    domain_age_days: int | None = None
    registrar: str | None = None


class DNSInfo(BaseModel):
    has_mx: bool = False
    mx_records: list[str] = Field(default_factory=list)
    has_spf: bool = False
    spf_record: str | None = None
    has_dmarc: bool = False
    dmarc_record: str | None = None


class ReputationResult(BaseModel):
    """Aggregated reputation data."""

    whois: WHOISInfo = Field(default_factory=WHOISInfo)
    dns: DNSInfo = Field(default_factory=DNSInfo)
    tranco_rank: int | None = None
    error: str | None = None


class SSLResult(BaseModel):
    """SSL / TLS certificate analysis."""

    is_valid: bool = False
    issuer: str | None = None
    subject: str | None = None
    serial_number: str | None = None
    not_before: datetime | None = None
    not_after: datetime | None = None
    days_until_expiry: int | None = None
    san_list: list[str] = Field(default_factory=list)
    san_matches_domain: bool = False
    protocol_version: str | None = None
    key_size: int | None = None
    key_type: str | None = None
    chain_length: int | None = None
    is_self_signed: bool = False
    error: str | None = None


class ScreenshotResult(BaseModel):
    """Headless browser screenshot capture."""

    success: bool = False
    file_path: str | None = None
    url: str | None = None
    error: str | None = None


class MalwareMLResult(BaseModel):
    """LightGBM binary malware detection."""

    is_malicious: bool = False
    confidence: float | None = None
    error: str | None = None


class ScriptMLResult(BaseModel):
    """LongFormer malicious script detection."""

    is_malicious: bool = False
    confidence: float | None = None
    error: str | None = None


class PhishingMLResult(BaseModel):
    """Visual phishing page detection (Faster R-CNN + Siamese + domain analysis)."""

    is_phishing: bool = False
    confidence: float | None = None
    matched_brand: str | None = None
    url: str | None = None
    # Domain-vs-logo comparison details.
    match_type: str | None = None
    domain_match_reason: str | None = None
    error: str | None = None


class FileAnalysisResult(BaseModel):
    """Results from conditional file download analysis."""

    was_downloaded: bool = False
    content_type: str | None = None
    file_extension: str | None = None
    sha256_hash: str | None = None
    file_size_bytes: int | None = None
    malware_detection: MalwareMLResult = Field(default_factory=MalwareMLResult)
    script_detection: ScriptMLResult = Field(default_factory=ScriptMLResult)
    error: str | None = None


# ═══════════════════════════════════════════════════════════════════════════════
# Top-level response
# ═══════════════════════════════════════════════════════════════════════════════


class ScanResponse(BaseModel):
    """Complete scan result aggregating every pipeline stage."""

    url: str
    final_url: str | None = Field(
        None,
        description="The URL after following all redirects; equals 'url' when there are none",
    )
    redirect_chain: list[str] = Field(
        default_factory=list,
        description="Ordered list of all URLs in the redirect chain (empty when no redirects)",
    )
    scanned_at: datetime
    safe_browsing: SafeBrowsingResult = Field(default_factory=SafeBrowsingResult)
    virustotal: VirusTotalResult = Field(default_factory=VirusTotalResult)
    reputation: ReputationResult = Field(default_factory=ReputationResult)
    ssl: SSLResult = Field(default_factory=SSLResult)
    screenshot: ScreenshotResult = Field(default_factory=ScreenshotResult)
    file_analysis: FileAnalysisResult = Field(default_factory=FileAnalysisResult)
    phishing_detection: PhishingMLResult = Field(default_factory=lambda: PhishingMLResult())
    risk_score: float | None = Field(
        None, description="Overall 0-100 risk score (higher = more dangerous)"
    )
    risk_factors: list[str] = Field(default_factory=list)
