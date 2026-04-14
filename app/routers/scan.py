"""
POST /scan endpoint — the external surface of the analysis pipeline.
"""

from fastapi import APIRouter
from app.schemas import ScanRequest, ScanResponse
from app.services.orchestrator import analyze_url

router = APIRouter(prefix="/scan", tags=["Scan"])


@router.post(
    "",
    response_model=ScanResponse,
    summary="Analyse a URL for malicious indicators",
    description=(
        "Runs the full analysis pipeline: Google Safe Browsing, VirusTotal, "
        "reputation checking (WHOIS, DNS, Tranco, Shodan), SSL validation, "
        "screenshot capture, conditional file download & ML-based threat "
        "detection."
    ),
)
async def scan_url(request: ScanRequest) -> ScanResponse:
    """Scan a single URL and return aggregated results."""
    return await analyze_url(str(request.url))
