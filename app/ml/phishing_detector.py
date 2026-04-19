"""
Visual phishing page detection — Faster R-CNN, Siamese NN, and ResNet.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

from app.schemas import PhishingMLResult

logger = logging.getLogger(__name__)

# Ensure pipeline script can be imported
_PHISHING_DETECTION_DIR = Path(__file__).parent / "models" / "phishing_detection"
if str(_PHISHING_DETECTION_DIR) not in sys.path:
    sys.path.insert(0, str(_PHISHING_DETECTION_DIR))

try:
    from pipeline import PhishingDetector as UserPhishingDetector
except Exception as exc:
    logger.warning("Phishing pipeline import failed at startup: %s", exc)
    UserPhishingDetector = None


class PhishingDetector:
    """
    Visual phishing detection pipeline wrapper.
    """

    def __init__(self, models_dir: str) -> None:
        self.models_dir = Path(models_dir) / "phishing_detection"
        self.detector = None
        self._load_models()

    def _load_models(self) -> None:
        """Load the user's PhishingDetector pipeline."""
        if UserPhishingDetector is None:
            logger.error("UserPhishingDetector could not be imported.")
            return

        try:
            self.detector = UserPhishingDetector()
            logger.info("Visual phishing detection pipeline loaded successfully.")
        except Exception as exc:
            logger.error("Failed to load PhishingDetector: %s", exc)

    def predict(self, screenshot_path: str, domain: str) -> PhishingMLResult:
        """
        Full phishing detection pipeline using the wrapped model.

        Args:
            screenshot_path: Path to the webpage screenshot.
            domain: The domain (or full URL) to check against detected logos.
        """
        if self.detector is None:
            return PhishingMLResult(error="Model not loaded")

        try:
            faux_url = f"http://{domain}" if not domain.startswith("http") else domain

            result = self.detector.analyze(screenshot_path, url=faux_url)

            is_phishing = result.get("is_phishing", False)
            phishing_brands = result.get("phishing_brands", [])
            detections = result.get("detections", [])

            confidence = None
            matched_brand = phishing_brands[0] if phishing_brands else None
            match_type: str | None = None
            domain_match_reason: str | None = None

            if detections:
                confidence = max(
                    (d.get("best_match_similarity", 0.0) for d in detections),
                    default=0.0,
                )

                # Surface domain-vs-logo analysis from the first phishing detection,
                # or from the highest-confidence detection if nothing is phishing.
                phishing_dets = [d for d in detections if d.get("is_phishing")]
                source_det = (
                    phishing_dets[0]
                    if phishing_dets
                    else max(detections, key=lambda d: d.get("best_match_similarity", 0.0))
                )
                domain_info = source_det.get("domain_info") or {}
                match_type = domain_info.get("match_type")
                domain_match_reason = domain_info.get("reason")

                if is_phishing and matched_brand is None:
                    matched_brand = source_det.get("best_match_brand")

            return PhishingMLResult(
                is_phishing=is_phishing,
                confidence=confidence,
                matched_brand=matched_brand,
                url=faux_url,
                match_type=match_type,
                domain_match_reason=domain_match_reason,
            )
        except Exception as exc:
            logger.exception("Phishing detection error")
            return PhishingMLResult(error=str(exc))
