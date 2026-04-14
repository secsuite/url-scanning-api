"""
Central ML model registry.

All three detectors are initialized here as module-level singletons and
pre-loaded once at application startup via ``preload_all()``.  Service modules
import the accessors from here instead of managing their own lazy-init globals.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

from app.config import settings
from app.ml.binary_malware import BinaryMalwareDetector
from app.ml.phishing_detector import PhishingDetector
from app.ml.script_detector import ScriptDetector

logger = logging.getLogger(__name__)

_phishing_detector: PhishingDetector | None = None
_malware_detector: BinaryMalwareDetector | None = None
_script_detector: ScriptDetector | None = None


def get_phishing_detector() -> PhishingDetector | None:
    global _phishing_detector
    if _phishing_detector is None:
        logger.info("Lazy-loading phishing detector on first use.")
        _load_phishing()
    return _phishing_detector


def get_malware_detector() -> BinaryMalwareDetector | None:
    global _malware_detector
    if _malware_detector is None:
        logger.info("Lazy-loading binary malware detector on first use.")
        _load_malware()
    return _malware_detector


def get_script_detector() -> ScriptDetector | None:
    global _script_detector
    if _script_detector is None:
        logger.info("Lazy-loading script detector on first use.")
        _load_script()
    return _script_detector


def _load_phishing() -> None:
    global _phishing_detector
    _phishing_detector = PhishingDetector(models_dir=settings.MODELS_DIR)


def _load_malware() -> None:
    global _malware_detector
    _malware_detector = BinaryMalwareDetector(
        model_path=str(Path(settings.MODELS_DIR) / "malicious_binary_detection" / "PE_detector.lgb")
    )


def _load_script() -> None:
    global _script_detector
    _script_detector = ScriptDetector(
        model_path=str(Path(settings.MODELS_DIR) / "malicious_script_detection" / "saved_model")
    )


async def preload_all() -> None:
    """Load all ML models concurrently in the thread pool at startup."""
    logger.info("Pre-loading ML models...")
    await asyncio.gather(
        asyncio.to_thread(_load_phishing),
        asyncio.to_thread(_load_malware),
        asyncio.to_thread(_load_script),
    )
    logger.info("All ML models loaded.")
