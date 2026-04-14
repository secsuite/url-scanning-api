"""
Malicious script detection — LongFormer-based classifier.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from app.schemas import ScriptMLResult

logger = logging.getLogger(__name__)


class ScriptDetector:
    """
    LongFormer-based malicious script detector.
    """

    def __init__(self, model_path: str) -> None:
        self.model_path = model_path
        self.model: Any | None = None
        self.tokenizer: Any | None = None
        self.device: Any | None = None
        self._load_model()

    def _load_model(self) -> None:
        """Load the LongFormer model and tokenizer."""
        path = Path(self.model_path)
        if not path.exists():
            logger.warning(
                "LongFormer model directory not found at %s — predictions will be skipped.",
                path,
            )
            return

        try:
            import torch
            from transformers import AutoModelForSequenceClassification, AutoTokenizer

            self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
            self.tokenizer = AutoTokenizer.from_pretrained(str(path))
            self.model = AutoModelForSequenceClassification.from_pretrained(str(path))
            self.model.to(self.device)
            self.model.eval()
            logger.info("LongFormer script detector loaded from %s onto %s", path, self.device)
        except Exception as exc:
            logger.error("Failed to load LongFormer model: %s", exc)

    def predict(self, script_content: str) -> ScriptMLResult:
        """
        Run malicious script detection on *script_content*.
        """
        if self.model is None or self.tokenizer is None:
            return ScriptMLResult(error="Model not loaded")

        try:
            import torch

            inputs = self.tokenizer(
                script_content,
                return_tensors="pt",
                padding="max_length",
                truncation=True,
                max_length=4096,
            )
            inputs = {k: v.to(self.device) for k, v in inputs.items()}

            with torch.no_grad():
                outputs = self.model(**inputs)
                logits = outputs.logits
                probs = torch.nn.functional.softmax(logits, dim=-1)

                # Assuming index 1 = malicious, index 0 = benign based on inference.py logic -> class_names = ["Benign (0)", "Malicious (1)"]
                confidence = probs[0][1].item()
                is_malicious = confidence >= 0.5

            return ScriptMLResult(
                is_malicious=is_malicious,
                confidence=confidence,
            )
        except Exception as exc:
            logger.exception("LongFormer prediction error")
            return ScriptMLResult(error=str(exc))
