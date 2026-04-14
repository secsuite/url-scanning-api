"""
PE Malicious Binary Detection - Inference Script
=================================================
Standalone inference script for the trained LightGBM PE malware detector.
Reads PE files from disk (or bytes), extracts features via thrember's
PEFeatureExtractor, and returns malicious/benign predictions.

Usage:
    # Single file
    python inference.py path/to/suspicious.exe

    # Multiple files
    python inference.py file1.exe file2.dll file3.sys

    # Custom model path & threshold
    python inference.py --model ./my_model.lgb --threshold 0.7 suspicious.exe

    # Scan an entire directory
    python inference.py --scan-dir ./samples/

    # JSON output (for programmatic consumption)
    python inference.py --json suspicious.exe

    # Use as a Python module
    from inference import PEMalwareDetector
    detector = PEMalwareDetector("PE_detector.lgb")
    result = detector.predict_file("suspicious.exe")
    print(result)
"""

import os
import sys
import json
import glob
import argparse
import logging
from dataclasses import dataclass, asdict
from typing import Optional

import numpy as np
import lightgbm as lgb

# ---------------------------------------------------------------------------
# The thrember package lives next to this script (inside src/).
# We make sure it's importable regardless of where the user invokes the script.
# ---------------------------------------------------------------------------
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if _SCRIPT_DIR not in sys.path:
    sys.path.insert(0, _SCRIPT_DIR)

from thrember.features import PEFeatureExtractor

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("pe_inference")


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class PredictionResult:
    """Container for a single prediction."""

    file_path: str
    score: float
    verdict: str  # "MALICIOUS" or "BENIGN"
    threshold: float
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Detector class
# ---------------------------------------------------------------------------
class PEMalwareDetector:
    """
    Lightweight wrapper around the trained LightGBM booster + thrember
    feature extractor, designed for inference only.

    Parameters
    ----------
    model_path : str
        Path to the saved LightGBM model file (*.lgb).
    threshold : float, default 0.5
        Decision threshold. Scores >= threshold are labelled MALICIOUS.
    """

    def __init__(self, model_path: str, threshold: float = 0.5):
        if not os.path.isfile(model_path):
            raise FileNotFoundError(f"Model file not found: {model_path}")

        log.info("Loading LightGBM model from %s", model_path)
        self.booster = lgb.Booster(model_file=model_path)
        self.threshold = threshold

        log.info("Initialising PEFeatureExtractor ...")
        self.extractor = PEFeatureExtractor()
        log.info("Feature vector dimension: %d", self.extractor.dim)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def predict_bytes(self, file_data: bytes) -> float:
        """
        Return the malicious probability for raw PE bytes.

        Returns
        -------
        float
            Probability in [0, 1]. Higher → more likely malicious.
        """
        vec = np.array(self.extractor.feature_vector(file_data), dtype=np.float32)
        score = float(self.booster.predict([vec])[0])
        return score

    def predict_file(self, file_path: str) -> PredictionResult:
        """
        Read a file from disk, extract features, predict, and return
        a structured PredictionResult.
        """
        file_path = os.path.abspath(file_path)
        if not os.path.isfile(file_path):
            return PredictionResult(
                file_path=file_path,
                score=0.0,
                verdict="ERROR",
                threshold=self.threshold,
                error=f"File not found: {file_path}",
            )

        try:
            with open(file_path, "rb") as f:
                file_data = f.read()

            score = self.predict_bytes(file_data)
            verdict = "MALICIOUS" if score >= self.threshold else "BENIGN"

            return PredictionResult(
                file_path=file_path,
                score=round(score, 6),
                verdict=verdict,
                threshold=self.threshold,
            )
        except Exception as e:
            return PredictionResult(
                file_path=file_path,
                score=0.0,
                verdict="ERROR",
                threshold=self.threshold,
                error=str(e),
            )

    def predict_files(self, file_paths: list[str]) -> list[PredictionResult]:
        """Batch prediction over a list of file paths."""
        results = []
        for fp in file_paths:
            result = self.predict_file(fp)
            results.append(result)
        return results

    def predict_directory(
        self,
        directory: str,
        extensions: tuple[str, ...] = (".exe", ".dll", ".sys", ".ocx", ".scr", ".drv", ".cpl"),
        recursive: bool = True,
    ) -> list[PredictionResult]:
        """
        Scan all PE-like files in a directory.

        Parameters
        ----------
        directory : str
            Root directory to scan.
        extensions : tuple of str
            File extensions to consider (case-insensitive).
        recursive : bool
            If True, walk subdirectories recursively.
        """
        if not os.path.isdir(directory):
            log.error("Directory not found: %s", directory)
            return []

        file_paths = []
        if recursive:
            for root, _, files in os.walk(directory):
                for fname in files:
                    if any(fname.lower().endswith(ext) for ext in extensions):
                        file_paths.append(os.path.join(root, fname))
        else:
            for fname in os.listdir(directory):
                full = os.path.join(directory, fname)
                if os.path.isfile(full) and any(fname.lower().endswith(ext) for ext in extensions):
                    file_paths.append(full)

        log.info("Found %d PE files in %s", len(file_paths), directory)
        return self.predict_files(file_paths)


# ---------------------------------------------------------------------------
# Pretty-print helpers
# ---------------------------------------------------------------------------
def _print_table(results: list[PredictionResult]) -> None:
    """Print results in a human-friendly table."""
    header = f"{'Verdict':<12} {'Score':>8}  {'File'}"
    print("\n" + "=" * 70)
    print(header)
    print("-" * 70)

    malicious_count = 0
    for r in results:
        if r.error:
            print(f"{'ERROR':<12} {'---':>8}  {r.file_path}  ({r.error})")
        else:
            tag = r.verdict
            print(f"{tag:<12} {r.score:>8.4f}  {r.file_path}")
            if r.verdict == "MALICIOUS":
                malicious_count += 1

    print("=" * 70)
    total = len(results)
    errors = sum(1 for r in results if r.error)
    benign = total - malicious_count - errors
    print(
        f"Total: {total}  |  Malicious: {malicious_count}  |  "
        f"Benign: {benign}  |  Errors: {errors}"
    )
    print()


def _print_json(results: list[PredictionResult]) -> None:
    """Print results as a JSON array."""
    print(json.dumps([r.to_dict() for r in results], indent=2))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="PE Malicious Binary Detector — Inference",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument(
        "files",
        nargs="*",
        help="PE files to scan.",
    )
    p.add_argument(
        "--model",
        default=os.path.join(_SCRIPT_DIR, "PE_detector.lgb"),
        help="Path to the LightGBM model file (default: ./PE_detector.lgb next to this script).",
    )
    p.add_argument(
        "--threshold",
        type=float,
        default=0.5,
        help="Decision threshold (default: 0.5). Scores >= threshold → MALICIOUS.",
    )
    p.add_argument(
        "--scan-dir",
        default=None,
        help="Scan all PE files in a directory instead of listing individual files.",
    )
    p.add_argument(
        "--no-recursive",
        action="store_true",
        help="Do not recurse into subdirectories when using --scan-dir.",
    )
    p.add_argument(
        "--json",
        action="store_true",
        dest="output_json",
        help="Output results as JSON.",
    )
    return p.parse_args()


def main() -> None:
    args = parse_args()

    if not args.files and not args.scan_dir:
        print("[!] Provide PE file paths as arguments, or use --scan-dir <directory>.")
        sys.exit(1)

    detector = PEMalwareDetector(args.model, threshold=args.threshold)

    results: list[PredictionResult] = []

    # Scan a directory
    if args.scan_dir:
        results.extend(detector.predict_directory(args.scan_dir, recursive=not args.no_recursive))

    # Individual files
    if args.files:
        results.extend(detector.predict_files(args.files))

    # Output
    if args.output_json:
        _print_json(results)
    else:
        _print_table(results)


if __name__ == "__main__":
    main()
