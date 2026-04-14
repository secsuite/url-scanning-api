"""
End-to-end phishing detection pipeline.

Chains Faster R-CNN (logo detection) and Siamese Network (logo matching)
to determine if a webpage screenshot is a phishing attempt.

Pipeline:
    1. Input: webpage screenshot + URL
    2. Faster R-CNN detects logo bounding boxes
    3. For each detected logo, crop the region
    4. Siamese Network compares crop against all 15 reference logos
    5. If best match similarity > threshold:
        - Extract domain from URL
        - Check domain against brand's legitimate domain whitelist
        - If domain NOT in whitelist → PHISHING
    6. Output: list of detection results

Usage:
    python pipeline.py --image <path> --url <url>
    python pipeline.py --image <path>  (without URL, just detection + matching)
"""

import os
import argparse
import torch
import torchvision.transforms as T
from PIL import Image, ImageDraw
from urllib.parse import urlparse

import config
from model_frcnn import get_model as get_frcnn_model
from model_siamese import get_siamese_model
import torchvision.transforms.functional as TF


class PhishingDetector:
    """
    End-to-end phishing detection pipeline.

    Combines Faster R-CNN for logo detection and Siamese Network for
    logo matching, with domain verification.
    """

    def __init__(
        self,
        frcnn_checkpoint=None,
        siamese_checkpoint=None,
        reference_dir=None,
        score_threshold=None,
        similarity_threshold=None,
        device=None,
    ):
        if frcnn_checkpoint is None:
            frcnn_checkpoint = config.FRCNN_CHECKPOINT
        if siamese_checkpoint is None:
            siamese_checkpoint = config.SIAMESE_CHECKPOINT
        if reference_dir is None:
            reference_dir = config.REFERENCE_LOGOS_DIR
        if score_threshold is None:
            score_threshold = config.FRCNN_SCORE_THRESHOLD
        if similarity_threshold is None:
            similarity_threshold = config.SIAMESE_SIMILARITY_THRESHOLD
        if device is None:
            device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

        self.device = device
        self.score_threshold = score_threshold
        self.similarity_threshold = similarity_threshold

        # Load Faster R-CNN
        print("Loading Faster R-CNN...")
        self.frcnn = get_frcnn_model()
        frcnn_ckpt = torch.load(frcnn_checkpoint, map_location=device)
        self.frcnn.load_state_dict(frcnn_ckpt["model_state_dict"])
        self.frcnn.to(device)
        self.frcnn.eval()

        # Load Siamese Network
        print("Loading Siamese Network...")
        self.siamese = get_siamese_model(pretrained=False)
        siamese_ckpt = torch.load(siamese_checkpoint, map_location=device)
        self.siamese.load_state_dict(siamese_ckpt["model_state_dict"])
        self.siamese.to(device)
        self.siamese.eval()

        # Load reference logo embeddings
        print("Computing reference logo embeddings...")
        self.reference_embeddings = {}
        self.siamese_transform = T.Compose(
            [
                T.Resize((config.SIAMESE_IMAGE_SIZE, config.SIAMESE_IMAGE_SIZE)),
                T.ToTensor(),
                T.Normalize(mean=[0.485, 0.456, 0.406], std=[0.229, 0.224, 0.225]),
            ]
        )

        for brand in config.BRAND_NAMES:
            ref_path = os.path.join(reference_dir, f"{brand}.png")
            if os.path.exists(ref_path):
                ref_img = Image.open(ref_path).convert("RGB")
                ref_tensor = self.siamese_transform(ref_img).unsqueeze(0).to(device)
                with torch.no_grad():
                    embedding = self.siamese.get_embedding(ref_tensor)
                self.reference_embeddings[brand] = embedding
            else:
                print(f"  Warning: No reference logo for {brand}")

        print(f"Loaded {len(self.reference_embeddings)} reference logos")
        print("Pipeline ready!")

    @torch.no_grad()
    def detect_logos(self, image):
        """
        Detect logos in an image using Faster R-CNN.

        Args:
            image: PIL Image

        Returns:
            list of dict: Each dict has 'bbox' [x1,y1,x2,y2], 'label', 'score'
        """
        img_tensor = TF.to_tensor(image).unsqueeze(0).to(self.device)
        outputs = self.frcnn(img_tensor)[0]

        detections = []
        for i in range(len(outputs["boxes"])):
            score = outputs["scores"][i].item()
            if score < self.score_threshold:
                continue
            detections.append(
                {
                    "bbox": outputs["boxes"][i].cpu().tolist(),
                    "label": outputs["labels"][i].item(),
                    "frcnn_label": "logo",
                    "score": score,
                }
            )

        return detections

    @torch.no_grad()
    def match_logo(self, logo_crop):
        """
        Match a logo crop against all reference logos using Siamese Network.

        Args:
            logo_crop: PIL Image of the cropped logo region

        Returns:
            list of dict: Sorted by similarity (descending).
                Each dict has 'brand', 'similarity'.
        """
        crop_tensor = self.siamese_transform(logo_crop).unsqueeze(0).to(self.device)
        crop_embedding = self.siamese.get_embedding(crop_tensor)

        matches = []
        for brand, ref_emb in self.reference_embeddings.items():
            sim = torch.nn.functional.cosine_similarity(crop_embedding, ref_emb, dim=1).item()
            matches.append({"brand": brand, "similarity": sim})

        matches.sort(key=lambda x: x["similarity"], reverse=True)
        return matches

    # Brand name aliases used to catch variants in domains
    _BRAND_ALIASES = {
        "boa": ["bankofamerica", "bank-of-america"],
        "office": ["office365", "office-365"],
        "facebook": ["fb", "meta"],
        "google": ["gmail", "youtube"],
        "microsoft": ["msn", "outlook", "hotmail", "azure"],
        "wellsfargo": ["wellsfargo", "wells-fargo"],
    }

    def _extract_domain(self, url: str) -> str:
        """Return the bare domain (no scheme, no port, no www.)."""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower().split(":")[0]
            if domain.startswith("www."):
                domain = domain[4:]
            return domain
        except Exception:
            return url.lower()

    def _domain_vs_brand(self, domain: str, brand: str) -> dict:
        """
        Deep comparison between a domain and a brand's known-good domains.

        Returns a dict with:
            match_type  – 'legitimate' | 'brand_in_domain' | 'typosquatting' | 'unrelated'
            risk_level  – 'safe' | 'high'
            reason      – human-readable explanation
            (optional) closest_legitimate, typo_similarity
        """
        import difflib

        legitimate_domains = config.BRAND_DOMAINS.get(brand, [])

        # 1. Exact or subdomain match → safe
        if any(domain == ld or domain.endswith("." + ld) for ld in legitimate_domains):
            return {
                "match_type": "legitimate",
                "risk_level": "safe",
                "reason": f"'{domain}' is an official {brand} domain",
            }

        # 2. Brand name (or alias) appears inside the domain → phishing keyword trick
        keywords = [brand] + self._BRAND_ALIASES.get(brand, [])
        for kw in keywords:
            if kw in domain:
                return {
                    "match_type": "brand_in_domain",
                    "risk_level": "high",
                    "reason": (
                        f"Brand keyword '{kw}' found in '{domain}' "
                        f"but it is not an official {brand} domain"
                    ),
                }

        # 3. Typosquatting: domain is very close to a legitimate one
        best_ratio, best_legit = 0.0, None
        for ld in legitimate_domains:
            ratio = difflib.SequenceMatcher(None, domain, ld).ratio()
            if ratio > best_ratio:
                best_ratio, best_legit = ratio, ld

        if best_ratio >= 0.75:
            return {
                "match_type": "typosquatting",
                "risk_level": "high",
                "reason": (
                    f"'{domain}' closely resembles '{best_legit}' "
                    f"({best_ratio:.0%} similarity) — possible typosquat"
                ),
                "closest_legitimate": best_legit,
                "typo_similarity": round(best_ratio, 3),
            }

        # 4. Completely unrelated domain
        return {
            "match_type": "unrelated",
            "risk_level": "high",
            "reason": f"'{domain}' is unrelated to {brand}",
        }

    def check_domain(self, url, brand):
        """
        Check if the URL domain matches the brand's legitimate domains.

        Args:
            url: URL string
            brand: Brand name

        Returns:
            dict with 'domain', 'is_legitimate', 'legitimate_domains',
            'match_type', 'risk_level', 'reason'
        """
        domain = self._extract_domain(url)
        legitimate_domains = config.BRAND_DOMAINS.get(brand, [])
        analysis = self._domain_vs_brand(domain, brand)
        is_legitimate = analysis["match_type"] == "legitimate"

        return {
            "domain": domain,
            "is_legitimate": is_legitimate,
            "legitimate_domains": legitimate_domains,
            "match_type": analysis["match_type"],
            "risk_level": analysis["risk_level"],
            "reason": analysis["reason"],
            **{
                k: v for k, v in analysis.items() if k not in ("match_type", "risk_level", "reason")
            },
        }

    def analyze(self, image_path, url=None):
        """
        Full phishing analysis pipeline.

        Args:
            image_path: Path to webpage screenshot
            url: Optional URL of the webpage

        Returns:
            dict with:
                - 'detections': list of detected logos
                - 'is_phishing': bool (True if any detection indicates phishing)
                - 'phishing_brands': list of brands suspected of impersonation
        """
        image = Image.open(image_path).convert("RGB")

        # Step 1: Detect logos
        detections = self.detect_logos(image)

        results = {
            "image_path": image_path,
            "url": url,
            "detections": [],
            "is_phishing": False,
            "phishing_brands": [],
        }

        if not detections:
            return results

        # Step 2 & 3: Match each detected logo and check domain
        for det in detections:
            x1, y1, x2, y2 = det["bbox"]
            logo_crop = image.crop(
                (
                    max(0, int(x1)),
                    max(0, int(y1)),
                    min(image.width, int(x2)),
                    min(image.height, int(y2)),
                )
            )

            # Match against reference logos
            matches = self.match_logo(logo_crop)
            best_match = matches[0] if matches else None

            detection_result = {
                "bbox": det["bbox"],
                "frcnn_label": det["frcnn_label"],
                "frcnn_score": det["score"],
                "best_match_brand": best_match["brand"] if best_match else None,
                "best_match_similarity": best_match["similarity"] if best_match else 0,
                "top_3_matches": matches[:3],
                "is_phishing": False,
                "domain_info": None,
            }

            # Always check domain against detected brand regardless of similarity score.
            # A low-confidence match on the wrong domain is still suspicious.
            if best_match:
                brand = best_match["brand"]

                if url:
                    domain_info = self.check_domain(url, brand)
                    detection_result["domain_info"] = domain_info

                    if not domain_info["is_legitimate"]:
                        detection_result["is_phishing"] = True
                        results["is_phishing"] = True
                        if brand not in results["phishing_brands"]:
                            results["phishing_brands"].append(brand)
                else:
                    # No URL provided — flag as potential phishing
                    detection_result["is_phishing"] = None  # Unknown without URL

            results["detections"].append(detection_result)

        return results

    def visualize_result(self, result, output_path):
        """Draw detection results on the image and save."""
        image = Image.open(result["image_path"]).convert("RGB")
        draw = ImageDraw.Draw(image)

        for det in result["detections"]:
            bbox = det["bbox"]
            brand = det["best_match_brand"] or det["frcnn_label"]
            sim = det["best_match_similarity"]
            is_phishing = det["is_phishing"]

            # Color based on phishing status
            if is_phishing is True:
                color = "#FF0000"  # Red for phishing
                label = f"PHISHING: {brand} ({sim:.2f})"
            elif is_phishing is False:
                color = "#00FF00"  # Green for legitimate
                label = f"OK: {brand} ({sim:.2f})"
            else:
                color = "#FFAA00"  # Orange for unknown
                label = f"?: {brand} ({sim:.2f})"

            draw.rectangle(bbox, outline=color, width=3)
            draw.text((bbox[0], bbox[1] - 15), label, fill=color)

        image.save(output_path)
        print(f"Visualization saved to {output_path}")


def main():
    parser = argparse.ArgumentParser(description="Phishing Detection Pipeline")
    parser.add_argument("--image", type=str, required=True, help="Path to screenshot")
    parser.add_argument("--url", type=str, default=None, help="URL of the webpage")
    parser.add_argument("--frcnn-checkpoint", type=str, default=config.FRCNN_CHECKPOINT)
    parser.add_argument("--siamese-checkpoint", type=str, default=config.SIAMESE_CHECKPOINT)
    parser.add_argument("--score-threshold", type=float, default=config.FRCNN_SCORE_THRESHOLD)
    parser.add_argument(
        "--similarity-threshold", type=float, default=config.SIAMESE_SIMILARITY_THRESHOLD
    )
    parser.add_argument("--output", type=str, default=None, help="Output visualization path")
    args = parser.parse_args()

    config.ensure_dirs()

    detector = PhishingDetector(
        frcnn_checkpoint=args.frcnn_checkpoint,
        siamese_checkpoint=args.siamese_checkpoint,
        score_threshold=args.score_threshold,
        similarity_threshold=args.similarity_threshold,
    )

    print(f"\nAnalyzing: {args.image}")
    if args.url:
        print(f"URL: {args.url}")

    result = detector.analyze(args.image, args.url)

    print(f"\n{'=' * 60}")
    print("ANALYSIS RESULTS")
    print(f"{'=' * 60}")
    print(f"Image: {result['image_path']}")
    print(f"URL: {result['url']}")
    print(f"Detected logos: {len(result['detections'])}")

    for i, det in enumerate(result["detections"]):
        print(f"\n  Detection #{i+1}:")
        print(f"    FRCNN label: {det['frcnn_label']} (score={det['frcnn_score']:.3f})")
        print(
            f"    Best match:  {det['best_match_brand']} (sim={det['best_match_similarity']:.3f})"
        )
        if det["domain_info"]:
            di = det["domain_info"]
            print(f"    Domain:      {di['domain']} ({di.get('match_type', '')})")
            print(f"    Reason:      {di.get('reason', '')}")
        status = (
            "PHISHING"
            if det["is_phishing"]
            else ("SAFE" if det["is_phishing"] is False else "UNKNOWN")
        )
        print(f"    Status:      {status}")

    print(f"\n{'=' * 60}")
    if result["is_phishing"]:
        print(f"PHISHING DETECTED — Impersonating: {', '.join(result['phishing_brands'])}")
    else:
        print("No phishing detected")

    if args.output or result["detections"]:
        output_path = args.output or os.path.join(config.OUTPUT_DIR, "pipeline_result.png")
        detector.visualize_result(result, output_path)


if __name__ == "__main__":
    main()
