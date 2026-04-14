# Malicious URL Scanner API

A FastAPI-based REST API that performs multi-stage URL analysis for malicious content detection.

## Features

| Stage | What It Does |
|---|---|
| **Google Safe Browsing** | Checks against Google's threat database (malware, social engineering, unwanted software) |
| **VirusTotal** | Submits URL for multi-engine scanning and retrieves detection ratios |
| **Reputation** | WHOIS domain age, DNS config (MX/SPF/DMARC), Tranco top-1M ranking |
| **SSL Validation** | Certificate validity, expiry, issuer, SANs, chain completeness, protocol version, key strength |
| **Screenshot** | Headless Chromium capture of the target URL |
| **File Analysis** | Conditional download of executables → SHA-256 hash → ML-based malware/script detection |
| **Phishing Detection** | Visual analysis of screenshots (Faster R-CNN + Siamese NN + ResNet) |

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
playwright install chromium
```

### 2. Configure API Keys

```bash
cp .env.example .env
# Edit .env with your API keys
```

Required keys:
- `GOOGLE_SAFE_BROWSING_API_KEY`
- `VIRUSTOTAL_API_KEY`

### 3. Run the Server

```bash
uvicorn app.main:app --reload
```

The API will be available at `http://127.0.0.1:8000`.

### 4. Open the Docs

Visit `http://127.0.0.1:8000/docs` for the interactive Swagger UI.

## API Endpoints

### `POST /scan`

Analyse a URL for malicious indicators.

**Request:**
```json
{
  "url": "https://example.com"
}
```

**Response:** Full `ScanResponse` with results from all pipeline stages, an overall risk score (0–100), and a list of risk factors.

### `GET /health`

Liveness check.

## Quality Gates

Install development tooling:

```bash
pip install -e ".[dev]"
pre-commit install
```

Run all quality gates with one command:

```bash
make quality
```

Manual equivalent:

```bash
black --check app tests
ruff check app tests
mypy app tests
pytest -q --maxfail=1
```

Run all configured pre-commit hooks on the full codebase:

```bash
pre-commit run --all-files
```

## Project Structure

```
api/
├── app/
│   ├── main.py               # FastAPI app entry-point
│   ├── config.py              # Settings from .env
│   ├── schemas.py             # Pydantic request/response models
│   ├── dependencies.py        # Shared HTTP client & Playwright browser
│   ├── routers/
│   │   └── scan.py            # POST /scan endpoint
│   ├── services/
│   │   ├── orchestrator.py    # Parallel analysis pipeline
│   │   ├── safe_browsing.py   # Google Safe Browsing v4
│   │   ├── virustotal.py      # VirusTotal API v3
│   │   ├── reputation.py      # WHOIS, DNS, Tranco
│   │   ├── ssl_validator.py   # TLS certificate analysis
│   │   ├── screenshot.py      # Headless browser capture
│   │   └── file_analyzer.py   # Download analysis + ML dispatch
│   └── ml/
│       ├── binary_malware.py  # LightGBM interface wrapper
│       ├── script_detector.py # LongFormer pipeline
│       ├── phishing_detector.py # Visual phishing wrapper
│       └── models/            # ML models and inference scripts
├── screenshots/               # Captured screenshots
├── downloads/                 # Temporary downloads
├── .env.example
├── requirements.txt
└── README.md
```

## ML Models

The API fully integrates with the trained machine learning models stored within the `app/ml/models/` directory.

| Component | Architecture & Integration | Path |
|---|---|---|
| **Binary Malware** | LightGBM PE-feature classifier wrapped via local inference script | `app/ml/models/malicious_binary_detection/PE_detector.lgb` |
| **Script Malware** | LongFormer sequence classifier (restricted strictly to `.ps1` files) | `app/ml/models/malicious_script_detection/saved_model/` |
| **Phishing Visuals** | Faster R-CNN + Siamese NN wrapped via the full detection pipeline | `app/ml/models/phishing_detection/checkpoints/` |

The intermediate hooks inside the `app/ml/` folder dynamically extend pathing to your `inference` / `pipeline` files, automatically preserving your engineered thresholding, tokenization boundaries, and evaluation logic.
