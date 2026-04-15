# syntax=docker/dockerfile:1.7
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    SCREENSHOT_DIR=/tmp/screenshots \
    DOWNLOAD_DIR=/tmp/downloads

WORKDIR /app

# OS libraries required by Playwright Chromium and common ML/runtime deps.
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    wget \
    libnss3 \
    libnspr4 \
    libatk-bridge2.0-0 \
    libatk1.0-0 \
    libatspi2.0-0 \
    libcups2 \
    libdrm2 \
    libdbus-1-3 \
    libxkbcommon0 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxrandr2 \
    libgbm1 \
    libasound2 \
    libxshmfence1 \
    libx11-6 \
    libx11-xcb1 \
    libxcb1 \
    libxcursor1 \
    libxi6 \
    libgtk-3-0 \
    libglib2.0-0 \
    libpangocairo-1.0-0 \
    libpango-1.0-0 \
    libcairo2 \
    libxext6 \
    libxrender1 \
    fonts-liberation \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./requirements.txt

RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --upgrade pip setuptools wheel \
    && pip install -r requirements.txt \
    && python -m playwright install chromium

# Keep heavyweight model artifacts in a dedicated layer so regular app code
# changes do not force re-copying/re-layering ~1GB of model files.
COPY app/ml/models ./app/ml/models

# Copy the rest of the application without model artifacts.
COPY app/__init__.py app/config.py app/dependencies.py app/main.py app/schemas.py ./app/
COPY app/routers ./app/routers
COPY app/services ./app/services
COPY app/ml/__init__.py app/ml/binary_malware.py app/ml/phishing_detector.py app/ml/registry.py app/ml/script_detector.py ./app/ml/
COPY tranco_top1m.csv ./tranco_top1m.csv

EXPOSE 8080

CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8080}"]
