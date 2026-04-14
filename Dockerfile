FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    SCREENSHOT_DIR=/tmp/screenshots \
    DOWNLOAD_DIR=/tmp/downloads

WORKDIR /app

# OS libraries required by Playwright Chromium and common ML/runtime deps.
RUN apt-get update && apt-get install -y --no-install-recommends \
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
COPY app/ml/models/phishing_detection/requirements.txt ./app/ml/models/phishing_detection/requirements.txt
COPY app/ml/models/malicious_script_detection/requirements.txt ./app/ml/models/malicious_script_detection/requirements.txt

RUN pip install --upgrade pip setuptools wheel \
    && pip install -r requirements.txt \
    && pip install -r app/ml/models/phishing_detection/requirements.txt \
    && pip install -r app/ml/models/malicious_script_detection/requirements.txt \
    && python -m playwright install chromium

COPY . .

EXPOSE 8080

CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8080}"]
