"""
Application configuration loaded from environment variables / .env file.
"""

from pathlib import Path

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Central configuration — values are read from env vars or a .env file."""

    # ── API Keys ──────────────────────────────────────────────────────────
    GOOGLE_SAFE_BROWSING_API_KEY: str = ""
    VIRUSTOTAL_API_KEY: str = ""
    # ── Paths ─────────────────────────────────────────────────────────────
    TRANCO_LIST_PATH: str = "tranco_top1m.csv"
    SCREENSHOT_DIR: str = "screenshots"
    DOWNLOAD_DIR: str = "downloads"
    MODELS_DIR: str = str(Path(__file__).resolve().parent / "ml" / "models")

    # ── Server ────────────────────────────────────────────────────────────
    APP_HOST: str = "127.0.0.1"
    APP_PORT: int = 8000
    DEBUG: bool = False

    # ── Timeouts (seconds) ────────────────────────────────────────────────
    HTTP_TIMEOUT: float = 30.0
    SCREENSHOT_TIMEOUT: float = 15000  # Playwright uses ms
    FILE_DOWNLOAD_MAX_SIZE: int = 50 * 1024 * 1024  # 50 MB
    # Maximum seconds to poll VirusTotal for a *fresh* scan result.
    # Cached results are returned immediately and are unaffected by this limit.
    # When the deadline is reached the scan_id is returned so callers can
    # retrieve the completed report later.
    VIRUSTOTAL_POLL_TIMEOUT: float = 6.0

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": True,
    }

    def ensure_directories(self) -> None:
        """Create output directories if they don't exist."""
        for dir_path in (self.SCREENSHOT_DIR, self.DOWNLOAD_DIR, self.MODELS_DIR):
            Path(dir_path).mkdir(parents=True, exist_ok=True)


settings = Settings()
settings.ensure_directories()
