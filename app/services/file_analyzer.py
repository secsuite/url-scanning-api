"""
Conditional file download & analysis service.

Sends a HEAD request to the URL, checks Content-Type / extension against a
list of executable/script types.  If it matches, downloads the file, hashes it,
and dispatches to the ML models for binary malware and script detection.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from pathlib import Path
from urllib.parse import urlparse

import httpx

from app.config import settings
from app.dependencies import get_http_client
from app.ml.registry import get_malware_detector, get_script_detector
from app.schemas import FileAnalysisResult, MalwareMLResult, ScriptMLResult

logger = logging.getLogger(__name__)

# Extensions that trigger a download + ML analysis
EXECUTABLE_EXTENSIONS = {
    ".exe",
    ".dll",
    ".scr",
    ".sys",
    ".com",
    ".ps1",
}

SCRIPT_EXTENSIONS = {
    ".ps1",
}

# Suspicious content-types
EXECUTABLE_CONTENT_TYPES = {
    "application/x-msdownload",
    "application/x-msdos-program",
    "application/x-dosexec",
    "application/octet-stream",
    "application/vnd.microsoft.portable-executable",
    "application/x-powershell",
    "text/x-powershell",
}


def _determine_file_extension(file_bytes: bytes, url: str, content_type: str) -> str | None:
    """
    Determine the most likely file extension based on magic bytes,
    HTTP content-type headers, and the URL suffix.
    """
    # 1. Magic bytes
    if file_bytes.startswith(b"MZ"):
        return ".exe"
    if file_bytes.startswith(b"\x7fELF"):
        return ".elf"
    if file_bytes.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        path_suffix = Path(urlparse(url).path).suffix.lower()
        if path_suffix in {".msi", ".doc", ".xls", ".ppt"}:
            return path_suffix
        return ".msi"
    if file_bytes.startswith(b"PK\x03\x04"):
        if content_type == "application/java-archive":
            return ".jar"
        path_suffix = Path(urlparse(url).path).suffix.lower()
        if path_suffix in {".jar", ".zip", ".docx", ".xlsx"}:
            return path_suffix
        return ".zip"

    # 2. Content-Type header
    content_type_map = {
        "application/vnd.microsoft.portable-executable": ".exe",
        "application/x-msdownload": ".exe",
        "application/x-msdos-program": ".exe",
        "application/x-executable": ".elf",
        "application/x-dosexec": ".exe",
        "application/x-msi": ".msi",
        "application/java-archive": ".jar",
        "text/x-powershell": ".ps1",
        "application/x-powershell": ".ps1",
    }
    if content_type in content_type_map:
        return content_type_map[content_type]

    # 3. Fallback to URL suffix
    path = urlparse(url).path
    suffix = Path(path).suffix.lower()

    # 4. Powershell heuristic (often text with specific keywords)
    if not suffix or suffix == ".txt":
        try:
            head = file_bytes[:2048].decode("utf-8", errors="ignore")
            if any(
                kw in head
                for kw in ("Invoke-", "Write-Host", "New-Object", "$PSVersionTable", "powershell")
            ):
                return ".ps1"
        except Exception:
            pass

    return suffix if suffix else None


async def analyze_file(url: str) -> FileAnalysisResult:
    """Conditionally download and analyse the file behind *url*."""
    client = await get_http_client()
    result = FileAnalysisResult()

    try:
        # ── HEAD request ──────────────────────────────────────────────────
        head_resp = await client.head(url)
        content_type = (head_resp.headers.get("content-type", "")).split(";")[0].strip().lower()
        content_length = head_resp.headers.get("content-length")

        url_path = urlparse(url).path
        url_ext = Path(url_path).suffix.lower()

        result.content_type = content_type
        result.file_extension = url_ext if url_ext else None

        # Decide whether to download
        should_download = (
            url_ext and url_ext in EXECUTABLE_EXTENSIONS
        ) or content_type in EXECUTABLE_CONTENT_TYPES

        if not should_download:
            return result

        # Respect size limit
        if content_length and int(content_length) > settings.FILE_DOWNLOAD_MAX_SIZE:
            result.error = (
                f"File too large ({content_length} bytes); "
                f"limit is {settings.FILE_DOWNLOAD_MAX_SIZE}"
            )
            return result

        # ── Download ──────────────────────────────────────────────────────
        dl_resp = await client.get(url)
        dl_resp.raise_for_status()
        file_bytes = dl_resp.content
        result.was_downloaded = True
        result.file_size_bytes = len(file_bytes)

        # Determine real extension based on content
        ext = _determine_file_extension(file_bytes, url, content_type)
        result.file_extension = ext

        # SHA-256 hash
        sha256 = hashlib.sha256(file_bytes).hexdigest()
        result.sha256_hash = sha256

        # Save to disk for model consumption
        tmp_path = Path(settings.DOWNLOAD_DIR) / f"{uuid.uuid4().hex}_{sha256[:12]}"
        tmp_path.write_bytes(file_bytes)

        # ── ML analysis ───────────────────────────────────────────────────
        try:
            is_pe = ext and ext in {".exe", ".dll", ".scr", ".sys", ".com"}
            is_script = ext and ext in SCRIPT_EXTENSIONS

            if is_pe:
                # Binary malware detection (PE files)
                detector = get_malware_detector()
                if detector is None:
                    raise RuntimeError("Binary malware detector not loaded")
                result.malware_detection = detector.predict(str(tmp_path))
            elif is_script:
                # Script detection (PowerShell)
                script_det = get_script_detector()
                if script_det is None:
                    raise RuntimeError("Script detector not loaded")
                script_content = file_bytes.decode("utf-8", errors="replace")
                result.script_detection = script_det.predict(script_content)
            else:
                result.error = f"Unsupported file type '{ext}'. Only PE files and PowerShell scripts are analyzed."
        except Exception as ml_exc:
            logger.warning("ML analysis error: %s", ml_exc)
            result.malware_detection = MalwareMLResult(error=str(ml_exc))
            result.script_detection = ScriptMLResult(error=str(ml_exc))

        # Cleanup
        try:
            tmp_path.unlink()
        except OSError:
            pass

    except httpx.HTTPStatusError as exc:
        result.error = f"HTTP {exc.response.status_code}"
    except Exception as exc:
        logger.exception("File analysis error for %s", url)
        result.error = str(exc)

    return result
