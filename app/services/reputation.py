"""
Reputation checking — WHOIS, DNS, Tranco.
"""

from __future__ import annotations

import asyncio
import csv
import logging
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import dns.resolver
import whois

from app.config import settings
from app.schemas import (
    ReputationResult,
    WHOISInfo,
    DNSInfo,
)

logger = logging.getLogger(__name__)

# ── Tranco list (loaded once) ────────────────────────────────────────────────

_tranco_ranks: dict[str, int] = {}
_tranco_loaded = False


def _load_tranco() -> None:
    global _tranco_ranks, _tranco_loaded
    if _tranco_loaded:
        return
    path = Path(settings.TRANCO_LIST_PATH)
    if not path.exists():
        logger.warning("Tranco list not found at %s — ranking checks disabled", path)
        _tranco_loaded = True
        return
    with path.open(newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) >= 2:
                try:
                    _tranco_ranks[row[1].strip().lower()] = int(row[0])
                except ValueError:
                    continue
    _tranco_loaded = True
    logger.info("Tranco list loaded — %d entries", len(_tranco_ranks))


def _extract_domain(url: str) -> str:
    parsed = urlparse(url)
    domain = parsed.hostname or parsed.path
    return domain.lower().strip(".")


# ── WHOIS ─────────────────────────────────────────────────────────────────────

def _check_whois(domain: str) -> WHOISInfo:
    try:
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        expiration = w.expiration_date
        if isinstance(expiration, list):
            expiration = expiration[0]

        age_days = None
        if creation:
            if isinstance(creation, datetime):
                age_days = (datetime.now(timezone.utc) - creation.replace(tzinfo=timezone.utc)).days
            else:
                age_days = None

        domain_name = w.domain_name
        if isinstance(domain_name, list):
            domain_name = domain_name[0]

        return WHOISInfo(
            domain_name=str(domain_name) if domain_name else None,
            creation_date=creation,
            expiration_date=expiration,
            domain_age_days=age_days,
            registrar=w.registrar,
        )
    except Exception as exc:
        logger.warning("WHOIS lookup failed for %s: %s", domain, exc)
        return WHOISInfo()


# ── DNS ───────────────────────────────────────────────────────────────────────

def _check_dns(domain: str) -> DNSInfo:
    info = DNSInfo()

    # MX records
    try:
        mx_answers = dns.resolver.resolve(domain, "MX")
        info.has_mx = True
        info.mx_records = [str(r.exchange).rstrip(".") for r in mx_answers]
    except Exception:
        pass

    # SPF (TXT records)
    try:
        txt_answers = dns.resolver.resolve(domain, "TXT")
        for rdata in txt_answers:
            txt = rdata.to_text().strip('"')
            if txt.startswith("v=spf1"):
                info.has_spf = True
                info.spf_record = txt
                break
    except Exception:
        pass

    # DMARC
    try:
        dmarc_answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        for rdata in dmarc_answers:
            txt = rdata.to_text().strip('"')
            if txt.startswith("v=DMARC1"):
                info.has_dmarc = True
                info.dmarc_record = txt
                break
    except Exception:
        pass

    return info


# ── Public API ────────────────────────────────────────────────────────────────

async def check_reputation(url: str) -> ReputationResult:
    """Run all reputation checks for the given URL."""
    _load_tranco()

    domain = _extract_domain(url)

    try:
        # Run blocking WHOIS and DNS lookups concurrently in the thread pool
        whois_info, dns_info = await asyncio.gather(
            asyncio.to_thread(_check_whois, domain),
            asyncio.to_thread(_check_dns, domain),
        )
        tranco_rank = _tranco_ranks.get(domain)
        if tranco_rank is None:
            # Strip leading "www." and try the registered domain
            parts = domain.split(".")
            for i in range(1, len(parts)):
                candidate = ".".join(parts[i:])
                if candidate in _tranco_ranks:
                    tranco_rank = _tranco_ranks[candidate]
                    break

        return ReputationResult(
            whois=whois_info,
            dns=dns_info,
            tranco_rank=tranco_rank,
        )
    except Exception as exc:
        logger.exception("Reputation check error")
        return ReputationResult(error=str(exc))
