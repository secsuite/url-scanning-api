"""
SSL / TLS certificate validation service.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import ssl
from datetime import datetime, timezone
from typing import Any, cast
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import ExtensionOID

from app.schemas import SSLResult

logger = logging.getLogger(__name__)

DEFAULT_PORT = 443


def _extract_host_port(url: str) -> tuple[str, int]:
    parsed = urlparse(url)
    host = parsed.hostname or parsed.path
    port = parsed.port or DEFAULT_PORT
    return host, port


def _get_key_info(public_key: Any) -> tuple[str, int | None]:
    """Return (key_type, key_size) for the certificate's public key."""
    if isinstance(public_key, rsa.RSAPublicKey):
        return "RSA", public_key.key_size
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        return "EC", public_key.key_size
    elif isinstance(public_key, dsa.DSAPublicKey):
        return "DSA", public_key.key_size
    elif isinstance(public_key, ed25519.Ed25519PublicKey | ed448.Ed448PublicKey):
        return "EdDSA", None
    return "Unknown", None


def _validate_ssl_sync(url: str) -> SSLResult:
    """
    Synchronous TLS inspection — runs in a thread pool via asyncio.to_thread.

    All blocking socket and cryptography operations are kept here so the
    async event loop is never stalled.
    """
    host, port = _extract_host_port(url)

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # we inspect manually

        conn = ctx.wrap_socket(
            socket.create_connection((host, port), timeout=10),
            server_hostname=host,
        )

        der_cert = conn.getpeercert(binary_form=True)
        protocol_version = conn.version()

        chain_length = None
        try:
            chain = conn.get_verified_chain()  # type: ignore[attr-defined]
            chain_length = len(chain) if chain else None
        except (AttributeError, Exception):
            pass

        conn.close()

        if der_cert is None:
            return SSLResult(error="No certificate received")

        cert = x509.load_der_x509_certificate(der_cert)

        issuer = cert.issuer.rfc4514_string()
        subject = cert.subject.rfc4514_string()

        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
        now = datetime.now(timezone.utc)
        days_until_expiry = (not_after - now).days
        is_valid = not_before <= now <= not_after

        is_self_signed = cert.issuer == cert.subject

        san_list: list[str] = []
        san_matches = False
        try:
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san_value = cast(x509.SubjectAlternativeName, san_ext.value)
            san_list = san_value.get_values_for_type(x509.DNSName)
            san_matches = any(_san_matches_host(san, host) for san in san_list)
        except x509.ExtensionNotFound:
            pass

        key_type, key_size = _get_key_info(cert.public_key())

        return SSLResult(
            is_valid=is_valid,
            issuer=issuer,
            subject=subject,
            serial_number=str(cert.serial_number),
            not_before=not_before,
            not_after=not_after,
            days_until_expiry=days_until_expiry,
            san_list=san_list,
            san_matches_domain=san_matches,
            protocol_version=protocol_version,
            key_size=key_size,
            key_type=key_type,
            chain_length=chain_length,
            is_self_signed=is_self_signed,
        )

    except TimeoutError:
        return SSLResult(error="Connection timed out")
    except socket.gaierror as exc:
        return SSLResult(error=f"DNS resolution failed: {exc}")
    except ssl.SSLError as exc:
        return SSLResult(error=f"SSL error: {exc}")
    except Exception as exc:
        logger.exception("SSL validation error for %s", url)
        return SSLResult(error=str(exc))


async def validate_ssl(url: str) -> SSLResult:
    """Connect to the host and analyse its TLS certificate."""
    return await asyncio.to_thread(_validate_ssl_sync, url)


def _san_matches_host(san: str, host: str) -> bool:
    """Check if a SAN entry matches the target host (supports wildcards)."""
    san = san.lower()
    host = host.lower()
    if san == host:
        return True
    if san.startswith("*."):
        wildcard_base = san[2:]
        return host.endswith(f".{wildcard_base}")
    return False
