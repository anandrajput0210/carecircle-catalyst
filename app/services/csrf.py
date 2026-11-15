"""CSRF Protection Service using Double-Submit HMAC Token."""
import hashlib
import hmac
import os
import secrets
import time
from typing import Optional
from urllib.parse import urlparse

from fastapi import HTTPException, Request, Response, status

from app.config import settings


def generate_csrf_token() -> str:
    """
    Generate a cryptographic double-submit CSRF token: nonce:timestamp:hmac_signature.
    """
    nonce = secrets.token_urlsafe(16)
    timestamp = str(int(time.time()))
    payload = f"{nonce}:{timestamp}"
    signature = hmac.new(
        settings.SECRET_KEY.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"{nonce}:{timestamp}:{signature}"


def verify_csrf_token(token: Optional[str]) -> bool:
    """
    Verify the cryptographic signature and timestamp freshness of a CSRF token.
    Enforces maximum age of CSRF_MAX_AGE_SECONDS (24h).
    """
    if not token or not isinstance(token, str):
        return False
    parts = token.split(":")
    if len(parts) != 3:
        return False

    nonce, timestamp_str, received_sig = parts
    try:
        ts = int(timestamp_str)
    except ValueError:
        return False

    # Check expiration (max 24h, reject future timestamps > 5m clock skew)
    now = int(time.time())
    if ts > now + 300:
        return False
    if now - ts > settings.CSRF_MAX_AGE_SECONDS:
        return False

    expected_payload = f"{nonce}:{timestamp_str}"
    expected_sig = hmac.new(
        settings.SECRET_KEY.encode("utf-8"),
        expected_payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(expected_sig, received_sig)


def is_allowed_origin(origin_or_referer: Optional[str]) -> bool:
    """
    Validate that request Origin or Referer belongs to permitted production, preview,
    or local development hosts.
    Rejects arbitrary wildcard *.vercel.app origins to prevent cross-subdomain CSRF.
    """
    if not origin_or_referer:
        return False

    parsed = urlparse(origin_or_referer)
    hostname = (parsed.hostname or "").lower()
    netloc = (parsed.netloc or "").lower()
    scheme = (parsed.scheme or "").lower()

    # 1. Allow local development and testclient hosts
    if hostname in ("localhost", "127.0.0.1", "::1", "testserver"):
        return True
    if netloc.startswith("localhost:") or netloc.startswith("127.0.0.1:"):
        return True

    # 2. Check explicit allowed origins from settings
    origin_full = f"{scheme}://{netloc}" if scheme and netloc else ""
    for allowed in settings.ALLOWED_ORIGINS:
        allowed_clean = allowed.strip().rstrip("/").lower()
        if origin_full == allowed_clean:
            return True
        allowed_parsed = urlparse(allowed_clean)
        if allowed_parsed.hostname and hostname == allowed_parsed.hostname.lower():
            return True

    # 3. Allow current project-scoped Vercel deployment URL if present in runtime environment
    vercel_url = os.getenv("VERCEL_URL", "").lower().strip()
    if vercel_url and (hostname == vercel_url or netloc == vercel_url):
        return True

    # 4. Allow only specific project-scoped Vercel preview subdomains (e.g. carecircle-catalyst-*)
    if hostname.startswith("carecircle-catalyst") and hostname.endswith(".vercel.app"):
        return True

    return False


def set_csrf_cookie(response: Response, token: str) -> None:
    """
    Set CSRF cookie with strict flags matching production requirements.
    In production, uses __Host- prefix with no Domain attribute.
    """
    response.set_cookie(
        key=settings.CSRF_COOKIE_NAME,
        value=token,
        max_age=settings.CSRF_MAX_AGE_SECONDS,
        httponly=False,  # Client JS / forms need to read/submit double-submit token
        secure=settings.COOKIE_SECURE,
        samesite="lax",
        path="/",
    )


def validate_csrf_request(request: Request, submitted_token: Optional[str] = None) -> None:
    """
    Validate Origin/Referer and double-submit CSRF token on state-changing requests.
    Raises HTTPException(403) on any violation.
    """
    # 1. Validate Origin / Referer
    origin = request.headers.get("origin")
    referer = request.headers.get("referer")
    target_origin = origin or referer

    if not target_origin or not is_allowed_origin(target_origin):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF validation failed: Untrusted or missing request origin.",
        )

    # 2. Extract cookie token
    cookie_token = request.cookies.get(settings.CSRF_COOKIE_NAME)
    if not cookie_token or not verify_csrf_token(cookie_token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF validation failed: Missing or invalid CSRF cookie.",
        )

    # 3. Extract submitted token if not explicitly provided
    if not submitted_token:
        submitted_token = request.headers.get(settings.CSRF_HEADER_NAME)

    if not submitted_token:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF validation failed: Missing CSRF token header.",
        )

    # 4. Double-submit constant-time match
    if not hmac.compare_digest(cookie_token, submitted_token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF validation failed: Token mismatch.",
        )
