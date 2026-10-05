"""
Google Safe Browsing v4 client — production-grade.

Features:
  • Typed result envelope (status + threats + provider + reason)
  • Structured error classification (no_api_key, rate_limited, network, http_4xx, http_5xx)
  • Short-TTL in-memory LRU cache (5-minute) keyed by URL
  • Retry with exponential back-off on transient failures
  • Aggressive timeout (5s) so a slow GSB never delays user-facing requests
  • Startup validation helper: verify_api_key()

Get a free API key here:
  https://console.cloud.google.com/  (enable "Safe Browsing API")
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Any, Dict, List, Optional, Tuple

import httpx

from app.config import settings

logger = logging.getLogger(__name__)

# Prefer pydantic-loaded value (reads .env reliably) — fall back to raw env
# var for cases where the service is imported without app.config being ready.
GSB_API_KEY = (
    getattr(settings, "GOOGLE_SAFE_BROWSING_API_KEY", "")
    or os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
).strip()
GSB_API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
GSB_CLIENT_ID = "secureshield-ai"
GSB_CLIENT_VERSION = "1.0.0"
GSB_TIMEOUT = 5.0  # seconds — never block the user request longer than this
GSB_MAX_RETRIES = 2  # 1 immediate + 2 retries on transient failures
GSB_CACHE_TTL = 5 * 60  # seconds — short TTL keeps results fresh enough for AV use
GSB_CACHE_MAX_SIZE = 2048

THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
]

THREAT_LABELS: Dict[str, str] = {
    "MALWARE": "Malware",
    "SOCIAL_ENGINEERING": "Phishing / Social Engineering",
    "UNWANTED_SOFTWARE": "Unwanted Software",
    "POTENTIALLY_HARMFUL_APPLICATION": "Potentially Harmful App",
}


# ──────────────────────────────────────────────────────────────────────────────
# In-memory LRU cache (URL → (verdict_dict, expires_at_ts))
# ──────────────────────────────────────────────────────────────────────────────
_cache: Dict[str, Tuple[Dict[str, Any], float]] = {}
_cache_lock = asyncio.Lock()


async def _cache_get(url: str) -> Optional[Dict[str, Any]]:
    async with _cache_lock:
        entry = _cache.get(url)
        if entry is None:
            return None
        verdict, expires_at = entry
        if time.time() > expires_at:
            _cache.pop(url, None)
            return None
        return verdict


async def _cache_put(url: str, verdict: Dict[str, Any]) -> None:
    async with _cache_lock:
        if len(_cache) >= GSB_CACHE_MAX_SIZE:
            # Drop the oldest 10% — cheap LRU approximation
            for k in list(_cache.keys())[: GSB_CACHE_MAX_SIZE // 10]:
                _cache.pop(k, None)
        _cache[url] = (verdict, time.time() + GSB_CACHE_TTL)


def is_configured() -> bool:
    """Returns True when an API key is present in the environment."""
    return bool(GSB_API_KEY)


async def verify_api_key() -> bool:
    """
    Startup-time validation. Hits GSB with a benign known-safe URL and
    confirms the API responds 200. Use from main.py's startup event so
    you fail fast on a typo or revoked key.
    """
    if not GSB_API_KEY:
        logger.warning("[GSB] API key is not configured (GOOGLE_SAFE_BROWSING_API_KEY)")
        return False
    try:
        result = await check_url_gsb("https://www.google.com")
        if result and result.get("status") in {"safe", "malicious"}:
            logger.info("[GSB] API key verified — provider is live")
            return True
        logger.error(
            "[GSB] API key verification failed: status=%s reason=%s",
            result.get("status") if result else None,
            result.get("reason") if result else None,
        )
        return False
    except Exception as e:
        logger.error("[GSB] API key verification crashed: %s", type(e).__name__)
        return False


async def check_url_gsb(url: str) -> Dict[str, Any]:
    """
    Check `url` against Google Safe Browsing v4.

    Always returns a dict with this envelope:
        {
          "status": "safe" | "malicious" | "no_api_key" | "rate_limited"
                  | "network_error" | "http_error" | "unknown_error",
          "safe":    bool,            # True for "safe", False otherwise
          "threats": list[dict],      # threat details (only populated if status="malicious")
          "provider": "google_safe_browsing",
          "reason":  Optional[str],   # human-readable diagnostic for non-safe non-malicious statuses
        }

    Callers should treat status in {"no_api_key", "rate_limited", "network_error",
    "http_error", "unknown_error"} as "indeterminate" and fall back to the next tier.
    """
    if not GSB_API_KEY:
        return _envelope("no_api_key", reason="GOOGLE_SAFE_BROWSING_API_KEY is not set")

    cached = await _cache_get(url)
    if cached is not None:
        # Re-tag as cache hit so the router can attribute it cleanly.
        return {**cached, "cached": True}

    payload = {
        "client": {
            "clientId": GSB_CLIENT_ID,
            "clientVersion": GSB_CLIENT_VERSION,
        },
        "threatInfo": {
            "threatTypes": THREAT_TYPES,
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    last_error: Optional[str] = None
    for attempt in range(GSB_MAX_RETRIES + 1):
        try:
            async with httpx.AsyncClient(timeout=GSB_TIMEOUT) as client:
                # The key travels in a header, NOT the query string: URLs end up in
                # exception messages, proxies and access logs.
                response = await client.post(
                    GSB_API_URL,
                    json=payload,
                    headers={"X-Goog-Api-Key": GSB_API_KEY},
                )

                # Hard non-recoverable failures
                if response.status_code == 400:
                    logger.warning(
                        "[GSB] HTTP 400 — bad request body: %s", response.text[:200]
                    )
                    return _envelope(
                        "http_error",
                        reason="bad_request",
                        http_status=response.status_code,
                    )
                if response.status_code in (401, 403):
                    logger.error(
                        "[GSB] HTTP %s — API key invalid or quota exceeded: %s",
                        response.status_code,
                        response.text[:200],
                    )
                    return _envelope(
                        "http_error",
                        reason="auth_failed",
                        http_status=response.status_code,
                    )
                if response.status_code == 429:
                    # Rate-limited — back off if we have attempts left.
                    last_error = "rate_limited"
                    logger.warning(
                        "[GSB] HTTP 429 — rate limited (attempt %d)", attempt + 1
                    )
                    if attempt < GSB_MAX_RETRIES:
                        await asyncio.sleep(0.5 * (2**attempt))
                        continue
                    return _envelope("rate_limited", reason="quota_exceeded")
                if 500 <= response.status_code < 600:
                    # Transient server error — retry.
                    last_error = f"http_{response.status_code}"
                    logger.warning(
                        "[GSB] HTTP %s (attempt %d)", response.status_code, attempt + 1
                    )
                    if attempt < GSB_MAX_RETRIES:
                        await asyncio.sleep(0.4 * (2**attempt))
                        continue
                    return _envelope(
                        "http_error",
                        reason="server_error",
                        http_status=response.status_code,
                    )

                response.raise_for_status()
                data = response.json()

                matches: List[Dict] = data.get("matches", [])
                if matches:
                    threats = [
                        {
                            "threat_type": m.get("threatType"),
                            "threat_label": THREAT_LABELS.get(
                                m.get("threatType", ""), m.get("threatType", "")
                            ),
                            "platform_type": m.get("platformType"),
                            "threat_entry_type": m.get("threatEntryType"),
                            "url": m.get("threat", {}).get("url"),
                        }
                        for m in matches
                    ]
                    verdict = _envelope("malicious", threats=threats)
                else:
                    verdict = _envelope("safe")

                await _cache_put(url, verdict)
                return verdict

        except httpx.TimeoutException:
            last_error = "timeout"
            logger.warning("[GSB] Timeout (attempt %d)", attempt + 1)
            if attempt < GSB_MAX_RETRIES:
                await asyncio.sleep(0.4 * (2**attempt))
                continue
            return _envelope("network_error", reason="timeout")
        except httpx.RequestError as e:
            last_error = f"request_error:{type(e).__name__}"
            logger.warning(
                "[GSB] Request error: %s (attempt %d)", type(e).__name__, attempt + 1
            )
            if attempt < GSB_MAX_RETRIES:
                await asyncio.sleep(0.4 * (2**attempt))
                continue
            # type name only: exception text can embed the request URL
            return _envelope("network_error", reason=type(e).__name__)
        except Exception as e:
            logger.error("[GSB] Unexpected error: %s", type(e).__name__)
            return _envelope("unknown_error", reason=type(e).__name__)

    return _envelope("unknown_error", reason=last_error or "exhausted_retries")


def _envelope(
    status: str,
    *,
    threats: Optional[List[Dict]] = None,
    reason: Optional[str] = None,
    http_status: Optional[int] = None,
) -> Dict[str, Any]:
    """Construct the canonical response shape."""
    return {
        "status": status,
        "safe": status == "safe",
        "threats": threats or [],
        "provider": "google_safe_browsing",
        "reason": reason,
        "http_status": http_status,
        "cached": False,
    }
