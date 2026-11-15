"""
URLhaus (abuse.ch) threat-intel client.

Free, but abuse.ch requires an Auth-Key (HTTP 401 without one): set URLHAUS_AUTH_KEY.
Without it this client reports status "no_api_key" (inconclusive) rather than pretending
to have checked. Consulted alongside Google Safe Browsing (they cover different threats).

API docs: https://urlhaus-api.abuse.ch/
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Dict, List, Optional, Tuple

import httpx

from app.services.url_privacy import cache_key

from app.config import settings

logger = logging.getLogger(__name__)

URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/url/"
URLHAUS_TIMEOUT = 5.0
URLHAUS_MAX_RETRIES = 1
URLHAUS_CACHE_TTL = 5 * 60  # 5-minute cache (matches GSB)
URLHAUS_CACHE_MAX_SIZE = 2048

_cache: Dict[str, Tuple[Dict[str, Any], float]] = {}
_cache_lock = asyncio.Lock()


async def _cache_get(url: str) -> Optional[Dict[str, Any]]:
    async with _cache_lock:
        entry = _cache.get(cache_key(url))
        if entry is None:
            return None
        verdict, expires_at = entry
        if time.time() > expires_at:
            _cache.pop(cache_key(url), None)
            return None
        return verdict


async def _cache_put(url: str, verdict: Dict[str, Any]) -> None:
    async with _cache_lock:
        if len(_cache) >= URLHAUS_CACHE_MAX_SIZE:
            for k in list(_cache.keys())[: URLHAUS_CACHE_MAX_SIZE // 10]:
                _cache.pop(k, None)
        _cache[cache_key(url)] = (verdict, time.time() + URLHAUS_CACHE_TTL)


async def check_url_urlhaus(url: str) -> Dict[str, Any]:
    """
    Check `url` against URLhaus (abuse.ch).

    Returns the canonical envelope:
        {
          "status":   "safe" | "malicious" | "network_error" | "http_error" | "unknown_error",
          "safe":     bool,
          "threats":  list[dict],
          "provider": "urlhaus",
          "reason":   Optional[str],
        }

    URLhaus only reports KNOWN-bad URLs — a "safe" verdict from URLhaus
    means "not in the malware database", not "verified safe".
    """
    auth_key = (settings.URLHAUS_AUTH_KEY or "").strip()
    if not auth_key:
        # abuse.ch rejects unauthenticated calls (HTTP 401). Say so honestly instead of
        # pretending to have checked: the caller treats this as inconclusive.
        return _envelope("no_api_key", reason="URLHAUS_AUTH_KEY is not set")

    cached = await _cache_get(url)
    if cached is not None:
        return {**cached, "cached": True}

    for attempt in range(URLHAUS_MAX_RETRIES + 1):
        try:
            async with httpx.AsyncClient(timeout=URLHAUS_TIMEOUT) as client:
                response = await client.post(
                    URLHAUS_API, data={"url": url}, headers={"Auth-Key": auth_key}
                )

                if response.status_code >= 500:
                    if attempt < URLHAUS_MAX_RETRIES:
                        await asyncio.sleep(0.3 * (2**attempt))
                        continue
                    return _envelope(
                        "http_error",
                        reason="server_error",
                        http_status=response.status_code,
                    )
                if response.status_code in (401, 403):
                    logger.error(
                        "[URLhaus] HTTP %s - Auth-Key rejected", response.status_code
                    )
                    return _envelope(
                        "http_error",
                        reason="auth_failed",
                        http_status=response.status_code,
                    )
                if response.status_code != 200:
                    return _envelope(
                        "http_error",
                        reason="unexpected_status",
                        http_status=response.status_code,
                    )

                data = response.json()
                qs = data.get("query_status", "")

                if qs == "ok":
                    threats = _build_threats(data)
                    verdict = _envelope(
                        "malicious",
                        threats=threats,
                        extra={
                            "threat": data.get("threat"),
                            "tags": data.get("tags") or [],
                        },
                    )
                elif qs == "no_results":
                    # URLhaus has never seen this URL — treat as "not malicious" but
                    # NOT as positive confirmation that it's safe. The router uses
                    # this as a fall-through signal.
                    verdict = _envelope("safe", reason="not_in_database")
                elif qs == "invalid_url":
                    verdict = _envelope("http_error", reason="invalid_url")
                else:
                    verdict = _envelope("unknown_error", reason=f"query_status={qs}")

                await _cache_put(url, verdict)
                return verdict

        except httpx.TimeoutException:
            if attempt < URLHAUS_MAX_RETRIES:
                await asyncio.sleep(0.3 * (2**attempt))
                continue
            return _envelope("network_error", reason="timeout")
        except httpx.RequestError as e:
            if attempt < URLHAUS_MAX_RETRIES:
                await asyncio.sleep(0.3 * (2**attempt))
                continue
            return _envelope("network_error", reason=type(e).__name__)
        except Exception as e:
            logger.error("[URLhaus] Unexpected error: %s", type(e).__name__)
            return _envelope("unknown_error", reason=type(e).__name__)

    return _envelope("unknown_error", reason="exhausted_retries")


def _build_threats(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Map URLhaus payload to the same threat shape used by GSB results."""
    threat = data.get("threat") or "malicious_url"
    label_map = {
        "malware_download": "Malware Download",
        "phishing": "Phishing / Social Engineering",
        "exploit": "Exploit Kit",
    }
    return [
        {
            "threat_type": threat.upper(),
            "threat_label": label_map.get(threat, threat.replace("_", " ").title()),
            "platform_type": "ANY_PLATFORM",
            "threat_entry_type": "URL",
            "url": data.get("url"),
            "tags": data.get("tags") or [],
            "date_added": data.get("date_added"),
        }
    ]


def _envelope(
    status: str,
    *,
    threats: Optional[List[Dict]] = None,
    reason: Optional[str] = None,
    http_status: Optional[int] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    env = {
        "status": status,
        "safe": status == "safe",
        "threats": threats or [],
        "provider": "urlhaus",
        "reason": reason,
        "http_status": http_status,
        "cached": False,
    }
    if extra:
        env.update(extra)
    return env
