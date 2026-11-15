"""BH-1 per-user rate limiting for the two scam-analysis endpoints.

* ``POST /api/v1/message/analyze``: 20 per minute and 200 per hour, per authenticated user.
* ``POST /api/v1/link-scanner/scan``: 10 per minute and 120 per hour, per authenticated user.

Design (see docs/development/BH1_IMPLEMENTATION_PLAN.md):

* **Identity** is the authenticated user id produced by ``get_current_user`` (the signature-verified ``sub`` of an access
  token, confirmed against an active user row). Request bodies, query strings and headers are never read for identity.
* **Both windows are evaluated together and atomically.** A request is admitted only if the minute AND the hour window
  have room; only then is one hit recorded. A rejected request records nothing, so it never extends a lock-out.
* **Retry-After** is the wait until every exceeded window would admit the request again (the larger wait when both are
  exceeded), rounded up, at least one second.
* **Storage is process-local memory.** It is exact for one process only, so the configuration is validated: a production
  boot requires the owner's single-process attestation, ``WEB_CONCURRENCY`` above one is refused, and a request-time
  configuration or limiter failure answers HTTP 503. There is **no** fallback to a weaker local mode and the Redis backend
  is not implemented: selecting it is refused.
* **Rejections are not written to the error log table**; they have their own exception types and handlers, and the log
  lines are bounded, throttled and free of user content, URLs, tokens and complete user ids.
* The existing per-IP middleware and the AI limiter are untouched.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import os
import re
import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from typing import Callable, Deque, Dict, List, Mapping, Optional, Tuple

from fastapi import Depends
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.config import _resolve_env_files, settings
from app.services.logger_service import get_logger

logger = get_logger(__name__)

MINUTE = 60
HOUR = 3600

# Approved limits (messages 20/200, links 10/120).
DEFAULT_LIMITS: Dict[str, Tuple[int, int]] = {
    "message_analyze": (20, 200),
    "link_scan": (10, 120),
}
_LIMIT_VARIABLES: Dict[str, Tuple[str, str]] = {
    "message_analyze": ("MESSAGE_ANALYZE_PER_MINUTE", "MESSAGE_ANALYZE_PER_HOUR"),
    "link_scan": ("LINK_SCAN_PER_MINUTE", "LINK_SCAN_PER_HOUR"),
}
_MAX_LIMIT = 100_000
RECOGNISED_ENVIRONMENTS = frozenset(
    {"development", "dev", "local", "test", "staging", "production"}
)
RAILWAY_MARKERS = (
    "RAILWAY_ENVIRONMENT_NAME",
    "RAILWAY_SERVICE_ID",
    "RAILWAY_PROJECT_ID",
)
_PASSTHROUGH_ENV = ("WEB_CONCURRENCY", "REDIS_URL") + RAILWAY_MARKERS


class RateLimitSettings(BaseSettings):
    """Raw (string) values so malformed input is detected instead of silently coerced. ``None`` = not configured."""

    USER_RATE_LIMIT_ENABLED: Optional[str] = None
    MESSAGE_ANALYZE_PER_MINUTE: Optional[str] = None
    MESSAGE_ANALYZE_PER_HOUR: Optional[str] = None
    LINK_SCAN_PER_MINUTE: Optional[str] = None
    LINK_SCAN_PER_HOUR: Optional[str] = None
    RATE_LIMIT_BACKEND: Optional[str] = None
    RATE_LIMIT_SINGLE_INSTANCE_CONFIRMED: Optional[str] = None

    model_config = SettingsConfigDict(
        env_file=_resolve_env_files(),
        env_file_encoding="utf-8",
        extra="ignore",
    )


rate_limit_settings = RateLimitSettings()
SETTING_NAMES: Tuple[str, ...] = tuple(RateLimitSettings.model_fields)


# ======================================================================================================================
# Configuration validation: ONE function used by application startup, request-time checks and the preflight CLI
# ======================================================================================================================
FATAL = "fatal"
WARN = "warn"


@dataclass(frozen=True)
class Issue:
    severity: str
    variable: str
    rule: str

    def __str__(self) -> str:  # never contains a variable VALUE
        return f"{self.severity.upper()} {self.variable}: {self.rule}"


@dataclass(frozen=True)
class Policy:
    enabled: bool
    backend: str
    windows: Dict[
        str, Tuple[Tuple[str, int, int], ...]
    ]  # endpoint -> (("minute", limit, 60), ("hour", limit, 3600))


@dataclass(frozen=True)
class Validation:
    issues: Tuple[Issue, ...]
    policy: Optional[Policy]
    environment: str

    @property
    def fatal(self) -> List[Issue]:
        return [i for i in self.issues if i.severity == FATAL]

    @property
    def warnings(self) -> List[Issue]:
        return [i for i in self.issues if i.severity == WARN]

    @property
    def ok(self) -> bool:
        return not self.fatal


_INT = re.compile(r"[1-9][0-9]{0,5}")
_BOOL = re.compile(r"(?i)(true|false)")
_BACKEND = re.compile(r"(?i)(memory|redis)")


def _parse_bool(
    env: Mapping[str, str], name: str, default: bool, issues: List[Issue]
) -> bool:
    raw = env.get(name)
    if raw is None:
        return default
    if not _BOOL.fullmatch(raw):
        issues.append(Issue(FATAL, name, "must be exactly 'true' or 'false'"))
        return default
    return raw.lower() == "true"


def resolve_environment(env: Mapping[str, str], issues: List[Issue]) -> str:
    """Environment name with a fail-safe policy. A deployed Railway service must set ENVIRONMENT explicitly."""
    raw = env.get("ENVIRONMENT")
    if raw is None or raw.strip() == "":
        if any(env.get(m) for m in RAILWAY_MARKERS):
            issues.append(
                Issue(
                    FATAL,
                    "ENVIRONMENT",
                    "must be set explicitly on a deployed service (development, staging or production)",
                )
            )
            return "production"  # fail safe: never fall back to the lenient branch
        issues.append(Issue(WARN, "ENVIRONMENT", "not set; treated as development"))
        return "development"
    name = raw.strip().lower()
    if name not in RECOGNISED_ENVIRONMENTS:
        issues.append(
            Issue(FATAL, "ENVIRONMENT", "is not a recognised environment name")
        )
        return "production"
    return name


def validate_rate_limit_config(
    env: Mapping[str, str], environment_override: Optional[str] = None
) -> Validation:
    """Validate the BH-1 configuration. Pure: no I/O. Messages name the variable and the rule, never a value."""
    issues: List[Issue] = []
    if environment_override is not None:
        environment = environment_override.strip().lower()
        if environment not in RECOGNISED_ENVIRONMENTS:
            issues.append(
                Issue(FATAL, "--environment", "is not a recognised environment name")
            )
            environment = "production"
    else:
        environment = resolve_environment(env, issues)
    production = environment == "production"

    enabled = _parse_bool(env, "USER_RATE_LIMIT_ENABLED", True, issues)

    limits: Dict[str, Tuple[int, int]] = {}
    for endpoint, (per_min_name, per_hour_name) in _LIMIT_VARIABLES.items():
        default_min, default_hour = DEFAULT_LIMITS[endpoint]
        values: List[int] = []
        for name, default in (
            (per_min_name, default_min),
            (per_hour_name, default_hour),
        ):
            raw = env.get(name)
            if raw is None:
                values.append(default)
                continue
            if not _INT.fullmatch(raw) or int(raw) > _MAX_LIMIT:
                issues.append(
                    Issue(
                        FATAL,
                        name,
                        f"must be a whole number from 1 to {_MAX_LIMIT} with no sign, spaces or exponent",
                    )
                )
                values.append(default)
            else:
                values.append(int(raw))
        if values[1] < values[0]:
            issues.append(
                Issue(FATAL, per_hour_name, f"must not be lower than {per_min_name}")
            )
        limits[endpoint] = (values[0], values[1])

    raw_backend = env.get("RATE_LIMIT_BACKEND")
    backend = "memory"
    if raw_backend is not None:
        if not _BACKEND.fullmatch(raw_backend):
            issues.append(
                Issue(FATAL, "RATE_LIMIT_BACKEND", "must be 'memory' or 'redis'")
            )
        else:
            backend = raw_backend.lower()
    if backend == "redis":
        issues.append(
            Issue(
                FATAL,
                "RATE_LIMIT_BACKEND",
                "'redis' is not implemented in this release; use 'memory' on a verified single-process deployment",
            )
        )

    attested = _parse_bool(env, "RATE_LIMIT_SINGLE_INSTANCE_CONFIRMED", False, issues)

    if enabled and backend == "memory":
        wc = env.get("WEB_CONCURRENCY")
        if wc is not None and wc.strip() != "":
            if not re.fullmatch(r"[0-9]{1,4}", wc.strip()):
                issues.append(Issue(FATAL, "WEB_CONCURRENCY", "must be a whole number"))
            elif int(wc.strip()) > 1:
                issues.append(
                    Issue(
                        FATAL,
                        "WEB_CONCURRENCY",
                        "more than one worker would multiply the per-process limits; use one worker or a shared limiter",
                    )
                )
        if not attested:
            issues.append(
                Issue(
                    FATAL if production else WARN,
                    "RATE_LIMIT_SINGLE_INSTANCE_CONFIRMED",
                    "production requires 'true' after verifying one process and one replica"
                    if production
                    else "not 'true'; per-user limits are exact only for one process",
                )
            )
        if env.get("REDIS_URL"):
            issues.append(
                Issue(WARN, "REDIS_URL", "is ignored by this release (memory backend)")
            )

    fatal = any(i.severity == FATAL for i in issues)
    policy = None
    if not fatal:
        policy = Policy(
            enabled=enabled,
            backend=backend,
            windows={
                ep: (("minute", lim[0], MINUTE), ("hour", lim[1], HOUR))
                for ep, lim in limits.items()
            },
        )
    return Validation(tuple(issues), policy, environment)


def runtime_mapping() -> Dict[str, str]:
    """The configuration as the running application sees it (settings object, then the process environment)."""
    m: Dict[str, str] = {}
    for name in SETTING_NAMES:
        value = getattr(rate_limit_settings, name, None)
        if value is not None:
            m[name] = value
    for name in _PASSTHROUGH_ENV:
        if name in os.environ:
            m[name] = os.environ[name]
    if "ENVIRONMENT" in os.environ:
        m["ENVIRONMENT"] = os.environ["ENVIRONMENT"]
    elif not any(os.environ.get(x) for x in RAILWAY_MARKERS):
        m["ENVIRONMENT"] = (
            getattr(settings, "ENVIRONMENT", "") or ""
        )  # a value from the .env file of a local run
    return m


_cache: Dict[str, object] = {"key": None, "value": None}
_cache_lock = threading.Lock()


def current_validation() -> Validation:
    """Validation of the live configuration, recomputed only when an input changes (cheap, exact)."""
    mapping = runtime_mapping()
    key = tuple(sorted(mapping.items()))
    with _cache_lock:
        if _cache["key"] == key and _cache["value"] is not None:
            return _cache["value"]  # type: ignore[return-value]
        value = validate_rate_limit_config(mapping)
        _cache["key"], _cache["value"] = key, value
        return value


# ======================================================================================================================
# The limiter
# ======================================================================================================================
@dataclass(frozen=True)
class Decision:
    allowed: bool
    window: Optional[str] = None  # "minute", "hour" or "both" when rejected
    retry_after_seconds: int = 0


class UserRateLimiter:
    """Sliding-window log limiter for several windows at once. All checks and the recording happen under one lock with no
    ``await`` between them, so concurrent coroutines and threads can never over-admit."""

    def __init__(
        self, clock: Callable[[], float] = time.monotonic, max_keys: int = 100_000
    ) -> None:
        self._clock = clock
        self._max_keys = max_keys
        self._hits: "OrderedDict[str, Deque[float]]" = OrderedDict()
        self._lock = threading.Lock()
        self._calls = 0

    def check_and_record(
        self, key: str, windows: Tuple[Tuple[str, int, int], ...]
    ) -> Decision:
        longest = max(w[2] for w in windows)
        with self._lock:
            now = self._clock()
            self._calls += 1
            if self._calls % 512 == 0 or len(self._hits) >= self._max_keys:
                self._sweep(now, longest)
            stamps = self._hits.get(key)
            if stamps:
                while stamps and stamps[0] <= now - longest:
                    stamps.popleft()
            exceeded: List[Tuple[str, float]] = []
            for name, limit, seconds in windows:
                recent = [t for t in stamps if t > now - seconds] if stamps else []
                if len(recent) >= limit:
                    # wait until the (count - limit + 1)th oldest hit leaves the window
                    exceeded.append((name, recent[len(recent) - limit] + seconds - now))
            if exceeded:
                wait = max(w for _, w in exceeded)
                label = exceeded[0][0] if len(exceeded) == 1 else "both"
                return Decision(False, label, max(1, math.ceil(wait)))
            if stamps is None:
                stamps = self._hits.setdefault(key, deque())
            else:
                self._hits.move_to_end(key)
            stamps.append(now)
            return Decision(True)

    def _sweep(self, now: float, longest: int) -> None:
        for k in [k for k, v in self._hits.items() if not v or v[-1] <= now - longest]:
            del self._hits[k]
        while (
            len(self._hits) >= self._max_keys
        ):  # still full: drop the least recently used keys
            self._hits.popitem(last=False)

    def key_count(self) -> int:
        with self._lock:
            return len(self._hits)

    def clear(self) -> None:
        with self._lock:
            self._hits.clear()


default_limiter = UserRateLimiter()


# ======================================================================================================================
# Exceptions (handled without touching the database) and bounded, privacy-safe logging
# ======================================================================================================================
class RateLimitExceeded(Exception):
    """The user is over a limit. Rendered as HTTP 429 by ``app.middleware.error_handler``; never written to error_logs."""

    def __init__(self, window: str, retry_after_seconds: int) -> None:
        super().__init__("rate limit exceeded")
        self.window = window
        self.retry_after_seconds = retry_after_seconds


class RateLimitUnavailable(Exception):
    """The limiter cannot be trusted right now (invalid configuration or an internal failure). Rendered as HTTP 503."""

    retry_after_seconds = 5


def user_ref(user_id: object) -> str:
    """Keyed 8-hex-character reference for correlating log lines. Not the id, not a prefix of it, not reversible."""
    secret = hashlib.sha256(
        (str(getattr(settings, "SECRET_KEY", "")) + "|bh1-log-ref").encode()
    ).digest()
    return hmac.new(secret, str(user_id).encode(), hashlib.sha256).hexdigest()[:8]


@dataclass
class _LogState:
    clock: Callable[[], float] = time.monotonic
    table_cap: int = 1000
    per_minute_cap: int = 30
    lock: threading.Lock = field(default_factory=threading.Lock)
    seen: "OrderedDict[Tuple[str, str, str], float]" = field(
        default_factory=OrderedDict
    )
    minute_start: float = 0.0
    lines_this_minute: int = 0
    suppressed: int = 0
    counts: Dict[str, int] = field(
        default_factory=lambda: {"rejected": 0, "unavailable": 0}
    )


_log = _LogState()


def log_event(kind: str, endpoint: str, window: str, who: str = "") -> bool:
    """Emit at most one WARNING per (endpoint, window, user reference) per window and 30 lines per minute overall; the rest
    is summarised by counts. Returns True when a line was written. Only fixed words and the keyed reference are logged."""
    to_write: List[str] = []
    with _log.lock:
        now = _log.clock()
        if now - _log.minute_start >= MINUTE:
            if _log.suppressed or _log.counts["rejected"] or _log.counts["unavailable"]:
                to_write.append(
                    "rate-limit summary: rejected=%d unavailable=%d suppressed_lines=%d"
                    % (
                        _log.counts["rejected"],
                        _log.counts["unavailable"],
                        _log.suppressed,
                    )
                )
            _log.minute_start, _log.lines_this_minute, _log.suppressed = now, 0, 0
            _log.counts = {"rejected": 0, "unavailable": 0}
        _log.counts[kind] = _log.counts.get(kind, 0) + 1
        written = False
        k = (endpoint, window, who)
        window_seconds = HOUR if window == "hour" else MINUTE
        last = _log.seen.get(k)
        if (
            last is None or now - last >= window_seconds
        ) and _log.lines_this_minute < _log.per_minute_cap:
            _log.seen[k] = now
            _log.seen.move_to_end(k)
            while len(_log.seen) > _log.table_cap:
                _log.seen.popitem(last=False)
            _log.lines_this_minute += 1
            to_write.append(
                f"rate limit {kind}: endpoint={endpoint} window={window} user_ref={who or '-'}"
            )
            written = True
        else:
            _log.suppressed += 1
    for line in to_write:  # logging happens outside every lock
        logger.warning(line)
    return written


# ======================================================================================================================
# Enforcement
# ======================================================================================================================
def enforce_user_limit(
    endpoint: str, user_id: object, limiter: Optional[UserRateLimiter] = None
) -> None:
    """Raise ``RateLimitExceeded`` (429) or ``RateLimitUnavailable`` (503); return when the request may proceed."""
    validation = current_validation()
    if validation.policy is None:
        log_event("unavailable", endpoint, "config")
        raise RateLimitUnavailable()
    policy = validation.policy
    if not policy.enabled:
        return
    try:
        decision = (limiter or default_limiter).check_and_record(
            f"rl:user:{endpoint}:{user_id}", policy.windows[endpoint]
        )
    except Exception as exc:  # noqa: BLE001 - any limiter failure must fail closed, never open
        log_event("unavailable", endpoint, "limiter")
        logger.error("rate limiter failure class=%s", type(exc).__name__)
        raise RateLimitUnavailable() from None
    if not decision.allowed:
        log_event("rejected", endpoint, decision.window or "minute", user_ref(user_id))
        raise RateLimitExceeded(
            decision.window or "minute", decision.retry_after_seconds
        )


def user_limit(endpoint: str):
    """FastAPI dependency factory. It depends on ``get_current_user``, so an unauthenticated or invalid request is rejected
    by authentication first and never creates a limiter key; FastAPI caches the user lookup for the handler."""
    from app.routers.auth import (
        get_current_user,
    )  # local import: avoids a router import cycle

    if endpoint not in DEFAULT_LIMITS:
        raise ValueError(f"unknown rate-limited endpoint: {endpoint}")

    async def _dependency(current_user=Depends(get_current_user)) -> None:
        enforce_user_limit(endpoint, current_user.id)

    return _dependency


def startup_report(validation: Validation) -> str:
    p = validation.policy
    if p is None:
        return "per-user rate limiting: configuration INVALID"
    if not p.enabled:
        return "per-user rate limiting: DISABLED (USER_RATE_LIMIT_ENABLED=false); per-IP limits unaffected"
    parts = ", ".join(
        f"{ep}={w[0][1]}/min+{w[1][1]}/hour" for ep, w in p.windows.items()
    )
    return (
        f"per-user rate limiting: ENABLED backend={p.backend} environment={validation.environment} {parts}; "
        "per-user and per-IP limits are per-process"
    )
