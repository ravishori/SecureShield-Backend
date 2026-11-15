"""Database URL normalisation helpers (pure: no settings, no I/O).

Kept separate from ``app.config`` so that ``app.db_identity`` and the operator scripts can parse and check database URLs
without constructing ``Settings`` (which needs a full environment). ``app.config`` re-exports these names.
"""

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

# libpq-only URL parameters that asyncpg rejects with a TypeError. Neon's console connection string ends with
# ``?sslmode=require&channel_binding=require``; TLS is requested with ``ssl=`` and channel binding is not supported by asyncpg.
_LIBPQ_ONLY_PARAMS = frozenset({"channel_binding"})

# asyncpg connection options that are INTEGERS. A URL query value is always a string and SQLAlchemy's asyncpg dialect only
# converts ``prepared_statement_cache_size`` (and ``port``), so e.g. ``?statement_cache_size=0`` reached asyncpg as "0" and
# failed with ``TypeError: '<' not supported between instances of 'str' and 'int'``.
ASYNCPG_INT_OPTIONS = frozenset(
    {
        "statement_cache_size",
        "max_cached_statement_lifetime",
        "max_cacheable_statement_size",
        "command_timeout",
        "timeout",
    }
)


def normalize_async_db_url(url: str) -> str:
    """Return a SQLAlchemy ``postgresql+asyncpg://`` URL.

    Railway (and most hosts) hand out ``postgresql://`` or ``postgres://``
    URLs. ``postgres://`` is not a valid SQLAlchemy dialect and bare
    ``postgresql://`` selects psycopg2, which is not installed. An already
    correct ``postgresql+asyncpg://`` URL is returned unchanged.

    asyncpg rejects the libpq ``sslmode`` parameter, so ``?sslmode=X`` is
    rewritten to ``?ssl=X`` (an explicit ``ssl`` wins). It also rejects the
    libpq-only ``channel_binding`` parameter that Neon's connection string
    carries, so that parameter is dropped. No other part of the URL is
    touched, and the URL is never logged here.
    """
    url = url.strip()
    for prefix in ("postgres://", "postgresql://"):
        if url.startswith(prefix):
            url = "postgresql+asyncpg://" + url[len(prefix) :]
            break
    if not url.startswith("postgresql+asyncpg://"):
        return url
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    names = {k for k, _ in pairs}
    if not (names & ({"sslmode"} | _LIBPQ_ONLY_PARAMS)):
        return url
    has_ssl = "ssl" in names
    out = []
    for k, v in pairs:
        if k in _LIBPQ_ONLY_PARAMS:
            continue
        if k == "sslmode":
            if has_ssl:
                continue
            k = "ssl"
        out.append((k, v))
    return urlunsplit(parts._replace(query=urlencode(out)))


def split_asyncpg_options(url: str) -> tuple[str, dict[str, int]]:
    """Split asyncpg's integer options out of the URL query.

    Returns ``(url_without_those_options, {option: int})``; the dict is meant for ``create_async_engine(connect_args=...)``.
    A value that is not an integer raises ``ValueError`` naming only the option (never the URL, which holds the password).
    URLs that are not ``postgresql+asyncpg://`` or carry none of these options are returned unchanged.
    """
    if not url.startswith("postgresql+asyncpg://"):
        return url, {}
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    if not any(k in ASYNCPG_INT_OPTIONS for k, _ in pairs):
        return url, {}
    kept: list[tuple[str, str]] = []
    options: dict[str, int] = {}
    for k, v in pairs:
        if k in ASYNCPG_INT_OPTIONS:
            try:
                options[k] = int(v)
            except ValueError:
                raise ValueError(
                    f"database URL option '{k}' must be an integer"
                ) from None
        else:
            kept.append((k, v))
    return urlunsplit(parts._replace(query=urlencode(kept))), options
