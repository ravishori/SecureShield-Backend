import asyncio
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.cors_policy import ALLOWED_HEADERS, ALLOWED_METHODS, resolve_cors
from sqlalchemy import text

from app.routers import (
    auth,
    devices,
    app_scanner,
    link_scanner,
    alerts,
    scam_calls,
    evidence,
    family,
    reports,
    wifi,
    network,
    ai_coach,
)
from app.routers import recordings, emergency_contacts
from app.routers import community_scam, message_analyzer, video_call
from app.routers import app_monitor, clone_detection, elderly_protection
from app.routers import admin_errors
from app.routers import admin_auth
from app.routers import admin_users
from app.routers import admin_console
from app.routers import identity as identity_router
from app.routers import privacy as privacy_router
from app.routers import cyber_warrior
from app.middleware.access_log import install_access_log_redaction
from app.middleware.error_handler import (
    GlobalErrorHandlerMiddleware,
    register_exception_handlers,
)
from app.middleware.rate_limiter import RateLimitMiddleware
from app.services.logger_service import get_logger
from app.config import settings
from app.startup_checks import run_startup_checks

logger = get_logger(__name__)

# uvicorn's access log prints the full request target (query values, share tokens in paths);
# mask those before any handler formats the line.
install_access_log_redaction()


def api_doc_urls(current) -> dict:
    """Interactive API docs (/docs, /redoc, /openapi.json) are development tools: they list every route, so they are off in production."""
    if current.is_production():
        return {"docs_url": None, "redoc_url": None, "openapi_url": None}
    return {}


app = FastAPI(
    title="SecureShield AI API",
    description="Cyber Safety & Threat Prevention Backend",
    version="1.0.0",
    **api_doc_urls(settings),
)

# ── Middleware (order matters: error handler must be outermost) ──────────────
app.add_middleware(GlobalErrorHandlerMiddleware)

# Explicit allowlist, validated at import (a malformed CORS_ALLOWED_ORIGINS stops the app). See app/cors_policy.py.
_cors = resolve_cors(settings.ENVIRONMENT, settings.CORS_ALLOWED_ORIGINS)
app.add_middleware(
    CORSMiddleware,
    allow_origins=list(_cors.origins),
    allow_credentials=_cors.allow_credentials,
    allow_methods=ALLOWED_METHODS,
    allow_headers=ALLOWED_HEADERS,
)

# Rate limiting — 100 requests per IP per minute
app.add_middleware(RateLimitMiddleware)

# ── Custom exception handlers (FastAPI level) ────────────────────────────────
register_exception_handlers(app)

# ── Routers ──────────────────────────────────────────────────────────────────
PREFIX = "/api/v1"

app.include_router(auth.router, prefix=PREFIX)
app.include_router(identity_router.router, prefix=PREFIX)
app.include_router(privacy_router.router, prefix=PREFIX)
app.include_router(devices.router, prefix=PREFIX)
app.include_router(app_scanner.router, prefix=PREFIX)
app.include_router(link_scanner.router, prefix=PREFIX)
app.include_router(alerts.router, prefix=PREFIX)
app.include_router(scam_calls.router, prefix=PREFIX)
app.include_router(evidence.router, prefix=PREFIX)
app.include_router(family.router, prefix=PREFIX)
app.include_router(reports.router, prefix=PREFIX)
app.include_router(wifi.router, prefix=PREFIX)
app.include_router(network.router, prefix=PREFIX)
app.include_router(ai_coach.router, prefix=PREFIX)
app.include_router(recordings.router, prefix=PREFIX)
app.include_router(community_scam.router, prefix=PREFIX)
app.include_router(message_analyzer.router, prefix=PREFIX)
app.include_router(app_monitor.router, prefix=PREFIX)
app.include_router(clone_detection.router, prefix=PREFIX)
app.include_router(elderly_protection.router, prefix=PREFIX)
app.include_router(video_call.router, prefix=PREFIX)
app.include_router(emergency_contacts.router, prefix=PREFIX)
app.include_router(admin_errors.router, prefix=PREFIX)
app.include_router(admin_auth.router, prefix=PREFIX)
app.include_router(admin_users.router, prefix=PREFIX)
app.include_router(admin_console.router, prefix=PREFIX)
app.include_router(cyber_warrior.router, prefix=PREFIX)


# ── Startup / shutdown events ─────────────────────────────────────────────────
@app.on_event("startup")
async def on_startup():
    logger.info("=" * 60)
    logger.info("SecureShield AI API starting up...")
    logger.info(f"Environment: {settings.ENVIRONMENT}")
    logger.info("Logging → file: logs/secureshield.log  |  DB: error_logs table")
    logger.info(f"Rate limiting: {settings.API_RATE_LIMIT} req/min per IP")
    logger.info("=" * 60)

    # ── Fail-fast production readiness checks ────────────────────────────
    # Raises before any router is reachable if the config is unsafe for
    # the declared environment (missing TLS, dev-default secrets, etc.).
    # In dev these are no-ops. See app/startup_checks.py.
    run_startup_checks(settings)
    await _verify_database_identity()
    _warn_if_legacy_admin_token()

    # ── Retention ─────────────────────────────────────────────────────────
    # Startup NEVER deletes data. Retention runs only through the explicit maintenance CLIs
    # (python -m app.cli.purge_error_logs / purge_link_scans) and the gated guardian/link-scan jobs, and only when
    # RETENTION_CLEANUP_ENABLED=true (see app/db_identity.py).
    from app.db_identity import retention_gate

    decision = retention_gate(settings)
    logger.info(
        "Retention deletion: %s (%s)",
        "ENABLED" if decision.allowed else "OFF",
        decision.reason,
    )

    # ── Twilio configuration (local check only; no network call) ──────────
    _log_twilio_configuration()
    _start_guardian_worker()

    # ── Email alerting status ─────────────────────────────────────────────
    notify_email = getattr(settings, "ERROR_NOTIFY_EMAIL", "")
    if notify_email:
        logger.info(f"Error alerts will be emailed to: {notify_email}")
    else:
        logger.warning("ERROR_NOTIFY_EMAIL not set — no email alerts will be sent")


def _warn_if_legacy_admin_token() -> None:
    """The shared X-Admin-Token has no identity and no MFA: say so loudly in production until it is switched off."""
    from app.admin_settings import admin_settings

    if admin_settings.ADMIN_LEGACY_TOKEN_ENABLED:
        level = logger.warning if settings.ENVIRONMENT == "production" else logger.info
        level(
            "Legacy shared admin token is ENABLED (no identity, no MFA). Create named admin accounts "
            "(python -m app.cli.admin_accounts) and set ADMIN_LEGACY_TOKEN_ENABLED=false."
        )


async def _verify_database_identity() -> None:
    """Read-only ``SELECT current_database()`` check before the database is used for anything else. Fails closed."""
    from app.db_identity import DatabaseIdentityError, verify_connected_database
    from app.startup_checks import StartupCheckError

    try:
        await verify_connected_database(settings)
    except DatabaseIdentityError as exc:
        raise StartupCheckError(f"Database identity refused: {exc}") from None
    except Exception as exc:  # noqa: BLE001 - the connection error text can echo connection details; log the class only
        raise StartupCheckError(
            f"Database identity could not be verified (connection failed: {type(exc).__name__})"
        ) from None
    logger.info("Connected database name matches the configured database")


def _log_twilio_configuration() -> None:
    """Report whether Twilio credentials look configured. Local check only: no outbound call is made at startup."""
    from app.config import load_settings

    try:
        current = load_settings()
    except Exception:  # noqa: BLE001 - absent Twilio settings must never crash unrelated startup (no values are logged)
        logger.warning("Twilio is not configured - SMS login OTP will not work")
        return
    sid = (current.TWILIO_ACCOUNT_SID or "").strip()
    token = (current.TWILIO_AUTH_TOKEN or "").strip()
    if not sid or not token or not sid.startswith("AC"):
        logger.warning("Twilio is not configured - SMS login OTP will not work")
    else:
        logger.info("Twilio credentials are present (not verified at startup)")


def _start_guardian_worker() -> None:
    """Start the durable guardian-alert worker. Independent of Twilio: it depends only on GUARDIAN_WORKER_ENABLED and
    GUARDIAN_OUTBOX_POLL_SECONDS (0 or less disables it). Its retention purge is gated by RETENTION_CLEANUP_ENABLED."""
    from app.services import guardian_outbox

    if not settings.guardian_worker_enabled():
        logger.info(
            "Guardian-alert worker is OFF (enabled by default in production only; set GUARDIAN_WORKER_ENABLED=true to run it)"
        )
        return
    poll = guardian_outbox.poll_seconds_from_env()
    if poll <= 0:
        logger.info("Guardian-alert worker disabled (GUARDIAN_OUTBOX_POLL_SECONDS<=0)")
        return
    app.state.guardian_worker = asyncio.create_task(guardian_outbox.worker_loop(poll))
    logger.info("Guardian-alert worker started")


@app.on_event("shutdown")
async def on_shutdown():
    logger.info("SecureShield AI API shutting down.")
    worker = getattr(app.state, "guardian_worker", None)
    if worker is not None:
        worker.cancel()


# ── Health endpoints ──────────────────────────────────────────────────────────
@app.get("/")
async def root():
    return {"message": "SecureShield AI API running", "version": "1.0.0"}


@app.get("/health")
async def health():
    return {"status": "healthy"}


@app.get("/version")
async def version():
    """Which build is running (deployment verification). Exposes only the commit id and the schema revision
    the code expects - no hostnames, versions of dependencies or configuration."""
    import os

    from alembic.script import ScriptDirectory
    from alembic.config import Config

    sha = (
        os.environ.get("RAILWAY_GIT_COMMIT_SHA")
        or os.environ.get("GIT_COMMIT_SHA")
        or os.environ.get("GITHUB_SHA")
        or "unknown"
    )
    try:
        cfg = Config(
            os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "alembic.ini",
            )
        )
        cfg.set_main_option(
            "script_location",
            os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "alembic"
            ),
        )
        head = ScriptDirectory.from_config(cfg).get_current_head()
    except Exception:
        head = "unknown"
    return {"git_sha": sha[:40], "alembic_head": head}


@app.get("/ready")
async def ready():
    """Readiness: verifies database connectivity without writes or side effects."""
    from fastapi.responses import JSONResponse
    from sqlalchemy.ext.asyncio import AsyncSession

    from app.database import AsyncSessionLocal

    try:
        async with AsyncSessionLocal() as session:
            assert isinstance(session, AsyncSession)
            row = (
                await session.execute(text("SELECT current_database(), current_user"))
            ).one()
            return {
                "status": "ready",
                "database": row[0],
                "user": row[1],
            }
    except Exception:
        return JSONResponse(
            status_code=503,
            content={"status": "not_ready", "database": "unavailable"},
        )
