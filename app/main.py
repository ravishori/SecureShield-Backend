from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from app.routers import (
    auth, devices, app_scanner, link_scanner,
    alerts, scam_calls, evidence, family, reports, wifi, network, ai_coach
)
from app.routers import recordings, emergency_contacts
from app.routers import community_scam, message_analyzer, video_call
from app.routers import app_monitor, clone_detection, elderly_protection
from app.middleware.error_handler import GlobalErrorHandlerMiddleware, register_exception_handlers
from app.middleware.rate_limiter import RateLimitMiddleware
from app.services.logger_service import get_logger
from app.config import settings

logger = get_logger(__name__)

app = FastAPI(
    title="SecureShield AI API",
    description="Cyber Safety & Threat Prevention Backend",
    version="1.0.0",
)

# ── Middleware (order matters: error handler must be outermost) ──────────────
app.add_middleware(GlobalErrorHandlerMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Rate limiting — 100 requests per IP per minute
app.add_middleware(RateLimitMiddleware)

# ── Custom exception handlers (FastAPI level) ────────────────────────────────
register_exception_handlers(app)

# ── Routers ──────────────────────────────────────────────────────────────────
PREFIX = "/api/v1"

app.include_router(auth.router,         prefix=PREFIX)
app.include_router(devices.router,      prefix=PREFIX)
app.include_router(app_scanner.router,  prefix=PREFIX)
app.include_router(link_scanner.router, prefix=PREFIX)
app.include_router(alerts.router,       prefix=PREFIX)
app.include_router(scam_calls.router,   prefix=PREFIX)
app.include_router(evidence.router,     prefix=PREFIX)
app.include_router(family.router,       prefix=PREFIX)
app.include_router(reports.router,      prefix=PREFIX)
app.include_router(wifi.router,         prefix=PREFIX)
app.include_router(network.router,      prefix=PREFIX)
app.include_router(ai_coach.router,           prefix=PREFIX)
app.include_router(recordings.router,         prefix=PREFIX)
app.include_router(community_scam.router,      prefix=PREFIX)
app.include_router(message_analyzer.router,    prefix=PREFIX)
app.include_router(app_monitor.router,         prefix=PREFIX)
app.include_router(clone_detection.router,     prefix=PREFIX)
app.include_router(elderly_protection.router,  prefix=PREFIX)
app.include_router(video_call.router,         prefix=PREFIX)
app.include_router(emergency_contacts.router, prefix=PREFIX)


# ── Startup / shutdown events ─────────────────────────────────────────────────
@app.on_event("startup")
async def on_startup():
    logger.info("=" * 60)
    logger.info("SecureShield AI API starting up...")
    logger.info("Logging → file: logs/secureshield.log  |  DB: error_logs table")
    logger.info(f"Rate limiting: {settings.API_RATE_LIMIT} req/min per IP")
    logger.info("=" * 60)

    # ── Cleanup old error logs ────────────────────────────────────────────
    await _cleanup_old_error_logs()


async def _cleanup_old_error_logs() -> None:
    """Delete error_log rows older than LOG_RETENTION_DAYS. Runs at startup."""
    from app.database import AsyncSessionLocal

    retention_days = settings.LOG_RETENTION_DAYS
    try:
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                text(
                    f"DELETE FROM error_logs "
                    f"WHERE created_at < NOW() - INTERVAL '{retention_days} days' "
                    f"RETURNING id"
                )
            )
            deleted_count = len(result.fetchall())
            await session.commit()

            if deleted_count > 0:
                logger.info(
                    f"Startup cleanup: deleted {deleted_count} error_log records "
                    f"older than {retention_days} days."
                )
            else:
                logger.info(
                    f"Startup cleanup: no error_log records older than {retention_days} days found."
                )
    except Exception as exc:
        # Table may not exist yet on first run — non-fatal
        logger.warning(f"Error log cleanup skipped (possibly first run): {exc}")


@app.on_event("shutdown")
async def on_shutdown():
    logger.info("SecureShield AI API shutting down.")


# ── Health endpoints ──────────────────────────────────────────────────────────
@app.get("/")
async def root():
    return {"message": "SecureShield AI API running", "version": "1.0.0"}


@app.get("/health")
async def health():
    return {"status": "healthy"}
