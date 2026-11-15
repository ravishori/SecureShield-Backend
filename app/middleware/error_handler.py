"""
Global Exception Handler Middleware
====================================
Catches ALL unhandled exceptions before they bubble up to the client.
• Logs them via logger_service  (file + DB + email)
• Returns a clean, friendly JSON response — the user never sees a raw traceback.

Also registers FastAPI exception handlers for common HTTP errors
so every error path goes through the same logging pipeline.
"""

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.services.client_ip import client_ip_for
from app.services.logger_service import get_logger, log_error
from app.services.user_rate_limits import RateLimitExceeded, RateLimitUnavailable

logger = get_logger(__name__)

# Request headers that are safe to persist in error_logs / alert e-mails.
# EXPLICIT ALLOWLIST on purpose: anything not listed (Authorization, Cookie,
# X-Admin-Token, Proxy-Authorization, Referer, custom/vendor headers, ...) is
# never stored, so a new sensitive header can't leak just because nobody
# remembered to add it to a denylist.
_SAFE_HEADERS = (
    "user-agent",
    "content-type",
    "content-length",
    "accept",
    "accept-language",
    "accept-encoding",
    "host",
    "origin",
    "x-request-id",
    "x-correlation-id",
    "x-forwarded-for",
    "x-forwarded-proto",
    "x-real-ip",
)
_MAX_HEADER_VALUE = 256


def _safe_headers(request: Request) -> dict[str, str]:
    """Allowlisted subset of the request headers (lower-case names)."""
    return {
        name: request.headers[name][:_MAX_HEADER_VALUE]
        for name in _SAFE_HEADERS
        if name in request.headers
    }


def _safe_endpoint(request: Request) -> str:
    """Endpoint label for logs: the matched route TEMPLATE (``/recordings/share/{token}``),
    never the concrete path, which can carry share tokens or phone numbers
    (``/scam-calls/block/{number}``). Falls back to the raw path only when no
    route matched (404s on unknown URLs)."""
    route = request.scope.get("route")
    return getattr(route, "path", None) or request.url.path


def _safe_query(request: Request) -> list[str]:
    """Query-parameter NAMES only. Values are user data (emails, phones, tokens)."""
    return sorted(set(request.query_params.keys()))


# ---------------------------------------------------------------------------
# Starlette middleware — wraps every request/response cycle
# ---------------------------------------------------------------------------
class GlobalErrorHandlerMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        try:
            response = await call_next(request)
            return response

        except Exception as exc:
            client_ip = client_ip_for(request, None)
            endpoint = _safe_endpoint(request)
            method = request.method

            await log_error(
                message="Unhandled exception in request cycle",
                exc=exc,
                level="CRITICAL",
                endpoint=endpoint,
                method=method,
                client_ip=client_ip,
                extra={
                    "query_params": _safe_query(request),
                    "headers": _safe_headers(request),
                },
            )

            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={
                    "error": "An unexpected error occurred. Our team has been notified.",
                    "code": "INTERNAL_SERVER_ERROR",
                },
            )


# ---------------------------------------------------------------------------
# FastAPI exception handlers — register on the app instance
# ---------------------------------------------------------------------------
def register_exception_handlers(app: FastAPI) -> None:
    """Call this once in main.py after creating the FastAPI app."""

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException):
        """Log 4xx/5xx HTTP exceptions and return consistent JSON."""
        client_ip = client_ip_for(request, None)
        level = "ERROR" if exc.status_code >= 500 else "WARNING"

        await log_error(
            message=f"HTTP {exc.status_code}: {exc.detail}",
            level=level,
            endpoint=_safe_endpoint(request),
            method=request.method,
            client_ip=client_ip,
            send_email=(exc.status_code >= 500),
        )

        # Return user-friendly messages for common codes
        friendly = {
            400: "Invalid request. Please check your input.",
            401: "Session expired or unauthorised. Please log in again.",
            403: "Access denied. You don't have permission.",
            404: "The requested resource was not found.",
            409: "Conflict — the resource already exists.",
            422: "Validation failed. Please check your input.",
            429: "Too many requests. Please slow down.",
            500: "Server error. Our team has been notified.",
            503: "Service temporarily unavailable. Please try again shortly.",
        }
        user_message = friendly.get(exc.status_code, exc.detail)

        # Preserve headers the raiser set deliberately (Retry-After on 429,
        # WWW-Authenticate on 401, ...) — dropping them breaks client back-off.
        return JSONResponse(
            status_code=exc.status_code,
            headers=dict(getattr(exc, "headers", None) or {}),
            content={
                "error": user_message,
                "detail": exc.detail,
                "code": exc.status_code,
            },
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request, exc: RequestValidationError
    ):
        """Handle Pydantic / FastAPI validation errors (422)."""
        client_ip = client_ip_for(request, None)

        # Errors raised by custom @field_validator functions carry the raw
        # exception object in ``ctx['error']``; it is not JSON serialisable and
        # previously turned every such 422 into a 500. Encode exceptions as their
        # message string, and drop 'input' so request values are not echoed/logged.
        errors = jsonable_encoder(
            [{k: v for k, v in err.items() if k != "input"} for err in exc.errors()],
            custom_encoder={Exception: str},
        )

        await log_error(
            message=f"Validation error: {errors}",
            level="WARNING",
            endpoint=_safe_endpoint(request),
            method=request.method,
            client_ip=client_ip,
            send_email=False,
            extra={"errors": errors},
        )

        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "error": "Validation failed. Please check your input.",
                "details": errors,
                "code": 422,
            },
        )

    @app.exception_handler(RateLimitExceeded)
    async def user_rate_limit_handler(request: Request, exc: RateLimitExceeded):
        """BH-1: per-user limit reached. Deliberately NO log_error call: a rejected request must not become a database write."""
        seconds = exc.retry_after_seconds
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            headers={"Retry-After": str(seconds)},
            content={
                "error": "Too many requests. Please slow down.",
                "detail": f"You are sending requests too quickly. Try again in {seconds} seconds.",
                "code": 429,
                "error_code": "rate_limit_exceeded",
                "scope": "user",
                "window": exc.window,
                "retry_after_seconds": seconds,
            },
        )

    @app.exception_handler(RateLimitUnavailable)
    async def user_rate_limit_unavailable_handler(
        request: Request, exc: RateLimitUnavailable
    ):
        """BH-1: the limiter cannot be trusted, so the request is refused (fail closed). No database write, no detail."""
        seconds = exc.retry_after_seconds
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            headers={"Retry-After": str(seconds)},
            content={
                "error": "Service temporarily unavailable. Please try again shortly.",
                "detail": "Request limiting is temporarily unavailable.",
                "code": 503,
                "error_code": "rate_limit_unavailable",
                "scope": "user",
                "retry_after_seconds": seconds,
            },
        )

    @app.exception_handler(Exception)
    async def generic_exception_handler(request: Request, exc: Exception):
        """Catch-all for anything the middleware misses."""
        client_ip = client_ip_for(request, None)

        await log_error(
            message="Unhandled generic exception",
            exc=exc,
            level="CRITICAL",
            endpoint=_safe_endpoint(request),
            method=request.method,
            client_ip=client_ip,
        )

        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": "An unexpected error occurred. Our team has been notified.",
                "code": "INTERNAL_SERVER_ERROR",
            },
        )
