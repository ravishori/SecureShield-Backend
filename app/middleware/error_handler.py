"""
Global Exception Handler Middleware
====================================
Catches ALL unhandled exceptions before they bubble up to the client.
• Logs them via logger_service  (file + DB + email)
• Returns a clean, friendly JSON response — the user never sees a raw traceback.

Also registers FastAPI exception handlers for common HTTP errors
so every error path goes through the same logging pipeline.
"""

import traceback
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.services.logger_service import get_logger, log_error

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Starlette middleware — wraps every request/response cycle
# ---------------------------------------------------------------------------
class GlobalErrorHandlerMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        try:
            response = await call_next(request)
            return response

        except Exception as exc:
            client_ip = request.client.host if request.client else None
            endpoint = str(request.url.path)
            method = request.method

            await log_error(
                message="Unhandled exception in request cycle",
                exc=exc,
                level="CRITICAL",
                endpoint=endpoint,
                method=method,
                client_ip=client_ip,
                extra={
                    "query": str(request.query_params),
                    "headers": dict(request.headers),
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
        client_ip = request.client.host if request.client else None
        level = "ERROR" if exc.status_code >= 500 else "WARNING"

        await log_error(
            message=f"HTTP {exc.status_code}: {exc.detail}",
            level=level,
            endpoint=str(request.url.path),
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

        return JSONResponse(
            status_code=exc.status_code,
            content={"error": user_message, "detail": exc.detail, "code": exc.status_code},
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        """Handle Pydantic / FastAPI validation errors (422)."""
        client_ip = request.client.host if request.client else None

        await log_error(
            message=f"Validation error: {exc.errors()}",
            level="WARNING",
            endpoint=str(request.url.path),
            method=request.method,
            client_ip=client_ip,
            send_email=False,
            extra={"errors": exc.errors()},
        )

        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "error": "Validation failed. Please check your input.",
                "details": exc.errors(),
                "code": 422,
            },
        )

    @app.exception_handler(Exception)
    async def generic_exception_handler(request: Request, exc: Exception):
        """Catch-all for anything the middleware misses."""
        client_ip = request.client.host if request.client else None

        await log_error(
            message="Unhandled generic exception",
            exc=exc,
            level="CRITICAL",
            endpoint=str(request.url.path),
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
