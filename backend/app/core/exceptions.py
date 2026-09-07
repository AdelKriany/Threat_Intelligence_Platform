from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException


class APIError(HTTPException):
    """An expected API failure with a stable, client-safe error code."""

    def __init__(self, status_code: int, error_code: str, message: str) -> None:
        super().__init__(status_code=status_code, detail=message)
        self.error_code = error_code


async def handle_http_exception(request: Request, exc: Exception) -> JSONResponse:
    """Return structured JSON for HTTP errors."""

    if not isinstance(exc, HTTPException):
        return await handle_unexpected_error(request, exc)

    error = exc.error_code if isinstance(exc, APIError) else exc.__class__.__name__
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": error, "message": exc.detail},
    )


async def handle_unexpected_error(request: Request, exc: Exception) -> JSONResponse:
    """Return structured JSON for unexpected internal errors."""

    return JSONResponse(
        status_code=500,
        content={"error": "Internal Server Error", "message": "An unexpected error occurred."},
    )


def register_exception_handlers(app: FastAPI) -> None:
    """Register centralized exception handlers."""

    app.add_exception_handler(HTTPException, handle_http_exception)
    app.add_exception_handler(Exception, handle_unexpected_error)
