from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException


async def handle_http_exception(request: Request, exc: Exception) -> JSONResponse:
    """Return structured JSON for HTTP errors."""

    if not isinstance(exc, HTTPException):
        return await handle_unexpected_error(request, exc)

    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.__class__.__name__, "message": exc.detail},
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
