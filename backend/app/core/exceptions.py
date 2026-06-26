from fastapi import FastAPI, Request
from fastapi.exceptions import HTTPException
from fastapi.responses import JSONResponse


async def handle_http_exception(request: Request, exc: HTTPException) -> JSONResponse:
    """Return structured JSON for HTTP errors."""

    return JSONResponse(status_code=exc.status_code, content={"error": exc.__class__.__name__, "message": exc.detail})


async def handle_unexpected_error(request: Request, exc: Exception) -> JSONResponse:
    """Return structured JSON for unexpected internal errors."""

    return JSONResponse(status_code=500, content={"error": "Internal Server Error", "message": "An unexpected error occurred."})


def register_exception_handlers(app: FastAPI) -> None:
    """Register centralized exception handlers."""

    app.add_exception_handler(HTTPException, handle_http_exception)
    app.add_exception_handler(Exception, handle_unexpected_error)
