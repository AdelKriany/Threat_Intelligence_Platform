from fastapi import FastAPI

from app.api.v1.router import router as api_router
from app.core.config import settings
from app.core.exceptions import register_exception_handlers
from app.core.logging import setup_logging


def create_app() -> FastAPI:
    """Create and configure the FastAPI application factory."""

    setup_logging()
    app = FastAPI(
        title=settings.project_name,
        version="1.0.0",
        description="ThreatLens Phase 1 foundation API",
        docs_url="/docs",
        redoc_url="/redoc",
    )
    register_exception_handlers(app)
    app.include_router(api_router, prefix="/api/v1")

    @app.get("/")
    async def root() -> dict[str, str]:
        return {"message": f"{settings.project_name} API is running"}

    return app


app = create_app()
