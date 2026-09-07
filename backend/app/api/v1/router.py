from fastapi import APIRouter

from app.api.v1.health import router as health_router
from app.api.v1.indicator_scores import router as indicator_scores_router

router = APIRouter()
router.include_router(health_router)
router.include_router(indicator_scores_router)
