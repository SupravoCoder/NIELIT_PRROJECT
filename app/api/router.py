"""API router assembly for VulnSense AI."""

from fastapi import APIRouter

from app.api.routes.health import router as health_router
from app.api.routes.reports import router as reports_router
from app.api.routes.scan import router as scan_router

api_router = APIRouter()
api_router.include_router(health_router)
api_router.include_router(scan_router)
api_router.include_router(reports_router)

