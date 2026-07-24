"""Health check endpoints."""

from fastapi import APIRouter

router = APIRouter(prefix="/health", tags=["health"])


@router.get("", summary="Service health check")
async def health_check() -> dict[str, str]:
    """Return a simple uptime-friendly health payload."""

    return {
        "status": "ok",
        "service": "VulnSense AI API",
    }
