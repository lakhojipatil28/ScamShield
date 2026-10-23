"""
Health and Status Router for ScamShield.
"""
from fastapi import APIRouter
from backend.config import settings
from backend.services.gemini_service import gemini_service

router = APIRouter(tags=["Health"])


@router.get("/health")
async def health_check():
    """Service health check for Cloud Run and monitoring."""
    return {
        "status": "healthy",
        "app_name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT,
        "gemini_ai": {
            "configured": gemini_service.is_configured,
            "model": settings.GEMINI_MODEL,
        },
        "storage": {
            "type": settings.STORAGE_TYPE,
        },
    }
