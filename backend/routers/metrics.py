"""
Operational Metrics Endpoint for ScamShield Dashboard.
"""

from fastapi import APIRouter

from backend.services.metrics_service import metrics_service

router = APIRouter(prefix="/api/v1", tags=["Metrics"])


@router.get("/metrics")
async def get_metrics():
    """Retrieve operational telemetry and detection statistics."""
    return metrics_service.get_summary()
