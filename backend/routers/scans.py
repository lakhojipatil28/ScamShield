"""
Scan API Endpoints for ScamShield.
Handles text, email, URL, and screenshot threat analyses.
"""
from typing import Optional, List
from fastapi import APIRouter, HTTPException, UploadFile, File, Form, Query, Header
from pydantic import ValidationError

from backend.schemas.scan_schemas import (
    TextScanRequest,
    EmailScanRequest,
    UrlScanRequest,
    ScanResponse,
)
from backend.services.pipeline import pipeline
from backend.services.screenshot_service import screenshot_service
from backend.services.storage import storage

router = APIRouter(prefix="/api/v1", tags=["Scans"])


def get_user_id(authorization: Optional[str] = Header(None)) -> str:
    """Extract optional user identifier from Bearer token or default to guest."""
    if authorization and authorization.startswith("Bearer "):
        token = authorization[7:].strip()
        # In full Firebase auth deployment, verify token via firebase_admin
        # Fallback to sanitized token preview as user id
        return f"user_{token[:12]}"
    return "guest"


@router.post("/scan/text", response_model=ScanResponse)
async def scan_text(request: TextScanRequest, authorization: Optional[str] = Header(None)):
    """Analyze a suspicious plain text message, SMS, or conversation snippet."""
    user_id = get_user_id(authorization)
    try:
        return pipeline.process_text_scan(
            content=request.content,
            context=request.context,
            user_id=user_id,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Text analysis error: {str(e)}")


@router.post("/scan/email", response_model=ScanResponse)
async def scan_email(request: EmailScanRequest, authorization: Optional[str] = Header(None)):
    """Analyze a suspicious email, job offer, or invoice notice."""
    user_id = get_user_id(authorization)
    try:
        return pipeline.process_email_scan(
            body=request.body,
            sender=request.sender,
            subject=request.subject,
            context=request.context,
            user_id=user_id,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Email analysis error: {str(e)}")


@router.post("/scan/url", response_model=ScanResponse)
async def scan_url(request: UrlScanRequest, authorization: Optional[str] = Header(None)):
    """Safely inspect a URL for lookalike spoofing, SSRF targets, and malicious redirect structures."""
    user_id = get_user_id(authorization)
    try:
        return pipeline.process_url_scan(
            raw_url=request.url,
            user_id=user_id,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"URL analysis error: {str(e)}")


@router.post("/scan/screenshot", response_model=ScanResponse)
async def scan_screenshot(
    file: UploadFile = File(...),
    authorization: Optional[str] = Header(None),
):
    """
    Upload and analyze a screenshot of a suspicious message or advertisement.
    Supports PNG, JPEG, and WebP up to 5MB.
    """
    user_id = get_user_id(authorization)

    # Read uploaded bytes
    try:
        file_bytes = await file.read()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to read uploaded file: {str(e)}")

    # Validate image file integrity
    is_valid, msg, detected_mime = screenshot_service.validate_image(file_bytes, file.content_type)
    if not is_valid:
        raise HTTPException(status_code=400, detail=msg)

    try:
        return pipeline.process_screenshot_scan(
            image_bytes=file_bytes,
            mime_type=detected_mime or "image/png",
            user_id=user_id,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Screenshot analysis error: {str(e)}")


@router.get("/scans", response_model=List[ScanResponse])
async def list_scans(
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    risk_level: Optional[str] = None,
    scan_type: Optional[str] = None,
    authorization: Optional[str] = Header(None),
):
    """Retrieve saved scan records with user-level partition and filters."""
    user_id = get_user_id(authorization)
    records = storage.get_scans(
        user_id=user_id,
        limit=limit,
        offset=offset,
        risk_level=risk_level,
        scan_type=scan_type,
    )
    return records


@router.get("/scans/{scan_id}", response_model=ScanResponse)
async def get_scan_report(scan_id: str, authorization: Optional[str] = Header(None)):
    """Retrieve full scan report by ID."""
    user_id = get_user_id(authorization)
    scan = storage.get_scan_by_id(scan_id, user_id=user_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan report not found")
    return scan


@router.delete("/scans/{scan_id}")
async def delete_scan(scan_id: str, authorization: Optional[str] = Header(None)):
    """Delete a scan record permanently from user history."""
    user_id = get_user_id(authorization)
    success = storage.delete_scan(scan_id, user_id=user_id)
    if not success:
        raise HTTPException(status_code=404, detail="Scan not found or already deleted")
    return {"status": "success", "message": "Scan report permanently removed"}
