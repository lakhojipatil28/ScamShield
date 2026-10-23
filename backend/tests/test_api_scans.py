"""Integration and API Endpoint tests for ScamShield."""
import io
import pytest
from fastapi.testclient import TestClient
from PIL import Image

from backend.main import app

client = TestClient(app)


def create_test_image_bytes(format="PNG"):
    """Generate small in-memory valid image bytes for testing upload."""
    img = Image.new("RGB", (60, 30), color=(73, 109, 137))
    buf = io.BytesIO()
    img.save(buf, format=format)
    buf.seek(0)
    return buf.getvalue()


def test_health_endpoint():
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert "gemini_ai" in data
    assert "storage" in data


def test_security_headers_present():
    res = client.get("/health")
    assert res.headers["x-content-type-options"] == "nosniff"
    assert res.headers["x-frame-options"] == "DENY"
    assert res.headers["x-xss-protection"] == "1; mode=block"


def test_scan_text_suspicious():
    payload = {
        "content": "URGENT from Bank of America: Account locked. Text back your OTP to unlock immediately.",
        "context": "SMS from unknown 5-digit shortcode",
    }
    res = client.post("/api/v1/scan/text", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "scan_id" in data
    assert data["assessment"]["risk_score"] >= 60
    assert len(data["indicators"]) > 0
    assert len(data["recommendations"]) > 0
    assert "metrics" in data


def test_scan_text_validation_empty():
    res = client.post("/api/v1/scan/text", json={"content": ""})
    assert res.status_code == 422  # Pydantic validation error for min_length=1


def test_scan_email_job_scam():
    payload = {
        "sender": "hiring@quick-careers.buzz",
        "subject": "Job Offer - Immediate Start",
        "body": "Congratulations! Earn $900 daily. Please pay the $150 refundable equipment deposit via gift card. Contact on Telegram @JobsDesk.",
    }
    res = client.post("/api/v1/scan/email", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["assessment"]["risk_level"] in ["HIGH", "CRITICAL"]


def test_scan_url_ssrf():
    res = client.post("/api/v1/scan/url", json={"url": "http://169.254.169.254/meta-data"})
    assert res.status_code == 200
    data = res.json()
    assert data["assessment"]["risk_level"] == "CRITICAL"


def test_scan_url_lookalike():
    res = client.post("/api/v1/scan/url", json={"url": "http://paypa1.com/login"})
    assert res.status_code == 200
    data = res.json()
    assert data["assessment"]["risk_score"] >= 60


def test_scan_screenshot_valid_png():
    img_bytes = create_test_image_bytes("PNG")
    files = {"file": ("screenshot.png", img_bytes, "image/png")}
    res = client.post("/api/v1/scan/screenshot", files=files)
    assert res.status_code == 200
    data = res.json()
    assert data["scan_type"] == "screenshot"
    assert "assessment" in data


def test_scan_screenshot_invalid_file():
    bad_bytes = b"This is not a real image header"
    files = {"file": ("fake.png", bad_bytes, "image/png")}
    res = client.post("/api/v1/scan/screenshot", files=files)
    assert res.status_code == 400
    assert any(term in res.json()["detail"].lower() for term in ["corrupted", "invalid", "too small"])


def test_scan_history_and_deletion():
    # Submit a scan
    text_res = client.post(
        "/api/v1/scan/text",
        json={"content": "Routine test notification 12345"},
        headers={"Authorization": "Bearer test_token_xyz"},
    )
    scan_id = text_res.json()["scan_id"]

    # Retrieve history
    list_res = client.get("/api/v1/scans", headers={"Authorization": "Bearer test_token_xyz"})
    assert list_res.status_code == 200
    scans = list_res.json()
    assert any(s["scan_id"] == scan_id for s in scans)

    # Get single scan
    detail_res = client.get(f"/api/v1/scans/{scan_id}", headers={"Authorization": "Bearer test_token_xyz"})
    assert detail_res.status_code == 200
    assert detail_res.json()["scan_id"] == scan_id

    # Delete scan
    del_res = client.delete(f"/api/v1/scans/{scan_id}", headers={"Authorization": "Bearer test_token_xyz"})
    assert del_res.status_code == 200
    assert del_res.json()["status"] == "success"

    # Verify 404 after deletion
    del_verify = client.get(f"/api/v1/scans/{scan_id}", headers={"Authorization": "Bearer test_token_xyz"})
    assert del_verify.status_code == 404


def test_metrics_endpoint():
    res = client.get("/api/v1/metrics")
    assert res.status_code == 200
    data = res.json()
    assert "total_scans" in data
    assert "latency_metrics" in data
    assert "risk_distribution" in data


def test_scan_text_oversized():
    # Attempt to submit text exceeding 25,000 characters
    huge_content = "A" * 25001
    res = client.post("/api/v1/scan/text", json={"content": huge_content})
    assert res.status_code == 422


def test_cross_user_isolation():
    # User A submits a private scan
    user_a_header = {"Authorization": "Bearer alpha_token_12345"}
    user_b_header = {"Authorization": "Bearer bravo_token_67890"}

    res_a = client.post(
        "/api/v1/scan/text",
        json={"content": "Confidential internal alert for User A"},
        headers=user_a_header,
    )
    assert res_a.status_code == 200
    scan_id_a = res_a.json()["scan_id"]

    # User B attempts to read User A's scan
    res_b_read = client.get(f"/api/v1/scans/{scan_id_a}", headers=user_b_header)
    assert res_b_read.status_code == 404

    # User B attempts to delete User A's scan
    res_b_del = client.delete(f"/api/v1/scans/{scan_id_a}", headers=user_b_header)
    assert res_b_del.status_code == 404

    # Verify User A can still access their own scan
    res_a_verify = client.get(f"/api/v1/scans/{scan_id_a}", headers=user_a_header)
    assert res_a_verify.status_code == 200
    assert res_a_verify.json()["scan_id"] == scan_id_a


def test_scan_malformed_url_safe_handling():
    # Submitting a broken/malformed URL should be handled safely without unhandled 500 crash
    res = client.post("/api/v1/scan/url", json={"url": "http://"})
    assert res.status_code == 200
    data = res.json()
    assert "assessment" in data
    assert data["assessment"]["risk_level"] in ["MODERATE", "HIGH", "CRITICAL"]

