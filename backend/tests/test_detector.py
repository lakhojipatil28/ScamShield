"""Unit tests for Deterministic Threat Detector."""
import pytest
from backend.services.detector import detector
from backend.schemas.scan_schemas import ThreatType


def test_detect_otp_solicitation():
    text = "Please text back your 6-digit verification code immediately to keep your account open."
    result = detector.analyze_text(text)
    assert result["deterministic_score"] >= 40
    assert any(ind.name == "OTP / Verification Code Solicitation" for ind in result["indicators"])
    assert result["primary_threat"] == ThreatType.CREDENTIAL_HARVESTING


def test_detect_fake_job_offer():
    text = "Work from home and earn $850 per day! Please pay a registration fee of $150 via Apple gift card."
    result = detector.analyze_text(text)
    assert result["deterministic_score"] >= 60
    assert any(ind.name == "Upfront Job Fee / Fake Employment Trap" for ind in result["indicators"])
    assert any(ind.name == "Irreversible / Untraceable Payment Demand" for ind in result["indicators"])
    assert result["primary_threat"] in [ThreatType.ADVANCE_FEE_FRAUD, ThreatType.PHISHING]


def test_detect_extortion_and_arrest_threat():
    text = "Arrest warrant issued by the IRS. Police officers dispatched unless immediate action required."
    result = detector.analyze_text(text)
    assert result["deterministic_score"] >= 60
    assert any(ind.name == "Extortion / Arrest Threat" for ind in result["indicators"])
    assert result["primary_threat"] == ThreatType.EXTORTION


def test_benign_appointment_reminder():
    text = "Dr. Smith: Your dental appointment is scheduled for tomorrow at 3 PM. Reply CONFIRM or CANCEL."
    result = detector.analyze_text(text)
    assert result["deterministic_score"] <= 25
    assert result["primary_threat"] == ThreatType.BENIGN


def test_benign_2fa_alert_not_sharing():
    text = "Your verification code is 918234. Never share this code with anyone. We will never call to ask for it."
    result = detector.analyze_text(text)
    assert result["deterministic_score"] <= 25
    assert result["primary_threat"] == ThreatType.BENIGN
