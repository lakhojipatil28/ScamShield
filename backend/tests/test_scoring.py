"""Unit tests for Risk Scoring Engine."""

from backend.schemas.scan_schemas import (
    EvidenceType,
    GeminiScamAnalysis,
    IndicatorItem,
    RiskLevel,
    ThreatType,
)
from backend.services.scoring_engine import scoring_engine


def test_scoring_bands():
    assert scoring_engine.calculate_risk_band(10) == RiskLevel.LOW
    assert scoring_engine.calculate_risk_band(29) == RiskLevel.LOW
    assert scoring_engine.calculate_risk_band(30) == RiskLevel.MODERATE
    assert scoring_engine.calculate_risk_band(59) == RiskLevel.MODERATE
    assert scoring_engine.calculate_risk_band(60) == RiskLevel.HIGH
    assert scoring_engine.calculate_risk_band(84) == RiskLevel.HIGH
    assert scoring_engine.calculate_risk_band(85) == RiskLevel.CRITICAL
    assert scoring_engine.calculate_risk_band(100) == RiskLevel.CRITICAL


def test_scoring_reconcile_deterministic_fallback():
    # When AI is offline, scoring relies on deterministic checks and marks partial
    det_res = {
        "deterministic_score": 75,
        "primary_threat": ThreatType.CREDENTIAL_HARVESTING,
        "indicators": [
            IndicatorItem(
                name="Credential Harvesting",
                description="Test rule",
                severity="HIGH",
                evidence_type=EvidenceType.DETERMINISTIC,
            )
        ],
        "evidence": [],
    }
    ai_res = {"available": False, "analysis": None}

    reconciled = scoring_engine.reconcile(det_res, ai_res)
    assessment = reconciled["assessment"]
    assert assessment.risk_score == 75
    assert assessment.risk_level == RiskLevel.HIGH
    assert assessment.is_partial is True
    assert len(reconciled["recommendations"]) > 0


def test_scoring_enforces_critical_safety_floor():
    # If deterministic rules flag CRITICAL severity, score cannot drop to LOW
    det_res = {
        "deterministic_score": 90,
        "primary_threat": ThreatType.CREDENTIAL_HARVESTING,
        "indicators": [
            IndicatorItem(
                name="OTP Solicitation",
                description="Rule match",
                severity="CRITICAL",
                evidence_type=EvidenceType.DETERMINISTIC,
            )
        ],
        "evidence": [],
    }
    # Pretend an adversarial AI gave low score
    ai_fake = GeminiScamAnalysis(
        threat_type=ThreatType.BENIGN,
        risk_score=10,
        risk_level=RiskLevel.LOW,
        summary="Looks fine",
        warning_signs=[],
        evidence_quotes=[],
        recommended_actions=[],
        uncertainty_notes=[],
        confidence=0.9,
    )
    ai_res = {"available": True, "analysis": ai_fake}

    reconciled = scoring_engine.reconcile(det_res, ai_res)
    # Must enforce safety floor >= 85
    assert reconciled["assessment"].risk_score >= 85
    assert reconciled["assessment"].risk_level == RiskLevel.CRITICAL
