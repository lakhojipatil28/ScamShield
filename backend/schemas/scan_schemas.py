"""
Pydantic Schemas for ScamShield Analysis and Reporting.
"""

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ScanType(StrEnum):
    TEXT = "text"
    EMAIL = "email"
    URL = "url"
    SCREENSHOT = "screenshot"


class RiskLevel(StrEnum):
    LOW = "LOW"
    MODERATE = "MODERATE"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ThreatType(StrEnum):
    PHISHING = "PHISHING"
    CREDENTIAL_HARVESTING = "CREDENTIAL_HARVESTING"
    IMPERSONATION = "IMPERSONATION"
    ADVANCE_FEE_FRAUD = "ADVANCE_FEE_FRAUD"
    MALICIOUS_URL = "MALICIOUS_URL"
    EXTORTION = "EXTORTION"
    INVESTMENT_SCAM = "INVESTMENT_SCAM"
    BENIGN = "BENIGN"
    UNKNOWN = "UNKNOWN"


class EvidenceType(StrEnum):
    DETERMINISTIC = "DETERMINISTIC"
    EXTERNAL = "EXTERNAL"
    AI_INTERPRETATION = "AI_INTERPRETATION"


class IndicatorItem(BaseModel):
    name: str = Field(..., description="Short title of the warning sign/indicator")
    description: str = Field(..., description="Detailed explanation of what was found")
    severity: str = Field("MEDIUM", description="LOW, MEDIUM, HIGH, or CRITICAL")
    evidence_type: EvidenceType = Field(
        EvidenceType.DETERMINISTIC, description="Source category"
    )
    supporting_quote: str | None = Field(
        None, description="Exact snippet or extracted string triggering finding"
    )


class EvidenceItem(BaseModel):
    source: str = Field(..., description="Name of module or engine generating evidence")
    evidence_type: EvidenceType = Field(
        ..., description="DETERMINISTIC, EXTERNAL, or AI_INTERPRETATION"
    )
    detail: str = Field(..., description="Observation or factual finding")
    verified: bool = Field(
        True, description="Whether this is a corroborated fact vs inferred possibility"
    )


class RecommendationItem(BaseModel):
    priority: int = Field(
        1, description="1=Immediate/Urgent, 2=Verification, 3=Safe Practice"
    )
    action: str = Field(..., description="Imperative recommendation action")
    explanation: str = Field(..., description="Why this step is important")


class RiskAssessment(BaseModel):
    risk_score: int = Field(
        ...,
        ge=0,
        le=100,
        description="Composite risk score from 0 (safest) to 100 (highest risk)",
    )
    risk_level: RiskLevel = Field(
        ..., description="LOW, MODERATE, HIGH, or CRITICAL band"
    )
    threat_type: ThreatType = Field(
        ..., description="Primary identified threat category"
    )
    summary: str = Field(
        ..., description="Executive plain-language summary of the threat"
    )
    confidence_score: float = Field(
        0.9, ge=0.0, le=1.0, description="Subjective confidence of assessment"
    )
    uncertainty_notes: list[str] = Field(
        default_factory=list,
        description="Explicit caveats, missing information or limits",
    )
    is_partial: bool = Field(
        False,
        description="True if AI was offline or external reputation could not be queried",
    )


class OperationalMetrics(BaseModel):
    scan_id: str
    duration_ms: float
    deterministic_duration_ms: float
    ai_duration_ms: float
    tokens_used: int | None = None
    timestamp: str


class ScanResponse(BaseModel):
    scan_id: str
    scan_type: ScanType
    target_analyzed: str = Field(
        ..., description="Sanitized, redacted preview of content or URL"
    )
    assessment: RiskAssessment
    indicators: list[IndicatorItem] = Field(default_factory=list)
    evidence: list[EvidenceItem] = Field(default_factory=list)
    recommendations: list[RecommendationItem] = Field(default_factory=list)
    deterministic_checks: dict[str, Any] = Field(default_factory=dict)
    extracted_text: str | None = Field(
        None, description="Extracted OCR text if scan was a screenshot"
    )
    metrics: OperationalMetrics
    created_at: str
    user_id: str | None = None


# Input Request Schemas
class TextScanRequest(BaseModel):
    content: str = Field(
        ...,
        min_length=1,
        max_length=25000,
        description="Raw text message or SMS to analyze",
    )
    context: str | None = Field(
        None,
        description="Optional context (e.g. Received via WhatsApp, unknown number)",
    )


class EmailScanRequest(BaseModel):
    sender: str | None = Field(
        None, description="Claimed sender email address or display name"
    )
    subject: str | None = Field(None, description="Email subject line")
    body: str = Field(
        ...,
        min_length=1,
        max_length=50000,
        description="Email body content or job description",
    )
    context: str | None = Field(
        None, description="Optional job platform (e.g. LinkedIn, Telegram)"
    )


class UrlScanRequest(BaseModel):
    url: str = Field(
        ..., min_length=3, max_length=2048, description="URL to safely inspect"
    )


# Gemini AI Structured Output Schema
class GeminiScamAnalysis(BaseModel):
    threat_type: ThreatType = Field(
        ..., description="Categorized threat classification"
    )
    risk_score: int = Field(
        ..., ge=0, le=100, description="Subjective AI risk estimate 0-100"
    )
    risk_level: RiskLevel = Field(..., description="LOW, MODERATE, HIGH, CRITICAL")
    summary: str = Field(
        ...,
        description="2-3 sentence clear summary explaining what this is and the danger level",
    )
    warning_signs: list[str] = Field(
        default_factory=list, description="Key warning signs identified in context"
    )
    evidence_quotes: list[str] = Field(
        default_factory=list,
        description="Direct quotes from content supporting findings",
    )
    recommended_actions: list[str] = Field(
        default_factory=list, description="Safe next steps for the user"
    )
    uncertainty_notes: list[str] = Field(
        default_factory=list,
        description="Things unknown, missing, or requiring verification",
    )
    confidence: float = Field(
        0.85, ge=0.0, le=1.0, description="AI confidence in this interpretation"
    )
