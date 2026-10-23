"""
Transparent Risk Scoring Engine for ScamShield.
Reconciles deterministic rule matches, external check statuses, and Gemini AI contextual interpretation
into an evidence-grounded risk score and risk level.
"""

from typing import Any

from backend.config import settings
from backend.schemas.scan_schemas import (
    EvidenceItem,
    EvidenceType,
    GeminiScamAnalysis,
    IndicatorItem,
    RecommendationItem,
    RiskAssessment,
    RiskLevel,
    ThreatType,
)


class ScoringEngine:
    def __init__(
        self,
        low_threshold: int = settings.RISK_LOW_THRESHOLD,
        moderate_threshold: int = settings.RISK_MODERATE_THRESHOLD,
        high_threshold: int = settings.RISK_HIGH_THRESHOLD,
    ):
        self.low_threshold = low_threshold
        self.moderate_threshold = moderate_threshold
        self.high_threshold = high_threshold

    def calculate_risk_band(self, score: int) -> RiskLevel:
        """Categorize raw score (0-100) into documented risk band."""
        if score <= self.low_threshold:
            return RiskLevel.LOW
        elif score <= self.moderate_threshold:
            return RiskLevel.MODERATE
        elif score <= self.high_threshold:
            return RiskLevel.HIGH
        else:
            return RiskLevel.CRITICAL

    def reconcile(
        self,
        deterministic_result: dict[str, Any],
        gemini_result: dict[str, Any],
        injection_detected: bool = False,
        scan_type: str = "text",
    ) -> dict[str, Any]:
        """
        Synthesize multi-modal findings into an auditable final assessment.
        """
        det_score = deterministic_result.get("deterministic_score", 0)
        det_threat = deterministic_result.get("primary_threat", ThreatType.UNKNOWN)
        det_indicators: list[IndicatorItem] = list(
            deterministic_result.get("indicators", [])
        )
        det_evidence: list[EvidenceItem] = list(
            deterministic_result.get("evidence", [])
        )

        uncertainty_notes: list[str] = []
        is_partial = False
        reconciled_score: int = 0
        final_threat: ThreatType = det_threat
        confidence: float = 0.85
        summary: str = ""
        recommendations: list[RecommendationItem] = []

        # 1. Prompt Injection Handling
        if injection_detected:
            det_score = max(det_score, 85)
            det_indicators.append(
                IndicatorItem(
                    name="Adversarial Prompt Injection / Instruction Override Detected",
                    description="The input contains commands attempting to hijack or manipulate AI security analysis.",
                    severity="CRITICAL",
                    evidence_type=EvidenceType.DETERMINISTIC,
                    supporting_quote="Adversarial pattern match",
                )
            )
            det_evidence.append(
                EvidenceItem(
                    source="PromptGuard",
                    evidence_type=EvidenceType.DETERMINISTIC,
                    detail="Adversarial jailbreak phrases detected in untrusted content payload.",
                    verified=True,
                )
            )
            final_threat = ThreatType.EXTORTION

        # 2. Check Gemini Availability
        ai_available = gemini_result.get("available", False)
        ai_analysis: GeminiScamAnalysis | None = gemini_result.get("analysis")

        if not ai_available or not ai_analysis:
            # Deterministic Only Mode
            is_partial = True
            reconciled_score = det_score
            final_threat = det_threat
            confidence = 0.70
            uncertainty_notes.append(
                "Partial analysis: Google Gemini AI service was unavailable or unconfigured. Assessment relies purely on deterministic pattern rules."
            )
            uncertainty_notes.append(
                "Missing external reputation check: domain intelligence services not actively queried."
            )

            # Generate rule-based summary
            if reconciled_score >= 85:
                summary = f"CRITICAL RISK: Multiple verified high-severity indicators detected matching {final_threat.value} attack patterns."
            elif reconciled_score >= 60:
                summary = f"HIGH RISK: Suspicious patterns detected consistent with {final_threat.value}. Caution advised."
            elif reconciled_score >= 30:
                summary = "MODERATE RISK: Some anomalous or persuasive patterns identified; verify sender through independent channels."
            else:
                summary = "LOW RISK: No blatant deterministic fraud indicators detected. Note that sophisticated novel scams may still evade basic static rules."

            # Generate default rule-based recommendations
            recommendations = self._generate_default_recommendations(
                final_threat, reconciled_score, scan_type
            )

        else:
            # AI + Deterministic Corroboration Mode
            ai_score = ai_analysis.risk_score
            ai_threat = ai_analysis.threat_type
            confidence = ai_analysis.confidence

            # Weighting Policy:
            # - If deterministic rules found CRITICAL flags (e.g. SSRF or OTP theft), enforce strict safety floor
            has_critical_det = any(ind.severity == "CRITICAL" for ind in det_indicators)

            if has_critical_det:
                # Deterministic critical evidence cannot be softened by AI
                reconciled_score = max(det_score, ai_score, 85)
                final_threat = (
                    det_threat if det_threat != ThreatType.UNKNOWN else ai_threat
                )
            elif det_score > 0 and ai_score > 0:
                # Corroborated risk: 50% deterministic, 50% AI contextual + corroboration boost
                base_score = int(0.45 * det_score + 0.55 * ai_score)
                # If both independently classify high risk, apply corroboration boost
                if det_score >= 50 and ai_score >= 50:
                    base_score = min(100, base_score + 5)
                reconciled_score = min(100, base_score)
                final_threat = (
                    ai_threat if ai_threat != ThreatType.UNKNOWN else det_threat
                )
            elif det_score > 0:
                reconciled_score = det_score
                final_threat = det_threat
            else:
                # Deterministic rules found nothing, AI contextual analysis took lead
                reconciled_score = ai_score
                final_threat = ai_threat

            summary = ai_analysis.summary

            # Add AI warnings to indicators list
            for ws in ai_analysis.warning_signs:
                det_indicators.append(
                    IndicatorItem(
                        name="Contextual Warning Sign",
                        description=ws,
                        severity="HIGH" if reconciled_score >= 60 else "MEDIUM",
                        evidence_type=EvidenceType.AI_INTERPRETATION,
                        supporting_quote=ai_analysis.evidence_quotes[0]
                        if ai_analysis.evidence_quotes
                        else None,
                    )
                )

            # Add AI evidence item
            det_evidence.append(
                EvidenceItem(
                    source="GeminiAI",
                    evidence_type=EvidenceType.AI_INTERPRETATION,
                    detail=f"Gemini evaluated semantic context with {int(confidence * 100)}% confidence.",
                    verified=False,
                )
            )

            # Inherit AI uncertainty notes
            if ai_analysis.uncertainty_notes:
                uncertainty_notes.extend(ai_analysis.uncertainty_notes)

            # Format recommendations from AI
            priority_counter = 1
            for act in ai_analysis.recommended_actions:
                recommendations.append(
                    RecommendationItem(
                        priority=priority_counter,
                        action=act,
                        explanation="Recommended by AI cybersecurity analysis based on observed threat vectors.",
                    )
                )
                priority_counter = min(3, priority_counter + 1)

        # Ensure uncertainty notes mention no external reputation if not queried
        if "reputation" not in " ".join(uncertainty_notes).lower():
            uncertainty_notes.append(
                "External domain reputation and threat databases could not be verified."
            )

        risk_level = self.calculate_risk_band(reconciled_score)

        assessment = RiskAssessment(
            risk_score=reconciled_score,
            risk_level=risk_level,
            threat_type=final_threat,
            summary=summary,
            confidence_score=confidence,
            uncertainty_notes=uncertainty_notes,
            is_partial=is_partial,
        )

        return {
            "assessment": assessment,
            "indicators": det_indicators,
            "evidence": det_evidence,
            "recommendations": recommendations,
        }

    def _generate_default_recommendations(
        self, threat_type: ThreatType, score: int, scan_type: str
    ) -> list[RecommendationItem]:
        """Produce safe prescriptive recommendations when in deterministic mode."""
        recs = []
        if score >= 60:
            recs.append(
                RecommendationItem(
                    priority=1,
                    action="Do not click any links, open attachments, or send funds.",
                    explanation="High threat likelihood detected. Engaging may lead to credential theft or financial loss.",
                )
            )
            if threat_type == ThreatType.CREDENTIAL_HARVESTING:
                recs.append(
                    RecommendationItem(
                        priority=1,
                        action="Never share OTPs, passwords, or PINs via text or email.",
                        explanation="Banks and legitimate companies will never request your secret verification codes.",
                    )
                )
            elif threat_type == ThreatType.ADVANCE_FEE_FRAUD:
                recs.append(
                    RecommendationItem(
                        priority=1,
                        action="Reject any job or grant asking for upfront registration or equipment fees.",
                        explanation="Legitimate employers provide equipment and training at company expense.",
                    )
                )
            elif threat_type == ThreatType.MALICIOUS_URL:
                recs.append(
                    RecommendationItem(
                        priority=1,
                        action="Do not enter credentials on this domain.",
                        explanation="The URL exhibits characteristics of domain spoofing or an SSRF target.",
                    )
                )

            recs.append(
                RecommendationItem(
                    priority=2,
                    action="Verify the sender through an official, bookmarked phone number or website.",
                    explanation="Contact the organization directly using public contact info rather than details in the message.",
                )
            )
        else:
            recs.append(
                RecommendationItem(
                    priority=2,
                    action="Exercise standard vigilance before acting on unexpected requests.",
                    explanation="Even with low apparent risk, verify unusual payment requests or sudden contact.",
                )
            )
            recs.append(
                RecommendationItem(
                    priority=3,
                    action="Report suspicious activity to your security administrator or carrier.",
                    explanation="Forward suspicious SMS messages to 7726 (SPAM) to help protect other consumers.",
                )
            )
        return recs


scoring_engine = ScoringEngine()
