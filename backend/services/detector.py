"""
Deterministic Rule Engine for Message, Email, and Threat Analysis.
Combines high-precision regex matching, brand impersonation detection, credential theft traps,
financial extortion flags, and benign intent mitigation.
"""
import re
from typing import Dict, Any, List, Optional
from backend.schemas.scan_schemas import (
    IndicatorItem,
    EvidenceItem,
    EvidenceType,
    ThreatType,
    RiskLevel,
)


class DeterministicDetector:
    def __init__(self):
        # 1. Credential & Verification Phishing Rules
        self.credential_rules = [
            {
                "id": "OTP_SOLICITATION",
                "pattern": r"(?i)\b(?:send|share|reply\s+with|reply|text\s+back|provide|enter|submit)\s+(?:me\s+|us\s+)?(?:your\s+|the\s+)?(?:[\d\w\-]+\s+)?(?:otp|one-time\s+code|verification\s+code|security\s+code|code|pin)\b",
                "name": "OTP / Verification Code Solicitation",
                "desc": "Requests the recipient to share an OTP, verification code, or PIN. Legitimate organizations never ask you to send your code back.",
                "severity": "CRITICAL",
                "weight": 45,
                "threat_type": ThreatType.CREDENTIAL_HARVESTING,
            },
            {
                "id": "PASSWORD_RESET_TRAP",
                "pattern": r"(?i)\b(?:confirm|verify|update|validate)\s+your\s+(?:password|security\s+questions|credentials|banking\s+details)\b",
                "name": "Credential Harvesting Action",
                "desc": "Directly requests confirmation or updating of sensitive passwords or banking credentials.",
                "severity": "HIGH",
                "weight": 35,
                "threat_type": ThreatType.CREDENTIAL_HARVESTING,
            },
        ]

        # 2. Impersonation of High-Risk Institutions
        self.impersonation_rules = [
            {
                "id": "GOV_TAX_IMPERSONATION",
                "pattern": r"(?i)\b(?:irs|internal\s+revenue|hmrc|social\s+security\s+administration|fbi|police\s+department|customs\s+and\s+border)\b",
                "name": "Government / Tax Authority Impersonation",
                "desc": "Mentions official law enforcement or tax authorities. Common in arrest threats, unpaid tax scams, and warrant hoaxes.",
                "severity": "HIGH",
                "weight": 25,
                "threat_type": ThreatType.IMPERSONATION,
            },
            {
                "id": "BANK_IMPERSONATION",
                "pattern": r"(?i)\b(?:chase\s+bank|bank\s+of\s+america|wells\s+fargo|citibank|capital\s+one|barclays|hsbc|td\s+bank|paypal|venmo|zelle)\b",
                "name": "Financial Institution / Wallet Brand Mention",
                "desc": "References major retail banks or payment networks, often used to create fake security alerts.",
                "severity": "MEDIUM",
                "weight": 20,
                "threat_type": ThreatType.IMPERSONATION,
            },
            {
                "id": "DELIVERY_IMPERSONATION",
                "pattern": r"(?i)\b(?:usps|fedex|ups|dhl|postal\s+service|package\s+delivery|parcel\s+tracking)\b",
                "name": "Delivery Service Brand Mention",
                "desc": "Claims a missed delivery, unpaid customs fee, or suspended parcel.",
                "severity": "MEDIUM",
                "weight": 15,
                "threat_type": ThreatType.PHISHING,
            },
            {
                "id": "TECH_SUPPORT_IMPERSONATION",
                "pattern": r"(?i)\b(?:geek\s+squad|microsoft\s+support|apple\s+support|mcafee\s+renewal|norton\s+antivirus\s+invoice)\b",
                "name": "Tech Support / Renewal Impersonation",
                "desc": "Claims unauthorized subscriptions or fake antivirus/tech renewals to induce panic refund calls.",
                "severity": "HIGH",
                "weight": 30,
                "threat_type": ThreatType.IMPERSONATION,
            },
        ]

        # 3. Urgency and Coercion Patterns
        self.urgency_rules = [
            {
                "id": "EXTREME_URGENCY",
                "pattern": r"(?i)\b(?:within\s+(?:24|12|48|15)\s+(?:hours|minutes)|immediate\s+action\s+required|urgent|urgent\s+notice|final\s+warning|account\s+(?:suspended|terminated|frozen|locked|restricted)\s+immediately|account\s+(?:has\s+been\s+)?locked)\b",
                "name": "Artificial High Urgency & Time Pressure",
                "desc": "Imposes tight deadlines or immediate negative consequences to force rash decision making.",
                "severity": "HIGH",
                "weight": 25,
                "threat_type": ThreatType.PHISHING,
            },
            {
                "id": "LEGAL_ARREST_THREAT",
                "pattern": r"(?i)\b(?:arrest\s+warrant|legal\s+action|lawsuit|prosecution|summoned\s+to\s+court|sheriff|police\s+officers\s+dispatched)\b",
                "name": "Extortion / Arrest Threat",
                "desc": "Threatens criminal prosecution, arrest, or police involvement to coerce payment.",
                "severity": "CRITICAL",
                "weight": 40,
                "threat_type": ThreatType.EXTORTION,
            },
        ]

        # 4. Advance Fee & Fake Job Scams
        self.advance_fee_rules = [
            {
                "id": "JOB_REGISTRATION_FEE",
                "pattern": r"(?i)\b(?:pay\s+(?:the\s+|a\s+)?(?:\$\d+\s+)?(?:refundable\s+)?(?:registration|processing|training|interview|background\s+check|equipment|deposit)(?:\s+fee|\s+deposit)?|refundable\s+deposit\s+for\s+laptop)\b",
                "name": "Upfront Job Fee / Fake Employment Trap",
                "desc": "Legitimate employers never require candidates to pay upfront fees for interviews, training, or equipment.",
                "severity": "CRITICAL",
                "weight": 45,
                "threat_type": ThreatType.ADVANCE_FEE_FRAUD,
            },
            {
                "id": "UNREALISTIC_EARNINGS",
                "pattern": r"(?i)\b(?:earn\s+\$(?:[3-9]\d{2}|\d{4,})\s+(?:per\s+day|daily|per\s+hour)|work\s+10\s+minutes\s+make\s+\$\d+|guaranteed\s+(?:daily\s+)?profit)\b",
                "name": "Unrealistic Guaranteed Compensation",
                "desc": "Promises extreme earnings for minimal or trivial remote tasks (task-based scam / pig butchering prelude).",
                "severity": "HIGH",
                "weight": 30,
                "threat_type": ThreatType.ADVANCE_FEE_FRAUD,
            },
            {
                "id": "LOTTERY_PRIZE_FEE",
                "pattern": r"(?i)\b(?:congratulations\s+you\s+(?:have\s+)?won|claim\s+your\s+prize|winner\s+of\s+\$\d+|\bpay\s+processing\s+tax\s+to\s+release\s+(?:funds|winnings))\b",
                "name": "Unsolicited Lottery / Prize Claim",
                "desc": "Claims you won a lottery or sweepstakes you never entered, demanding taxes or fees to release money.",
                "severity": "HIGH",
                "weight": 35,
                "threat_type": ThreatType.ADVANCE_FEE_FRAUD,
            },
        ]

        # 5. Untraceable Payment Demands
        self.payment_rules = [
            {
                "id": "GIFT_CARD_CRYPTO_PAYMENT",
                "pattern": r"(?i)\b(?:apple\s+gift\s+card|gift\s+card|steam\s+wallet|google\s+play\s+card|bitcoin\s+atm|crypto\s+transfer|usdt\s+deposit|western\s+union|moneygram)\b",
                "name": "Irreversible / Untraceable Payment Demand",
                "desc": "Demands payment through gift cards, Bitcoin ATMs, or cryptocurrency. No legitimate business or court accepts gift cards as payment.",
                "severity": "CRITICAL",
                "weight": 40,
                "threat_type": ThreatType.PHISHING,
            },
        ]

        # 6. Off-Platform Channel Redirection
        self.offplatform_rules = [
            {
                "id": "OFF_PLATFORM_REDIRECTION",
                "pattern": r"(?i)\b(?:contact\s+(?:me|our\s+hiring\s+manager)\s+on\s+whatsapp|add\s+(?:me\s+on\s+)?telegram|message\s+me\s+on\s+signal|wa\.me/\d+|t\.me/[a-zA-Z0-9_]+|contact\s+on\s+telegram)\b",
                "name": "Off-Platform Messaging Redirection",
                "desc": "Directs communication to private encrypted messaging apps (Telegram, WhatsApp) to evade workplace / platform fraud detection.",
                "severity": "HIGH",
                "weight": 25,
                "threat_type": ThreatType.ADVANCE_FEE_FRAUD,
            },
            {
                "id": "SECRECY_COERCION",
                "pattern": r"(?i)\b(?:do\s+not\s+(?:tell|inform|contact)\s+your\s+(?:bank|family|manager|police)|keep\s+this\s+strictly\s+confidential|do\s+not\s+hang\s+up\s+the\s+phone)\b",
                "name": "Secrecy & Isolation Directive",
                "desc": "Instructs the victim to conceal the interaction from relatives, bankers, or coworkers.",
                "severity": "CRITICAL",
                "weight": 40,
                "threat_type": ThreatType.EXTORTION,
            },
        ]

        # 7. Benign Mitigating Patterns (Positive Indicators of legitimate security notices)
        self.benign_mitigation_rules = [
            {
                "id": "LEGIT_2FA_WARNING",
                "pattern": r"(?i)\b(?:never\s+share\s+this\s+code|we\s+will\s+never\s+call\s+you\s+to\s+ask|do\s+not\s+share\s+with\s+anyone|if\s+you\s+did\s+not\s+request\s+this,\s+ignore)\b",
                "name": "Legitimate Security Advice Header",
                "desc": "Contains standard consumer protection advisory warning the user never to share their code.",
                "mitigation_weight": -30,
            },
            {
                "id": "APPOINTMENT_REMINDER",
                "pattern": r"(?i)\b(?:appointment\s+reminder|dr\.\s+[a-zA-Z]+|scheduled\s+for\s+\w+day|reply\s+confirm\s+or\s+cancel|calendar\s+invite)\b",
                "name": "Routine Service / Appointment Notification",
                "desc": "Routine scheduling or calendar confirmation with no financial solicitation.",
                "mitigation_weight": -25,
            },
        ]

    def analyze_text(self, text: str, context: Optional[str] = None) -> Dict[str, Any]:
        """
        Execute deterministic security checks on text.
        Extracts matched indicators, quotes, calculates preliminary risk score,
        and provides transparent evidence.
        """
        all_rules = (
            self.credential_rules
            + self.impersonation_rules
            + self.urgency_rules
            + self.advance_fee_rules
            + self.payment_rules
            + self.offplatform_rules
        )

        indicators: List[IndicatorItem] = []
        evidence: List[EvidenceItem] = []
        threat_type_counts: Dict[ThreatType, int] = {}
        total_weight = 0
        quotes: List[str] = []

        full_content = f"{text}\n{context or ''}"

        # 1. Match threat rules
        for rule in all_rules:
            match = re.search(rule["pattern"], full_content)
            if match:
                snippet = match.group(0).strip()
                quotes.append(snippet)
                total_weight += rule["weight"]

                tt = rule.get("threat_type", ThreatType.PHISHING)
                threat_type_counts[tt] = threat_type_counts.get(tt, 0) + rule["weight"]

                indicators.append(
                    IndicatorItem(
                        name=rule["name"],
                        description=rule["desc"],
                        severity=rule["severity"],
                        evidence_type=EvidenceType.DETERMINISTIC,
                        supporting_quote=snippet,
                    )
                )

                evidence.append(
                    EvidenceItem(
                        source="DeterministicRuleEngine",
                        evidence_type=EvidenceType.DETERMINISTIC,
                        detail=f"Rule [{rule['id']}] triggered by exact text match: '{snippet}'",
                        verified=True,
                    )
                )

        # 2. Check for benign mitigating patterns
        benign_applied = False
        for mit in self.benign_mitigation_rules:
            match = re.search(mit["pattern"], full_content)
            if match:
                snippet = match.group(0).strip()
                total_weight += mit["mitigation_weight"]
                benign_applied = True
                evidence.append(
                    EvidenceItem(
                        source="BenignIntentMitigator",
                        evidence_type=EvidenceType.DETERMINISTIC,
                        detail=f"Benign contextual indicator found: '{snippet}' ({mit['name']})",
                        verified=True,
                    )
                )

        has_otp_solicitation = any(ind.name == "OTP / Verification Code Solicitation" for ind in indicators)
        has_gift_card_or_crypto = any(ind.name == "Irreversible / Untraceable Payment Demand" for ind in indicators)
        has_extortion = any(ind.name == "Extortion / Arrest Threat" for ind in indicators)

        if not has_otp_solicitation and not has_gift_card_or_crypto and not has_extortion:
            if benign_applied and total_weight <= 20:
                total_weight = max(0, total_weight - 15)

        # Clamp raw deterministic score to 0..100
        det_score = max(0, min(100, total_weight))

        # Select primary threat type
        if det_score < 25:
            primary_threat = ThreatType.BENIGN
        elif threat_type_counts:
            primary_threat = max(threat_type_counts, key=threat_type_counts.get)
        else:
            primary_threat = ThreatType.UNKNOWN

        return {
            "deterministic_score": det_score,
            "primary_threat": primary_threat,
            "indicators": indicators,
            "evidence": evidence,
            "quotes": quotes,
            "rules_triggered_count": len(indicators),
        }


# Singleton instance
detector = DeterministicDetector()
