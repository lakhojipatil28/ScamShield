"""
Safe URL Risk Analyzer Service for ScamShield.
Conducts safe structural, homograph, protocol, and reputation analysis on web links.
Guaranteed safe: never issues server-side GET requests or clicks links.
"""

from typing import Any

from backend.schemas.scan_schemas import (
    EvidenceItem,
    EvidenceType,
    IndicatorItem,
    ThreatType,
)
from backend.security.ssrf_guard import analyze_safe_url


class UrlAnalyzerService:
    def analyze(self, raw_url: str) -> dict[str, Any]:
        """
        Analyze a URL safely and return structured security findings.
        """
        safe_res = analyze_safe_url(raw_url)
        indicators: list[IndicatorItem] = []
        evidence: list[EvidenceItem] = []

        # 1. SSRF & Private IP Defense
        if safe_res["is_private_ssrf"]:
            indicators.append(
                IndicatorItem(
                    name="Private Network / Cloud Metadata Target (SSRF)",
                    description=(
                        f"The host '{safe_res['hostname']}' resolves to a private, loopback, or cloud-metadata IP. "
                        "Submitting internal network addresses is characteristic of Server-Side Request Forgery attempts."
                    ),
                    severity="CRITICAL",
                    evidence_type=EvidenceType.DETERMINISTIC,
                    supporting_quote=safe_res["hostname"],
                )
            )
            evidence.append(
                EvidenceItem(
                    source="SSRFGuard",
                    evidence_type=EvidenceType.DETERMINISTIC,
                    detail=f"Target IP address '{safe_res['hostname']}' belongs to blocked private RFC range.",
                    verified=True,
                )
            )
        elif safe_res["is_ip_host"]:
            indicators.append(
                IndicatorItem(
                    name="Direct IP Address Host",
                    description=(
                        f"URL utilizes a bare IP address ({safe_res['hostname']}) instead of a registered domain. "
                        "Legitimate public commercial platforms almost universally use registered domains with trusted SSL certificates."
                    ),
                    severity="HIGH",
                    evidence_type=EvidenceType.DETERMINISTIC,
                    supporting_quote=safe_res["hostname"],
                )
            )
            evidence.append(
                EvidenceItem(
                    source="SafeUrlInspector",
                    evidence_type=EvidenceType.DETERMINISTIC,
                    detail=f"Raw IP host '{safe_res['hostname']}' used to bypass domain reputation checks.",
                    verified=True,
                )
            )

        # 2. Embedded Userinfo Obfuscation
        if safe_res["has_userinfo"]:
            indicators.append(
                IndicatorItem(
                    name="Embedded Userinfo Credentials (@) Spoofing",
                    description=(
                        f"The URL contains '{safe_res['userinfo']}@'. Web browsers treat everything before the '@' symbol "
                        f"as login credentials and actually navigate to '{safe_res['hostname']}'. Scammers use this to fake URLs like 'paypal.com@evil-site.com'."
                    ),
                    severity="CRITICAL",
                    evidence_type=EvidenceType.DETERMINISTIC,
                    supporting_quote=safe_res["userinfo"] + "@",
                )
            )
            evidence.append(
                EvidenceItem(
                    source="SafeUrlInspector",
                    evidence_type=EvidenceType.DETERMINISTIC,
                    detail="RFC 3986 userinfo syntax exploited to obscure the genuine destination host.",
                    verified=True,
                )
            )

        # 3. Lookalike / Homograph / Brand Spoofing
        homograph_res = safe_res.get("homograph_check", {})
        if homograph_res.get("is_lookalike"):
            target_brand = homograph_res.get("target_brand") or "trusted institution"
            indicators.append(
                IndicatorItem(
                    name="Domain Impersonation / Lookalike (Typosquatting)",
                    description=(
                        f"Hostname '{safe_res['hostname']}' closely mimics legitimate brand '{target_brand}'. "
                        "Fraudsters register visually similar character combinations or punycode characters to deceive users."
                    ),
                    severity="CRITICAL",
                    evidence_type=EvidenceType.DETERMINISTIC,
                    supporting_quote=safe_res["hostname"],
                )
            )
            for d in homograph_res.get("details", []):
                evidence.append(
                    EvidenceItem(
                        source="HomographEngine",
                        evidence_type=EvidenceType.DETERMINISTIC,
                        detail=d,
                        verified=True,
                    )
                )

        # 4. Open Redirect Warning
        for redirect in safe_res.get("open_redirect_params", []):
            indicators.append(
                IndicatorItem(
                    name="Potential Open Redirect Mechanism",
                    description=(
                        f"Parameter '{redirect['param']}' contains a destination URL '{redirect['target']}'. "
                        "This may redirect visitors from an otherwise trusted domain directly into an attacker-controlled login page."
                    ),
                    severity="HIGH",
                    evidence_type=EvidenceType.DETERMINISTIC,
                    supporting_quote=f"{redirect['param']}={redirect['target']}",
                )
            )

        # 5. Suspicious TLD & Deep Subdomains
        if safe_res.get("suspicious_tld"):
            indicators.append(
                IndicatorItem(
                    name=f"High-Abuse Top-Level Domain (.{safe_res['tld']})",
                    description=(
                        f"Domain utilizes the '.{safe_res['tld']}' TLD, which is frequently exploited by automated phishing kit infrastructure."
                    ),
                    severity="MEDIUM",
                    evidence_type=EvidenceType.DETERMINISTIC,
                    supporting_quote=f".{safe_res['tld']}",
                )
            )

        if safe_res.get("subdomain_depth", 0) >= 4 and not safe_res["is_ip_host"]:
            indicators.append(
                IndicatorItem(
                    name="Excessive Subdomain Depth",
                    description=f"Hostname has {safe_res['subdomain_depth']} label levels, often used to conceal real domains on free sub-hosting providers.",
                    severity="MEDIUM",
                    evidence_type=EvidenceType.DETERMINISTIC,
                    supporting_quote=safe_res["hostname"],
                )
            )

        # 6. Scheme check
        if not safe_res["is_https"]:
            indicators.append(
                IndicatorItem(
                    name="Insecure Transport (Non-HTTPS / Plaintext HTTP)",
                    description="Traffic is not encrypted with TLS/SSL. Any login credentials or data entered can be intercepted by eavesdroppers on public networks.",
                    severity="MEDIUM",
                    evidence_type=EvidenceType.DETERMINISTIC,
                    supporting_quote=safe_res["scheme"] or "http",
                )
            )

        # 7. External Threat Intelligence Status Caveat (Requirement 5)
        evidence.append(
            EvidenceItem(
                source="ReputationStatus",
                evidence_type=EvidenceType.EXTERNAL,
                detail="External commercial domain reputation service (e.g. VirusTotal API) is not configured in environment. Domain reputation could not be externally corroborated.",
                verified=False,
            )
        )

        # Calculate primary threat and score
        risk_score = min(100, safe_res["risk_points"])
        if safe_res["is_private_ssrf"]:
            primary_threat = ThreatType.MALICIOUS_URL
            risk_score = max(risk_score, 95)
        elif homograph_res.get("is_lookalike"):
            primary_threat = ThreatType.IMPERSONATION
            risk_score = max(risk_score, 85)
        elif safe_res["has_userinfo"]:
            primary_threat = ThreatType.PHISHING
            risk_score = max(risk_score, 85)
        elif risk_score >= 50:
            primary_threat = ThreatType.MALICIOUS_URL
        elif risk_score >= 20:
            primary_threat = ThreatType.UNKNOWN
        else:
            primary_threat = ThreatType.BENIGN

        return {
            "deterministic_score": risk_score,
            "primary_threat": primary_threat,
            "indicators": indicators,
            "evidence": evidence,
            "safe_res": safe_res,
        }


url_analyzer = UrlAnalyzerService()
