# ScamShield — REST API Documentation

Base URL: `http://127.0.0.1:8000/api/v1` (or deployed Cloud Run URL)  
Interactive OpenAPI UI: `http://127.0.0.1:8000/docs`

---

## 1. Authentication & Security Headers

All endpoints accept an optional standard Bearer token in the `Authorization` header:
```http
Authorization: Bearer <firebase_jwt_or_user_token>
```
If omitted, operations run under an isolated `guest` user session.

### Defensive HTTP Headers Returned:
```http
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Referrer-Policy: strict-origin-when-cross-origin
Strict-Transport-Security: max-age=31536000; includeSubDomains
```

---

## 2. Endpoints

### 2.1 Scan Text Message / SMS
`POST /api/v1/scan/text`

Analyzes suspicious text messages, SMS alerts, or conversational snippets.

#### Request Body:
```json
{
  "content": "URGENT from Chase Bank: Account locked. Text back your OTP to unlock immediately.",
  "context": "SMS from unknown number"
}
```

#### Response (`200 OK`):
```json
{
  "scan_id": "scan_4a8f9c21b3e7",
  "scan_type": "text",
  "target_analyzed": "URGENT from Chase Bank: Account locked. Text back your [REDACTED_OTP] to unlock...",
  "assessment": {
    "risk_score": 90,
    "risk_level": "CRITICAL",
    "threat_type": "CREDENTIAL_HARVESTING",
    "summary": "CRITICAL RISK: Multiple verified high-severity indicators detected matching CREDENTIAL_HARVESTING attack patterns.",
    "confidence_score": 0.85,
    "uncertainty_notes": [
      "External domain reputation and threat databases could not be verified."
    ],
    "is_partial": false
  },
  "indicators": [
    {
      "name": "OTP / Verification Code Solicitation",
      "description": "Requests the recipient to share an OTP, verification code, or PIN.",
      "severity": "CRITICAL",
      "evidence_type": "DETERMINISTIC",
      "supporting_quote": "Text back your OTP"
    }
  ],
  "evidence": [
    {
      "source": "DeterministicRuleEngine",
      "evidence_type": "DETERMINISTIC",
      "detail": "Rule [OTP_SOLICITATION] triggered by exact text match: 'Text back your OTP'",
      "verified": true
    }
  ],
  "recommendations": [
    {
      "priority": 1,
      "action": "Never share OTPs, passwords, or PINs via text or email.",
      "explanation": "Banks and legitimate companies will never request your secret verification codes."
    }
  ],
  "metrics": {
    "scan_id": "scan_4a8f9c21b3e7",
    "duration_ms": 14.2,
    "deterministic_duration_ms": 1.1,
    "ai_duration_ms": 0.0,
    "tokens_used": null,
    "timestamp": "2026-10-23T07:41:49Z"
  },
  "created_at": "2026-10-23T07:41:49Z"
}
```

---

### 2.2 Scan Email / Job Offer
`POST /api/v1/scan/email`

Analyzes suspicious emails, invoice notices, and fake employment offers.

#### Request Body:
```json
{
  "sender": "hiring@quick-careers.buzz",
  "subject": "Offer Letter - Remote Data Associate",
  "body": "Congratulations! Earn $900 daily. Pay $150 refundable equipment deposit via Apple Gift Card. Contact on Telegram @JobsDesk.",
  "context": "Unsolicited cold email"
}
```

---

### 2.3 Safe URL Inspection
`POST /api/v1/scan/url`

Performs offline syntactic inspection, SSRF check, homograph detection, and open-redirect analysis. **Never makes outbound HTTP requests to the URL.**

#### Request Body:
```json
{
  "url": "http://paypa1.com/verify-account"
}
```

---

### 2.4 Screenshot Multimodal Analysis
`POST /api/v1/scan/screenshot`

Accepts `multipart/form-data` with an image file (`PNG`, `JPEG`, or `WebP` up to 5 MB). Performs Pillow integrity validation, Gemini vision OCR transcription, and pipeline analysis.

#### Request Form:
- `file`: Binary image file

---

### 2.5 List Saved Scans
`GET /api/v1/scans?limit=50&offset=0&risk_level=CRITICAL&scan_type=text`

Returns paginated list of previous scans for the authenticated user session.

---

### 2.6 Delete Scan
`DELETE /api/v1/scans/{scan_id}`

Permanently deletes a scan record from the database.

---

### 2.7 Telemetry & Operational Metrics
`GET /api/v1/metrics`

Returns aggregated scan counts, success rates, latency percentiles (p50, p95), and risk band distributions for dashboard rendering.

---

### 2.8 Service Health & Configuration Status
`GET /health`

Returns service status, active Gemini model name, and storage backend type.
```json
{
  "status": "healthy",
  "app_name": "ScamShield",
  "version": "1.0.0",
  "environment": "development",
  "gemini_ai": {
    "configured": true,
    "model": "gemini-3.8-flash"
  },
  "storage": {
    "type": "sqlite"
  }
}
```
