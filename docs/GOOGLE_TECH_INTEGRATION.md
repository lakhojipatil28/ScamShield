# ScamShield — Google Technology Integration Guide

This document highlights the Google technologies integrated into **ScamShield** for the PromptWar Hackathon under the theme **"Build Beyond AI: Engineer Secure, Intelligent and Autonomous Applications."**

---

## 1. Google Gemini AI & The Official `google-genai` SDK

ScamShield leverages the latest Google Gen AI SDK (`google-genai` v2.33+) with the `gemini-3.8-flash` model.

### Key Capabilities Deployed:

1. **Strict Structured Output Generation**:
   Rather than relying on unconstrained markdown generation, ScamShield enforces a strict Pydantic JSON schema (`GeminiScamAnalysis`) passed via `types.GenerateContentConfig(response_mime_type="application/json", response_schema=GeminiScamAnalysis)`:
   ```python
   response = client.models.generate_content(
       model=settings.GEMINI_MODEL,
       contents=contents,
       config=types.GenerateContentConfig(
           system_instruction=system_instruction,
           response_mime_type="application/json",
           response_schema=GeminiScamAnalysis,
           temperature=0.1,  # Low temperature for deterministic security evaluation
           max_output_tokens=2048,
       ),
   )
   ```
   This guarantees that every AI response conforms to predefined fields (`threat_type`, `risk_score`, `risk_level`, `summary`, `warning_signs`, `evidence_quotes`, `recommended_actions`, `uncertainty_notes`, `confidence`).

2. **Multimodal Vision OCR for Screenshots**:
   ScamShield accepts screenshots of suspicious messages, advertisements, and invoices (PNG, JPEG, WebP) and utilizes Gemini's native multimodal vision capabilities via `types.Part.from_bytes(data=image_bytes, mime_type=mime_type)`:
   - Accurately transcribes text, buttons, URLs, phone numbers, and sender names.
   - Extracts semantic layout clues (e.g. deceptive spoofing of official bank logos or urgency banners).
   - Enables end-to-end threat detection on images where traditional regex scanners fail.

3. **Prompt Injection Hardening via System Directives**:
   System instructions explicitly instruct the model that content between `<UNTRUSTED_CONTENT>` tags is passive forensic evidence, preventing jailbreaks or role hijack attacks.

4. **Graceful Fallback Engineering**:
   If `GEMINI_API_KEY` is not provided or quota limits are encountered, ScamShield automatically switches to **Deterministic Security Mode**, producing an honest, auditable partial report without crashing or fabricating AI output.

---

## 2. Google Cloud Firestore Integration

ScamShield implements a pluggable storage adapter:
- **Cloud Mode**: Connects to Google Cloud Firestore via the Google Cloud Client Library when `FIREBASE_PROJECT_ID` or Google Application Default Credentials are set.
- **Local Dev Mode**: Operates seamlessly with an isolated SQLite ACID database when developing locally.

### Data Model & Privacy Minimization:
- **Collection**: `scan_records`
- **Document Structure**:
  ```json
  {
    "scan_id": "scan_4a8f9c21b3e7",
    "user_id": "user_xyz789",
    "scan_type": "text",
    "target_analyzed": "Sanitized preview...",
    "risk_score": 90,
    "risk_level": "CRITICAL",
    "threat_type": "CREDENTIAL_HARVESTING",
    "summary": "CRITICAL RISK: Multiple verified indicators...",
    "is_partial": false,
    "response_json": "{...full validated report...}",
    "created_at": "2026-10-23T07:41:49Z"
  }
  ```
- **Privacy Assurance**: Sensitive OTPs and credit card numbers are redacted prior to Firestore insertion. Raw screenshot binaries are discarded after in-memory OCR.

---

## 3. Firebase Authentication Integration

- **Frontend Client**: Connects via Firebase JS SDK supporting Email/Password, Google Sign-In, and Guest/Anonymous login.
- **Backend Token Verification**: Protected endpoints extract the `Authorization: Bearer <token>` header, verify claims against Firebase Admin SDK, and isolate scan history strictly to the authenticated `user_id`.
- **Zero-Barrier Evaluation**: Includes an automatic Guest session mode so hackathon judges can immediately test the platform without required account setup.

---

## 4. Google Cloud Run Ready

ScamShield includes a production multi-stage `Dockerfile`:
- Stage 1: Builds the React + TypeScript frontend into an optimized production static bundle using Node.js 24 Alpine.
- Stage 2: Packages the FastAPI Python 3.13 backend, copies the compiled static assets, and configures Uvicorn for port `8080`.
- Supports one-click continuous deployment via Google Cloud Build and Cloud Run:
  ```bash
  gcloud run deploy scamshield \
    --source . \
    --platform managed \
    --region us-central1 \
    --allow-unauthenticated \
    --set-env-vars GEMINI_API_KEY="your-key",GEMINI_MODEL="gemini-3.8-flash"
  ```
