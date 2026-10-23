# ScamShield — Threat Scoring Methodology & Bounded Workflow

This document details the mathematical model, corroboration matrix, and bounded investigation architecture powering **ScamShield**.

---

## 1. The Bounded Agentic Workflow

Unlike unconstrained autonomous agents that risk runaway loops or unintended side effects, ScamShield implements a **strictly bounded 8-step investigation pipeline**:

```
[1. Input Intake & Sanitization]
               │
               ▼
[2. Module Selection & SSRF Inspection]
               │
               ▼
[3. Deterministic Security Rules Execution]
               │
               ▼
[4. Google Gemini AI Structured Analysis]
               │
               ▼
[5. Finding Reconciliation & Corroboration Matrix]
               │
               ▼
[6. Composite Risk Scoring & Band Assignment]
               │
               ▼
[7. Actionable Guidance & Remediation Plan]
               │
               ▼
[8. Privacy-Preserving Telemetry & Audit Persistence]
```

### Prohibited Autonomous Capabilities:
To eliminate safety risks, the AI is explicitly denied:
- Transferring money or interacting with payment gateways.
- Sending messages or emails on the user's behalf.
- Clicking, browsing, or crawling external URLs.
- Executing system shell commands or arbitrary code.
- Mutating or deleting external database records.

---

## 2. Risk Scoring Policy & Mathematical Formulation

ScamShield combines high-precision deterministic static checks with contextual semantic reasoning from Google Gemini AI into a single composite score $S \in [0, 100]$.

### A. Deterministic Rule Score ($S_{\text{det}}$)
Each matching regex pattern or syntactic indicator carries an assigned severity weight $W_i$:
$$S_{\text{det}} = \min\left(100, \sum_{i \in \text{matched}} W_i - \sum_{j \in \text{benign}} M_j\right)$$
- **Critical Rules ($W = 40-45$)**: Direct OTP solicitation, upfront job fee via gift card, SSRF target IP, homoglyph typosquatting.
- **High Rules ($W = 25-35$)**: Government arrest threats, fake tech support renewals, credential harvesting action phrases.
- **Medium Rules ($W = 15-20$)**: High-pressure urgency phrases, bank brand mentions, high-abuse TLDs (`.xyz`, `.buzz`).
- **Benign Mitigations ($M = 25-30$)**: Standard "never share this code" 2FA warnings, legitimate medical/appointment scheduling confirmations.

### B. Gemini AI Contextual Score ($S_{\text{ai}}$)
When Gemini API is configured, the model evaluates the semantic intent, psychological coercion, and narrative coherence, returning a subjective score $S_{\text{ai}} \in [0, 100]$ and confidence $C_{\text{ai}} \in [0.0, 1.0]$.

### C. Reconciliation & Corroboration Matrix
1. **Critical Safety Floor**:
   If any verified deterministic indicator has severity `CRITICAL`:
   $$S_{\text{final}} = \max(S_{\text{det}}, S_{\text{ai}}, 85)$$
   *Rationale: A model cannot soften a verified OTP solicitation or SSRF exploit attempt to 'Low Risk'.*

2. **Independent Corroboration Boost**:
   If both engines independently flag a threat ($S_{\text{det}} \ge 50$ and $S_{\text{ai}} \ge 50$):
   $$S_{\text{base}} = \min\left(100, \lfloor 0.45 \cdot S_{\text{det}} + 0.55 \cdot S_{\text{ai}} \rfloor + 5\right)$$
   *Rationale: When independent static rules and semantic AI corroborate the danger, user risk probability increases.*

3. **Adversarial Prompt Injection Penalty**:
   If prompt injection or jailbreak directives are detected:
   $$S_{\text{final}} = \max(S_{\text{final}}, 85)$$

4. **Deterministic Fallback (Offline Mode)**:
   When Gemini API is unavailable or unconfigured:
   $$S_{\text{final}} = S_{\text{det}}, \quad \text{Confidence} = 0.70, \quad \text{is\_partial} = \text{True}$$
   The resulting report clearly marks the assessment as partial without fabricating AI output.

---

## 3. Documented Risk Bands

| Band | Score Range | Status Color | Definition & Typical Findings |
|---|---|---|---|
| **LOW** | $0 \le S \le 29$ | Emerald Green | Benign transactional alerts, legitimate 2FA push notifications, routine calendar reminders, verified clean URLs. |
| **MODERATE** | $30 \le S \le 59$ | Amber Yellow | Unverified senders, anomalous redirect parameters, high-pressure language, or novel requests requiring independent verification. |
| **HIGH** | $60 \le S \le 84$ | Orange | Strong indicators of advance-fee job scams, fake parcel delivery alerts, or brand impersonation. |
| **CRITICAL** | $85 \le S \le 100$ | Crimson Red | Direct attempts to harvest OTPs/passwords, SSRF metadata probes, lookalike banking domains, or prompt injection attempts. |

---

## 4. Evidence Classification & Provenance

Every finding in a ScamShield threat report is classified by evidence provenance:
- **`DETERMINISTIC`**: Verifiable, reproducible syntactic pattern matches grounded in exact verbatim quotes.
- **`AI_INTERPRETATION`**: Contextual inferences, nuance evaluation, and holistic synthesis produced by Gemini.
- **`EXTERNAL`**: External reputation or network threat database status (explicitly noted as UNKNOWN when unconfigured, never assumed safe).
