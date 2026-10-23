# ScamShield — System Limitations & Future Engineering Roadmap

In accordance with responsible AI development and PromptWar Hackathon guidelines, this document transparently documents the technical limitations of ScamShield and outlines future enhancements.

---

## 1. Current System Limitations

1. **Lack of Live Outbound Network Reputation Queries**:
   - By defensive design, ScamShield prohibits outbound server-side HTTP calls to user-supplied URLs to prevent SSRF and DNS rebinding attacks.
   - *Limitation*: Newly registered benign domains or brand-new zero-day malicious sites without obvious homoglyphs or keywords cannot have their WHOIS domain age verified without dedicated external threat intelligence APIs (e.g., VirusTotal, Google Safe Browsing API).
   - *Mitigation*: ScamShield explicitly notes in every report: `"External domain reputation could not be verified; status UNKNOWN"` rather than falsely assuming safety.

2. **Visual Layout Camouflage in Low-Resolution Screenshots**:
   - In extremely blurred, low-contrast, or hand-drawn screenshots, OCR transcription confidence decreases.
   - *Mitigation*: ScamShield includes an image decoding check and uncertainty notes warning the user when text extraction is degraded.

3. **Language Scope**:
   - Deterministic regex heuristics are heavily calibrated for English-language scam idioms.
   - *Mitigation*: Gemini AI handles multilingual contextual nuances when online, but deterministic rules are primarily English-optimized.

4. **Novel Slang and Steganography**:
   - Attackers continuously evolve evasive slang (e.g. `p-a-y-p-a-l`, leetspeak, or image-embedded hidden payloads).
   - *Mitigation*: The multi-layered approach combines regex with Gemini semantic reasoning, catching variations that evade static rules.

---

## 2. Future Engineering Roadmap

1. **Google Safe Browsing & VirusTotal API Integration**:
   - Implement an isolated, rate-limited, caching proxy to query Google Safe Browsing v4 and VirusTotal for domain reputation scores without opening user URLs.

2. **Browser Extension for Real-Time Chrome Protection**:
   - Build a lightweight Manifest V3 Chrome extension that automatically invokes ScamShield's `/api/v1/scan/url` endpoint when navigating to newly registered or suspicious domains.

3. **Messaging Bot Webhooks (WhatsApp & Telegram)**:
   - Provide a verified WhatsApp Business & Telegram Bot allowing users to forward suspicious messages directly for instant analysis on mobile devices.

4. **Decentralized Threat Intelligence Sharing (STIX/TAXII)**:
   - Enable anonymized, sanitized threat indicator exports in STIX/TAXII formats so security analysts can ingest novel scam signatures into enterprise SIEMs.
