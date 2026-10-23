# ScamShield — Benchmark & Performance Audit Report

This report documents the measurable performance, accuracy, and latency metrics obtained from executing ScamShield's reproducible benchmark suite on a balanced synthetic dataset.

---

## 1. Benchmark Execution Environment

- **Date of Test Run**: October 23, 2026
- **Operating System**: Windows 11 AMD64
- **Runtime**: Python 3.13.3 + FastAPI + Uvicorn
- **Dataset**: `backend/data/labeled_samples.json` (12 labeled synthetic test cases covering suspicious SMS, benign 2FA, fake job offers, benign interview invites, lookalike domains, SSRF metadata targets, open redirects, and prompt injection attacks)
- **Reproduction Command**:
  ```powershell
  python -m backend.benchmark
  ```

---

## 2. Key Detection & Accuracy Results

| Metric | Measured Value | Analysis & Significance |
|---|---|---|
| **Total Test Cases** | **12** | Balanced distribution across Text, Email, and URL attack vectors. |
| **True Positives (TP)** | **7** | Correctly identified all malicious attacks (phishing, job fraud, lookalikes, SSRF, prompt injection). |
| **True Negatives (TN)** | **4** | Correctly identified all legitimate benign messages without false alarms (routine 2FA codes, calendar invites, clean URLs). |
| **False Positives (FP)** | **1** | Open redirect URL (`SYN-URL-005`) predicted as MODERATE risk (Score 30). |
| **False Negatives (FN)** | **0** | **Zero missed threats.** No scam was classified as benign. |
| **Accuracy** | **91.67%** | Comprehensive classification accuracy across all test inputs. |
| **Precision** | **87.50%** | Reliability of positive fraud classifications. |
| **Recall (Sensitivity)** | **100.00%** | Complete threat capture rate; zero false negatives. |
| **F1-Score** | **93.33%** | Harmonic mean of precision and recall. |

---

## 3. Latency & Operational Performance

| Metric | Measured Value | Target SLA |
|---|---|---|
| **Average End-to-End Latency** | **12.56 ms** | < 2,000 ms |
| **Median Latency (p50)** | **11.11 ms** | < 1,000 ms |
| **95th Percentile Latency (p95)** | **22.50 ms** | < 3,000 ms |
| **Avg Deterministic Rule Execution** | **0.90 ms** | < 50 ms |
| **Scan Success Rate** | **100.00%** | > 99.5% |

---

## 4. Per-Test Case Breakdown

| Sample ID | Type | Expected Level | Predicted Level (Score) | Latency | Outcome |
|---|---|---|---|---|---|
| `SYN-MSG-001` | text | CRITICAL | CRITICAL (90) | 22.5 ms | **True Positive** (OTP theft caught) |
| `SYN-MSG-002` | text | LOW | LOW (0) | 11.1 ms | **True Negative** (Benign doctor reminder) |
| `SYN-MSG-003` | text | CRITICAL | HIGH (65) | 16.8 ms | **True Positive** (IRS arrest extortion) |
| `SYN-MSG-004` | text | LOW | LOW (15) | 9.1 ms | **True Negative** (Benign Google 2FA) |
| `SYN-JOB-001` | email | CRITICAL | CRITICAL (100) | 10.9 ms | **True Positive** (Job deposit trap) |
| `SYN-JOB-002` | email | LOW | LOW (0) | 12.3 ms | **True Negative** (Benign interview invite) |
| `SYN-URL-001` | url | CRITICAL | CRITICAL (85) | 13.1 ms | **True Positive** (Typosquat `paypa1.com`) |
| `SYN-URL-002` | url | CRITICAL | CRITICAL (100) | 11.1 ms | **True Positive** (SSRF `169.254.169.254`) |
| `SYN-URL-003` | url | CRITICAL | CRITICAL (85) | 12.6 ms | **True Positive** (Userinfo obfuscation) |
| `SYN-URL-004` | url | LOW | LOW (0) | 10.8 ms | **True Negative** (Benign google.com) |
| `SYN-URL-005` | url | MODERATE | MODERATE (30) | 9.8 ms | **Correct Band** (Open redirect) |
| `SYN-INJ-001` | text | CRITICAL | CRITICAL (85) | 10.8 ms | **True Positive** (Prompt injection neutralized) |
