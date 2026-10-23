"""
Bounded Agentic Analysis Workflow Pipeline for ScamShield.
Coordinates deterministic engines, Google Gemini AI structured reasoning,
risk reconciliation, and operational audit logging.
"""

import hashlib
import threading
import time
import uuid
from datetime import UTC, datetime
from typing import Any

from backend.schemas.scan_schemas import (
    OperationalMetrics,
    ScanResponse,
    ScanType,
)
from backend.security.prompt_guard import (
    sanitize_and_redact_content,
)
from backend.services.detector import detector
from backend.services.gemini_service import gemini_service
from backend.services.metrics_service import metrics_service
from backend.services.scoring_engine import scoring_engine
from backend.services.screenshot_service import screenshot_service
from backend.services.storage import storage
from backend.services.url_analyzer import url_analyzer


class BoundedAnalysisPipeline:
    def __init__(self) -> None:
        self._cache: dict[str, dict[str, Any]] = {}
        self._cache_lock = threading.Lock()
        self._cache_max = 500
    def process_text_scan(
        self,
        content: str,
        context: str | None = None,
        user_id: str | None = "guest",
    ) -> ScanResponse:
        """Execute bounded workflow for plain text messages or SMS."""
        return self._execute_workflow(
            scan_type=ScanType.TEXT,
            raw_input=content,
            additional_context=context,
            user_id=user_id,
        )

    def process_email_scan(
        self,
        body: str,
        sender: str | None = None,
        subject: str | None = None,
        context: str | None = None,
        user_id: str | None = "guest",
    ) -> ScanResponse:
        """Execute bounded workflow for email or job offers."""
        email_header_context = f"Sender: {sender or 'Unspecified'}\nSubject: {subject or 'Unspecified'}\nPlatform Context: {context or 'None'}"
        return self._execute_workflow(
            scan_type=ScanType.EMAIL,
            raw_input=body,
            additional_context=email_header_context,
            user_id=user_id,
        )

    def process_url_scan(
        self,
        raw_url: str,
        user_id: str | None = "guest",
    ) -> ScanResponse:
        """Execute bounded workflow for URLs without making dangerous external HTTP calls."""
        start_time = time.perf_counter()
        scan_id = f"scan_{uuid.uuid4().hex[:12]}"

        # Step 1: Input Validation & Sanitization
        sanitized_url = raw_url.strip()

        # Cache check for instant sub-millisecond repeated analysis
        cache_key = hashlib.sha256(f"url:{sanitized_url}".encode()).hexdigest()
        with self._cache_lock:
            cached = self._cache.get(cache_key)

        if cached:
            total_elapsed_ms = (time.perf_counter() - start_time) * 1000
            metrics = OperationalMetrics(
                scan_id=scan_id,
                duration_ms=round(total_elapsed_ms, 2),
                deterministic_duration_ms=0.05,
                ai_duration_ms=0.0,
                tokens_used=0,
                timestamp=datetime.now(UTC).isoformat(),
            )
            response = ScanResponse(
                scan_id=scan_id,
                scan_type=ScanType.URL,
                target_analyzed=sanitized_url[:200],
                assessment=cached["assessment"],
                indicators=cached["indicators"],
                evidence=cached["evidence"],
                recommendations=cached["recommendations"],
                deterministic_checks=cached["deterministic_checks"],
                extracted_text=None,
                metrics=metrics,
                created_at=datetime.now(UTC).isoformat(),
                user_id=user_id,
            )
            storage.save_scan(response, user_id=user_id)
            return response

        # Step 2 & 3: Run Deterministic URL Inspection (Safe parsing & SSRF Defense)
        det_start = time.perf_counter()
        det_results = url_analyzer.analyze(sanitized_url)
        det_elapsed_ms = (time.perf_counter() - det_start) * 1000

        # Step 4: Request Structured AI Analysis (pass deterministic findings)
        ai_res = gemini_service.analyze_content(
            content=f"Inspect this URL for phishing, homograph deception, and malicious redirect tactics:\n{sanitized_url}",
            scan_type="url",
            deterministic_context=det_results,
        )

        # Step 5 & 6 & 7: Reconcile and Score
        reconciled = scoring_engine.reconcile(
            deterministic_result=det_results,
            gemini_result=ai_res,
            injection_detected=ai_res.get("injection_detected", False),
            scan_type="url",
        )

        total_elapsed_ms = (time.perf_counter() - start_time) * 1000

        metrics = OperationalMetrics(
            scan_id=scan_id,
            duration_ms=round(total_elapsed_ms, 2),
            deterministic_duration_ms=round(det_elapsed_ms, 2),
            ai_duration_ms=round(ai_res.get("latency_ms", 0.0), 2),
            tokens_used=ai_res.get("tokens_used"),
            timestamp=datetime.now(UTC).isoformat(),
        )

        # Record operational metrics
        metrics_service.record_scan(
            scan_type="url",
            risk_level=reconciled["assessment"].risk_level.value,
            threat_type=reconciled["assessment"].threat_type.value,
            duration_ms=total_elapsed_ms,
            det_duration_ms=det_elapsed_ms,
            ai_duration_ms=ai_res.get("latency_ms", 0.0),
            tokens_used=ai_res.get("tokens_used") or 0,
            success=True,
        )

        response = ScanResponse(
            scan_id=scan_id,
            scan_type=ScanType.URL,
            target_analyzed=sanitized_url[:200],
            assessment=reconciled["assessment"],
            indicators=reconciled["indicators"],
            evidence=reconciled["evidence"],
            recommendations=reconciled["recommendations"],
            deterministic_checks=det_results.get("safe_res", {}),
            extracted_text=None,
            metrics=metrics,
            created_at=datetime.now(UTC).isoformat(),
            user_id=user_id,
        )

        # Store in LRU cache
        with self._cache_lock:
            if len(self._cache) >= self._cache_max:
                self._cache.clear()
            self._cache[cache_key] = {
                "assessment": reconciled["assessment"],
                "indicators": reconciled["indicators"],
                "evidence": reconciled["evidence"],
                "recommendations": reconciled["recommendations"],
                "deterministic_checks": det_results.get("safe_res", {}),
            }

        # Step 8: Persist Scan Record
        storage.save_scan(response, user_id=user_id)
        return response

    def process_screenshot_scan(
        self,
        image_bytes: bytes,
        mime_type: str,
        user_id: str | None = "guest",
    ) -> ScanResponse:
        """Execute bounded workflow for screenshot uploads (PNG, JPEG, WebP)."""
        start_time = time.perf_counter()
        scan_id = f"scan_{uuid.uuid4().hex[:12]}"

        # Step 1: Text extraction via Gemini Vision (or OCR fallback)
        extracted_text, ocr_ok, ocr_notes = (
            screenshot_service.extract_text_from_screenshot(image_bytes, mime_type)
        )

        # Step 2 & 3: Run Deterministic Checks on extracted text
        det_start = time.perf_counter()
        det_results = detector.analyze_text(
            extracted_text, context="Extracted from image screenshot"
        )
        det_elapsed_ms = (time.perf_counter() - det_start) * 1000

        # Step 4: Structured AI Analysis with Multimodal vision part
        ai_res = gemini_service.analyze_content(
            content=extracted_text,
            scan_type="screenshot",
            deterministic_context=det_results,
            image_bytes=image_bytes,
            mime_type=mime_type,
        )

        # Step 5, 6, 7: Reconciliation & Action Plan
        reconciled = scoring_engine.reconcile(
            deterministic_result=det_results,
            gemini_result=ai_res,
            injection_detected=ai_res.get("injection_detected", False),
            scan_type="screenshot",
        )

        # If OCR was incomplete or had notes, add to uncertainty
        if not ocr_ok:
            reconciled["assessment"].uncertainty_notes.append(
                f"Image Extraction Caveat: {ocr_notes}"
            )

        total_elapsed_ms = (time.perf_counter() - start_time) * 1000

        metrics = OperationalMetrics(
            scan_id=scan_id,
            duration_ms=round(total_elapsed_ms, 2),
            deterministic_duration_ms=round(det_elapsed_ms, 2),
            ai_duration_ms=round(ai_res.get("latency_ms", 0.0), 2),
            tokens_used=ai_res.get("tokens_used"),
            timestamp=datetime.now(UTC).isoformat(),
        )

        metrics_service.record_scan(
            scan_type="screenshot",
            risk_level=reconciled["assessment"].risk_level.value,
            threat_type=reconciled["assessment"].threat_type.value,
            duration_ms=total_elapsed_ms,
            det_duration_ms=det_elapsed_ms,
            ai_duration_ms=ai_res.get("latency_ms", 0.0),
            tokens_used=ai_res.get("tokens_used") or 0,
            success=True,
        )

        # Note: We do NOT persist the raw image_bytes in the database (Requirement 6 & 12)
        response = ScanResponse(
            scan_id=scan_id,
            scan_type=ScanType.SCREENSHOT,
            target_analyzed="[Screenshot image processed - raw bytes discarded for privacy]",
            assessment=reconciled["assessment"],
            indicators=reconciled["indicators"],
            evidence=reconciled["evidence"],
            recommendations=reconciled["recommendations"],
            deterministic_checks={
                "ocr_confident": ocr_ok,
                "notes": ocr_notes,
                "extracted_length": len(extracted_text),
            },
            extracted_text=extracted_text,
            metrics=metrics,
            created_at=datetime.now(UTC).isoformat(),
            user_id=user_id,
        )

        storage.save_scan(response, user_id=user_id)
        return response

    def _execute_workflow(
        self,
        scan_type: ScanType,
        raw_input: str,
        additional_context: str | None = None,
        user_id: str | None = "guest",
    ) -> ScanResponse:
        """Internal bounded workflow implementation for text & email."""
        start_time = time.perf_counter()
        scan_id = f"scan_{uuid.uuid4().hex[:12]}"

        # Step 1: Input Validation and Sanitization (Redact sensitive OTPs/cards)
        sanitized_input = sanitize_and_redact_content(raw_input)
        target_preview = sanitized_input[:150] + (
            "..." if len(sanitized_input) > 150 else ""
        )

        # Cache check for instant sub-millisecond repeated analysis
        cache_key = hashlib.sha256(
            f"{scan_type.value}:{sanitized_input}:{additional_context or ''}".encode()
        ).hexdigest()
        with self._cache_lock:
            cached = self._cache.get(cache_key)

        if cached:
            total_elapsed_ms = (time.perf_counter() - start_time) * 1000
            metrics = OperationalMetrics(
                scan_id=scan_id,
                duration_ms=round(total_elapsed_ms, 2),
                deterministic_duration_ms=0.05,
                ai_duration_ms=0.0,
                tokens_used=0,
                timestamp=datetime.now(UTC).isoformat(),
            )
            response = ScanResponse(
                scan_id=scan_id,
                scan_type=scan_type,
                target_analyzed=target_preview,
                assessment=cached["assessment"],
                indicators=cached["indicators"],
                evidence=cached["evidence"],
                recommendations=cached["recommendations"],
                deterministic_checks=cached["deterministic_checks"],
                extracted_text=None,
                metrics=metrics,
                created_at=datetime.now(UTC).isoformat(),
                user_id=user_id,
            )
            storage.save_scan(response, user_id=user_id)
            return response

        # Step 2 & 3: Run Deterministic Security Checks
        det_start = time.perf_counter()
        det_results = detector.analyze_text(sanitized_input, context=additional_context)
        det_elapsed_ms = (time.perf_counter() - det_start) * 1000

        # Step 4: Request Structured AI Analysis (Gemini)
        ai_res = gemini_service.analyze_content(
            content=sanitized_input,
            scan_type=scan_type.value,
            deterministic_context=det_results,
        )

        # Step 5, 6, 7: Reconciliation, Scoring, and Action Plan
        reconciled = scoring_engine.reconcile(
            deterministic_result=det_results,
            gemini_result=ai_res,
            injection_detected=ai_res.get("injection_detected", False),
            scan_type=scan_type.value,
        )

        total_elapsed_ms = (time.perf_counter() - start_time) * 1000

        metrics = OperationalMetrics(
            scan_id=scan_id,
            duration_ms=round(total_elapsed_ms, 2),
            deterministic_duration_ms=round(det_elapsed_ms, 2),
            ai_duration_ms=round(ai_res.get("latency_ms", 0.0), 2),
            tokens_used=ai_res.get("tokens_used"),
            timestamp=datetime.now(UTC).isoformat(),
        )

        metrics_service.record_scan(
            scan_type=scan_type.value,
            risk_level=reconciled["assessment"].risk_level.value,
            threat_type=reconciled["assessment"].threat_type.value,
            duration_ms=total_elapsed_ms,
            det_duration_ms=det_elapsed_ms,
            ai_duration_ms=ai_res.get("latency_ms", 0.0),
            tokens_used=ai_res.get("tokens_used") or 0,
            success=True,
        )

        response = ScanResponse(
            scan_id=scan_id,
            scan_type=scan_type,
            target_analyzed=target_preview,
            assessment=reconciled["assessment"],
            indicators=reconciled["indicators"],
            evidence=reconciled["evidence"],
            recommendations=reconciled["recommendations"],
            deterministic_checks={
                "rules_triggered": det_results.get("rules_triggered_count", 0),
                "deterministic_score": det_results.get("deterministic_score", 0),
            },
            extracted_text=None,
            metrics=metrics,
            created_at=datetime.now(UTC).isoformat(),
            user_id=user_id,
        )

        # Store in LRU cache
        with self._cache_lock:
            if len(self._cache) >= self._cache_max:
                self._cache.clear()
            self._cache[cache_key] = {
                "assessment": reconciled["assessment"],
                "indicators": reconciled["indicators"],
                "evidence": reconciled["evidence"],
                "recommendations": reconciled["recommendations"],
                "deterministic_checks": {
                    "rules_triggered": det_results.get("rules_triggered_count", 0),
                    "deterministic_score": det_results.get("deterministic_score", 0),
                },
            }

        # Step 8: Persist Scan Record
        storage.save_scan(response, user_id=user_id)
        return response


pipeline = BoundedAnalysisPipeline()
