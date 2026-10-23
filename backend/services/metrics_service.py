"""
Operational Telemetry and Performance Metrics Service for ScamShield.
Tracks scan latencies (p50, p95), success/error rates, threat distributions, and token usage.
"""

import statistics
from typing import Any


class MetricsService:
    def __init__(self):
        self.total_scans: int = 0
        self.successful_scans: int = 0
        self.failed_scans: int = 0
        self.total_tokens_used: int = 0
        self.scan_types_count: dict[str, int] = {
            "text": 0,
            "email": 0,
            "url": 0,
            "screenshot": 0,
        }
        self.risk_levels_count: dict[str, int] = {
            "LOW": 0,
            "MODERATE": 0,
            "HIGH": 0,
            "CRITICAL": 0,
        }
        self.threat_types_count: dict[str, int] = {}
        self.latencies_ms: list[float] = []
        self.det_latencies_ms: list[float] = []
        self.ai_latencies_ms: list[float] = []

    def record_scan(
        self,
        scan_type: str,
        risk_level: str,
        threat_type: str,
        duration_ms: float,
        det_duration_ms: float,
        ai_duration_ms: float,
        tokens_used: int = 0,
        success: bool = True,
    ):
        """Record operational metrics for a completed scan."""
        self.total_scans += 1
        if success:
            self.successful_scans += 1
        else:
            self.failed_scans += 1

        self.scan_types_count[scan_type] = self.scan_types_count.get(scan_type, 0) + 1
        self.risk_levels_count[risk_level] = (
            self.risk_levels_count.get(risk_level, 0) + 1
        )
        self.threat_types_count[threat_type] = (
            self.threat_types_count.get(threat_type, 0) + 1
        )

        if tokens_used:
            self.total_tokens_used += tokens_used

        self.latencies_ms.append(duration_ms)
        self.det_latencies_ms.append(det_duration_ms)
        if ai_duration_ms > 0:
            self.ai_latencies_ms.append(ai_duration_ms)

        # Cap latency history to last 1000 scans to avoid memory leaks
        if len(self.latencies_ms) > 1000:
            self.latencies_ms.pop(0)
            self.det_latencies_ms.pop(0)
        if len(self.ai_latencies_ms) > 1000:
            self.ai_latencies_ms.pop(0)

    def get_summary(self) -> dict[str, Any]:
        """Generate aggregated operational metrics for the dashboard."""
        avg_latency = statistics.mean(self.latencies_ms) if self.latencies_ms else 0.0
        p50_latency = statistics.median(self.latencies_ms) if self.latencies_ms else 0.0
        p95_latency = (
            statistics.quantiles(self.latencies_ms, n=20)[18]
            if len(self.latencies_ms) >= 20
            else (max(self.latencies_ms) if self.latencies_ms else 0.0)
        )

        avg_det_ms = (
            statistics.mean(self.det_latencies_ms) if self.det_latencies_ms else 0.0
        )
        avg_ai_ms = (
            statistics.mean(self.ai_latencies_ms) if self.ai_latencies_ms else 0.0
        )

        success_rate = (
            (self.successful_scans / self.total_scans * 100)
            if self.total_scans > 0
            else 100.0
        )

        return {
            "total_scans": self.total_scans,
            "successful_scans": self.successful_scans,
            "failed_scans": self.failed_scans,
            "success_rate_percent": round(success_rate, 2),
            "total_tokens_used": self.total_tokens_used,
            "latency_metrics": {
                "avg_ms": round(avg_latency, 2),
                "p50_ms": round(p50_latency, 2),
                "p95_ms": round(p95_latency, 2),
                "avg_deterministic_ms": round(avg_det_ms, 2),
                "avg_ai_ms": round(avg_ai_ms, 2),
            },
            "risk_distribution": self.risk_levels_count,
            "scan_type_distribution": self.scan_types_count,
            "threat_type_distribution": self.threat_types_count,
        }


metrics_service = MetricsService()
