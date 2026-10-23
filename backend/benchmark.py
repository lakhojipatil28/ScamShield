"""
Reproducible Benchmark Script for ScamShield.
Evaluates precision, recall, F1-score, and latency distributions across labeled synthetic test cases.
Usage: python backend/benchmark.py
"""

import json
import os
import statistics
import sys
import time
from typing import Any

# Ensure parent directory is in sys.path for direct script execution
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.services.pipeline import pipeline


def run_benchmark(
    dataset_path: str = "backend/data/labeled_samples.json",
) -> dict[str, Any]:
    if not os.path.exists(dataset_path):
        print(f"Error: Dataset not found at {dataset_path}")
        return {}

    with open(dataset_path, encoding="utf-8") as f:
        samples = json.load(f)

    print("\n==================================================================")
    print("  SCAMSHIELD REPRODUCIBLE BENCHMARK ENGINE")
    print(f"  Evaluating {len(samples)} synthetic test cases...")
    print("==================================================================\n")

    true_positives = 0
    true_negatives = 0
    false_positives = 0
    false_negatives = 0

    latencies_ms: list[float] = []
    det_latencies_ms: list[float] = []

    results = []

    for item in samples:
        sample_id = item["id"]
        sample_type = item["type"]
        content = item["content"]
        expected_level = item["expected_risk_level"]
        is_expected_malicious = expected_level in ["HIGH", "CRITICAL", "MODERATE"]

        t0 = time.perf_counter()
        if sample_type == "text":
            res = pipeline.process_text_scan(content, user_id="benchmark")
        elif sample_type == "email":
            res = pipeline.process_email_scan(content, user_id="benchmark")
        elif sample_type == "url":
            res = pipeline.process_url_scan(content, user_id="benchmark")
        else:
            continue

        elapsed_ms = (time.perf_counter() - t0) * 1000
        latencies_ms.append(elapsed_ms)
        det_latencies_ms.append(res.metrics.deterministic_duration_ms)

        pred_level = res.assessment.risk_level.value
        is_pred_malicious = pred_level in ["HIGH", "CRITICAL", "MODERATE"]

        if is_expected_malicious and is_pred_malicious:
            true_positives += 1
            outcome = "TP"
        elif not is_expected_malicious and not is_pred_malicious:
            true_negatives += 1
            outcome = "TN"
        elif not is_expected_malicious and is_pred_malicious:
            false_positives += 1
            outcome = "FP"
        else:
            false_negatives += 1
            outcome = "FN"

        results.append(
            {
                "id": sample_id,
                "type": sample_type,
                "expected": expected_level,
                "predicted": pred_level,
                "score": res.assessment.risk_score,
                "latency_ms": round(elapsed_ms, 2),
                "outcome": outcome,
            }
        )

        print(
            f"[{outcome}] {sample_id:<12} | Type: {sample_type:<6} | Expected: {expected_level:<8} | Predicted: {pred_level:<8} ({res.assessment.risk_score:3d}) | Latency: {elapsed_ms:5.1f}ms"
        )

    # Metrics computation
    total = len(results)
    precision = (
        (true_positives / (true_positives + false_positives))
        if (true_positives + false_positives) > 0
        else 0.0
    )
    recall = (
        (true_positives / (true_positives + false_negatives))
        if (true_positives + false_negatives) > 0
        else 0.0
    )
    f1 = (
        (2 * precision * recall / (precision + recall))
        if (precision + recall) > 0
        else 0.0
    )
    accuracy = ((true_positives + true_negatives) / total) if total > 0 else 0.0

    p50_lat = statistics.median(latencies_ms) if latencies_ms else 0.0
    p95_lat = (
        statistics.quantiles(latencies_ms, n=20)[18]
        if len(latencies_ms) >= 20
        else max(latencies_ms)
    )
    avg_det_ms = statistics.mean(det_latencies_ms) if det_latencies_ms else 0.0

    print("\n==================================================================")
    print("  BENCHMARK SUMMARY & PERFORMANCE AUDIT")
    print("==================================================================")
    print(f"  Total Test Cases Evaluated : {total}")
    print(f"  True Positives (TP)        : {true_positives}")
    print(f"  True Negatives (TN)        : {true_negatives}")
    print(f"  False Positives (FP)       : {false_positives}")
    print(f"  False Negatives (FN)       : {false_negatives}")
    print("  --------------------------------------------------------------")
    print(f"  Accuracy                   : {accuracy * 100:.2f}%")
    print(f"  Precision                  : {precision * 100:.2f}%")
    print(f"  Recall (Sensitivity)       : {recall * 100:.2f}%")
    print(f"  F1-Score                   : {f1 * 100:.2f}%")
    print("  --------------------------------------------------------------")
    print(f"  Average E2E Latency        : {statistics.mean(latencies_ms):.2f} ms")
    print(f"  Median Latency (p50)       : {p50_lat:.2f} ms")
    print(f"  p95 Latency                : {p95_lat:.2f} ms")
    print(f"  Avg Deterministic Rule Time: {avg_det_ms:.2f} ms")
    print("==================================================================\n")

    summary = {
        "total": total,
        "true_positives": true_positives,
        "true_negatives": true_negatives,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "avg_latency_ms": round(statistics.mean(latencies_ms), 2),
        "p50_latency_ms": round(p50_lat, 2),
        "p95_latency_ms": round(p95_lat, 2),
        "avg_deterministic_ms": round(avg_det_ms, 2),
    }

    with open("backend/benchmark_results.json", "w", encoding="utf-8") as out:
        json.dump(summary, out, indent=2)

    return summary


if __name__ == "__main__":
    run_benchmark()
