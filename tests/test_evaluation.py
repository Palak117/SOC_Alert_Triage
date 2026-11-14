"""
Tests for Dual Ground-Truth Evaluation and Metrics Calculation.
"""

import pytest
import pandas as pd
import numpy as np

from backend.data_service import load_dashboard_data
from backend.evaluation_service import (
    compute_dual_ground_truth,
    evaluate_top_k_dual,
    evaluate_review_effort_dual,
    generate_comparative_benchmark,
)


def test_dual_ground_truth_counts():
    alerts, _, _, _ = load_dashboard_data("leakage_reduced")
    enriched = compute_dual_ground_truth(alerts)

    total = len(enriched)
    malicious = int(enriched["_is_malicious"].sum())
    suspicious = int(enriched["_is_suspicious"].sum())
    sec_rel = int(enriched["_is_security_relevant"].sum())
    benign = int(enriched["_is_benign"].sum())

    assert total == 402335, f"Expected 402,335 total alerts, got {total}"
    assert malicious == 3113, f"Expected 3,113 malicious alerts, got {malicious}"
    assert suspicious == 10277, f"Expected 10,277 suspicious ATT&CK alerts, got {suspicious}"
    assert sec_rel == 13390, f"Expected 13,390 security-relevant alerts, got {sec_rel}"
    assert benign == 388945, f"Expected 388,945 benign alerts, got {benign}"
    assert malicious + suspicious == sec_rel
    assert sec_rel + benign == total


def test_top_k_dual_evaluation():
    alerts, _, _, _ = load_dashboard_data("leakage_reduced")
    eval_df = evaluate_top_k_dual(alerts, k_list=[100, 500, 1000, 5000])

    assert len(eval_df) == 4
    # Security Precision@5000 must be > 95%
    top5k = eval_df[eval_df["K"] == 5000].iloc[0]
    assert top5k["Security_Precision_Pct"] > 95.0, f"Expected >95% security precision, got {top5k['Security_Precision_Pct']}%"
    assert top5k["Unique_Incidents_Found"] >= 34


def test_review_effort_dual():
    alerts, _, _, _ = load_dashboard_data("leakage_reduced")
    rev_df = evaluate_review_effort_dual(alerts, fractions=[0.01, 0.02, 0.05])

    assert len(rev_df) == 3
    # At 5% review, all 44 incidents should be discovered
    rev5 = rev_df[rev_df["Review_Fraction"] == 0.05].iloc[0]
    assert rev5["Unique_Incidents_Found"] == 44
    assert rev5["Alerts_Avoided_Pct"] == pytest.approx(95.0, abs=0.1)


def test_comparative_benchmark_generation():
    base_alerts, _, _, _ = load_dashboard_data("baseline")
    lr_alerts, _, _, _ = load_dashboard_data("leakage_reduced")

    comp_df = generate_comparative_benchmark(base_alerts, lr_alerts)
    assert not comp_df.empty
    assert "Baseline_Security_Precision" in comp_df.columns
    assert "Leakage_Reduced_Security_Precision" in comp_df.columns
