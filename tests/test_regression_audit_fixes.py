"""
Comprehensive Regression Test Suite for SAT-SA Forensic Audit Fixes.
Verifies all 28 audit issues across Phases A, B, C, and D remain permanently resolved.
"""

import os
import sys
import json
import re
from pathlib import Path
import pandas as pd
import numpy as np
import pytest

# Ensure workspace root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.config import DATA_DIR, SCORED_DIR, MODEL_DIR
from backend.batch_prediction import (
    extract_arrival_time_features,
    process_new_submission,
    GROUND_TRUTH_COLUMNS,
    LEAKAGE_COLUMNS
)
from backend.multientity_service import (
    load_multientity_summary,
    get_ranked_regulatory_queue,
    get_telemetry_coverage_matrix,
    generate_supervisory_dossier_text
)


# ==============================================================================
# PHASE A REGRESSION: ARRIVAL-TIME FEATURE ENGINEERING & PRIORS
# ==============================================================================

def test_v6_rarity_priors_file_exists_and_valid():
    """Verify precomputed v6 rarity priors cache exists and is fully populated."""
    priors_file = MODEL_DIR / "v6_rarity_priors.json"
    assert priors_file.exists(), "v6_rarity_priors.json must exist in model/"
    with open(priors_file, "r", encoding="utf-8") as f:
        priors = json.load(f)
    assert "pipeline" in priors
    assert "product_name" in priors
    assert "vendor_name" in priors
    assert "severity" in priors
    assert "action" in priors
    assert "network_behavior" in priors
    assert "high_level_behavior" in priors
    assert "historical_baseline_counts" in priors
    assert "message_length_rarity" in priors


def test_feature_engineering_exact_schema_alignment():
    """Verify extract_arrival_time_features returns exact 50 features matching unsupervised pipeline."""
    sample_df = pd.DataFrame([{
        "_alert_id": "REG_TEST_001",
        "timestamp_datetime": "2024-07-29 20:00:00",
        "timestamp": 1722283200.0,
        "src_ip": "10.0.0.1",
        "dst_ip": "192.168.1.1",
        "src_port": 443,
        "dst_port": 80,
        "protocol": 6,
        "severity": "High",
        "action": "Blocked",
        "product_name": "Firewall",
        "vendor_name": "PaloAlto",
        "message_type": "Traffic",
        "pipeline": "Network",
        "lifecycle_stage": "Detection",
        "category": "Malware"
    }])
    X = extract_arrival_time_features(sample_df)
    assert isinstance(X, pd.DataFrame)
    assert len(X) == 1
    assert X.shape[1] == 50, f"Expected 50 features, got {X.shape[1]}"
    # Verify no NaN values in extracted feature matrix
    assert not X.isna().any().any(), "Features must not contain NaN after alignment"


def test_strict_ground_truth_and_leakage_exclusion():
    """Verify ground truth and leakage columns are strictly forbidden from entering inference."""
    for col in ["incident_ids", "actual_incident", "label_binary", "label_confidence"]:
        assert col in GROUND_TRUTH_COLUMNS
    for col in ["suspicious_rate_per_user", "incident_rate_per_user"]:
        assert col in LEAKAGE_COLUMNS

    # Test that providing leakage/ground-truth columns in raw input does not contaminate extracted features
    dirty_df = pd.DataFrame([{
        "_alert_id": "DIRTY_001",
        "timestamp_datetime": "2024-07-29 20:00:00",
        "actual_incident": 1,
        "incident_ids": "MALICIOUS_LEAK",
        "suspicious_rate_per_user": 0.99,
        "disposition": "Disrupted",
        "src_port": 80
    }])
    X = extract_arrival_time_features(dirty_df)
    for forbidden in GROUND_TRUTH_COLUMNS + LEAKAGE_COLUMNS:
        assert forbidden not in X.columns, f"Forbidden column {forbidden} leaked into feature matrix!"


# ==============================================================================
# PHASE B REGRESSION: MULTI-CSE DATA INTEGRITY & BOUNDED Z-SCORES
# ==============================================================================

def test_multientity_summary_contains_four_entities():
    """Verify all four Critical Sector Entities are represented with 8 statutory domains."""
    summary = load_multientity_summary()
    assert summary["cohort_size"] == 4
    entities = summary["entities"]
    expected_orgs = ["ORG-0001", "ORG-0003", "ORG-0004", "ORG-0005"]
    for org in expected_orgs:
        assert org in entities, f"Entity {org} missing from supervisory summary"

    required_domains = [
        "Threat Detection",
        "Investigation",
        "Escalation",
        "Incident Response",
        "Security Operations",
        "Governance & Oversight",
        "Operational Discipline",
        "Cyber Resilience Index"
    ]
    for org, data in entities.items():
        scores = data.get("scores", {})
        for dom in required_domains:
            assert dom in scores, f"Domain '{dom}' missing for entity {org}"
            val = scores[dom]
            assert 0.0 <= val <= 100.0, f"Domain score {dom} for {org} out of bounds: {val}"


def test_cohort_robust_z_scores_are_strictly_bounded():
    """Verify cohort robust Z-scores do not explode (no +346 sigma artifacts)."""
    summary = load_multientity_summary()
    for org_id, ent in summary["entities"].items():
        z_scores = ent.get("cohort_robust_z", {})
        for metric_name, z_val in z_scores.items():
            assert -5.0 <= z_val <= 5.0, f"Z-score for {org_id} metric {metric_name} is not bounded: {z_val}"


def test_historical_trends_have_genuine_timestamps():
    """Verify historical quarterly trend analysis has genuine dates (no 1970 artifacts)."""
    summary = load_multientity_summary()
    for org_id, ent in summary["entities"].items():
        trends = ent.get("historical_trends", [])
        assert len(trends) == 4, f"Entity {org_id} must have exactly 4 quarters Q1..Q4"
        for tr in trends:
            assert not tr["start_time"].startswith("1970"), f"1970 epoch artifact found in {org_id} trend: {tr['start_time']}"
            assert not tr["end_time"].startswith("1970"), f"1970 epoch artifact found in {org_id} trend: {tr['end_time']}"
            assert tr["alerts"] > 0, f"Quarter alert volume must be positive in {org_id}"


def test_multientity_sample_parquet_exists_and_valid():
    """Verify multi-entity parquet sample is available and spans multiple CSEs."""
    p_path = SCORED_DIR / "dashboard_multientity_sample.parquet"
    assert p_path.exists(), "dashboard_multientity_sample.parquet must exist"
    df = pd.read_parquet(p_path)
    assert len(df) > 0
    assert "org_id" in df.columns
    unique_orgs = df["org_id"].unique().tolist()
    assert len(unique_orgs) == 4, f"Expected 4 distinct CSEs, got {unique_orgs}"


# ==============================================================================
# PHASE C REGRESSION: FRONTEND, THEME & EVALUATION LINKAGES
# ==============================================================================

def test_leakage_reduced_evaluation_files_exist():
    """Verify leakage-reduced evaluation files exist for the model toggle."""
    lr_summary = SCORED_DIR / "leakage_reduced_dashboard_summary.csv"
    lr_incidents = SCORED_DIR / "leakage_reduced_dashboard_incidents.csv"
    lr_review = SCORED_DIR / "leakage_reduced_review_fractions.csv"

    assert lr_summary.exists(), "leakage_reduced_dashboard_summary.csv missing"
    assert lr_incidents.exists(), "leakage_reduced_dashboard_incidents.csv missing"
    assert lr_review.exists(), "leakage_reduced_review_fractions.csv missing"

    df_sum = pd.read_csv(lr_summary)
    assert "K" in df_sum.columns
    assert "Unique_Incidents_Found" in df_sum.columns


def test_air_gapped_sovereignty_no_external_fonts():
    """Verify dashboard/ui_theme.py has zero external web font requests (@import url(https://...))."""
    theme_file = PROJECT_ROOT / "dashboard" / "ui_theme.py"
    content = theme_file.read_text(encoding="utf-8")
    assert "@import url('https://fonts.googleapis.com" not in content, "External Google Fonts @import violates air-gap requirement!"
    assert "fonts.gstatic.com" not in content


def test_xss_prevention_escaping_in_alert_investigation():
    """Verify HTML escaping is implemented in alert_investigation.py."""
    view_file = PROJECT_ROOT / "dashboard" / "views" / "alert_investigation.py"
    content = view_file.read_text(encoding="utf-8")
    assert "html.escape" in content, "alert_investigation.py must use html.escape() for XSS defense"
    assert "def esc(" in content


# ==============================================================================
# PHASE D REGRESSION: TEST ISOLATION & SUBMISSION INTEGRITY
# ==============================================================================

def test_zero_submissions_directory_pollution():
    """Verify data/submissions/ contains no test artifacts."""
    sub_dir = DATA_DIR / "submissions"
    assert sub_dir.exists()
    parquets = list(sub_dir.glob("sub_*.parquet"))
    assert len(parquets) == 0, f"data/submissions/ must be clean of test parquets! Found: {parquets}"


def test_dependencies_in_requirements_txt():
    """Verify plotly and datasets are in requirements.txt."""
    req_file = PROJECT_ROOT / "requirements.txt"
    content = req_file.read_text(encoding="utf-8")
    assert "plotly" in content
    assert "datasets" in content
    assert "pytest" in content


# ==============================================================================
# PHASE E REGRESSION: COMPLETE CSE NAMES & EVALUATION CLARITY
# ==============================================================================

def test_full_cse_names_and_zero_truncation_css():
    """Verify complete official CSE names and multi-line wrapping CSS."""
    theme_file = PROJECT_ROOT / "dashboard" / "ui_theme.py"
    content = theme_file.read_text(encoding="utf-8")

    # Authoritative full entity names
    assert "National Power Grid Infrastructure" in content
    assert "Central Banking & Financial Services" in content
    assert "Defense & National Telecommunications" in content
    assert "Petroleum & Pipeline Control Systems" in content

    # CSS text wrapping rules (no ellipses truncation)
    assert "white-space: normal" in content
    assert "word-break: break-word" in content
    assert "telemetry-chip-cse" in content


def test_binary_classification_vs_ranking_methodology():
    """Verify distinction between ranking evaluation and binary classification accuracy."""
    overview_file = PROJECT_ROOT / "dashboard" / "views" / "overview.py"
    content = overview_file.read_text(encoding="utf-8")

    # Clear distinction documented in view
    assert "Unsupervised Queue Ranking Paradigm" in content
    assert "Binary Classification Benchmark" in content
    assert "Class Imbalance Awareness" in content
    assert "99.57%" in content  # Top 1% binary classification accuracy
    assert "91.94%" in content  # Natural decision boundary accuracy

