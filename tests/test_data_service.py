"""
Tests for DataService and data consolidation.
"""

import pytest
import pandas as pd
import numpy as np

from backend.config import (
    CONSOLIDATED_LR_PARQUET,
    CONSOLIDATED_PARQUET,
)
from backend.data_service import (
    load_dashboard_data,
    get_top_k,
    get_alert_by_id,
    filter_alerts,
    vectorize_priority_label,
)


def test_consolidated_parquet_files_exist():
    assert CONSOLIDATED_LR_PARQUET.exists(), "Leakage-Reduced consolidated parquet must exist."
    assert CONSOLIDATED_PARQUET.exists(), "Baseline consolidated parquet must exist."


def test_load_dashboard_data_leakage_reduced():
    alerts, incidents, summary, review = load_dashboard_data("leakage_reduced")
    assert not alerts.empty, "Alerts dataframe must not be empty."
    assert len(alerts) == 402335, f"Expected 402,335 alerts, got {len(alerts)}"

    # Required columns
    expected_cols = [
        "_alert_id", "anomaly_score", "priority_score", "priority_rank",
        "priority_label", "Timestamp", "actual_incident", "security_relevant"
    ]
    for col in expected_cols:
        assert col in alerts.columns, f"Required column '{col}' missing from alerts."

    assert not incidents.empty, "Incidents dataframe must not be empty."
    assert not summary.empty, "Summary dataframe must not be empty."
    assert not review.empty, "Review dataframe must not be empty."


def test_load_dashboard_data_baseline():
    alerts, incidents, summary, review = load_dashboard_data("baseline")
    assert not alerts.empty, "Baseline alerts must not be empty."
    assert len(alerts) == 402335, f"Expected 402,335 alerts, got {len(alerts)}"


def test_get_top_k():
    alerts, _, _, _ = load_dashboard_data("leakage_reduced")
    top_10 = get_top_k(alerts, k=10)
    assert len(top_10) == 10
    # Ranks should be 1 to 10
    assert list(top_10["priority_rank"]) == list(range(1, 11))


def test_get_alert_by_id():
    alerts, _, _, _ = load_dashboard_data("leakage_reduced")
    alert_0 = get_alert_by_id(alerts, alert_id=0)
    assert alert_0 is not None
    assert alert_0["_alert_id"] == 0

    non_existent = get_alert_by_id(alerts, alert_id=9999999)
    assert non_existent is None


def test_filter_alerts():
    alerts, _, _, _ = load_dashboard_data("leakage_reduced")
    sample = alerts.head(1000)

    # Filter by incident only
    filtered_inc = filter_alerts(sample, incident_only=True)
    assert (filtered_inc["actual_incident"] == 1).all()

    # Filter by max rank
    filtered_rank = filter_alerts(sample, max_rank=50)
    assert len(filtered_rank) == 50
    assert (filtered_rank["priority_rank"] <= 50).all()


def test_vectorize_priority_label():
    df = pd.DataFrame({
        "priority_rank": [1, 50, 500, 2000],
        "severity": ["Critical", "High", "Low", "Unknown"]
    })
    labels = vectorize_priority_label(df)
    assert labels.iloc[0] == "Critical"
    assert labels.iloc[1] == "High"
    assert labels.iloc[2] == "Low"
