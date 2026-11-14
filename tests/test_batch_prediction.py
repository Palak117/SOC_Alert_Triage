"""
Tests for on-demand batch prediction engine (SIH26157 SAT-SA).
Verifies CSV/JSON submission, Isolation Forest inference, SHA-256 deduplication,
and strict exclusion of ground-truth labels from inference.
"""

import os
import sys
import json
import uuid
import pandas as pd
import pytest

# Ensure workspace root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.batch_prediction import (
    process_new_submission,
    get_submission_manifest,
    GROUND_TRUTH_COLUMNS,
    LEAKAGE_FEATURES
)

def make_sample_alerts():
    u = uuid.uuid4().hex[:8]
    return [
        {
            "_alert_id": f"test_alert_001_{u}",
            "timestamp_datetime": "2024-07-29 20:45:00",
            "severity": "High",
            "signature_id": f"SIG_1001_{u}",
            "category": "Malware",
            "user": "analyst_alice",
            "src_ip": "10.0.0.1",
            "dest_ip": "192.168.1.100",
            "asset_criticality": "Critical",
            "attack_tactics": "Execution",
            "attack_techniques": "T1059",
            "matched_rules": "RULE_DEF_1"
        },
        {
            "_alert_id": f"test_alert_002_{u}",
            "timestamp_datetime": "2024-07-29 20:46:00",
            "severity": "Medium",
            "signature_id": f"SIG_1002_{u}",
            "category": "Suspicious_Activity",
            "user": "analyst_bob",
            "src_ip": "10.0.0.2",
            "dest_ip": "192.168.1.101",
            "asset_criticality": "Medium",
            "attack_tactics": "Persistence",
            "attack_techniques": "T1547",
            "matched_rules": "RULE_DEF_2"
        },
        {
            "_alert_id": f"test_alert_003_{u}",
            "timestamp_datetime": "2024-07-29 20:47:00",
            "severity": "Low",
            "signature_id": f"SIG_1003_{u}",
            "category": "Policy_Violation",
            "user": "analyst_alice",
            "src_ip": "10.0.0.3",
            "dest_ip": "192.168.1.102",
            "asset_criticality": "Low",
            "attack_tactics": "Discovery",
            "attack_techniques": "T1087",
            "matched_rules": "RULE_DEF_3"
        }
    ]

def test_batch_prediction_csv():
    alerts = make_sample_alerts()
    df_raw = pd.DataFrame(alerts)
    csv_bytes = df_raw.to_csv(index=False).encode("utf-8")
    
    success, msg, df_scored, meta = process_new_submission(
        file_bytes=csv_bytes,
        filename="test_sample_batch.csv",
        user_notes="Pytest CSV Batch"
    )
    
    assert success is True
    assert df_scored is not None
    assert len(df_scored) == 3
    assert "submission_id" in meta
    assert meta["is_duplicate"] is False
    
    assert "predicted_anomaly_score" in df_scored.columns
    assert "priority_rank" in df_scored.columns
    assert "priority_label" in df_scored.columns
    assert "top_reason_code" in df_scored.columns
    
    # Check ranking monotonicity
    scores = df_scored["predicted_anomaly_score"].tolist()
    assert scores == sorted(scores, reverse=True)


def test_batch_prediction_json():
    alerts = make_sample_alerts()
    json_bytes = json.dumps(alerts).encode("utf-8")
    
    success, msg, df_scored, meta = process_new_submission(
        file_bytes=json_bytes,
        filename="test_sample_batch.json",
        user_notes="Pytest JSON Batch"
    )
    
    assert success is True
    assert df_scored is not None
    assert len(df_scored) == 3
    assert meta["is_duplicate"] is False


def test_batch_prediction_deduplication():
    # Submit the exact same bytes twice
    alerts = make_sample_alerts()
    json_bytes = json.dumps(alerts).encode("utf-8")
    
    s1, m1, df1, meta1 = process_new_submission(json_bytes, "dup_check.json")
    s2, m2, df2, meta2 = process_new_submission(json_bytes, "dup_check.json")
    
    assert s1 is True
    assert s2 is True
    assert meta1["is_duplicate"] is False
    assert meta2["is_duplicate"] is True
    assert meta1["submission_id"] == meta2["submission_id"]


def test_batch_prediction_ground_truth_stripping():
    # Intentionally inject ground truth and leakage columns
    alerts = make_sample_alerts()
    dirty_alerts = []
    for a in alerts:
        dirty = dict(a)
        dirty["incident_ids"] = "INC-9999"
        dirty["actual_incident"] = 1
        dirty["label_binary"] = 1
        dirty["label_confidence"] = 0.99
        dirty["suspicious_rate_per_user"] = 0.95
        dirty["incident_rate_per_user"] = 0.85
        dirty_alerts.append(dirty)
    
    csv_bytes = pd.DataFrame(dirty_alerts).to_csv(index=False).encode("utf-8")
    success, msg, scored_df, meta = process_new_submission(csv_bytes, "dirty_leakage_batch.csv")
    
    assert success is True
    assert scored_df is not None
    
    # Ground truth columns MUST be completely excluded from scored outputs
    for col in GROUND_TRUTH_COLUMNS:
        assert col not in scored_df.columns, f"Ground-truth column {col} was found in scored output!"
    
    for col in LEAKAGE_FEATURES:
        assert col not in scored_df.columns, f"Leakage column {col} was found in scored output!"


def test_manifest_persistence():
    manifest = get_submission_manifest()
    assert isinstance(manifest, list)
    assert len(manifest) >= 1
    assert "submission_id" in manifest[0]
