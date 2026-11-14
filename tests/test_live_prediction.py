"""
Tests for Live Alert Prediction Service (On-Demand Single Alert Inference)
Verifies:
1. Valid alert scoring with trained Isolation Forest
2. Missing field auditing and data-quality warnings
3. Ground-truth stripping (zero target leakage)
4. Persistent prediction history logging
5. Input hash generation and auditable prediction ID
"""

import os
import sys
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.live_prediction import (
    score_single_alert,
    get_live_prediction_history,
    GROUND_TRUTH_COLUMNS,
    LEAKAGE_COLUMNS
)

def test_valid_alert_scoring():
    alert = {
        "timestamp_datetime": "2024-07-29 22:30:00",
        "severity": "High",
        "signature_id": "SIG_TEST_01",
        "username": "admin_sys",
        "src_ip": "10.0.1.50",
        "dst_ip": "192.168.1.100",
        "src_port": 22,
        "dst_port": 443,
        "protocol": 6,
        "message_sanitized": "Outbound SSH connection established to external destination"
    }
    res = score_single_alert(alert)
    assert "prediction_id" in res
    assert "anomaly_score" in res
    assert res["priority_label"] in ["Critical", "High", "Medium", "Low"]
    assert isinstance(res["contributing_reasons"], list)
    assert len(res["contributing_reasons"]) > 0
    assert len(res["stripped_ground_truth_fields"]) == 0


def test_missing_fields_and_data_quality_warnings():
    # Submit alert with almost all fields missing
    sparse_alert = {
        "signature_id": "SPARSE_01"
    }
    res = score_single_alert(sparse_alert)
    assert res["priority_label"] in ["Critical", "High", "Medium", "Low"]
    assert "src_ip" in res["missing_fields"]
    assert "dst_ip" in res["missing_fields"]
    assert "username" in res["missing_fields"]
    assert len(res["data_quality_warnings"]) >= 3


def test_ground_truth_stripping_zero_leakage():
    dirty_alert = {
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "incident_ids": "INC-8888",
        "actual_incident": 1,
        "label_binary": "malicious",
        "label_confidence": 0.99,
        "suspicious_rate_per_user": 0.95,
        "incident_rate_per_user": 0.85
    }
    res = score_single_alert(dirty_alert)
    assert "incident_ids" in res["stripped_ground_truth_fields"]
    assert "actual_incident" in res["stripped_ground_truth_fields"]
    assert "label_binary" in res["stripped_ground_truth_fields"]
    assert "incident_ids" not in res["raw_input"]


def test_prediction_history_persistence():
    history_before = len(get_live_prediction_history())
    alert = {"src_ip": "172.16.0.5", "dst_ip": "172.16.0.10", "src_port": 80}
    res = score_single_alert(alert)
    history_after = len(get_live_prediction_history())
    assert history_after == history_before + 1
    recent = get_live_prediction_history()[0]
    assert recent["prediction_id"] == res["prediction_id"]
    assert recent["input_hash"] == res["input_hash"]
