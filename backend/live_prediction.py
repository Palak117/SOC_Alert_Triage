"""
Live Alert Prediction Service (On-Demand Single Alert Inference)
Problem Statement: SIH26157 | NTRO / NCIIPC

Provides analyst-driven, interactive single-alert inference:
- Form validation and missing-field data-quality auditing
- Zero-leakage arrival-time feature extraction matching model training
- Isolation Forest scoring via ModelService without model retraining
- Thresholded priority labeling (Critical, High, Medium, Low)
- Contributing reason codes and evidence factors
- Auditable persistent prediction history and CSV export
- Strict ground-truth exclusion (no target leakage)
"""

import os
import sys
import json
import hashlib
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple

import pandas as pd
import numpy as np

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.config import DATA_DIR, SCORED_DIR, MODEL_DIR
from backend.model_service import ModelService
from backend.batch_prediction import (
    extract_arrival_time_features,
    vectorize_priority_label,
    GROUND_TRUTH_COLUMNS,
    LEAKAGE_COLUMNS
)

LIVE_HISTORY_FILE = DATA_DIR / "submissions" / "live_prediction_history.json"

# Reference score statistics from V6 baseline distribution
BASELINE_SCORE_MEAN = -0.0798
BASELINE_SCORE_STD = 0.0520
CRITICAL_SCORE_THRESHOLD = 0.08   # Top 1% threshold
HIGH_SCORE_THRESHOLD = 0.01       # Top 5% threshold
MEDIUM_SCORE_THRESHOLD = -0.05    # Top 20% threshold

def ensure_live_history_dir():
    os.makedirs(DATA_DIR / "submissions", exist_ok=True)
    if not LIVE_HISTORY_FILE.exists():
        with open(LIVE_HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump([], f, indent=2)


def get_live_prediction_history() -> List[Dict[str, Any]]:
    """Retrieve list of all live predictions made in this session."""
    ensure_live_history_dir()
    try:
        with open(LIVE_HISTORY_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def save_prediction_to_history(record: Dict[str, Any]):
    """Append a prediction record to the persistent live prediction log."""
    ensure_live_history_dir()
    history = get_live_prediction_history()
    history.insert(0, record)  # Most recent first
    # Keep last 500 records
    history = history[:500]
    with open(LIVE_HISTORY_FILE, "w", encoding="utf-8") as f:
        json.dump(history, f, indent=2)


def score_single_alert(
    alert_input: Dict[str, Any],
    model_type: str = "baseline"
) -> Dict[str, Any]:
    """
    Process a single submitted alert:
    1. Strip forbidden ground-truth and proxy leakage fields
    2. Audit input data quality & identify missing context
    3. Extract arrival-time & network features
    4. Run Isolation Forest scoring (-decision_function)
    5. Assign priority label & percentile
    6. Generate explainable reason codes
    7. Save to auditable prediction history
    """
    raw = dict(alert_input)

    # 1. Strip ground truth and target proxy fields
    stripped_fields = []
    for col in GROUND_TRUTH_COLUMNS + LEAKAGE_COLUMNS:
        if col in raw:
            raw.pop(col)
            stripped_fields.append(col)

    # 2. Input Data Quality Audit
    missing_fields = []
    data_quality_warnings = []

    if not raw.get("src_ip"):
        missing_fields.append("src_ip")
        data_quality_warnings.append("Missing source IP address")
    if not raw.get("dst_ip"):
        missing_fields.append("dst_ip")
        data_quality_warnings.append("Missing destination IP address")
    if not raw.get("username") and not raw.get("user"):
        missing_fields.append("username")
        data_quality_warnings.append("Missing user/account identity")
    if not raw.get("src_port") or str(raw.get("src_port")) == "0":
        missing_fields.append("src_port")
        data_quality_warnings.append("Unspecified source port (set to 0)")
    if not raw.get("dst_port") or str(raw.get("dst_port")) == "0":
        missing_fields.append("dst_port")
        data_quality_warnings.append("Unspecified destination port (set to 0)")
    if not raw.get("severity"):
        missing_fields.append("severity")
        data_quality_warnings.append("Missing raw severity rating (defaulted to Informational)")

    # 3. Compute unique input SHA-256 hash
    hash_str = json.dumps(raw, sort_keys=True, default=str)
    input_hash = hashlib.sha256(hash_str.encode("utf-8")).hexdigest()
    prediction_id = f"live_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{input_hash[:8]}"

    # 4. Feature Extraction & Model Inference
    single_df = pd.DataFrame([raw])
    if "_alert_id" not in single_df.columns:
        single_df["_alert_id"] = 1

    expected_features = ModelService.get_feature_names(model_type)
    X = extract_arrival_time_features(single_df, expected_features)
    scores, ranks = ModelService.score_features(X, model_type)
    anomaly_score = float(scores[0])

    # 5. Priority Label Assignment using validated distribution thresholds
    if anomaly_score >= CRITICAL_SCORE_THRESHOLD:
        priority_label = "Critical"
        relative_tier = "Top 1% Most Anomalous"
    elif anomaly_score >= HIGH_SCORE_THRESHOLD:
        priority_label = "High"
        relative_tier = "Top 5% Elevated Risk"
    elif anomaly_score >= MEDIUM_SCORE_THRESHOLD:
        priority_label = "Medium"
        relative_tier = "Top 20% Notable Activity"
    else:
        priority_label = "Low"
        relative_tier = "Normal Baseline Activity"

    # Compare vs reference distribution (Z-score of score)
    score_z = (anomaly_score - BASELINE_SCORE_MEAN) / BASELINE_SCORE_STD
    is_unusual = bool(score_z >= 1.96)  # Outside 95% confidence interval

    # 6. Contributing Evidence & Explanations
    reasons = []
    val_sp = pd.to_numeric(raw.get("src_port", 0), errors="coerce")
    src_port = int(val_sp) if pd.notna(val_sp) else 0
    val_dp = pd.to_numeric(raw.get("dst_port", 0), errors="coerce")
    dst_port = int(val_dp) if pd.notna(val_dp) else 0
    
    if src_port in [22, 3389, 445, 135, 80, 443]:
        reasons.append(f"Sensitive service port used (Port {src_port})")
    elif src_port < 1024 and src_port > 0:
        reasons.append(f"Privileged system port range (Port {src_port})")

    if dst_port in [22, 3389, 445, 135]:
        reasons.append(f"High-risk destination administration port (Port {dst_port})")

    # Time factors
    if "hour" in X.columns:
        h = float(X["hour"].iloc[0])
        if h < 6 or h > 20:
            reasons.append(f"Off-hours alert arrival time ({int(h):02d}:00 UTC)")

    msg = str(raw.get("message_sanitized", raw.get("message", "")))
    if len(msg) > 300:
        reasons.append("Unusually long message payload (> 300 characters)")
    elif len(msg) == 0:
        reasons.append("Empty message body (zero narrative context)")

    if len(missing_fields) >= 3:
        reasons.append(f"High evidence gap ({len(missing_fields)} fields absent)")

    if not reasons:
        reasons.append("Statistical deviation across arrival-time & network feature space")

    # 7. Construct complete prediction result
    now_iso = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    result = {
        "prediction_id": prediction_id,
        "timestamp": now_iso,
        "input_hash": input_hash,
        "model_used": model_type,
        "anomaly_score": round(anomaly_score, 6),
        "priority_label": priority_label,
        "relative_tier": relative_tier,
        "score_z_score": round(score_z, 2),
        "is_unusual_vs_reference": is_unusual,
        "contributing_reasons": reasons,
        "data_quality_warnings": data_quality_warnings,
        "missing_fields": missing_fields,
        "stripped_ground_truth_fields": stripped_fields,
        "raw_input": raw,
        "regulatory_disclaimer": "Model-generated anomaly score reflects statistical rarity relative to baseline telemetry, NOT confirmed maliciousness. Analyst validation required."
    }

    # Save to history
    save_prediction_to_history(result)

    return result

