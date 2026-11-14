"""
SOC Alert Triage - Batch Prediction Service (On-Demand Inference)
SIH26157 Supervisory Analytics Tool for SOC Assessment (SAT-SA)

Provides on-demand batch inference for new alert submissions (CSV and JSON):
- File validation & SHA-256 deduplication
- Zero-leakage arrival-time feature engineering matching training pipeline
- Scoring with trained Isolation Forest model without retraining
- Queue ranking, priority labeling, and peer-benchmarking
- Persistent submission manifest and history
"""

import os
import sys
import json
import hashlib
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Union

import pandas as pd
import numpy as np

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.config import (
    BASE_DIR,
    DATA_DIR,
    SCORED_DIR,
    MODEL_DIR,
)
from backend.model_service import ModelService
from backend.data_service import vectorize_priority_label

SUBMISSIONS_DIR = DATA_DIR / "submissions"
MANIFEST_FILE = SUBMISSIONS_DIR / "submission_manifest.json"
PRIORS_FILE = MODEL_DIR / "v6_rarity_priors.json"

# Ground-truth columns that must NEVER enter feature extraction or model inference
GROUND_TRUTH_COLUMNS = [
    "incident_ids",
    "actual_incident",
    "label_binary",
    "label_confidence",
    "_incident",
    "is_false_positive",
    "v6_scores_or_ranks_modified",
]

# Leakage proxy columns that must NEVER enter inference
LEAKAGE_COLUMNS = [
    "suspicious_rate_per_user",
    "incident_rate_per_user",
]
LEAKAGE_FEATURES = LEAKAGE_COLUMNS

_PRIORS_CACHE: Optional[Dict[str, Any]] = None


def get_rarity_priors() -> Dict[str, Any]:
    """Load empirical training rarity and baseline distributions cached in memory."""
    global _PRIORS_CACHE
    if _PRIORS_CACHE is None:
        if PRIORS_FILE.exists():
            try:
                with open(PRIORS_FILE, "r", encoding="utf-8") as f:
                    _PRIORS_CACHE = json.load(f)
            except Exception:
                _PRIORS_CACHE = {}
        else:
            _PRIORS_CACHE = {}
    return _PRIORS_CACHE


def ensure_submissions_directory():
    """Ensure submission directory and manifest file exist."""
    os.makedirs(SUBMISSIONS_DIR, exist_ok=True)
    if not MANIFEST_FILE.exists():
        with open(MANIFEST_FILE, "w", encoding="utf-8") as f:
            json.dump([], f, indent=2)


def compute_content_hash(content_bytes: bytes) -> str:
    """Compute SHA-256 hash of raw submission content."""
    return hashlib.sha256(content_bytes).hexdigest()


def get_submission_manifest() -> List[Dict[str, Any]]:
    """Retrieve list of all processed submissions."""
    ensure_submissions_directory()
    try:
        with open(MANIFEST_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, list):
                return data
            elif isinstance(data, dict):
                return list(data.values())
            return []
    except Exception:
        return []


def is_duplicate_submission(content_hash: str) -> Optional[Dict[str, Any]]:
    """Check if submission with identical SHA-256 hash already exists."""
    manifest = get_submission_manifest()
    for entry in manifest:
        if entry.get("file_sha256") == content_hash:
            return entry
    return None


def clean_string_series(series: Optional[pd.Series], default_empty: str = "") -> pd.Series:
    """Safely normalizes string values without converting np.nan to 'nan' string."""
    if series is None:
        return pd.Series(default_empty)
    cleaned = series.fillna("").astype(str).str.strip().str.lower()
    return cleaned.replace({"nan": default_empty, "none": default_empty, "null": default_empty})


def extract_arrival_time_features(raw_df: pd.DataFrame, expected_features: Optional[List[str]] = None) -> pd.DataFrame:
    """
    Applies exact arrival-time feature engineering matching the training pipeline.
    Guarantees that no ground-truth columns are used.
    Reconstructs empirical rarity lookups and historical baseline prior counts.
    """
    if expected_features is None:
        try:
            expected_features = ModelService.get_model().feature_names_in_.tolist()
        except Exception:
            expected_features = []
    df = raw_df.copy()

    # Strip any ground-truth labels if present in uploaded file
    for gt_col in GROUND_TRUTH_COLUMNS + LEAKAGE_COLUMNS:
        if gt_col in df.columns:
            df = df.drop(columns=[gt_col])

    features_df = pd.DataFrame(index=df.index)
    priors = get_rarity_priors()

    # 1. Temporal Features
    ts_series = None
    if "timestamp_datetime" in df.columns:
        ts_series = pd.to_datetime(df["timestamp_datetime"], errors="coerce")
    elif "timestamp" in df.columns:
        # Check if numeric epoch seconds
        num_ts = pd.to_numeric(df["timestamp"], errors="coerce")
        if num_ts.notna().any():
            ts_series = pd.to_datetime(num_ts, unit="s", errors="coerce")
        else:
            ts_series = pd.to_datetime(df["timestamp"], errors="coerce")
    elif "event_time" in df.columns:
        ts_series = pd.to_datetime(df["event_time"], errors="coerce")

    if ts_series is not None and ts_series.notna().any():
        dt = ts_series.dt
        hour = dt.hour.fillna(12)
        dow = dt.dayofweek.fillna(0)
    else:
        hour = pd.Series(12, index=df.index)
        dow = pd.Series(0, index=df.index)

    features_df["hour"] = hour
    features_df["day_of_week"] = dow
    features_df["is_weekend"] = dow.isin([5, 6]).astype(int)
    features_df["hour_sin"] = np.sin(2 * np.pi * hour / 24.0)
    features_df["hour_cos"] = np.cos(2 * np.pi * hour / 24.0)
    features_df["dow_sin"] = np.sin(2 * np.pi * dow / 7.0)
    features_df["dow_cos"] = np.cos(2 * np.pi * dow / 7.0)

    # 2. Port & Protocol Features
    src_p = pd.to_numeric(df["src_port"] if "src_port" in df.columns else pd.Series(0, index=df.index), errors="coerce").fillna(0)
    dst_p = pd.to_numeric(df["dst_port"] if "dst_port" in df.columns else pd.Series(0, index=df.index), errors="coerce").fillna(0)
    proto = pd.to_numeric(df["protocol"] if "protocol" in df.columns else pd.Series(0, index=df.index), errors="coerce").fillna(0)

    features_df["src_port"] = src_p
    features_df["dst_port"] = dst_p
    features_df["protocol"] = proto
    features_df["same_port"] = (src_p == dst_p).astype(int)

    # Privileged port: 0 < port < 1024 (strictly matching training)
    features_df["src_port_privileged"] = ((src_p > 0) & (src_p < 1024)).astype(int)
    features_df["dst_port_privileged"] = ((dst_p > 0) & (dst_p < 1024)).astype(int)

    # Port categories: 0=missing/zero, 1=<1024, 2=<49152, 3>=49152
    features_df["src_port_category"] = np.select([src_p == 0, src_p < 1024, src_p < 49152, src_p >= 49152], [0, 1, 2, 3], default=0)
    features_df["dst_port_category"] = np.select([dst_p == 0, dst_p < 1024, dst_p < 49152, dst_p >= 49152], [0, 1, 2, 3], default=0)

    # Protocol category: {1: 1, 6: 6, 17: 17, other: 0}
    features_df["protocol_category"] = np.select([proto == 1, proto == 6, proto == 17], [1, 6, 17], default=0)

    # 3. Entity Presence Indicators (safely checking non-empty)
    src_ip_clean = clean_string_series(df["src_ip"] if "src_ip" in df.columns else None)
    dst_ip_clean = clean_string_series(df["dst_ip"] if "dst_ip" in df.columns else None)
    src_host_clean = clean_string_series(df["src_host"] if "src_host" in df.columns else None)
    dst_host_clean = clean_string_series(df["dst_host"] if "dst_host" in df.columns else None)

    features_df["has_src_ip"] = (src_ip_clean != "").astype(int)
    features_df["has_dst_ip"] = (dst_ip_clean != "").astype(int)
    features_df["has_src_host"] = (src_host_clean != "").astype(int)
    features_df["has_dst_host"] = (dst_host_clean != "").astype(int)

    # 4. Message Characteristics
    if "message_sanitized" in df.columns:
        msg_raw = df["message_sanitized"]
    elif "message" in df.columns:
        msg_raw = df["message"]
    else:
        msg_raw = pd.Series("", index=df.index)

    msg_clean = msg_raw.fillna("").astype(str).str.strip().replace({"nan": "", "None": "", "null": ""})
    features_df["message_length"] = msg_clean.str.len()
    features_df["message_word_count"] = msg_clean.apply(lambda x: len(x.split()) if x else 0)
    features_df["message_digit_count"] = msg_clean.str.count(r"\d")
    features_df["message_special_count"] = msg_clean.str.count(r"[^a-zA-Z0-9\s]")

    # Fixed behavioral bucket thresholds matching training [0, 100, 500, 1000, 5000]
    features_df["message_size_bucket"] = np.select(
        [
            features_df["message_length"] == 0,
            features_df["message_length"] <= 100,
            features_df["message_length"] <= 500,
            features_df["message_length"] <= 1000,
            features_df["message_length"] <= 5000,
            features_df["message_length"] > 5000,
        ],
        [0, 1, 2, 3, 4, 5],
        default=0,
    )

    # Numeric bucket rarities (if expected by Baseline V6)
    if "message_length_rarity" in expected_features:
        bins_l = priors.get("message_length_bins", [-1, 115, 500, 1000, 2000, 3000, 4000, 5000, 1e9])
        cut_l = pd.cut(features_df["message_length"], bins=bins_l, labels=False, include_lowest=True).astype(str)
        features_df["message_length_rarity"] = cut_l.map(priors.get("message_length_rarity", {})).fillna(1.0)

    if "message_word_count_rarity" in expected_features:
        bins_w = priors.get("message_word_bins", [-1, 14, 25, 50, 100, 200, 300, 360, 1e9])
        cut_w = pd.cut(features_df["message_word_count"], bins=bins_w, labels=False, include_lowest=True).astype(str)
        features_df["message_word_count_rarity"] = cut_w.map(priors.get("message_word_count_rarity", {})).fillna(1.0)

    # 5. User Features
    user_raw = df["username"] if "username" in df.columns else (df["user"] if "user" in df.columns else pd.Series("", index=df.index))
    user_clean = clean_string_series(user_raw)
    features_df["has_username"] = (user_clean != "").astype(int)
    features_df["username_length"] = user_clean.str.len()

    # Suspicion score (if expected by Baseline V6)
    if "suspicion_score" in expected_features:
        features_df["suspicion_score"] = pd.to_numeric(df["suspicion_score"] if "suspicion_score" in df.columns else pd.Series(0.0, index=df.index), errors="coerce").fillna(0.0)

    # 6. Static Categorical Rarities (reconstructed from training priors)
    rarity_cols = ["pipeline", "product_name", "vendor_name", "message_type", "stream_name", "action", "severity"]
    if "lifecycle_stage_rarity" in expected_features:
        rarity_cols.append("lifecycle_stage")

    for col in rarity_cols:
        col_out = f"{col}_rarity"
        if col_out in expected_features:
            vals = clean_string_series(df[col] if col in df.columns else None)
            rmap = priors.get(col, {})
            raw_rarity = vals.map(rmap).fillna(1.0)
            if col == "lifecycle_stage":
                # In training V6, lifecycle_stage_rarity did not use np.log1p
                features_df[col_out] = raw_rarity
            else:
                features_df[col_out] = np.log1p(raw_rarity)

    # 7. Combination Rarities (network_behavior & high_level_behavior)
    pipeline_clean = clean_string_series(df["pipeline"] if "pipeline" in df.columns else None)
    product_clean = clean_string_series(df["product_name"] if "product_name" in df.columns else None)
    msg_type_clean = clean_string_series(df["message_type"] if "message_type" in df.columns else None)
    action_clean = clean_string_series(df["action"] if "action" in df.columns else None)
    protocol_clean = clean_string_series(df["protocol"] if "protocol" in df.columns else None)

    if "network_behavior_rarity" in expected_features:
        dst_port_cat_str = features_df["dst_port_category"].astype(str)
        net_combo = (
            pipeline_clean + "|" +
            product_clean + "|" +
            msg_type_clean + "|" +
            action_clean + "|" +
            protocol_clean + "|" +
            dst_port_cat_str
        )
        features_df["network_behavior_rarity"] = net_combo.map(priors.get("network_behavior", {})).fillna(1.0)

    if "high_level_behavior_rarity" in expected_features:
        src_port_cat_str = features_df["src_port_category"].astype(str)
        dst_port_cat_str = features_df["dst_port_category"].astype(str)
        high_combo = (
            pipeline_clean + "|" +
            msg_type_clean + "|" +
            action_clean + "|" +
            protocol_clean + "|" +
            src_port_cat_str + "|" +
            dst_port_cat_str
        )
        features_df["high_level_behavior_rarity"] = high_combo.map(priors.get("high_level_behavior", {})).fillna(1.0)

    # 8. Causal History Features (combining historical training priors with arrival sequence)
    base_counts = priors.get("historical_baseline_counts", {})
    hist_cols = ["src_ip", "src_host", "username", "product_name", "message_type", "pipeline"]

    for col in hist_cols:
        col_prev = f"{col}_previous_count"
        col_first = f"{col}_first_seen"
        if col_prev in expected_features or col_first in expected_features:
            vals = clean_string_series(df[col] if col in df.columns else None)
            bmap = base_counts.get(col, {})
            prior_c = vals.map(bmap).fillna(0).astype(int)
            cum = vals.groupby(vals).cumcount()
            tot_c = prior_c + cum
            features_df[col_prev] = np.log1p(tot_c)
            features_df[col_first] = (tot_c == 0).astype(int)

    if "behavior_previous_count" in expected_features or "behavior_first_seen" in expected_features:
        beh_series = pipeline_clean + "|" + product_clean + "|" + msg_type_clean + "|" + action_clean
        b_prior = beh_series.map(base_counts.get("behavior", {})).fillna(0).astype(int)
        bcum = beh_series.groupby(beh_series).cumcount()
        btot = b_prior + bcum
        features_df["behavior_previous_count"] = np.log1p(btot)
        features_df["behavior_first_seen"] = (btot == 0).astype(int)

    # Fill any remaining expected features with 0.0 if not directly derivable
    for f in expected_features:
        if f not in features_df.columns:
            features_df[f] = 0.0

    # Ensure columns match expected model feature order and are numeric
    features_df = features_df[expected_features].apply(pd.to_numeric, errors="coerce").fillna(0.0)
    return features_df


def process_new_submission(
    content_bytes: Optional[bytes] = None,
    filename: str = "batch.csv",
    model_type: str = "leakage_reduced",
    file_bytes: Optional[bytes] = None,
    user_notes: str = "",
) -> Tuple[bool, str, Optional[pd.DataFrame], Optional[Dict[str, Any]]]:
    """
    On-Demand Inference Pipeline:
    1. Deduplication check via SHA-256
    2. Parse CSV / JSON safely
    3. Zero-leakage arrival-time feature engineering matching training
    4. Isolation Forest model scoring
    5. Priority ranking & labeling
    6. Persistent storage and manifest registration
    """
    if content_bytes is None and file_bytes is not None:
        content_bytes = file_bytes
    if content_bytes is None:
        return False, "No file content received.", None, None

    ensure_submissions_directory()
    content_hash = compute_content_hash(content_bytes)

    # Check for duplicate
    existing = is_duplicate_submission(content_hash)
    if existing:
        res_file = Path(existing.get("result_file", ""))
        if res_file.exists():
            existing_df = pd.read_parquet(res_file) if res_file.suffix == ".parquet" else pd.read_csv(res_file)
            dup_meta = dict(existing)
            dup_meta["is_duplicate"] = True
            dup_meta["sha256"] = content_hash
            dup_meta["row_count"] = len(existing_df)
            return True, f"Duplicate submission recognized. Loaded previous results from {existing.get('timestamp')}.", existing_df, dup_meta

    # Parse input content safely
    try:
        from io import BytesIO
        if filename.lower().endswith(".json"):
            raw_df = pd.read_json(BytesIO(content_bytes))
        else:
            raw_df = pd.read_csv(BytesIO(content_bytes), low_memory=False)
    except Exception as e:
        return False, f"Failed to parse alert file: {e}", None, None

    if raw_df.empty:
        return False, "Uploaded file contains 0 alert records.", None, None

    total_rows = len(raw_df)

    # Strip ground truth and leakage columns to guarantee zero target leakage
    all_forbidden = GROUND_TRUTH_COLUMNS + LEAKAGE_COLUMNS
    stripped_labels = [c for c in all_forbidden if c in raw_df.columns]
    for c in stripped_labels:
        raw_df = raw_df.drop(columns=[c])

    # Assign _alert_id if missing
    if "_alert_id" not in raw_df.columns:
        raw_df["_alert_id"] = raw_df.index.astype(int)

    # Model feature preparation & scoring
    try:
        expected_features = ModelService.get_feature_names(model_type)
        X = extract_arrival_time_features(raw_df, expected_features)
        scores, ranks = ModelService.score_features(X, model_type)
    except Exception as e:
        return False, f"Model inference failed: {e}", None, None

    # Attach predictions
    result_df = raw_df.copy()
    result_df["anomaly_score"] = scores
    result_df["predicted_anomaly_score"] = scores
    result_df["priority_score"] = scores
    result_df["priority_rank"] = ranks
    result_df["priority_label"] = vectorize_priority_label(result_df)
    result_df["top_reason_code"] = "MODEL_ANOMALY"

    # Format timestamp
    if "timestamp_datetime" in result_df.columns:
        result_df["Timestamp"] = pd.to_datetime(result_df["timestamp_datetime"], errors="coerce").dt.strftime("%Y-%m-%d %H:%M:%S")
    elif "timestamp" in result_df.columns:
        num_ts = pd.to_numeric(result_df["timestamp"], errors="coerce")
        if num_ts.notna().any():
            result_df["Timestamp"] = pd.to_datetime(num_ts, unit="s", errors="coerce").dt.strftime("%Y-%m-%d %H:%M:%S")
        else:
            result_df["Timestamp"] = pd.to_datetime(result_df["timestamp"], errors="coerce").dt.strftime("%Y-%m-%d %H:%M:%S")
    else:
        result_df["Timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Sort in ascending rank order
    result_df = result_df.sort_values("priority_rank", ascending=True).reset_index(drop=True)

    # Save to submissions directory
    safe_name = Path(filename).name
    submission_id = f"sub_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{content_hash[:8]}"
    out_parquet = SUBMISSIONS_DIR / f"{submission_id}.parquet"
    out_csv = SUBMISSIONS_DIR / f"{submission_id}.csv"

    try:
        result_df.to_parquet(out_parquet, engine="pyarrow", index=False)
        saved_file = str(out_parquet)
    except Exception:
        result_df.to_csv(out_csv, index=False)
        saved_file = str(out_csv)

    # Register in manifest
    manifest_entry = {
        "submission_id": submission_id,
        "filename": safe_name,
        "file_sha256": content_hash,
        "sha256": content_hash,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "model_used": model_type,
        "alert_count": total_rows,
        "row_count": total_rows,
        "mean_anomaly_score": float(np.mean(scores)),
        "max_anomaly_score": float(np.max(scores)),
        "critical_count": int((result_df["priority_label"] == "Critical").sum()),
        "high_count": int((result_df["priority_label"] == "High").sum()),
        "result_file": saved_file,
        "stripped_ground_truth_fields": stripped_labels,
        "is_duplicate": False,
    }

    manifest = get_submission_manifest()
    manifest.append(manifest_entry)
    with open(MANIFEST_FILE, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    msg = f"Successfully scored {total_rows:,} alerts using {model_type} model. Priority queue generated."
    return True, msg, result_df, manifest_entry
