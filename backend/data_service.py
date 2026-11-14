"""
SOC Alert Triage - Data Service
High-performance data consolidation, loading, caching, and querying service.
Provides sub-second data access via pre-consolidated Apache Parquet storage.
"""

import os
import sys
import re
import numpy as np
import pandas as pd
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

from backend.config import (
    BASE_DIR,
    DATA_DIR,
    SCORED_DIR,
    CONSOLIDATED_PARQUET,
    CONSOLIDATED_CSV,
    CONSOLIDATED_LR_PARQUET,
    CONSOLIDATED_LR_CSV,
    BASELINE_ALERTS_CSV,
    BASELINE_INCIDENTS_CSV,
    BASELINE_SUMMARY_CSV,
    BASELINE_REVIEW_CSV,
    LR_ALERTS_CSV,
    LR_INCIDENTS_CSV,
    LR_SUMMARY_CSV,
    LR_REVIEW_CSV,
    CONTEXT_LAYER_CSV,
    SUPERVISORY_AUDIT_CSV,
    SUPERVISORY_COMPLETE_CSV,
    CORE_COLUMNS,
)

# Optional Streamlit caching decorator
try:
    import streamlit as st
    cache_decorator = st.cache_data(show_spinner=False)
except ImportError:
    def cache_decorator(func):
        return func


def parse_incident_ids(value: Any) -> set:
    """Extract individual incident IDs from a string representation."""
    if pd.isna(value) or str(value).strip() in ("", "[]", "nan", "None", "0"):
        return set()
    cleaned = str(value).strip(" []'\"")
    return set(x for x in re.split(r"[,;|]\s*|\s+", cleaned) if x)


def vectorize_priority_label(df: pd.DataFrame) -> pd.Series:
    """
    Vectorized computation of display-only Priority label.
    Uses source severity if present, otherwise uses priority rank percentile:
    - Top 1%: Critical
    - Top 5%: High
    - Top 20%: Medium
    - Remainder: Low
    """
    total = len(df)
    if total == 0:
        return pd.Series(dtype=str)

    ranks = pd.to_numeric(df.get("priority_rank", pd.Series(np.nan, index=df.index)), errors="coerce")
    percentile = ranks / total

    label = pd.Series("Low", index=df.index)
    label[percentile <= 0.20] = "Medium"
    label[percentile <= 0.05] = "High"
    label[percentile <= 0.01] = "Critical"

    if "severity" in df.columns:
        sev = df["severity"].astype(str).str.lower()
        has_sev = sev.str.strip().ne("") & ~sev.isin(["nan", "none", "unknown", "null"])
        label[has_sev & sev.str.contains("low", na=False)] = "Low"
        label[has_sev & sev.str.contains("medium", na=False)] = "Medium"
        label[has_sev & sev.str.contains("high", na=False)] = "High"
        label[has_sev & sev.str.contains("critical", na=False)] = "Critical"

    return label


def build_incident_table_from_alerts(alerts_df: pd.DataFrame) -> pd.DataFrame:
    """
    Generates incident-level aggregation table from scored alerts.
    Calculates first discovered rank, best anomaly score, and metadata per incident.
    """
    has_inc = alerts_df["incident_ids"].notna() & ~alerts_df["incident_ids"].astype(str).str.strip().isin(["", "[]", "nan", "None"])
    incident_alerts = alerts_df[has_inc].copy()

    records = []
    # Explode alerts that have multiple incident IDs
    for idx, row in incident_alerts.iterrows():
        inc_ids = parse_incident_ids(row["incident_ids"])
        for inc_id in inc_ids:
            records.append({
                "incident_id": inc_id,
                "_alert_id": row.get("_alert_id", idx),
                "priority_rank": row.get("priority_rank", np.nan),
                "anomaly_score": row.get("anomaly_score", np.nan),
                "priority_score": row.get("priority_score", row.get("anomaly_score", np.nan)),
                "timestamp": row.get("Timestamp", row.get("timestamp_datetime", str(row.get("timestamp", "")))),
                "severity": row.get("severity", "Unknown"),
                "origin": row.get("origin", "Unknown"),
                "product_name": row.get("product_name", "Unknown"),
                "vendor_name": row.get("vendor_name", "Unknown"),
                "lifecycle_stage": row.get("lifecycle_stage", "Unknown"),
                "disposition": row.get("disposition", "Unknown"),
                "status_name": row.get("status_name", "Unknown"),
            })

    if not records:
        return pd.DataFrame(columns=[
            "incident_id", "alert_count", "first_priority_rank", "best_anomaly_score",
            "best_priority_score", "first_timestamp", "highest_severity",
            "origin", "product_name", "vendor_name", "lifecycle_stage", "disposition", "status_name"
        ])

    df_records = pd.DataFrame(records)
    grouped = df_records.groupby("incident_id")

    incidents_list = []
    for inc_id, group in grouped:
        sorted_group = group.sort_values("priority_rank", ascending=True)
        first_row = sorted_group.iloc[0]
        incidents_list.append({
            "incident_id": inc_id,
            "alert_count": len(group),
            "first_priority_rank": int(first_row["priority_rank"]) if pd.notna(first_row["priority_rank"]) else 999999,
            "best_anomaly_score": float(sorted_group["anomaly_score"].max()),
            "best_priority_score": float(sorted_group["priority_score"].max()),
            "first_timestamp": str(first_row["timestamp"]),
            "highest_severity": str(first_row["severity"]),
            "origin": str(first_row["origin"]),
            "product_name": str(first_row["product_name"]),
            "vendor_name": str(first_row["vendor_name"]),
            "lifecycle_stage": str(first_row["lifecycle_stage"]),
            "disposition": str(first_row["disposition"]),
            "status_name": str(first_row["status_name"]),
        })

    inc_df = pd.DataFrame(incidents_list)
    return inc_df.sort_values("first_priority_rank", ascending=True).reset_index(drop=True)


def build_evaluation_tables(alerts_df: pd.DataFrame, incidents_df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """
    Builds Top-K Summary and Review Fractions tables matching SIH evaluation format.
    """
    total = len(alerts_df)
    unique_incidents = len(incidents_df) if not incidents_df.empty else 44

    # Pre-parse incident sets for fast recall checking
    incident_sets = alerts_df["incident_ids"].apply(parse_incident_ids)
    is_incident = incident_sets.apply(bool)

    # 1. Top-K Summary
    k_values = [100, 500, 1000, 5000, 10000, 25000, 50000, 100000]
    summary_rows = []
    for k in k_values:
        sub = alerts_df[alerts_df["priority_rank"] <= k]
        inc_count = int(is_incident.loc[sub.index].sum())
        prec = (inc_count / len(sub)) * 100 if len(sub) > 0 else 0.0
        recall = (inc_count / is_incident.sum()) * 100 if is_incident.sum() > 0 else 0.0
        
        found_ids = set().union(*incident_sets.loc[sub.index]) if len(sub) > 0 else set()
        uniq_found = len(found_ids)
        uniq_recall = (uniq_found / unique_incidents) * 100 if unique_incidents > 0 else 0.0
        
        outside = total - len(sub)
        outside_pct = outside / total if total > 0 else 0.0

        summary_rows.append({
            "K": k,
            "Incidents_Found": inc_count,
            "Precision": prec / 100.0,
            "Incident_Recall": recall / 100.0,
            "Unique_Incidents_Found": uniq_found,
            "Unique_Incident_Recall": uniq_recall / 100.0,
            "Alerts_Outside_Top_K": outside,
            "Fraction_Outside_Top_K_Percentage": outside_pct,
        })
    summary_df = pd.DataFrame(summary_rows)

    # 2. Review Fractions
    fractions = [0.001, 0.005, 0.010, 0.020, 0.050, 0.100, 0.250]
    review_rows = []
    for frac in fractions:
        rev_count = max(1, int(np.ceil(total * frac)))
        sub = alerts_df[alerts_df["priority_rank"] <= rev_count]
        inc_count = int(is_incident.loc[sub.index].sum())
        
        found_ids = set().union(*incident_sets.loc[sub.index]) if len(sub) > 0 else set()
        uniq_found = len(found_ids)
        uniq_recall = (uniq_found / unique_incidents) if unique_incidents > 0 else 0.0
        
        avoided = total - rev_count
        avoided_pct = avoided / total if total > 0 else 0.0

        review_rows.append({
            "Review_Fraction": frac,
            "Alerts_Reviewed": rev_count,
            "Incidents_Found": inc_count,
            "Unique_Incidents_Found": uniq_found,
            "Unique_Incident_Recall": uniq_recall,
            "Alerts_Avoided": avoided,
            "Alerts_Avoided_Percentage": avoided_pct,
        })
    review_df = pd.DataFrame(review_rows)

    return summary_df, review_df


def consolidate_data(
    source_alerts_path: Path,
    output_parquet: Path,
    output_csv: Path,
    incidents_output_path: Optional[Path] = None,
    summary_output_path: Optional[Path] = None,
    review_output_path: Optional[Path] = None,
) -> pd.DataFrame:
    """
    Consolidates raw alerts with Context Layer, Supervisory Audit, and Complete Audit
    into an optimized Parquet and fallback CSV file with pre-computed fields.
    """
    print(f"Consolidating alerts from: {source_alerts_path} ...")
    alerts = pd.read_csv(source_alerts_path, low_memory=False)

    # Ensure _alert_id exists and is numeric int32
    if "_alert_id" not in alerts.columns:
        alerts["_alert_id"] = alerts.index.astype("int32")
    else:
        alerts["_alert_id"] = pd.to_numeric(alerts["_alert_id"], errors="coerce").fillna(alerts.index.to_series()).astype("int32")

    # Clean numeric score fields
    alerts["anomaly_score"] = pd.to_numeric(alerts.get("anomaly_score", 0), errors="coerce").fillna(0.0).astype("float32")
    if "priority_score" not in alerts.columns:
        alerts["priority_score"] = alerts["anomaly_score"]
    else:
        alerts["priority_score"] = pd.to_numeric(alerts["priority_score"], errors="coerce").fillna(alerts["anomaly_score"]).astype("float32")

    if "priority_rank" not in alerts.columns:
        alerts["priority_rank"] = alerts["anomaly_score"].rank(method="first", ascending=False).astype("int32")
    else:
        alerts["priority_rank"] = pd.to_numeric(alerts["priority_rank"], errors="coerce").fillna(999999).astype("int32")

    # Formatted Timestamp
    if "timestamp_datetime" in alerts.columns and alerts["timestamp_datetime"].notna().any():
        alerts["Timestamp"] = pd.to_datetime(alerts["timestamp_datetime"], errors="coerce").dt.strftime("%Y-%m-%d %H:%M:%S")
    elif "timestamp" in alerts.columns:
        alerts["Timestamp"] = pd.to_datetime(alerts["timestamp"], unit="s", errors="coerce").dt.strftime("%Y-%m-%d %H:%M:%S")
    else:
        alerts["Timestamp"] = ""
    alerts["Timestamp"] = alerts["Timestamp"].fillna("")

    # Ground Truth & Dual Security Relevance
    has_inc = alerts["incident_ids"].notna() & ~alerts["incident_ids"].astype(str).str.strip().isin(["", "[]", "nan", "None"])
    alerts["actual_incident"] = has_inc.astype("int8")

    tactics = alerts.get("attack_tactics", pd.Series("", index=alerts.index)).astype(str).str.strip()
    techniques = alerts.get("attack_techniques", pd.Series("", index=alerts.index)).astype(str).str.strip()
    has_mitre = (
        tactics.ne("") & ~tactics.isin(["nan", "none", "[]", "0"])
    ) | (
        techniques.ne("") & ~techniques.isin(["nan", "none", "[]", "0"])
    )
    alerts["is_suspicious_mitre"] = (~has_inc & has_mitre).astype("int8")
    alerts["security_relevant"] = (has_inc | has_mitre).astype("int8")

    # Vectorized display-only Priority label
    alerts["priority_label"] = vectorize_priority_label(alerts)

    # 1. Merge Context Layer
    if CONTEXT_LAYER_CSV.exists():
        print(f"Merging Context Layer from {CONTEXT_LAYER_CSV.name}...")
        context_df = pd.read_csv(CONTEXT_LAYER_CSV, low_memory=False)
        if "_alert_id" in context_df.columns:
            context_df["_alert_id"] = pd.to_numeric(context_df["_alert_id"], errors="coerce").astype("int32")
            ctx_fields = [
                c for c in [
                    "_alert_id", "evidence_gap_count", "evidence_gap_signal", "evidence_gap_level",
                    "investigation_without_evidence_signal", "low_telemetry_signal", "no_escalation_context_signal",
                    "critical_missing_context_signal", "repetitive_investigation_signal", "negative_space_signal",
                    "execution_gap_count", "execution_gap_level", "context_reason", "entity_key",
                    "entity_alert_frequency", "repeated_entity_signal", "high_frequency_entity_signal"
                ] if c in context_df.columns
            ]
            context_sub = context_df[ctx_fields].drop_duplicates("_alert_id")
            alerts = alerts.merge(context_sub, on="_alert_id", how="left", suffixes=("", "_ctx"))
            for c in ctx_fields:
                if c != "_alert_id" and f"{c}_ctx" in alerts.columns:
                    alerts[c] = alerts[f"{c}_ctx"]
                    alerts.drop(columns=[f"{c}_ctx"], inplace=True)

    # 2. Merge Supervisory Audit
    if SUPERVISORY_AUDIT_CSV.exists():
        print(f"Merging Supervisory Audit from {SUPERVISORY_AUDIT_CSV.name}...")
        audit_df = pd.read_csv(SUPERVISORY_AUDIT_CSV, low_memory=False)
        if "_alert_id" in audit_df.columns:
            audit_df["_alert_id"] = pd.to_numeric(audit_df["_alert_id"], errors="coerce").astype("int32")
            audit_fields = [
                c for c in [
                    "_alert_id", "peer_comparison_supported", "peer_comparison_status",
                    "supervisory_peer_reason", "supervisory_review_reason",
                    "supervisory_review_recommended", "supervisory_disclaimer",
                    "rapid_closure_duration_supported", "remediation_completion_supported",
                    "incident_labels_used_for_peer_comparison", "v6_scores_or_ranks_modified"
                ] if c in audit_df.columns
            ]
            audit_sub = audit_df[audit_fields].drop_duplicates("_alert_id")
            alerts = alerts.merge(audit_sub, on="_alert_id", how="left", suffixes=("", "_aud"))
            for c in audit_fields:
                if c != "_alert_id" and f"{c}_aud" in alerts.columns:
                    alerts[c] = alerts[f"{c}_aud"]
                    alerts.drop(columns=[f"{c}_aud"], inplace=True)

    # 3. Merge Supervisory Complete
    if SUPERVISORY_COMPLETE_CSV.exists():
        print(f"Merging Complete Supervisory Analytics from {SUPERVISORY_COMPLETE_CSV.name}...")
        complete_df = pd.read_csv(SUPERVISORY_COMPLETE_CSV, low_memory=False)
        if "_alert_id" in complete_df.columns:
            complete_df["_alert_id"] = pd.to_numeric(complete_df["_alert_id"], errors="coerce").astype("int32")
            comp_fields = [
                "_alert_id", "supervisory_evidence_gap_review", "supervisory_review_reason_codes",
                "supervisory_evidence_source_fields", "supervisory_traceability_note",
                "peer_comparison_supported_computed", "peer_deviation_review_signal",
                "peer_comparison_interpretation", "entity_frequency_review_signal",
                "entity_frequency_basis", "entity_frequency_interpretation", "peer_group_size",
                "supervisory_evidence_gap_count", "supervisory_execution_gap_count",
                "supervisory_negative_space_count"
            ]
            comp_fields += [c for c in complete_df.columns if c.startswith("peer_robust_z_") or c.startswith("peer_outlier_")]
            comp_fields = [c for c in dict.fromkeys(comp_fields) if c in complete_df.columns]
            comp_sub = complete_df[comp_fields].drop_duplicates("_alert_id")
            alerts = alerts.merge(comp_sub, on="_alert_id", how="left", suffixes=("", "_comp"))
            for c in comp_fields:
                if c != "_alert_id" and f"{c}_comp" in alerts.columns:
                    alerts[c] = alerts[f"{c}_comp"]
                    alerts.drop(columns=[f"{c}_comp"], inplace=True)

    # Filter to essential columns that exist
    final_cols = [c for c in CORE_COLUMNS if c in alerts.columns]
    # Add any remaining non-redundant columns
    alerts = alerts[final_cols].sort_values("priority_rank", ascending=True).reset_index(drop=True)

    # Save to Parquet and CSV
    os.makedirs(output_parquet.parent, exist_ok=True)
    print(f"Writing Parquet to {output_parquet}...")
    try:
        alerts.to_parquet(output_parquet, engine="pyarrow", compression="snappy", index=False)
        print(f"Successfully saved Parquet: {output_parquet.stat().st_size / (1024*1024):.2f} MB")
    except Exception as e:
        print(f"Warning: Failed to write Parquet: {e}")

    print(f"Writing CSV to {output_csv}...")
    alerts.to_csv(output_csv, index=False)
    print(f"Successfully saved CSV: {output_csv.stat().st_size / (1024*1024):.2f} MB")

    # Generate matching Incidents, Summary, and Review tables
    inc_df = build_incident_table_from_alerts(alerts)
    if incidents_output_path:
        inc_df.to_csv(incidents_output_path, index=False)
        print(f"Saved incident summary to {incidents_output_path}")

    summary_df, review_df = build_evaluation_tables(alerts, inc_df)
    if summary_output_path:
        summary_df.to_csv(summary_output_path, index=False)
        print(f"Saved summary metrics to {summary_output_path}")
    if review_output_path:
        review_df.to_csv(review_output_path, index=False)
        print(f"Saved review fractions to {review_output_path}")

    return alerts


@cache_decorator
def load_dashboard_data(model_type: str = "leakage_reduced") -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """
    Ultra-fast cached data loader.
    Loads pre-consolidated parquet in ~0.15s, falls back to CSV if needed.
    Returns: (alerts_df, incidents_df, summary_df, review_df)
    """
    if model_type == "baseline":
        parquet_path = CONSOLIDATED_PARQUET
        csv_path = CONSOLIDATED_CSV
        incidents_path = BASELINE_INCIDENTS_CSV
        summary_path = BASELINE_SUMMARY_CSV
        review_path = BASELINE_REVIEW_CSV
    else:
        parquet_path = CONSOLIDATED_LR_PARQUET
        csv_path = CONSOLIDATED_LR_CSV
        incidents_path = LR_INCIDENTS_CSV
        summary_path = LR_SUMMARY_CSV
        review_path = LR_REVIEW_CSV

    # 1. Load Alerts
    if parquet_path.exists():
        alerts = pd.read_parquet(parquet_path, engine="pyarrow")
    elif csv_path.exists():
        alerts = pd.read_csv(csv_path, low_memory=False)
    elif model_type == "baseline" and BASELINE_ALERTS_CSV.exists():
        alerts = pd.read_csv(BASELINE_ALERTS_CSV, low_memory=False)
    elif LR_ALERTS_CSV.exists():
        alerts = pd.read_csv(LR_ALERTS_CSV, low_memory=False)
    else:
        alerts = pd.DataFrame()

    # 2. Load Incidents
    if incidents_path.exists():
        incidents = pd.read_csv(incidents_path)
    elif BASELINE_INCIDENTS_CSV.exists():
        incidents = pd.read_csv(BASELINE_INCIDENTS_CSV)
    else:
        incidents = pd.DataFrame()

    # 3. Load Summary
    if summary_path.exists():
        summary = pd.read_csv(summary_path)
    elif BASELINE_SUMMARY_CSV.exists():
        summary = pd.read_csv(BASELINE_SUMMARY_CSV)
    else:
        summary = pd.DataFrame()

    # 4. Load Review Fractions
    if review_path.exists():
        review = pd.read_csv(review_path)
    elif BASELINE_REVIEW_CSV.exists():
        review = pd.read_csv(BASELINE_REVIEW_CSV)
    else:
        review = pd.DataFrame()

    return alerts, incidents, summary, review


def get_top_k(alerts: pd.DataFrame, k: int = 100) -> pd.DataFrame:
    """Retrieve top K alerts by priority rank."""
    if alerts.empty:
        return alerts
    return alerts.nsmallest(min(k, len(alerts)), "priority_rank").reset_index(drop=True)


def get_alert_by_id(alerts: pd.DataFrame, alert_id: int) -> Optional[pd.Series]:
    """Retrieve complete metadata and signals for an alert by _alert_id."""
    if alerts.empty or "_alert_id" not in alerts.columns:
        return None
    matches = alerts[alerts["_alert_id"] == alert_id]
    if matches.empty:
        return None
    return matches.iloc[0]


def filter_alerts(
    alerts: pd.DataFrame,
    query: str = "",
    severity_filter: Optional[List[str]] = None,
    priority_filter: Optional[List[str]] = None,
    origin_filter: Optional[List[str]] = None,
    incident_only: bool = False,
    security_relevant_only: bool = False,
    has_gaps_only: bool = False,
    max_rank: Optional[int] = None,
) -> pd.DataFrame:
    """Fast vectorized filtering of alerts table."""
    if alerts.empty:
        return alerts

    filtered = alerts

    if max_rank is not None and max_rank > 0:
        filtered = filtered[filtered["priority_rank"] <= max_rank]

    if incident_only:
        filtered = filtered[filtered["actual_incident"] == 1]

    if security_relevant_only and "security_relevant" in filtered.columns:
        filtered = filtered[filtered["security_relevant"] == 1]

    if has_gaps_only and "evidence_gap_count" in filtered.columns:
        filtered = filtered[filtered["evidence_gap_count"] > 0]

    if severity_filter:
        sev_clean = [s.strip().lower() for s in severity_filter]
        filtered = filtered[filtered["severity"].astype(str).str.lower().isin(sev_clean)]

    if priority_filter and "priority_label" in filtered.columns:
        filtered = filtered[filtered["priority_label"].isin(priority_filter)]

    if origin_filter:
        filtered = filtered[filtered["origin"].astype(str).isin(origin_filter)]

    if query and query.strip():
        q = query.strip().lower()
        search_cols = ["message_sanitized", "entity_key", "src_ip", "dst_ip", "username", "product_name", "action"]
        search_cols = [c for c in search_cols if c in filtered.columns]
        
        mask = pd.Series(False, index=filtered.index)
        for col in search_cols:
            mask |= filtered[col].astype(str).str.lower().str.contains(q, na=False)
        filtered = filtered[mask]

    return filtered
