"""
SOC Alert Triage - Evaluation Service
Provides dual ground-truth evaluation, comparative model benchmarking,
and supervisory workload reduction metrics.
"""

import os
import re
import numpy as np
import pandas as pd
from typing import Dict, List, Optional, Tuple, Any

from backend.config import (
    SCORED_DIR,
    LR_VS_BASELINE_COMPARISON_CSV,
)


def parse_incidents(value: Any) -> set:
    """Extract individual incident IDs from a string representation."""
    if pd.isna(value) or str(value).strip() in ("", "[]", "nan", "None", "0"):
        return set()
    cleaned = str(value).strip(" []'\"")
    return set(x for x in re.split(r"[,;|]\s*|\s+", cleaned) if x)


def compute_dual_ground_truth(df: pd.DataFrame) -> pd.DataFrame:
    """
    Enriches alert dataframe with dual ground truth flags:
    1. is_malicious: Ground-truth consolidated security incident (3,113 alerts)
    2. is_suspicious: Verified MITRE ATT&CK activity without consolidated incident_id (10,277 alerts)
    3. is_benign: Background alerts with neither incident ID nor ATT&CK mapping (388,945 alerts)
    4. is_security_relevant: is_malicious OR is_suspicious (13,390 alerts)
    """
    res = df.copy()
    
    # Malicious check
    has_inc = res["incident_ids"].notna() & ~res["incident_ids"].astype(str).str.strip().isin(["", "[]", "nan", "None", "0"])
    if "actual_incident" in res.columns:
        has_inc = has_inc | (pd.to_numeric(res["actual_incident"], errors="coerce").fillna(0) == 1)
    res["_is_malicious"] = has_inc

    # Suspicious check (MITRE tactics or techniques present)
    tactics = res.get("attack_tactics", pd.Series("", index=res.index)).astype(str).str.strip()
    techniques = res.get("attack_techniques", pd.Series("", index=res.index)).astype(str).str.strip()
    has_mitre = (
        tactics.ne("") & ~tactics.isin(["nan", "none", "[]", "0"])
    ) | (
        techniques.ne("") & ~techniques.isin(["nan", "none", "[]", "0"])
    )
    res["_is_suspicious"] = ~has_inc & has_mitre
    res["_is_security_relevant"] = res["_is_malicious"] | res["_is_suspicious"]
    res["_is_benign"] = ~res["_is_security_relevant"]

    return res


def evaluate_top_k_dual(
    df: pd.DataFrame,
    k_list: Optional[List[int]] = None,
    total_unique_incidents: int = 44,
) -> pd.DataFrame:
    """
    Calculates dual-evaluation metrics across specified Top-K ranks.
    Distinguishes Incident Precision (Malicious) from Total Security Precision.
    """
    if k_list is None:
        k_list = [100, 500, 1000, 5000, 10000, 25000]

    enriched = compute_dual_ground_truth(df)
    incident_sets = enriched["incident_ids"].apply(parse_incidents)
    total_alerts = len(enriched)

    records = []
    for k in k_list:
        sub = enriched[enriched["priority_rank"] <= min(k, total_alerts)]
        n = len(sub)
        if n == 0:
            continue

        mal_count = int(sub["_is_malicious"].sum())
        susp_count = int(sub["_is_suspicious"].sum())
        sec_count = int(sub["_is_security_relevant"].sum())
        benign_count = int(sub["_is_benign"].sum())

        found_incidents = set().union(*incident_sets.loc[sub.index])
        uniq_found = len(found_incidents)
        uniq_recall = (uniq_found / total_unique_incidents * 100.0) if total_unique_incidents > 0 else 0.0

        records.append({
            "K": k,
            "Alerts_Evaluated": n,
            "Malicious_Alerts": mal_count,
            "Incident_Precision_Pct": (mal_count / n) * 100.0,
            "Suspicious_Alerts": susp_count,
            "Suspicious_Precision_Pct": (susp_count / n) * 100.0,
            "Total_Security_Alerts": sec_count,
            "Security_Precision_Pct": (sec_count / n) * 100.0,
            "Benign_Background": benign_count,
            "Benign_Fraction_Pct": (benign_count / n) * 100.0,
            "Unique_Incidents_Found": uniq_found,
            "Unique_Incident_Recall_Pct": uniq_recall,
        })

    return pd.DataFrame(records)


def evaluate_review_effort_dual(
    df: pd.DataFrame,
    fractions: Optional[List[float]] = None,
    total_unique_incidents: int = 44,
) -> pd.DataFrame:
    """
    Calculates review workload reduction and discovery across review fractions.
    """
    if fractions is None:
        fractions = [0.001, 0.005, 0.010, 0.020, 0.050, 0.062, 0.100, 0.250]

    enriched = compute_dual_ground_truth(df)
    incident_sets = enriched["incident_ids"].apply(parse_incidents)
    total_alerts = len(enriched)

    records = []
    for frac in fractions:
        rev_count = max(1, int(np.ceil(total_alerts * frac)))
        sub = enriched[enriched["priority_rank"] <= rev_count]
        n = len(sub)

        mal_count = int(sub["_is_malicious"].sum())
        susp_count = int(sub["_is_suspicious"].sum())
        sec_count = int(sub["_is_security_relevant"].sum())
        found_incidents = set().union(*incident_sets.loc[sub.index])
        uniq_found = len(found_incidents)
        uniq_recall = (uniq_found / total_unique_incidents * 100.0) if total_unique_incidents > 0 else 0.0

        avoided_alerts = total_alerts - n
        avoided_pct = (avoided_alerts / total_alerts * 100.0) if total_alerts > 0 else 0.0

        records.append({
            "Review_Fraction": frac,
            "Review_Fraction_Display": f"{frac * 100:.1f}%",
            "Alerts_Reviewed": n,
            "Incidents_Found": mal_count,
            "Suspicious_Found": susp_count,
            "Total_Security_Found": sec_count,
            "Unique_Incidents_Found": uniq_found,
            "Unique_Incident_Recall_Pct": uniq_recall,
            "Alerts_Avoided": avoided_alerts,
            "Alerts_Avoided_Pct": avoided_pct,
        })

    return pd.DataFrame(records)


def generate_comparative_benchmark(
    baseline_df: pd.DataFrame,
    lr_df: pd.DataFrame,
) -> pd.DataFrame:
    """
    Generates comprehensive side-by-side comparison between
    the Original Baseline model and the Leakage-Reduced candidate.
    """
    eval_base = evaluate_top_k_dual(baseline_df)
    eval_lr = evaluate_top_k_dual(lr_df)

    rows = []
    for k in [100, 500, 1000, 5000, 10000, 25000]:
        b_match = eval_base[eval_base["K"] == k]
        l_match = eval_lr[eval_lr["K"] == k]

        b_mal_p = b_match["Incident_Precision_Pct"].iloc[0] if not b_match.empty else np.nan
        l_mal_p = l_match["Incident_Precision_Pct"].iloc[0] if not l_match.empty else np.nan

        b_sec_p = b_match["Security_Precision_Pct"].iloc[0] if not b_match.empty else np.nan
        l_sec_p = l_match["Security_Precision_Pct"].iloc[0] if not l_match.empty else np.nan

        b_uniq = b_match["Unique_Incidents_Found"].iloc[0] if not b_match.empty else np.nan
        l_uniq = l_match["Unique_Incidents_Found"].iloc[0] if not l_match.empty else np.nan

        b_rec = b_match["Unique_Incident_Recall_Pct"].iloc[0] if not b_match.empty else np.nan
        l_rec = l_match["Unique_Incident_Recall_Pct"].iloc[0] if not l_match.empty else np.nan

        rows.append({
            "K": k,
            "Baseline_Incident_Precision": f"{b_mal_p:.1f}%",
            "Leakage_Reduced_Incident_Precision": f"{l_mal_p:.1f}%",
            "Baseline_Security_Precision": f"{b_sec_p:.1f}%",
            "Leakage_Reduced_Security_Precision": f"{l_sec_p:.1f}%",
            "Baseline_Unique_Incidents": f"{int(b_uniq)}/44 ({b_rec:.1f}%)",
            "Leakage_Reduced_Unique_Incidents": f"{int(l_uniq)}/44 ({l_rec:.1f}%)",
        })

    comp_df = pd.DataFrame(rows)
    return comp_df


def save_comparison_table(comp_df: pd.DataFrame, output_path: Optional[str] = None):
    """Saves comparison table to CSV."""
    target = output_path or str(LR_VS_BASELINE_COMPARISON_CSV)
    os.makedirs(os.path.dirname(target), exist_ok=True)
    comp_df.to_csv(target, index=False)
    print(f"Saved comparative evaluation to {target}")
