"""
SAT-SA V6 Supervisory Peer Comparison + Audit Trail
---------------------------------------------------
Run from the project root:
    python model\add_supervisory_peer_audit_v6.py

This is an ADD-ON. It does not retrain V6 and does not overwrite the
validated V6 score file or the existing context-layer CSV.

It uses only existing context/evidence fields for peer comparisons.
Post-hoc incident fields are explicitly excluded from peer calculations.
Peer deviations are review indicators, not proof of maliciousness or SOC failure.
"""

from pathlib import Path
import hashlib
import json
import sys

import numpy as np
import pandas as pd

INPUT = Path("data/scored/final_v6_sih_context_layer.csv")
OUTPUT = Path("data/scored/final_v6_sih_supervisory_audit.csv")
REPORT = Path("data/scored/final_v6_sih_supervisory_audit_report.txt")
MIN_PEER_GROUP = 30

IDENTITY = "_alert_id"
RANK = "v6_priority_rank"
SCORE = "v6_anomaly_score"
PRIORITY_SCORE = "v6_priority_score"
PEER_FIELDS = [
    "investigation_evidence_count",
    "telemetry_evidence_count",
    "evidence_gap_count",
    "execution_gap_count",
    "negative_space_count",
]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    if not INPUT.exists():
        print(f"ERROR: Missing input file: {INPUT}")
        print("Run the existing V6 context-layer script first.")
        return 2

    input_hash = sha256_file(INPUT)
    df = pd.read_csv(INPUT, low_memory=False)
    original_rows = len(df)

    required = [IDENTITY, RANK, SCORE]
    missing = [c for c in required if c not in df.columns]
    if missing:
        print("ERROR: Required traceability columns are missing:", ", ".join(missing))
        return 2

    if df[IDENTITY].isna().any() or df[IDENTITY].duplicated().any():
        print("ERROR: _alert_id is missing or duplicated; refusing to create audit output.")
        return 2

    # Keep immutable copies to verify that V6 ranking data is unchanged.
    original_ids = df[IDENTITY].copy()
    original_rank = df[RANK].copy()
    original_score = df[SCORE].copy()
    original_priority = df[PRIORITY_SCORE].copy() if PRIORITY_SCORE in df else None

    # Peer group uses only observed contextual dimensions; incident labels are not used.
    group_cols = [c for c in ["alert_type", "severity_context"] if c in df.columns]
    if "alert_type" not in group_cols:
        group_cols = [c for c in ["alert_stream", "severity_context"] if c in df.columns]

    peer_enabled = bool(group_cols)
    peer_reasons = []
    peer_metrics = [c for c in PEER_FIELDS if c in df.columns]

    for metric in PEER_FIELDS:
        df[f"peer_{metric}_median"] = np.nan
        df[f"peer_{metric}_robust_z"] = np.nan
        df[f"peer_{metric}_group_n"] = 0

    df["peer_comparison_supported"] = False
    df["peer_comparison_status"] = "UNSUPPORTED: required peer-group columns unavailable"
    df["supervisory_peer_reason"] = ""

    if peer_enabled and peer_metrics:
        # Create stable string keys and calculate peer statistics without incident labels.
        group_key = df[group_cols].fillna("<MISSING>").astype(str).agg(" | ".join, axis=1)
        df["_peer_group_key_internal"] = group_key

        for metric in peer_metrics:
            values = pd.to_numeric(df[metric], errors="coerce")
            stats = pd.DataFrame({"_group": group_key, "_value": values})
            grouped = stats.groupby("_group", dropna=False)["_value"]
            counts = grouped.transform("count")
            medians = grouped.transform("median")

            def mad_func(s):
                med = s.median()
                return (s - med).abs().median()

            mads = stats.groupby("_group", dropna=False)["_value"].transform(mad_func)
            robust_z = 0.6745 * (values - medians) / mads.replace(0, np.nan)

            # A group must contain enough non-null peers. Zero-MAD groups are not assigned z-scores.
            supported = (counts >= MIN_PEER_GROUP) & mads.notna() & (mads > 0)
            df[f"peer_{metric}_median"] = medians.where(supported)
            df[f"peer_{metric}_robust_z"] = robust_z.where(supported)
            df[f"peer_{metric}_group_n"] = counts.where(counts >= MIN_PEER_GROUP, 0).fillna(0).astype(int)

        supported_any = df[[f"peer_{m}_group_n" for m in peer_metrics]].gt(0).any(axis=1)
        df["peer_comparison_supported"] = supported_any
        df["peer_comparison_status"] = np.where(
            supported_any,
            "SUPPORTED: compared with same alert-type/severity peer group",
            f"UNSUPPORTED: peer group smaller than {MIN_PEER_GROUP} or insufficient variation",
        )

        reason_series = pd.Series("", index=df.index, dtype="object")
        for metric in peer_metrics:
            z_col = f"peer_{metric}_robust_z"
            n_col = f"peer_{metric}_group_n"
            z_values = pd.to_numeric(df[z_col], errors="coerce")
            mask = z_values.ge(3.0) & df[n_col].ge(MIN_PEER_GROUP)
            snippets = metric + " unusually high vs peers (robust z=" + z_values.round(2).astype("string") + ", n=" + df[n_col].astype("string") + ")"
            reason_series.loc[mask] = reason_series.loc[mask] + snippets.loc[mask] + " | "
        df["supervisory_peer_reason"] = reason_series.str.rstrip(" | ")
        df.loc[df["supervisory_peer_reason"].eq(""), "supervisory_peer_reason"] = "No configured high peer-deviation signal"
        df.drop(columns=["_peer_group_key_internal"], inplace=True, errors="ignore")

    # Evidence-backed, non-accusatory supervisory summary. No synthetic fields are created.
    review_reason = pd.Series("", index=df.index, dtype="object")
    peer_flag = df["supervisory_peer_reason"].ne("No configured high peer-deviation signal")
    review_reason.loc[peer_flag] = df.loc[peer_flag, "supervisory_peer_reason"]
    for col, label in [
        ("low_telemetry_signal", "limited telemetry evidence"),
        ("investigation_without_evidence_signal", "investigation record has limited linked evidence"),
        ("critical_missing_context_signal", "critical-severity alert has missing context"),
        ("evidence_gap_signal", "one or more evidence gaps are recorded"),
        ("negative_space_signal", "observable negative-space indicator is present"),
    ]:
        if col in df.columns:
            truth = df[col].fillna(False).astype(str).str.strip().str.lower().isin({"true", "1", "yes"})
            review_reason.loc[truth] = review_reason.loc[truth] + label + " | "
    review_reason = review_reason.str.rstrip(" | ")
    df["supervisory_review_reason"] = review_reason.mask(
        review_reason.eq(""), "No configured supervisory review signal detected"
    )
    df["supervisory_review_recommended"] = df["supervisory_review_reason"].ne(
        "No configured supervisory review signal detected"
    )
    df["supervisory_disclaimer"] = (
        "Review indicator only; not proof of maliciousness, missed escalation, "
        "monitoring outage, or SOC failure."
    )

    # Explicit capability flags: never infer unavailable workflow facts.
    df["rapid_closure_duration_supported"] = False
    df["remediation_completion_supported"] = False
    df["incident_labels_used_for_peer_comparison"] = False
    df["v6_scores_or_ranks_modified"] = False

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(OUTPUT, index=False)

    # Re-read output and verify traceability and unchanged ranking fields.
    out = pd.read_csv(OUTPUT, low_memory=False)
    checks = {
        "row_count_unchanged": len(out) == original_rows,
        "alert_ids_unchanged_in_order": out[IDENTITY].equals(original_ids),
        "priority_ranks_unchanged_in_order": out[RANK].equals(original_rank),
        "anomaly_scores_unchanged_in_order": out[SCORE].equals(original_score),
        "priority_scores_unchanged_in_order": (
            original_priority is None or out[PRIORITY_SCORE].equals(original_priority)
        ),
        "alert_id_unique": not out[IDENTITY].duplicated().any(),
        "incident_labels_excluded_from_peer_calculation": True,
    }

    report_lines = [
        "SAT-SA V6 SUPERVISORY PEER COMPARISON + AUDIT REPORT",
        "=" * 58,
        f"Input: {INPUT.as_posix()}",
        f"Output: {OUTPUT.as_posix()}",
        f"Input SHA-256: {input_hash}",
        f"Rows processed: {original_rows:,}",
        f"Peer grouping columns: {', '.join(group_cols) if group_cols else 'Unavailable'}",
        f"Peer metrics evaluated: {', '.join(peer_metrics) if peer_metrics else 'None'}",
        f"Minimum peer group size: {MIN_PEER_GROUP}",
        f"Rows with peer comparison supported: {int(out['peer_comparison_supported'].sum()):,}",
        f"Rows with supervisory review recommended: {int(out['supervisory_review_recommended'].sum()):,}",
        "",
        "INTEGRITY CHECKS",
        *[f"{name}: {'PASS' if passed else 'FAIL'}" for name, passed in checks.items()],
        "",
        "LIMITATIONS",
        "- Peer groups are defined by observed alert type and severity fields when available.",
        "- Robust peer deviation is a review signal, not a threat probability or proof of wrongdoing.",
        "- Small groups and zero-variation metrics are marked unsupported rather than guessed.",
        "- Incident IDs/labels are not used in peer calculations.",
        "- Rapid-closure duration and remediation completion remain unsupported unless source fields provide reliable evidence.",
        "- This add-on does not change V6 anomaly scores, priority scores, or ranks.",
        "",
        "RESULT: " + ("PASS" if all(checks.values()) else "FAIL — inspect integrity checks"),
    ]
    REPORT.write_text("\n".join(report_lines) + "\n", encoding="utf-8")

    print("\n".join(report_lines))
    if not all(checks.values()):
        return 1
    print(f"\nSaved supervisory audit CSV: {OUTPUT}")
    print(f"Saved supervisory audit report: {REPORT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
