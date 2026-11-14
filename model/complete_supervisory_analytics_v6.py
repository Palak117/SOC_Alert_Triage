from pathlib import Path
import hashlib
import pandas as pd
import numpy as np

ROOT = Path.cwd()
SRC = ROOT / "data/scored/final_v6_sih_context_layer.csv"
DST = ROOT / "data/scored/final_v6_sih_supervisory_complete.csv"
RPT = ROOT / "data/scored/final_v6_sih_supervisory_complete_report.txt"

def sha256(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def main():
    if not SRC.exists():
        raise SystemExit(f"Missing input: {SRC}")
    digest = sha256(SRC)
    d = pd.read_csv(SRC, low_memory=False)
    required = ["_alert_id", "v6_priority_rank", "v6_anomaly_score", "v6_priority_score"]
    missing = [c for c in required if c not in d.columns]
    if missing:
        raise SystemExit("Missing required columns: " + ", ".join(missing))
    originals = {c: d[c].copy() for c in required}
    o = d.copy()

    # Explicit evidence-gap and workflow review indicators, without changing V6 ranking.
    for c in ["evidence_gap_count", "execution_gap_count", "negative_space_count"]:
        o[c] = pd.to_numeric(o[c], errors="coerce").fillna(0) if c in o else 0
    o["supervisory_evidence_gap_review"] = (
        (o["evidence_gap_count"] + o["execution_gap_count"] + o["negative_space_count"]) > 0
    )
    o["supervisory_review_reason_codes"] = ""
    reason_map = {
        "evidence_gap_signal": "EVIDENCE_GAP",
        "investigation_without_evidence_signal": "INVESTIGATION_WITHOUT_EVIDENCE",
        "critical_missing_context_signal": "CRITICAL_MISSING_CONTEXT",
        "low_telemetry_signal": "LOW_TELEMETRY",
        "no_escalation_context_signal": "NO_ESCALATION_CONTEXT",
        "rapid_closure_signal": "RAPID_CLOSURE",
        "negative_space_signal": "NEGATIVE_SPACE",
        "repeated_entity_signal": "REPEATED_ENTITY",
        "high_frequency_entity_signal": "HIGH_FREQUENCY_ENTITY",
    }
    reason_series = []
    for idx, row in o.iterrows():
        reasons = []
        for col, code in reason_map.items():
            if col in o and str(row[col]).strip().lower() in ("true", "1", "yes"):
                reasons.append(code)
        if reasons:
            reason_series.append("|".join(reasons))
        else:
            reason_series.append("NO_RECORDED_INDICATOR")
    o["supervisory_review_reason_codes"] = reason_series
    o["supervisory_evidence_source_fields"] = o.apply(
        lambda r: "|".join(c for c in [
            "context_reason", "evidence_gap_count", "execution_gap_count",
            "negative_space_count", "investigation_evidence_count",
            "telemetry_evidence_count", "escalation_evidence", "disposition",
            "source_host_context", "destination_host_context"
        ] if c in o.columns and pd.notna(r[c]) and str(r[c]).strip() not in ("", "nan", "None")),
        axis=1
    )
    o["supervisory_traceability_note"] = (
        "Review indicator only; verify underlying source records before treating as a confirmed finding."
    )

    # Robust peer deviation, grouped by alert type and severity when available.
    groups = [c for c in ["alert_type", "severity_context"] if c in o.columns]
    if not groups and "alert_type" in o.columns:
        groups = ["alert_type"]
    metrics = [c for c in [
        "investigation_evidence_count", "telemetry_evidence_count",
        "evidence_gap_count", "execution_gap_count", "negative_space_count",
        "entity_alert_frequency", "source_ip_frequency", "destination_ip_frequency"
    ] if c in o.columns]
    supported = pd.Series(False, index=o.index)
    if groups and metrics:
        group_size = o.groupby(groups, dropna=False)["v6_priority_rank"].transform("size")
        supported = group_size >= 30
        o["peer_group_size"] = group_size
        for metric in metrics:
            x = pd.to_numeric(o[metric], errors="coerce")
            med = x.groupby([o[g] for g in groups], dropna=False).transform("median")
            mad = (x - med).abs().groupby([o[g] for g in groups], dropna=False).transform("median")
            denom = 1.4826 * mad
            z = (x - med) / denom.replace(0, np.nan)
            z = z.where(denom.ne(0), np.where((x-med).abs() > 0, np.sign(x-med)*999.0, 0.0))
            o["peer_robust_z_" + metric] = z.round(4)
            o["peer_outlier_" + metric] = supported & z.abs().ge(3.5)
    o["peer_comparison_supported_computed"] = supported
    peer_cols = [c for c in o.columns if c.startswith("peer_outlier_")]
    if peer_cols:
        o["peer_deviation_review_signal"] = o[peer_cols].any(axis=1)
    else:
        o["peer_deviation_review_signal"] = False
    o["peer_comparison_interpretation"] = "Descriptive deviation only; not threat probability or proof of misconduct"

    # Descriptive entity-frequency indicator.
    entity_col = next((c for c in ["entity_alert_frequency", "source_ip_frequency", "destination_ip_frequency"] if c in o.columns), None)
    if entity_col:
        freq = pd.to_numeric(o[entity_col], errors="coerce")
        threshold = freq.quantile(0.95)
        o["entity_frequency_review_signal"] = freq.ge(threshold) & freq.notna()
        o["entity_frequency_basis"] = entity_col
    else:
        o["entity_frequency_review_signal"] = False
        o["entity_frequency_basis"] = "UNAVAILABLE"
    o["entity_frequency_interpretation"] = "Frequency is descriptive; high frequency alone does not establish malicious activity"

    checks = {
        "row_count_unchanged": len(o) == len(d),
        "alert_ids_unchanged_in_order": o["_alert_id"].equals(originals["_alert_id"]),
        "priority_ranks_unchanged_in_order": o["v6_priority_rank"].equals(originals["v6_priority_rank"]),
        "anomaly_scores_unchanged_in_order": o["v6_anomaly_score"].equals(originals["v6_anomaly_score"]),
        "priority_scores_unchanged_in_order": o["v6_priority_score"].equals(originals["v6_priority_score"]),
        "alert_id_unique": not o["_alert_id"].duplicated().any(),
    }
    DST.parent.mkdir(parents=True, exist_ok=True)
    o.to_csv(DST, index=False)
    lines = [
        "SAT-SA COMPLETE SUPERVISORY ANALYTICS + TRACEABILITY REPORT",
        "=" * 64,
        f"Input: {SRC.relative_to(ROOT)}",
        f"Output: {DST.relative_to(ROOT)}",
        f"Input SHA-256: {digest}",
        f"Rows processed: {len(o):,}",
        f"Peer grouping columns: {', '.join(groups) if groups else 'UNAVAILABLE'}",
        f"Peer metrics evaluated: {', '.join(metrics) if metrics else 'UNAVAILABLE'}",
        f"Rows with peer comparison supported: {int(supported.sum()):,}",
        f"Rows with peer deviation review signal: {int(o['peer_deviation_review_signal'].sum()):,}",
        f"Rows with evidence-gap review indicator: {int(o['supervisory_evidence_gap_review'].sum()):,}",
        f"Rows with entity-frequency review signal: {int(o['entity_frequency_review_signal'].sum()):,}",
        "", "INTEGRITY CHECKS"
    ]
    lines += [f"{k}: {'PASS' if v else 'FAIL'}" for k, v in checks.items()]
    lines += [
        "", "TRACEABILITY",
        "- Original source/context columns are retained.",
        "- supervisory_review_reason_codes lists observed signals for each row.",
        "- supervisory_evidence_source_fields lists populated fields relevant to review.",
        "- Peer deviations and entity frequency are descriptive review indicators only.",
        "- Incident labels are not used in peer calculations.",
        "- V6 anomaly scores, priority scores, and ranks are not recalculated or changed.",
        "", "LIMITATIONS",
        "- This script cannot create missing source-system case IDs, escalation paths, remediation records, or asset criticality.",
        "- A populated support flag is not proof that the underlying external source record exists.",
        "- Validate sample findings against original SOC records before calling them confirmed findings.",
        "", "RESULT: " + ("PASS" if all(checks.values()) else "FAIL")
    ]
    RPT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    if not all(checks.values()):
        raise SystemExit(2)

if __name__ == "__main__":
    main()
