import pandas as pd
import numpy as np
import ast
import os

# ============================================================
# PATHS
# ============================================================

SCORED_PATH = "data/scored/test_behavioral_scored.csv"
ORIGINAL_TEST_PATH = "data/train_test/test_20.csv"

# ============================================================
# LOAD DATA
# ============================================================

print("Loading behavioral scored results...")
scored = pd.read_csv(SCORED_PATH)

print("Loading original test data...")
original = pd.read_csv(
    ORIGINAL_TEST_PATH,
    low_memory=False
)

print()
print("=" * 70)
print("BEHAVIORAL RANKING ANALYSIS")
print("=" * 70)

print(f"Scored rows   : {len(scored):,}")
print(f"Original rows : {len(original):,}")

# ============================================================
# BASIC SCORE ANALYSIS
# ============================================================

print()
print("=" * 70)
print("SCORE DISTRIBUTION")
print("=" * 70)

print(f"Unique scores : {scored['anomaly_score'].nunique():,}")
print(f"Minimum score : {scored['anomaly_score'].min():.6f}")
print(f"Maximum score : {scored['anomaly_score'].max():.6f}")
print(f"Mean score    : {scored['anomaly_score'].mean():.6f}")
print(f"Median score  : {scored['anomaly_score'].median():.6f}")

print()
print("Score quantiles:")
print(
    scored["anomaly_score"].quantile(
        [0.001, 0.01, 0.05, 0.10, 0.25, 0.50, 0.75, 0.90, 0.99]
    )
)

# ============================================================
# CHECK REQUIRED COLUMNS
# ============================================================

required_scored = [
    "priority_rank",
    "anomaly_score",
    "priority_score"
]

for col in required_scored:
    if col not in scored.columns:
        print(f"\nERROR: Missing column in scored data: {col}")
        raise SystemExit

# ============================================================
# TOP-K ANALYSIS
# ============================================================

print()
print("=" * 70)
print("TOP-K RANKING ANALYSIS")
print("=" * 70)

for k in [100, 500, 1000, 5000, 10000]:

    top = scored.head(k)

    print()
    print(f"TOP-{k}")
    print("-" * 50)

    print(
        f"Score range : "
        f"{top['anomaly_score'].min():.6f} "
        f"to "
        f"{top['anomaly_score'].max():.6f}"
    )

    print(
        f"Unique scores in Top-{k}: "
        f"{top['anomaly_score'].nunique():,}"
    )

# ============================================================
# ATTACH ORIGINAL DATA ONLY FOR POST-HOC ANALYSIS
# ============================================================

print()
print("=" * 70)
print("POST-HOC DATA ANALYSIS")
print("=" * 70)

if len(scored) != len(original):
    print("ERROR: Row counts do not match.")
    raise SystemExit

# Important:
# This does NOT affect model scores.
# It is only for evaluating what the unsupervised model ranked.

analysis = scored.copy()

for col in original.columns:
    if col not in analysis.columns:
        analysis[col] = original[col].values

# ============================================================
# INCIDENT ANALYSIS
# ============================================================

if "actual_incident" in analysis.columns:

    print()
    print("=" * 70)
    print("KNOWN INCIDENTS - POST-HOC ONLY")
    print("=" * 70)

    print(
        analysis["actual_incident"]
        .value_counts(dropna=False)
    )

    for k in [100, 500, 1000, 5000, 10000]:

        top = analysis.head(k)

        incidents = top["actual_incident"].fillna(False).sum()

        print(
            f"Top-{k:<5} "
            f"known incident rows: {incidents}"
        )

# ============================================================
# LABEL ANALYSIS
# ============================================================

if "label_binary" in analysis.columns:

    print()
    print("=" * 70)
    print("LABEL DISTRIBUTION IN RANKED QUEUE")
    print("=" * 70)

    for k in [100, 500, 1000, 5000, 10000]:

        top = analysis.head(k)

        print()
        print(f"Top-{k}:")
        print(
            top["label_binary"]
            .value_counts(dropna=False)
        )

# ============================================================
# FEATURE PATTERN ANALYSIS
# ============================================================

behavioral_features = [
    "hour",
    "day_of_week",
    "is_weekend",
    "src_port",
    "dst_port",
    "protocol",
    "suspicion_score",
    "severity",
    "action",
    "lifecycle_stage",
    "product_name",
    "vendor_name",
    "pipeline",
    "message_length",
    "matched_rules_count",
    "has_username",
    "has_src_host",
    "has_dst_host"
]

available_features = [
    col for col in behavioral_features
    if col in analysis.columns
]

print()
print("=" * 70)
print("TOP-100 BEHAVIORAL PROFILE")
print("=" * 70)

top100 = analysis.head(100)

for col in available_features:

    print()
    print(f"--- {col} ---")

    if pd.api.types.is_numeric_dtype(top100[col]):

        print(
            f"min={top100[col].min():.4f}, "
            f"max={top100[col].max():.4f}, "
            f"mean={top100[col].mean():.4f}, "
            f"unique={top100[col].nunique():,}"
        )

    else:

        print(
            top100[col]
            .value_counts(dropna=False)
            .head(10)
        )

# ============================================================
# DUPLICATE / PATTERN ANALYSIS
# ============================================================

print()
print("=" * 70)
print("TOP-RANKED DUPLICATE PATTERN ANALYSIS")
print("=" * 70)

if available_features:

    # Convert features to strings so mixed categorical/numeric
    # values can safely be compared.
    pattern_columns = available_features

    top10000 = analysis.head(10000).copy()

    top10000["_behavior_pattern"] = (
        top10000[pattern_columns]
        .astype(str)
        .agg("|".join, axis=1)
    )

    pattern_counts = (
        top10000["_behavior_pattern"]
        .value_counts()
    )

    print(
        f"Unique behavioral patterns in Top-10,000: "
        f"{pattern_counts.size:,}"
    )

    print()
    print("Most repeated patterns in Top-10,000:")

    print(
        pattern_counts
        .head(20)
        .to_string()
    )

# ============================================================
# CHECK WHETHER TOP RANKS ARE DOMINATED BY ONE PATTERN
# ============================================================

print()
print("=" * 70)
print("RANKING CONCENTRATION")
print("=" * 70)

if available_features:

    for k in [100, 500, 1000, 5000, 10000]:

        subset = analysis.head(k).copy()

        subset["_behavior_pattern"] = (
            subset[available_features]
            .astype(str)
            .agg("|".join, axis=1)
        )

        counts = subset["_behavior_pattern"].value_counts()

        largest_group = counts.iloc[0]
        unique_groups = counts.size

        print(
            f"Top-{k:<5} | "
            f"Unique groups: {unique_groups:,} | "
            f"Largest group: {largest_group:,} alerts"
        )

# ============================================================
# INCIDENT DIVERSITY
# ============================================================

if "actual_incident" in analysis.columns:

    print()
    print("=" * 70)
    print("INCIDENT DIVERSITY IN TOP-K")
    print("=" * 70)

    for k in [100, 500, 1000, 5000, 10000]:

        subset = analysis.head(k)

        incident_rows = subset[
            subset["actual_incident"].fillna(False)
        ]

        if "incident_ids" in incident_rows.columns:

            incident_ids = set()

            for value in incident_rows["incident_ids"].dropna():

                try:

                    parsed = ast.literal_eval(str(value))

                    if isinstance(parsed, list):

                        for incident_id in parsed:
                            if incident_id:
                                incident_ids.add(
                                    str(incident_id)
                                )

                except Exception:
                    pass

            print(
                f"Top-{k:<5} | "
                f"Incident rows: {len(incident_rows):,} | "
                f"Unique incidents: {len(incident_ids):,}"
            )

# ============================================================
# SAVE ANALYSIS FILE
# ============================================================

output_path = "data/scored/behavioral_ranking_analysis.csv"

# Save a useful sample rather than duplicating the entire dataset.
analysis.head(10000).to_csv(
    output_path,
    index=False
)

print()
print("=" * 70)
print("ANALYSIS COMPLETE")
print("=" * 70)

print()
print("Saved analysis sample:")
print(output_path)

print()
print("IMPORTANT:")
print("This analysis did NOT modify model scores.")
print("Ground-truth incident information was used ONLY for post-hoc evaluation.")
print("No labels were used to train or score the Isolation Forest.")