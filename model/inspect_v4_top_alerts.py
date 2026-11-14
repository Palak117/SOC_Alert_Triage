import pandas as pd
import numpy as np

print("=" * 70)
print("V4 TOP ALERT INSPECTION")
print("=" * 70)

# ============================================================
# LOAD
# ============================================================

scored = pd.read_csv(
    "data/scored/test_unsupervised_v4_scored.csv",
    low_memory=False
)

features = pd.read_csv(
    "data/unsupervised_features/X_test_unsupervised_v4.csv",
    low_memory=False
)

original = pd.read_csv(
    "data/train_test/test_20.csv",
    low_memory=False
)

print(f"Scored rows   : {len(scored):,}")
print(f"Feature rows  : {len(features):,}")
print(f"Original rows : {len(original):,}")

# ============================================================
# SAFETY CHECK
# ============================================================

if not (
    len(scored)
    == len(features)
    == len(original)
):
    raise ValueError("Row counts do not match.")

# ============================================================
# COMBINE
# ============================================================

result = pd.concat(
    [
        scored.reset_index(drop=True),
        features.reset_index(drop=True),
        original.reset_index(drop=True)
    ],
    axis=1
)

# Remove duplicated column names if any
result = result.loc[
    :,
    ~result.columns.duplicated()
]

# ============================================================
# TOP ALERTS
# ============================================================

ranked = result.sort_values(
    "priority_rank",
    ascending=True,
    kind="mergesort"
).reset_index(drop=True)

print("\n" + "=" * 70)
print("TOP 100 SCORE DISTRIBUTION")
print("=" * 70)

top100 = ranked.head(100)

print(
    top100["anomaly_score"]
    .value_counts()
    .head(20)
)

# ============================================================
# TOP SCORE GROUP SIZE
# ============================================================

top_score = ranked.iloc[0]["anomaly_score"]

same_top_score = ranked[
    ranked["anomaly_score"] == top_score
]

print("\n" + "=" * 70)
print("EXTREME SCORE GROUP")
print("=" * 70)

print(
    f"Top anomaly score : {top_score:.6f}"
)

print(
    f"Records with this score: "
    f"{len(same_top_score):,}"
)

# ============================================================
# TOP 20 FEATURE SUMMARY
# ============================================================

print("\n" + "=" * 70)
print("TOP 20 ALERT FEATURE SUMMARY")
print("=" * 70)

feature_columns = [
    "src_ip_rarity",
    "src_host_rarity",
    "product_name_rarity",
    "dst_ip_rarity",
    "username_length",
    "has_dst_ip",
    "dst_port_rarity",
    "dst_port",
    "has_username",
    "high_level_behavior_rarity",
    "stream_name_rarity",
    "same_port",
    "dst_port_category",
    "src_port_rarity",
    "message_type_rarity",
    "username_rarity",
    "protocol_rarity",
    "pipeline_rarity",
    "network_behavior_rarity",
    "src_port_category"
]

available = [
    c for c in feature_columns
    if c in ranked.columns
]

print(
    ranked[
        [
            "priority_rank",
            "anomaly_score"
        ] + available
    ]
    .head(20)
    .to_string(index=False)
)

# ============================================================
# FEATURE VARIABILITY IN TOP SCORE GROUP
# ============================================================

print("\n" + "=" * 70)
print("TOP SCORE GROUP FEATURE VARIABILITY")
print("=" * 70)

for column in available:

    unique_count = (
        same_top_score[column]
        .nunique(dropna=False)
    )

    print(
        f"{column:<32} "
        f"unique values: {unique_count:,}"
    )

# ============================================================
# ORIGINAL DATA SUMMARY
# ============================================================

original_columns = [
    "timestamp",
    "src_ip",
    "dst_ip",
    "src_host",
    "dst_host",
    "src_port",
    "dst_port",
    "protocol",
    "pipeline",
    "product_name",
    "message_type",
    "action",
    "severity",
    "lifecycle_stage",
    "username",
    "suspicion_score",
    "incident_ids"
]

available_original = [
    c for c in original_columns
    if c in ranked.columns
]

print("\n" + "=" * 70)
print("TOP 20 ORIGINAL ALERT INFORMATION")
print("=" * 70)

print(
    ranked[
        [
            "priority_rank",
            "anomaly_score"
        ] + available_original
    ]
    .head(20)
    .to_string(index=False)
)

# ============================================================
# SAVE
# ============================================================

output_path = (
    "data/scored/"
    "v4_top_alerts_diagnostic.csv"
)

ranked.head(1000).to_csv(
    output_path,
    index=False
)

print("\n" + "=" * 70)
print("DIAGNOSTIC COMPLETE")
print("=" * 70)

print(
    f"\nSaved top 1000 alerts to:\n"
    f"{output_path}"
)

print("""
IMPORTANT:

This is POST-HOC analysis only.

The V4 model was NOT retrained.
V4 scores were NOT modified.
V4 ranking was NOT modified.
No incident information was used to modify the model.
""")

print("=" * 70)