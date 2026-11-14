import pandas as pd
import numpy as np

print("=" * 70)
print("V5 TOP ALERT DIAGNOSTIC")
print("=" * 70)

SCORED_PATH = "data/scored/test_unsupervised_v5_scored.csv"
TEST_PATH = "data/train_test/test_20.csv"
FEATURE_PATH = "data/unsupervised_features/X_test_unsupervised_v5.csv"

# ============================================================
# LOAD
# ============================================================

print("\nLoading V5 scored results...")
scored = pd.read_csv(SCORED_PATH, low_memory=False)

print(f"Scored rows   : {len(scored):,}")

print("\nLoading original test data...")
original = pd.read_csv(TEST_PATH, low_memory=False)

print(f"Original rows : {len(original):,}")

print("\nLoading V5 features...")
features = pd.read_csv(FEATURE_PATH, low_memory=False)

print(f"Feature rows  : {len(features):,}")

# ============================================================
# ALIGN
# ============================================================

if not (
    len(scored) == len(original) == len(features)
):
    raise ValueError("Row counts do not match!")

print("\nRow count check: PASS")

# ============================================================
# CREATE INSPECTION TABLE
# ============================================================

# IMPORTANT:
# The scored dataframe has already been sorted by
# priority rank.
#
# Therefore, scores/ranks must NOT be attached to
# original data using row position.
#
# We use _alert_id to correctly match every scored
# alert back to its original test record.

inspection = original.copy()

# Create the same stable alert ID used during scoring.
inspection["_alert_id"] = np.arange(
    len(inspection)
)

# Select ranking information from scored results.
ranking_columns = [
    "_alert_id",
    "anomaly_score",
    "priority_score",
    "priority_rank"
]

ranking = scored[
    ranking_columns
].copy()

# Merge ranking information back to the
# correct original alert.
inspection = inspection.merge(
    ranking,
    on="_alert_id",
    how="left",
    validate="one_to_one"
)

# Safety check
if inspection["priority_rank"].isna().any():
    raise ValueError(
        "Some alerts could not be matched "
        "with their V5 ranking!"
    )

print(
    "\nAlert-to-ranking mapping: PASS"
)

# Add selected causal features

feature_columns = [
    "src_ip_previous_count",
    "src_ip_first_seen",
    "src_host_previous_count",
    "src_host_first_seen",
    "username_previous_count",
    "username_first_seen",
    "product_name_previous_count",
    "product_name_first_seen",
    "message_type_previous_count",
    "message_type_first_seen",
    "pipeline_previous_count",
    "pipeline_first_seen",
    "behavior_previous_count",
    "behavior_first_seen",
    "src_ip_rarity",
    "src_host_rarity",
    "username_rarity",
    "product_name_rarity",
    "message_type_rarity",
    "pipeline_rarity",
    "network_behavior_rarity",
    "high_level_behavior_rarity",
]

# Add stable alert ID to the feature table.
features["_alert_id"] = np.arange(
    len(features)
)

# Attach causal feature values to the
# correct alert.
available_feature_columns = [
    col
    for col in feature_columns
    if col in features.columns
]

feature_data = features[
    ["_alert_id"] + available_feature_columns
].copy()

inspection = inspection.merge(
    feature_data,
    on="_alert_id",
    how="left",
    validate="one_to_one"
)

print(
    "Alert-to-feature mapping: PASS"
)

# ============================================================
# CREATE POST-HOC INCIDENT FLAG
# ONLY FOR DIAGNOSTIC ANALYSIS
# ============================================================

def is_incident(value):
    if pd.isna(value):
        return False

    value = str(value).strip()

    if value in ["", "[]", "nan", "None"]:
        return False

    return True


if "incident_ids" in inspection.columns:

    inspection["actual_incident"] = (
        inspection["incident_ids"]
        .apply(is_incident)
    )

else:
    raise ValueError(
        "incident_ids column not found in original test data!"
    )

# ============================================================
# TOP 100
# ============================================================

print("\n" + "=" * 70)
print("TOP 100 V5 ALERTS")
print("=" * 70)

top100 = (
    inspection
    .sort_values(
        "priority_rank",
        ascending=True
    )
    .head(100)
)

print(
    top100[
        [
            "priority_rank",
            "anomaly_score",
            "priority_score",
            "actual_incident",
            "timestamp",
            "src_ip",
            "src_host",
            "dst_ip",
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
        ]
    ].to_string(index=False)
)

# ============================================================
# FIRST INCIDENT
# ============================================================

print("\n" + "=" * 70)
print("FIRST ACTUAL INCIDENT IN V5 RANKING")
print("=" * 70)

incidents = (
    inspection[
        inspection["actual_incident"] == True
    ]
    .sort_values("priority_rank")
)

if len(incidents) == 0:

    print("No incidents found.")

else:

    first_incident = incidents.iloc[0]

    print(
        f"\nFirst incident rank : "
        f"{int(first_incident['priority_rank']):,}"
    )

    print(
        f"Anomaly score      : "
        f"{first_incident['anomaly_score']:.6f}"
    )

    print(
        "\nFirst incident details:\n"
    )

    print(
        first_incident[
            [
                "priority_rank",
                "anomaly_score",
                "priority_score",
                "timestamp",
                "src_ip",
                "src_host",
                "dst_ip",
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
                "incident_ids",
            ]
        ].to_string()
    )

# ============================================================
# ALERTS BEFORE FIRST INCIDENT
# ============================================================

if len(incidents) > 0:

    first_rank = int(
        first_incident["priority_rank"]
    )

    start_rank = max(1, first_rank - 20)
    end_rank = first_rank + 20

    print("\n" + "=" * 70)
    print(
        f"ALERTS AROUND FIRST INCIDENT "
        f"(RANK {start_rank} - {end_rank})"
    )
    print("=" * 70)

    around_first = (
        inspection[
            (
                inspection["priority_rank"] >= start_rank
            )
            &
            (
                inspection["priority_rank"] <= end_rank
            )
        ]
        .sort_values("priority_rank")
    )

    print(
        around_first[
            [
                "priority_rank",
                "anomaly_score",
                "actual_incident",
                "timestamp",
                "src_ip",
                "src_host",
                "dst_ip",
                "pipeline",
                "product_name",
                "message_type",
                "action",
                "severity",
                "username",
                "suspicion_score",
            ]
        ].to_string(index=False)
    )

# ============================================================
# INCIDENT SCORE DISTRIBUTION
# ============================================================

print("\n" + "=" * 70)
print("INCIDENT VS NON-INCIDENT SCORE DISTRIBUTION")
print("=" * 70)

incident_scores = inspection.loc[
    inspection["actual_incident"] == True,
    "anomaly_score"
]

nonincident_scores = inspection.loc[
    inspection["actual_incident"] == False,
    "anomaly_score"
]

print("\nActual incidents:")
print(
    f"Count : {len(incident_scores):,}"
)

print(
    f"Mean  : {incident_scores.mean():.6f}"
)

print(
    f"Median: {incident_scores.median():.6f}"
)

print(
    f"Min   : {incident_scores.min():.6f}"
)

print(
    f"Max   : {incident_scores.max():.6f}"
)

print("\nNon-incidents:")
print(
    f"Count : {len(nonincident_scores):,}"
)

print(
    f"Mean  : {nonincident_scores.mean():.6f}"
)

print(
    f"Median: {nonincident_scores.median():.6f}"
)

print(
    f"Min   : {nonincident_scores.min():.6f}"
)

print(
    f"Max   : {nonincident_scores.max():.6f}"
)

# ============================================================
# SAVE
# ============================================================

OUTPUT_PATH = (
    "data/scored/v5_top_alerts_diagnostic.csv"
)

inspection.sort_values(
    "priority_rank"
).head(1000).to_csv(
    OUTPUT_PATH,
    index=False
)

print("\n" + "=" * 70)
print("DIAGNOSTIC COMPLETE")
print("=" * 70)

print(
    f"\nSaved top 1000 alerts to:\n{OUTPUT_PATH}"
)

print("\nIMPORTANT:")
print("This is POST-HOC diagnostic analysis only.")
print("incident_ids were NOT used to calculate scores.")
print("incident_ids were NOT used to create rankings.")
print("No model retraining was performed.")
print("=" * 70)