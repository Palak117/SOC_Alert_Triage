import pandas as pd
import numpy as np

# ============================================================
# V2 FEATURE BEHAVIOR ANALYSIS
# POST-HOC ONLY
# ============================================================

SCORED_PATH = "data/scored/test_unsupervised_v2_scored.csv"
ORIGINAL_TEST_PATH = "data/train_test/test_20.csv"

OUTPUT_PATH = "data/scored/v2_feature_behavior_analysis.csv"

print("=" * 70)
print("V2 FEATURE BEHAVIOR ANALYSIS")
print("=" * 70)

# ------------------------------------------------------------
# LOAD SCORED DATA
# ------------------------------------------------------------

print("\nLoading scored results...")
scored = pd.read_csv(SCORED_PATH)

print(f"Scored rows : {len(scored):,}")

# ------------------------------------------------------------
# LOAD ORIGINAL TEST DATA
# ------------------------------------------------------------

print("\nLoading original test data...")
original = pd.read_csv(
    ORIGINAL_TEST_PATH,
    low_memory=False
)

print(f"Original rows : {len(original):,}")

if len(scored) != len(original):
    raise ValueError(
        "Scored data and original test data have different row counts!"
    )

# ------------------------------------------------------------
# CREATE GROUND TRUTH ONLY FOR POST-HOC ANALYSIS
# ------------------------------------------------------------

print("\nCreating ground truth ONLY for evaluation...")

if "actual_incident" in original.columns:
    actual_incident = original["actual_incident"].astype(bool)

else:
    # This section is ONLY for post-hoc evaluation.
    # It is NEVER used for model training or scoring.
    if "incident_ids" not in original.columns:
        raise ValueError(
            "Neither actual_incident nor incident_ids exists "
            "in the original test data."
        )

    actual_incident = (
        original["incident_ids"]
        .fillna("[]")
        .astype(str)
        .str.strip()
        .ne("[]")
    )

scored["actual_incident"] = actual_incident.values

print("\nGround-truth distribution:")
print(scored["actual_incident"].value_counts())

# ------------------------------------------------------------
# FEATURE COLUMNS
# ------------------------------------------------------------

FEATURE_COLUMNS = [
    "hour",
    "day_of_week",
    "is_weekend",
    "hour_sin",
    "hour_cos",
    "dow_sin",
    "dow_cos",
    "src_port",
    "dst_port",
    "protocol",
    "src_port_privileged",
    "dst_port_privileged",
    "same_port",
    "has_src_ip",
    "has_dst_ip",
    "has_src_host",
    "has_dst_host",
    "message_length",
    "message_word_count",
    "message_digit_count",
    "message_special_count",
    "has_username",
    "username_length",
    "suspicion_score",
    "pipeline_rarity",
    "product_name_rarity",
    "vendor_name_rarity",
    "message_type_rarity",
    "stream_name_rarity",
    "action_rarity",
    "severity_rarity",
    "lifecycle_stage_rarity",
    "src_ip_rarity",
    "dst_ip_rarity",
    "src_host_rarity",
    "dst_host_rarity",
    "username_rarity",
    "src_port_rarity",
    "dst_port_rarity",
    "protocol_rarity",
    "network_combo_rarity",
]

missing_features = [
    col for col in FEATURE_COLUMNS
    if col not in scored.columns
]

if missing_features:
    raise ValueError(
        f"Missing feature columns: {missing_features}"
    )

# ------------------------------------------------------------
# TOP-K FEATURE ANALYSIS
# ------------------------------------------------------------

TOP_K = 10000

ranked = scored.sort_values(
    "priority_rank",
    ascending=True
).copy()

top_k = ranked.head(TOP_K)

incidents = ranked[
    ranked["actual_incident"] == True
]

non_incidents = ranked[
    ranked["actual_incident"] == False
]

print("\n" + "=" * 70)
print("POST-HOC FEATURE COMPARISON")
print("=" * 70)

print(f"\nTop-{TOP_K} alerts       : {len(top_k):,}")
print(f"Actual incidents        : {len(incidents):,}")
print(f"Non-incidents           : {len(non_incidents):,}")

# ------------------------------------------------------------
# CALCULATE FEATURE STATISTICS
# ------------------------------------------------------------

results = []

for feature in FEATURE_COLUMNS:

    all_values = pd.to_numeric(
        ranked[feature],
        errors="coerce"
    )

    top_values = pd.to_numeric(
        top_k[feature],
        errors="coerce"
    )

    incident_values = pd.to_numeric(
        incidents[feature],
        errors="coerce"
    )

    normal_values = pd.to_numeric(
        non_incidents[feature],
        errors="coerce"
    )

    result = {
        "feature": feature,

        "all_mean": all_values.mean(),
        "all_median": all_values.median(),

        "top10000_mean": top_values.mean(),
        "top10000_median": top_values.median(),

        "incident_mean": incident_values.mean(),
        "incident_median": incident_values.median(),

        "non_incident_mean": normal_values.mean(),
        "non_incident_median": normal_values.median(),

        "incident_count": incident_values.notna().sum(),

        "top10000_non_null": top_values.notna().sum(),

        "unique_all": all_values.nunique(),
        "unique_top10000": top_values.nunique(),
    }

    # Difference between incident and non-incident behavior.
    result["incident_vs_nonincident_difference"] = (
        result["incident_mean"]
        - result["non_incident_mean"]
    )

    results.append(result)

analysis = pd.DataFrame(results)

# ------------------------------------------------------------
# STANDARDIZED DIFFERENCE
# ------------------------------------------------------------

def standardized_difference(row):

    feature = row["feature"]

    incident = pd.to_numeric(
        incidents[feature],
        errors="coerce"
    ).dropna()

    normal = pd.to_numeric(
        non_incidents[feature],
        errors="coerce"
    ).dropna()

    if len(incident) < 2 or len(normal) < 2:
        return np.nan

    pooled_std = np.sqrt(
        (
            incident.var()
            + normal.var()
        ) / 2
    )

    if pooled_std == 0:
        return 0.0

    return (
        incident.mean()
        - normal.mean()
    ) / pooled_std


analysis["standardized_difference"] = analysis.apply(
    standardized_difference,
    axis=1
)

# ------------------------------------------------------------
# SORT BY ABSOLUTE DIFFERENCE
# ------------------------------------------------------------

analysis["absolute_standardized_difference"] = (
    analysis["standardized_difference"]
    .abs()
)

analysis = analysis.sort_values(
    "absolute_standardized_difference",
    ascending=False
)

# ------------------------------------------------------------
# DISPLAY
# ------------------------------------------------------------

pd.set_option("display.max_rows", 100)
pd.set_option("display.max_columns", 20)
pd.set_option("display.width", 180)

print("\n" + "=" * 70)
print("FEATURES WITH LARGEST INCIDENT / NON-INCIDENT DIFFERENCE")
print("=" * 70)

display_columns = [
    "feature",
    "incident_mean",
    "non_incident_mean",
    "incident_vs_nonincident_difference",
    "standardized_difference",
]

print(
    analysis[display_columns]
    .head(20)
    .to_string(index=False)
)

# ------------------------------------------------------------
# FEATURE VALUES IN TOP 100
# ------------------------------------------------------------

print("\n" + "=" * 70)
print("TOP-100 FEATURE BEHAVIOR")
print("=" * 70)

top100 = ranked.head(100)

for feature in FEATURE_COLUMNS:

    values = pd.to_numeric(
        top100[feature],
        errors="coerce"
    ).dropna()

    if len(values) == 0:
        continue

    print(
        f"{feature:30s} | "
        f"min={values.min():.6f} | "
        f"max={values.max():.6f} | "
        f"mean={values.mean():.6f} | "
        f"unique={values.nunique()}"
    )

# ------------------------------------------------------------
# FEATURE BEHAVIOR OF FIRST 100 INCIDENT ALERTS
# ------------------------------------------------------------
