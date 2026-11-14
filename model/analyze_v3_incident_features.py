import pandas as pd
import numpy as np

print("=" * 70)
print("V3 INCIDENT FEATURE DIAGNOSTIC")
print("=" * 70)

# ============================================================
# 1. LOAD V3 SCORES
# ============================================================

print("\nLoading V3 scored results...")

scored = pd.read_csv(
    "data/scored/test_unsupervised_v3_scored.csv",
    low_memory=False
)

print(f"Scored rows : {len(scored):,}")

# ============================================================
# 2. LOAD V3 TEST FEATURES
# ============================================================

print("\nLoading V3 test features...")

features = pd.read_csv(
    "data/unsupervised_features/X_test_unsupervised_v3.csv",
    low_memory=False
)

print(f"Feature rows   : {len(features):,}")
print(f"Feature columns: {len(features.columns)}")

# ============================================================
# 3. LOAD ORIGINAL TEST DATA
# ============================================================

print("\nLoading original test data...")

original = pd.read_csv(
    "data/train_test/test_20.csv",
    low_memory=False
)

print(f"Original rows : {len(original):,}")

# ============================================================
# 4. SAFETY CHECK
# ============================================================

if not (
    len(scored)
    == len(features)
    == len(original)
):
    raise ValueError(
        "Row mismatch between scored results, "
        "features and original test data."
    )

# ============================================================
# 5. CREATE POST-HOC GROUND TRUTH
# ============================================================

print("\nCreating ground truth ONLY for evaluation...")

if "incident_ids" not in original.columns:
    raise ValueError(
        "incident_ids column not found."
    )


def has_incident(value):

    if pd.isna(value):
        return False

    text = str(value).strip()

    if text == "":
        return False

    if text.lower() in {
        "nan",
        "none",
        "null",
        "[]",
        "{}"
    }:
        return False

    return True


actual_incident = original[
    "incident_ids"
].apply(has_incident)

print("\nGround-truth distribution:")

print(
    actual_incident.value_counts()
)

incident_count = int(
    actual_incident.sum()
)

non_incident_count = (
    len(actual_incident) - incident_count
)

print(
    f"\nIncident alerts     : {incident_count:,}"
)

print(
    f"Non-incident alerts : {non_incident_count:,}"
)

# ============================================================
# 6. CHECK SCORE DISTRIBUTION BY GROUND TRUTH
# ============================================================

print("\n" + "=" * 70)
print("ANOMALY SCORE BY GROUND TRUTH")
print("=" * 70)

score_df = pd.DataFrame({
    "anomaly_score": scored["anomaly_score"],
    "actual_incident": actual_incident.values
})

print(
    score_df.groupby(
        "actual_incident"
    )["anomaly_score"].agg(
        [
            "count",
            "mean",
            "median",
            "min",
            "max",
            "std"
        ]
    )
)

# ============================================================
# 7. FEATURE COMPARISON
# ============================================================

print("\n" + "=" * 70)
print("ALL-TEST FEATURE COMPARISON")
print("=" * 70)

incident_features = features[
    actual_incident.values
]

non_incident_features = features[
    ~actual_incident.values
]

numeric_features = features.select_dtypes(
    include=[np.number]
).columns

results = []

for feature in numeric_features:

    incident_values = pd.to_numeric(
        incident_features[feature],
        errors="coerce"
    )

    non_incident_values = pd.to_numeric(
        non_incident_features[feature],
        errors="coerce"
    )

    incident_mean = incident_values.mean()
    non_incident_mean = non_incident_values.mean()

    difference = (
        incident_mean
        - non_incident_mean
    )

    pooled_std = np.sqrt(
        (
            incident_values.var()
            +
            non_incident_values.var()
        ) / 2
    )

    if pooled_std > 0:
        standardized_difference = (
            difference / pooled_std
        )
    else:
        standardized_difference = 0

    results.append({
        "feature": feature,
        "incident_mean": incident_mean,
        "non_incident_mean": non_incident_mean,
        "difference": difference,
        "standardized_difference":
            standardized_difference
    })

comparison = pd.DataFrame(results)

comparison[
    "abs_standardized_difference"
] = comparison[
    "standardized_difference"
].abs()

comparison = comparison.sort_values(
    "abs_standardized_difference",
    ascending=False
)

print(
    comparison[
        [
            "feature",
            "incident_mean",
            "non_incident_mean",
            "difference",
            "standardized_difference"
        ]
    ].head(30).to_string(index=False)
)

# ============================================================
# 8. INCIDENT RATE BY SCORE QUANTILE
# ============================================================

print("\n" + "=" * 70)
print("INCIDENT RATE BY ANOMALY SCORE GROUP")
print("=" * 70)

score_df["score_percentile"] = (
    score_df["anomaly_score"]
    .rank(pct=True)
)

groups = [
    ("Top 0.1%", 0.999),
    ("Top 1%", 0.99),
    ("Top 5%", 0.95),
    ("Top 10%", 0.90),
    ("Top 25%", 0.75),
    ("Bottom 25%", 0.00),
]

for name, threshold in groups:

    if name.startswith("Top"):

        subset = score_df[
            score_df["score_percentile"]
            <= (1 - threshold)
        ]

    else:

        subset = score_df[
            score_df["score_percentile"]
            <= 0.25
        ]

    if len(subset) > 0:

        incident_rate = (
            subset["actual_incident"].sum()
            / len(subset)
        )

        print(
            f"{name:<12} | "
            f"Alerts: {len(subset):,} | "
            f"Incidents: "
            f"{int(subset['actual_incident'].sum()):,} | "
            f"Incident rate: "
            f"{incident_rate:.4%}"
        )

# ============================================================
# 9. SCORE OVERLAP
# ============================================================

print("\n" + "=" * 70)
print("SCORE OVERLAP")
print("=" * 70)

incident_scores = score_df[
    score_df["actual_incident"]
]["anomaly_score"]

non_incident_scores = score_df[
    ~score_df["actual_incident"]
]["anomaly_score"]

print(
    f"Incident median score     : "
    f"{incident_scores.median():.6f}"
)

print(
    f"Non-incident median score : "
    f"{non_incident_scores.median():.6f}"
)

print(
    f"Incident 10th percentile  : "
    f"{incident_scores.quantile(.10):.6f}"
)

print(
    f"Incident 90th percentile  : "
    f"{incident_scores.quantile(.90):.6f}"
)

print(
    f"Non-incident 10th pct     : "
    f"{non_incident_scores.quantile(.10):.6f}"
)

print(
    f"Non-incident 90th pct     : "
    f"{non_incident_scores.quantile(.90):.6f}"
)

# ============================================================
# 10. SAVE DIAGNOSTIC RESULTS
# ============================================================

output_path = (
    "data/scored/"
    "v3_incident_feature_comparison.csv"
)

comparison.to_csv(
    output_path,
    index=False
)

print("\n" + "=" * 70)
print("DIAGNOSTIC COMPLETE")
print("=" * 70)

print(
    f"\nSaved feature comparison to:\n"
    f"{output_path}"
)

print("""
IMPORTANT:
This script is POST-HOC analysis only.

No labels were used for:
- feature engineering
- model training
- anomaly scoring
- priority ranking

Ground truth was used ONLY to understand
why the V3 ranking behaves as it does.
""")

print("=" * 70)