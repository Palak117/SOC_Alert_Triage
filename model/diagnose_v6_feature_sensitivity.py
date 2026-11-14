import pandas as pd
import numpy as np
import joblib

print("=" * 70)
print("V6 FEATURE SENSITIVITY DIAGNOSTIC")
print("=" * 70)

# ============================================================
# LOAD MODEL AND FEATURES
# ============================================================

print("\nLoading V6 model...")

model = joblib.load(
    "model/isolation_forest_unsupervised_v6.pkl"
)

print("Loading V6 test features...")

X = pd.read_csv(
    "data/unsupervised_features/X_test_unsupervised_v6.csv"
)

# _alert_id is NOT a model feature.
if "_alert_id" in X.columns:
    X = X.drop(columns=["_alert_id"])

# Use a deterministic sample for faster diagnosis
SAMPLE_SIZE = 10000

X_sample = X.iloc[:SAMPLE_SIZE].copy()

print(f"\nDiagnostic rows : {len(X_sample):,}")
print(f"Features        : {X_sample.shape[1]}")

# ============================================================
# BASELINE
# ============================================================

print("\nCalculating baseline scores...")

baseline = model.decision_function(X_sample)

# ============================================================
# FEATURE SENSITIVITY
# ============================================================

results = []

print("\nTesting feature sensitivity...")

for column in X_sample.columns:

    X_modified = X_sample.copy()

    # Deterministic permutation
    shuffled = (
        X_modified[column]
        .sample(
            frac=1.0,
            random_state=42
        )
        .reset_index(drop=True)
    )

    X_modified[column] = shuffled.values

    modified_score = model.decision_function(
        X_modified
    )

    difference = np.abs(
        baseline - modified_score
    )

    results.append({
        "feature": column,
        "mean_score_change": difference.mean(),
        "max_score_change": difference.max(),
        "changed_records": np.sum(
            difference > 1e-12
        )
    })

# ============================================================
# RESULTS
# ============================================================

results_df = pd.DataFrame(results)

results_df = results_df.sort_values(
    "mean_score_change",
    ascending=False
).reset_index(drop=True)

print("\n" + "=" * 70)
print("V6 FEATURE SENSITIVITY RANKING")
print("=" * 70)

print(
    results_df.head(30).to_string(
        index=False
    )
)

# ============================================================
# SAVE
# ============================================================

output_path = (
    "data/scored/"
    "v6_feature_sensitivity.csv"
)

results_df.to_csv(
    output_path,
    index=False
)

print("\n" + "=" * 70)
print("V6 DIAGNOSTIC COMPLETE")
print("=" * 70)

print("\nSaved to:")
print(output_path)

print("""
IMPORTANT:

This is a diagnostic only.

The V6 model was NOT retrained.
V6 anomaly scores were NOT modified.
The production ranking was NOT modified.

Each feature was independently shuffled only
to measure how sensitive the trained model is
to that feature.

_alert_id was excluded because it is only
an identity key and is NOT a model feature.
""")

print("=" * 70)