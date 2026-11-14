import pandas as pd
import joblib
import os

print("=" * 70)
print("UNSUPERVISED V3 TEST SCORING")
print("=" * 70)

# ---------------------------------------------------------
# PATHS
# ---------------------------------------------------------

MODEL_PATH = "model/isolation_forest_unsupervised_v3.pkl"
TEST_FEATURE_PATH = "data/unsupervised_features/X_test_unsupervised_v3.csv"
OUTPUT_PATH = "data/scored/test_unsupervised_v3_scored.csv"

# ---------------------------------------------------------
# LOAD MODEL
# ---------------------------------------------------------

print("\nLoading trained V3 model...")
model = joblib.load(MODEL_PATH)

# ---------------------------------------------------------
# LOAD TEST FEATURES
# ---------------------------------------------------------

print("Loading V3 test features...")
X_test = pd.read_csv(TEST_FEATURE_PATH)

print("\n==============================")
print("SCORING INFORMATION")
print("==============================")
print(f"Test records : {len(X_test)}")
print(f"Features     : {X_test.shape[1]}")

# ---------------------------------------------------------
# REMOVE NON-FEATURE COLUMNS IF PRESENT
# ---------------------------------------------------------

non_feature_columns = [
    "timestamp",
    "label",
    "label_binary",
    "actual_incident",
    "incident_id",
    "attack_label"
]

feature_columns = [
    col for col in X_test.columns
    if col not in non_feature_columns
]

X = X_test[feature_columns]

# ---------------------------------------------------------
# CHECK FEATURE COUNT
# ---------------------------------------------------------

expected_features = model.n_features_in_

if X.shape[1] != expected_features:
    raise ValueError(
        f"Feature mismatch!\n"
        f"Model expects: {expected_features}\n"
        f"Test data has: {X.shape[1]}"
    )

# ---------------------------------------------------------
# GENERATE ANOMALY SCORES
# ---------------------------------------------------------

print("\nGenerating anomaly scores...")

# Isolation Forest:
# lower score = more anomalous
anomaly_scores = model.decision_function(X)

# Positive priority score:
# higher value = higher anomaly priority
priority_scores = -anomaly_scores

# ---------------------------------------------------------
# CREATE RANKED QUEUE
# ---------------------------------------------------------

result = X_test.copy()

result["anomaly_score"] = anomaly_scores
result["priority_score"] = priority_scores

result = result.sort_values(
    by="priority_score",
    ascending=False
).reset_index(drop=True)

result["priority_rank"] = range(1, len(result) + 1)

# ---------------------------------------------------------
# SAVE
# ---------------------------------------------------------

os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)

result.to_csv(
    OUTPUT_PATH,
    index=False
)

# ---------------------------------------------------------
# REPORT
# ---------------------------------------------------------

print("\n==============================")
print("V3 TEST SCORING COMPLETE")
print("==============================")

print(f"Saved to:")
print(OUTPUT_PATH)

print("\nScore analysis:")
print(f"Minimum anomaly score : {result['anomaly_score'].min():.6f}")
print(f"Maximum anomaly score : {result['anomaly_score'].max():.6f}")
print(f"Mean anomaly score    : {result['anomaly_score'].mean():.6f}")
print(f"Unique anomaly scores : {result['anomaly_score'].nunique():,}")

print("\nTop 20 priority scores:")
print(
    result[
        ["priority_rank", "anomaly_score", "priority_score"]
    ].head(20).to_string(index=False)
)

print("\nIMPORTANT:")
print("No labels were used.")
print("No incident IDs were used.")
print("No ground-truth information was used.")
print("Scores are based only on learned behavioral patterns.")

print("=" * 70)