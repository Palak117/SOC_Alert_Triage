import pandas as pd
import joblib
import os

MODEL_PATH = "model/isolation_forest_soc.pkl"
TEST_PATH = "data/soc_features/X_test_soc.csv"
OUTPUT_DIR = "data/scored"
OUTPUT_PATH = "data/scored/test_soc_scored.csv"

os.makedirs(OUTPUT_DIR, exist_ok=True)

print("Loading trained SOC model...")
model = joblib.load(MODEL_PATH)

print("Loading SOC test features...")
X_test = pd.read_csv(TEST_PATH)

print("\n==============================")
print("SCORING SOC TEST DATA")
print("==============================")

print(f"Test records : {len(X_test):,}")
print(f"Features     : {len(X_test.columns)}")

print("\nGenerating anomaly scores...")

# Isolation Forest:
# Lower decision_function = more anomalous
raw_scores = model.decision_function(X_test)

# Convert so HIGHER priority_score = more anomalous
priority_score = -raw_scores

result = X_test.copy()
result["anomaly_score"] = raw_scores
result["priority_score"] = priority_score

# Highest priority first
result = result.sort_values(
    "priority_score",
    ascending=False
).reset_index(drop=True)

result["priority_rank"] = range(1, len(result) + 1)

print("Scoring complete.")
print("Sorting alerts by priority...")

result.to_csv(OUTPUT_PATH, index=False)

print("\n==============================")
print("SOC TEST SCORING COMPLETE")
print("==============================")

print(f"Saved to: {OUTPUT_PATH}")

print("\nScore analysis:")
print(f"Minimum anomaly score : {result['anomaly_score'].min():.6f}")
print(f"Maximum anomaly score : {result['anomaly_score'].max():.6f}")
print(f"Mean anomaly score    : {result['anomaly_score'].mean():.6f}")
print(f"Unique anomaly scores : {result['anomaly_score'].nunique():,}")

print("\nTop 10 priority scores:")
print(
    result[
        ["priority_rank", "anomaly_score", "priority_score"]
    ].head(10).to_string(index=False)
)

print("\n==============================")
print("SCORING COMPLETE")
print("==============================")