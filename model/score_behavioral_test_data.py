import pandas as pd
import pickle
import os

MODEL_PATH = "model/isolation_forest_behavioral.pkl"
TEST_PATH = "data/behavioral_features/X_test_behavioral.csv"
OUTPUT_PATH = "data/scored/test_behavioral_scored.csv"

print("Loading trained behavioral model...")

with open(MODEL_PATH, "rb") as f:
    model = pickle.load(f)

print("Loading behavioral test features...")

X_test = pd.read_csv(TEST_PATH)

print("\n==============================")
print("SCORING BEHAVIORAL TEST DATA")
print("==============================")

print(f"Test records : {len(X_test):,}")
print(f"Features     : {X_test.shape[1]}")

print("\nGenerating anomaly scores...")

# Isolation Forest:
# lower decision_function = more anomalous
anomaly_score = model.decision_function(X_test)

# Convert so HIGHER = HIGHER PRIORITY
priority_score = -anomaly_score

# Create results
results = X_test.copy()

results["anomaly_score"] = anomaly_score
results["priority_score"] = priority_score

# Highest priority first
results = results.sort_values(
    "priority_score",
    ascending=False
).reset_index(drop=True)

# Priority rank
results["priority_rank"] = (
    results.index + 1
)

# Create directory
os.makedirs(
    os.path.dirname(OUTPUT_PATH),
    exist_ok=True
)

print("Saving scored test data...")

results.to_csv(
    OUTPUT_PATH,
    index=False
)

print("\n==============================")
print("BEHAVIORAL TEST SCORING COMPLETE")
print("==============================")

print("Saved to:")
print(OUTPUT_PATH)

print("\nScore analysis:")

print(
    f"Minimum anomaly score : "
    f"{anomaly_score.min():.6f}"
)

print(
    f"Maximum anomaly score : "
    f"{anomaly_score.max():.6f}"
)

print(
    f"Mean anomaly score    : "
    f"{anomaly_score.mean():.6f}"
)

print(
    f"Unique anomaly scores : "
    f"{len(set(anomaly_score)):,}"
)

print("\nTop 20 priority alerts:")

print(
    results[
        [
            "priority_rank",
            "anomaly_score",
            "priority_score"
        ]
    ].head(20).to_string(index=False)
)