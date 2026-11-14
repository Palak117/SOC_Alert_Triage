import pandas as pd
import joblib
import os

MODEL_PATH = "model/isolation_forest.pkl"
TEST_FEATURES_PATH = "data/features/X_test.csv"
OUTPUT_DIR = "data/scored"

os.makedirs(OUTPUT_DIR, exist_ok=True)

OUTPUT_PATH = os.path.join(
    OUTPUT_DIR,
    "test_scored.csv"
)

print("Loading trained model...")
model = joblib.load(MODEL_PATH)

print("Loading test features...")
X_test = pd.read_csv(TEST_FEATURES_PATH)

print("\n==============================")
print("SCORING TEST DATA")
print("==============================")

print(f"Test records : {len(X_test):,}")
print(f"Features     : {X_test.shape[1]}")

print("\nGenerating anomaly scores...")

# Isolation Forest:
# Higher decision_function value = more normal
# Lower value = more anomalous
raw_scores = model.decision_function(X_test)

# Convert so that HIGHER score = MORE ANOMALOUS
anomaly_score = -raw_scores

# Add score to test features
X_test["anomaly_score"] = anomaly_score

print("Scoring complete.")

print("\nSorting alerts by anomaly score...")

X_test = X_test.sort_values(
    "anomaly_score",
    ascending=False
).reset_index(drop=True)

# Add priority rank
X_test["priority_rank"] = range(1, len(X_test) + 1)

print("\nSaving scored test data...")

X_test.to_csv(
    OUTPUT_PATH,
    index=False
)

print("\n==============================")
print("TEST SCORING COMPLETE")
print("==============================")

print(f"Saved to: {OUTPUT_PATH}")

print("\nTop 10 most anomalous alerts:")

print(
    X_test[
        ["priority_rank", "anomaly_score"]
    ].head(10)
)

print("\n==============================")
print("ANOMALY SCORE ANALYSIS")
print("==============================")

print(f"Minimum score : {X_test['anomaly_score'].min():.6f}")
print(f"Maximum score : {X_test['anomaly_score'].max():.6f}")
print(f"Mean score    : {X_test['anomaly_score'].mean():.6f}")
print(f"Unique scores : {X_test['anomaly_score'].nunique():,}")

print("\nTop 20 anomaly scores:")
print(X_test["anomaly_score"].head(20).to_string(index=False))

print("\nBottom 20 anomaly scores:")
print(X_test["anomaly_score"].tail(20).to_string(index=False))