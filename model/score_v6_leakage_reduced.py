import os
import joblib
import numpy as np
import pandas as pd

FEATURES = "data/unsupervised_features_v6_leakage_reduced/X_test.csv"
TEST_DATA = "data/train_test/test_20.csv"
MODEL_PATH = "model/isolation_forest_v6_leakage_reduced.pkl"
OUTPUT = "data/scored/test_v6_leakage_reduced_scored.csv"

print("Loading test features...")
X = pd.read_csv(FEATURES, low_memory=False)

if "_alert_id" in X.columns:
    X = X.drop(columns=["_alert_id"])

X = X.apply(pd.to_numeric, errors="coerce")
X = X.replace([np.inf, -np.inf], 0).fillna(0)

model = joblib.load(MODEL_PATH)

if X.shape[1] != model.n_features_in_:
    raise ValueError(
        f"Feature mismatch: test has {X.shape[1]}, model expects {model.n_features_in_}"
    )

print("Scoring", f"{len(X):,}", "test alerts...")
raw = model.decision_function(X)
scores = -raw

original = pd.read_csv(TEST_DATA, low_memory=False)

if len(original) != len(X):
    raise ValueError("Test data and feature row counts do not match.")

# Preserve the test-row alignment; rank higher anomaly scores first.
result = original.copy()
result["anomaly_score"] = scores
result["priority_rank"] = (
    result["anomaly_score"].rank(method="first", ascending=False).astype("int64")
)

os.makedirs("data/scored", exist_ok=True)
result.to_csv(OUTPUT, index=False)

print("\nSCORING COMPLETE")
print("Output:", OUTPUT)
print("Alerts scored:", f"{len(result):,}")
print("Incident/label columns, if present, were not passed to the model.")
print("Top 10 anomaly scores:")
print(result.nlargest(10, "anomaly_score")[["anomaly_score", "priority_rank"]].to_string(index=False))
