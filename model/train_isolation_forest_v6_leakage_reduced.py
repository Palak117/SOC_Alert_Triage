import os
import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest

TRAIN_FEATURES = "data/unsupervised_features_v6_leakage_reduced/X_train.csv"
MODEL_OUTPUT = "model/isolation_forest_v6_leakage_reduced.pkl"

print("Loading leakage-reduced training features...")
X_train = pd.read_csv(TRAIN_FEATURES, low_memory=False)

if "_alert_id" in X_train.columns:
    X_train = X_train.drop(columns=["_alert_id"])

X_train = X_train.apply(pd.to_numeric, errors="coerce")
X_train = X_train.replace([float("inf"), float("-inf")], 0).fillna(0)

print("Training rows:", len(X_train))
print("Model features:", X_train.shape[1])
print("Training separate Isolation Forest (300 trees)...")

model = IsolationForest(
    n_estimators=300,
    contamination=0.05,
    random_state=42,
    n_jobs=-1
)
model.fit(X_train)

os.makedirs("model", exist_ok=True)
joblib.dump(model, MODEL_OUTPUT)

print("\nTRAINING COMPLETE")
print("Saved separate model:", MODEL_OUTPUT)
print("Training rows:", len(X_train))
print("Features:", model.n_features_in_)
print("No incident labels were supplied to model.fit().")
