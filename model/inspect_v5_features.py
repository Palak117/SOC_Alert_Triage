import pandas as pd
import joblib
import os

print("=" * 70)
print("V5 FEATURE INSPECTION")
print("=" * 70)

MODEL_PATH = "model/isolation_forest_unsupervised_v5.pkl"
FEATURE_PATH = "data/features/X_test.csv"

# ---------------------------------------------------------
# Load model
# ---------------------------------------------------------

print("\nLoading V5 model...")

if not os.path.exists(MODEL_PATH):
    print("ERROR: Model file not found:")
    print(MODEL_PATH)
    raise SystemExit

model = joblib.load(MODEL_PATH)

print("Model type:", type(model))
print("Number of trees:", model.n_estimators)
print("Random state:", model.random_state)

# ---------------------------------------------------------
# Load test features
# ---------------------------------------------------------

print("\nLoading V5 test features...")

if not os.path.exists(FEATURE_PATH):
    print("ERROR: Feature file not found:")
    print(FEATURE_PATH)
    raise SystemExit

X_test = pd.read_csv(FEATURE_PATH)

print("Test rows    :", len(X_test))
print("Test columns :", len(X_test.columns))
print("Missing vals :", X_test.isna().sum().sum())

# ---------------------------------------------------------
# Model feature count
# ---------------------------------------------------------

print("\nModel expected feature count:")

if hasattr(model, "n_features_in_"):
    print(model.n_features_in_)
else:
    print("Not available")

# ---------------------------------------------------------
# Feature names
# ---------------------------------------------------------

print("\n" + "=" * 70)
print("V5 FEATURE NAMES")
print("=" * 70)

for i, feature in enumerate(X_test.columns, start=1):
    print(f"{i:02d}. {feature}")

# ---------------------------------------------------------
# Feature data types
# ---------------------------------------------------------

print("\n" + "=" * 70)
print("V5 FEATURE DATA TYPES")
print("=" * 70)

for feature in X_test.columns:
    print(f"{feature:40} {X_test[feature].dtype}")

# ---------------------------------------------------------
# Basic statistics
# ---------------------------------------------------------

print("\n" + "=" * 70)
print("V5 FEATURE SUMMARY")
print("=" * 70)

print(X_test.describe().T.to_string())

# ---------------------------------------------------------
# Check
# ---------------------------------------------------------

print("\n" + "=" * 70)
print("V5 FEATURE INSPECTION COMPLETE")
print("=" * 70)