import pandas as pd
import numpy as np
import joblib
import os

from sklearn.ensemble import IsolationForest


# ============================================================
# PATHS
# ============================================================

TRAIN_FEATURES = (
    "data/unsupervised_features/"
    "X_train_unsupervised_v6.csv"
)

MODEL_OUTPUT = (
    "model/"
    "isolation_forest_unsupervised_v6.pkl"
)


# ============================================================
# SETTINGS
# ============================================================

CONTAMINATION = 0.05
N_ESTIMATORS = 300
RANDOM_STATE = 42
N_JOBS = -1


print("=" * 70)
print("ISOLATION FOREST V6 TRAINING")
print("=" * 70)


# ============================================================
# LOAD FEATURES
# ============================================================

print("\nLoading V6 training features...")

X_train = pd.read_csv(
    TRAIN_FEATURES,
    low_memory=False
)

print(
    f"Training feature shape: {X_train.shape}"
)


# ============================================================
# REMOVE NON-MODEL COLUMNS
# ============================================================

# _alert_id is an identifier, not a feature.
# If it exists, remove it before training.

if "_alert_id" in X_train.columns:

    print("\nRemoving _alert_id from model features...")

    X_train = X_train.drop(
        columns=["_alert_id"]
    )


# ============================================================
# BASIC VALIDATION
# ============================================================

print("\nChecking feature matrix...")

print(
    "Number of features:",
    X_train.shape[1]
)

print(
    "Number of rows:",
    X_train.shape[0]
)

missing_values = X_train.isna().sum().sum()

print(
    "Missing values:",
    missing_values
)


# Replace infinite values just in case.

X_train = X_train.replace(
    [np.inf, -np.inf],
    np.nan
)

X_train = X_train.fillna(0)


# ============================================================
# ENSURE NUMERIC DATA
# ============================================================

print("\nConverting features to numeric...")

for column in X_train.columns:

    X_train[column] = pd.to_numeric(
        X_train[column],
        errors="coerce"
    )

X_train = X_train.fillna(0)


# ============================================================
# FINAL FEATURE CHECK
# ============================================================

numeric_columns = X_train.select_dtypes(
    include=[np.number]
).columns.tolist()

non_numeric_columns = [
    c for c in X_train.columns
    if c not in numeric_columns
]

if non_numeric_columns:

    print(
        "\nERROR: Non-numeric columns found:"
    )

    print(non_numeric_columns)

    raise ValueError(
        "All Isolation Forest features must be numeric."
    )


infinite_count = np.isinf(
    X_train.to_numpy()
).sum()

print(
    "Infinite values:",
    infinite_count
)

if infinite_count > 0:

    raise ValueError(
        "Infinite values remain in training data."
    )


# ============================================================
# DISPLAY FEATURES
# ============================================================

print("\n" + "=" * 70)
print("FEATURE LIST")
print("=" * 70)

for i, column in enumerate(
    X_train.columns,
    start=1
):

    print(
        f"{i:02d}. {column}"
    )


# ============================================================
# TRAIN ISOLATION FOREST
# ============================================================

print("\n" + "=" * 70)
print("TRAINING ISOLATION FOREST")
print("=" * 70)

print(
    f"\nEstimators    : {N_ESTIMATORS}"
)

print(
    f"Contamination : {CONTAMINATION}"
)

print(
    f"Random state  : {RANDOM_STATE}"
)

print(
    f"Jobs          : {N_JOBS}"
)


model = IsolationForest(
    n_estimators=N_ESTIMATORS,
    contamination=CONTAMINATION,
    random_state=RANDOM_STATE,
    n_jobs=N_JOBS
)


print("\nFitting model...")

model.fit(X_train)


print(
    "\nModel training completed."
)


# ============================================================
# SAVE MODEL
# ============================================================

os.makedirs(
    os.path.dirname(MODEL_OUTPUT),
    exist_ok=True
)


joblib.dump(
    model,
    MODEL_OUTPUT
)


# ============================================================
# VERIFY MODEL
# ============================================================

print("\n" + "=" * 70)
print("MODEL VERIFICATION")
print("=" * 70)

print(
    "Model saved:",
    MODEL_OUTPUT
)

print(
    "Model features:",
    model.n_features_in_
)

print(
    "Training features:",
    X_train.shape[1]
)


if hasattr(model, "feature_names_in_"):

    print(
        "\nFeature names stored in model:"
    )

    for i, feature in enumerate(
        model.feature_names_in_,
        start=1
    ):

        print(
            f"{i:02d}. {feature}"
        )


# ============================================================
# FINAL CHECK
# ============================================================

if model.n_features_in_ != X_train.shape[1]:

    raise ValueError(
        "MODEL FEATURE COUNT DOES NOT MATCH "
        "TRAINING FEATURE COUNT."
    )


print("\n" + "=" * 70)
print("V6 TRAINING SUCCESSFUL")
print("=" * 70)

print(
    "\nModel:"
)

print(
    MODEL_OUTPUT
)

print(
    f"\nFeatures used: {model.n_features_in_}"
)

print(
    f"Training rows: {len(X_train):,}"
)

print(
    "\nNo labels were used."
)

print(
    "No actual_incident column was used."
)

print(
    "No ground truth was used."
)

print(
    "Training is fully unsupervised."
)

print("=" * 70)