import pandas as pd
import joblib
import numpy as np

print("=" * 70)
print("CAUSAL CHRONOLOGICAL UNSUPERVISED V6 SCORING")
print("=" * 70)

# ============================================================
# PATHS
# ============================================================

MODEL_PATH = "model/isolation_forest_unsupervised_v6.pkl"

TEST_FEATURE_PATH = (
    "data/unsupervised_features/"
    "X_test_unsupervised_v6.csv"
)

OUTPUT_PATH = (
    "data/scored/"
    "test_unsupervised_v6_scored.csv"
)

# ============================================================
# 1. LOAD MODEL
# ============================================================

print("\nLoading V6 Isolation Forest...")

model = joblib.load(MODEL_PATH)

print(f"Model type: {type(model)}")
print(f"Number of trees: {len(model.estimators_):,}")
print(f"Random state: {model.random_state}")

# ============================================================
# 2. LOAD TEST FEATURES
# ============================================================

print("\nLoading V6 test features...")

X_test = pd.read_csv(
    TEST_FEATURE_PATH,
    low_memory=False
)

print(f"Test rows : {len(X_test):,}")
print(f"Features  : {X_test.shape[1]:,}")
print(f"Missing values : {X_test.isna().sum().sum():,}")

# ============================================================
# 3. CHECK ALERT ID
# ============================================================

if "_alert_id" not in X_test.columns:
    raise ValueError(
        "_alert_id column is missing from V6 test features!"
    )

print("\nStable alert ID check: PASS")

if X_test["_alert_id"].nunique() != len(X_test):
    raise ValueError(
        "Alert IDs are not unique!"
    )

print("Alert ID uniqueness: PASS")

# ============================================================
# 4. REMOVE ALERT ID FROM MODEL FEATURES
# ============================================================

alert_ids = X_test["_alert_id"].copy()

model_features = X_test.drop(
    columns=["_alert_id"]
)

# ============================================================
# 5. FEATURE COUNT CHECK
# ============================================================

if model_features.shape[1] != model.n_features_in_:
    raise ValueError(
        "Feature count mismatch!\n"
        f"Model expects: {model.n_features_in_}\n"
        f"Test contains: {model_features.shape[1]}"
    )

print("\nFeature count check: PASS")
print(f"Model features used: {model_features.shape[1]}")

# ============================================================
# 6. CALCULATE ANOMALY SCORE
# ============================================================

print("\nCalculating anomaly scores...")

decision_scores = model.decision_function(
    model_features
)

# More negative decision_function
# means more anomalous.
#
# Therefore:
# anomaly_score = -decision_function
#
# Higher anomaly score = higher priority.

anomaly_score = -decision_scores

# ============================================================
# 7. CREATE RESULT DATAFRAME
# ============================================================

scored = X_test.copy()

scored["anomaly_score"] = anomaly_score

# ============================================================
# 8. PRIORITY SCORE
# ============================================================

print("\nCreating priority scores...")

scored["priority_score"] = (
    scored["anomaly_score"]
)

# ============================================================
# 9. CREATE ORIGINAL ORDER FOR TIE-BREAKING
# ============================================================

print("\nCreating risk-priority ranking...")

scored["_original_order"] = np.arange(
    len(scored)
)

# ============================================================
# 10. SORT BY PRIORITY
# ============================================================

scored = scored.sort_values(
    by=[
        "priority_score",
        "_original_order"
    ],
    ascending=[
        False,
        True
    ],
    kind="mergesort"
).reset_index(drop=True)

# ============================================================
# 11. CREATE PRIORITY RANK
# ============================================================

scored["priority_rank"] = np.arange(
    1,
    len(scored) + 1
)

# Remove temporary column
scored = scored.drop(
    columns=["_original_order"]
)

# ============================================================
# 12. RANKING SAFETY CHECK
# ============================================================

print("\n" + "=" * 70)
print("V6 RANKING SAFETY CHECK")
print("=" * 70)

score_order_pass = (
    scored["anomaly_score"]
    .diff()
    .dropna()
    .le(0)
    .all()
)

rank_order_pass = (
    scored["priority_rank"]
    .equals(
        pd.Series(
            np.arange(
                1,
                len(scored) + 1
            ),
            index=scored.index,
            name="priority_rank"
        )
    )
)

print(
    "Higher anomaly score -> higher priority: PASS"
    if score_order_pass
    else
    "Higher anomaly score -> higher priority: FAIL"
)

print(
    "Priority ranks are sequential: PASS"
    if rank_order_pass
    else
    "Priority ranks are sequential: FAIL"
)

print(
    f"\nHighest anomaly score: "
    f"{scored['anomaly_score'].iloc[0]:.6f}"
)

print(
    f"Rank of highest score: "
    f"{scored['priority_rank'].iloc[0]}"
)

print(
    f"Lowest anomaly score: "
    f"{scored['anomaly_score'].iloc[-1]:.6f}"
)

print(
    f"Last priority rank: "
    f"{scored['priority_rank'].iloc[-1]:,}"
)

# ============================================================
# 13. ALERT ID SAFETY CHECK
# ============================================================

print("\n" + "=" * 70)
print("STABLE ALERT ID SAFETY CHECK")
print("=" * 70)

if scored["_alert_id"].nunique() != len(scored):
    raise ValueError(
        "Alert IDs are no longer unique!"
    )

print(
    "Alert IDs preserved after ranking: PASS"
)

print(
    "Alert IDs remain attached to scored alerts: PASS"
)

# ============================================================
# 14. SCORE SANITY CHECK
# ============================================================

print("\n" + "=" * 70)
print("V6 SCORE SANITY CHECK")
print("=" * 70)

print(
    f"Minimum anomaly score: "
    f"{scored['anomaly_score'].min():.6f}"
)

print(
    f"Maximum anomaly score: "
    f"{scored['anomaly_score'].max():.6f}"
)

print(
    f"Mean anomaly score: "
    f"{scored['anomaly_score'].mean():.6f}"
)

print(
    f"Median anomaly score: "
    f"{scored['anomaly_score'].median():.6f}"
)

print(
    f"Total alerts: "
    f"{len(scored):,}"
)

# ============================================================
# 15. TOP 20 ALERTS
# ============================================================

print("\n" + "=" * 70)
print("TOP 20 HIGHEST-PRIORITY ALERTS")
print("=" * 70)

top_columns = [
    "_alert_id",
    "priority_rank",
    "anomaly_score",
    "priority_score"
]

print(
    scored[
        top_columns
    ].head(20).to_string(
        index=False
    )
)

# ============================================================
# 16. TOP-K QUEUE SUMMARY
# ============================================================

print("\n" + "=" * 70)
print("RISK-RANKED REVIEW QUEUE")
print("=" * 70)

for k in [
    100,
    500,
    1000,
    5000,
    10000
]:

    if k <= len(scored):

        kth_score = (
            scored
            .iloc[k - 1]
            ["anomaly_score"]
        )

        print(
            f"Top-{k:<6} | "
            f"Score range: "
            f"{scored['anomaly_score'].iloc[0]:.6f}"
            f" -> "
            f"{kth_score:.6f}"
        )

# ============================================================
# 17. SAVE RESULTS
# ============================================================

print("\n" + "=" * 70)
print("SAVING V6 SCORED RESULTS")
print("=" * 70)

scored.to_csv(
    OUTPUT_PATH,
    index=False
)

print("\nSaved to:")
print(OUTPUT_PATH)

# ============================================================
# 18. VERIFY SAVED FILE
# ============================================================

saved_check = pd.read_csv(
    OUTPUT_PATH,
    low_memory=False
)

if "_alert_id" not in saved_check.columns:
    raise ValueError(
        "_alert_id was not saved in the scored file!"
    )

if len(saved_check) != len(scored):
    raise ValueError(
        "Saved row count does not match scored row count!"
    )

print("\nSaved file verification: PASS")
print("_alert_id preserved in scored CSV: PASS")

# ============================================================
# 19. FINAL MESSAGE
# ============================================================

print("\n" + "=" * 70)
print("V6 SCORING COMPLETE")
print("=" * 70)

print(
    """
IMPORTANT:

The V6 Isolation Forest was NOT retrained.

No incident IDs were used.

No ground-truth labels were used.

No attack labels were used.

No actual_incident information was used.

No incident information was used to
calculate anomaly scores.

No incident information was used to
create priority rankings.

Higher anomaly score = higher priority.

Rank 1 = highest anomaly score.

Top-K contains the K highest-scoring
alerts from the unsupervised model.

Equal anomaly scores preserve the
original chronological order.

_alert_id is only an identity key.

_alert_id is NOT used as a model feature.

Incident information may only be used
later during POST-HOC VALIDATION.

This scoring stage remains fully
UNSUPERVISED.
"""
)

print("=" * 70)