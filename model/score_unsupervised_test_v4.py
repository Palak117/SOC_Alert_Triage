import pandas as pd
import joblib

print("=" * 70)
print("UNSUPERVISED V4 TEST SCORING")
print("=" * 70)

# ============================================================
# 1. LOAD TRAINED V4 MODEL
# ============================================================

print("\nLoading trained V4 model...")

model = joblib.load(
    "model/isolation_forest_unsupervised_v4.pkl"
)

# ============================================================
# 2. LOAD V4 TEST FEATURES
# ============================================================

print("Loading V4 test features...")

X_test = pd.read_csv(
    "data/unsupervised_features/X_test_unsupervised_v4.csv"
)

print("\n" + "=" * 30)
print("SCORING INFORMATION")
print("=" * 30)

print(f"Test records : {len(X_test):,}")
print(f"Features     : {X_test.shape[1]:,}")

# ============================================================
# 3. GENERATE ANOMALY SCORES
# ============================================================

print("\nGenerating anomaly scores...")

# Isolation Forest:
# lower decision_function = more anomalous
anomaly_score = model.decision_function(X_test)

# Convert to priority score:
# higher priority = more anomalous
priority_score = -anomaly_score

scored = pd.DataFrame({
    "anomaly_score": anomaly_score,
    "priority_score": priority_score
})

# ============================================================
# 4. CREATE PRIORITY RANKING
# ============================================================

scored = scored.sort_values(
    "priority_score",
    ascending=False
).reset_index(drop=True)

scored["priority_rank"] = (
    range(1, len(scored) + 1)
)

# ============================================================
# 5. SAVE
# ============================================================

output_path = (
    "data/scored/"
    "test_unsupervised_v4_scored.csv"
)

scored.to_csv(
    output_path,
    index=False
)

# ============================================================
# 6. SCORE ANALYSIS
# ============================================================

print("\n" + "=" * 30)
print("V4 TEST SCORING COMPLETE")
print("=" * 30)

print("Saved to:")
print(output_path)

print("\nScore analysis:")

print(
    f"Minimum anomaly score : "
    f"{scored['anomaly_score'].min():.6f}"
)

print(
    f"Maximum anomaly score : "
    f"{scored['anomaly_score'].max():.6f}"
)

print(
    f"Mean anomaly score    : "
    f"{scored['anomaly_score'].mean():.6f}"
)

print(
    f"Unique anomaly scores : "
    f"{scored['anomaly_score'].nunique():,}"
)

# ============================================================
# 7. TOP 20
# ============================================================

print("\nTop 20 priority scores:")

print(
    scored[
        [
            "priority_rank",
            "anomaly_score",
            "priority_score"
        ]
    ].head(20).to_string(index=False)
)

# ============================================================
# 8. SAFETY STATEMENT
# ============================================================

print("\n" + "=" * 30)
print("IMPORTANT:")
print("=" * 30)

print("No labels were used.")
print("No incident IDs were used.")
print("No ground-truth information was used.")
print("Scores are based only on learned behavioral patterns.")

print("=" * 70)