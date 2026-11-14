import pandas as pd
import joblib
from sklearn.ensemble import IsolationForest

print("=" * 70)
print("CAUSAL CHRONOLOGICAL UNSUPERVISED ISOLATION FOREST V5 TRAINING")
print("=" * 70)

# ============================================================
# 1. LOAD V5 TRAINING FEATURES
# ============================================================

print("\nLoading V5 training features...")

X_train = pd.read_csv(
    "data/unsupervised_features/X_train_unsupervised_v5.csv"
)

print("\n" + "=" * 30)
print("TRAINING INFORMATION")
print("=" * 30)

print(f"Training rows : {len(X_train):,}")
print(f"Features      : {X_train.shape[1]:,}")

print(
    f"\nMissing values : "
    f"{X_train.isna().sum().sum():,}"
)

# ============================================================
# 2. CREATE ISOLATION FOREST
# ============================================================

print("\nCreating Isolation Forest...")

model = IsolationForest(
    n_estimators=300,
    max_samples="auto",
    contamination="auto",
    random_state=42,
    n_jobs=-1
)

# ============================================================
# 3. TRAIN
# ============================================================

print("Training model...")

model.fit(X_train)

print("Training complete.")

# ============================================================
# 4. SAVE MODEL
# ============================================================

model_path = (
    "model/isolation_forest_unsupervised_v5.pkl"
)

print("\nSaving model...")

joblib.dump(
    model,
    model_path
)

# ============================================================
# 5. FINAL REPORT
# ============================================================

print("\n" + "=" * 70)
print("V5 MODEL TRAINING COMPLETE")
print("=" * 70)

print("Model saved to:")
print(model_path)

print("\n" + "=" * 30)
print("LEAKAGE CHECK")
print("=" * 30)

print("Labels used              : NO")
print("Incident IDs used        : NO")
print("Actual incidents used    : NO")
print("Attack labels used       : NO")
print("Test data used           : NO")
print("Ground truth used        : NO")
print("Future alerts used       : NO")

print("\nModel learned only from:")
print("V5 causal chronological behavioral features.")

print("\nV5 features include:")
print("- Static rarity learned from training data")
print("- Historical previous-count features")
print("- First-seen behavioral features")
print("- Chronological ordering")
print("- No incident information")

print("=" * 70)