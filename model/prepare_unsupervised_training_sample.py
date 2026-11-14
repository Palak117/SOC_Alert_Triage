import pandas as pd
from pathlib import Path

# ============================================================
# DUPLICATE-AWARE UNSUPERVISED TRAINING SAMPLE
# ============================================================

RAW_TRAIN_PATH = "data/train_test/train_80.csv"
FEATURE_PATH = "data/unsupervised_features/X_train_unsupervised_v2.csv"
OUTPUT_PATH = "data/unsupervised_features/X_train_unsupervised_v2_sampled.csv"

MAX_PER_PATTERN = 20

print("=" * 70)
print("DUPLICATE-AWARE UNSUPERVISED TRAINING SAMPLE")
print("=" * 70)

# ------------------------------------------------------------
# LOAD RAW TRAINING DATA
# ------------------------------------------------------------

print("\nLoading raw training data...")
raw = pd.read_csv(RAW_TRAIN_PATH, low_memory=False)

print(f"Raw training rows : {len(raw):,}")

# ------------------------------------------------------------
# LOAD ENGINEERED FEATURES
# ------------------------------------------------------------

print("\nLoading engineered training features...")
features = pd.read_csv(FEATURE_PATH)

print(f"Feature rows      : {len(features):,}")
print(f"Feature columns   : {features.shape[1]}")

if len(raw) != len(features):
    raise ValueError(
        "Raw training data and engineered features have different row counts!"
    )

# ------------------------------------------------------------
# BEHAVIORAL COLUMNS
#
# These describe the alert itself.
# We deliberately DO NOT use:
# - labels
# - actual_incident
# - incident_ids
# - attack techniques
# - attack tactics
# - rarity features
# - any ground-truth field
# ------------------------------------------------------------

BEHAVIOR_COLUMNS = [
    "timestamp",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "pipeline",
    "product_name",
    "vendor_name",
    "message_type",
    "stream_name",
    "action",
    "severity",
    "lifecycle_stage",
    "message_sanitized",
    "username",
    "src_host",
    "dst_host",
    "matched_rules",
    "set_roles",
]

# Keep only columns that actually exist.
available_columns = [
    col for col in BEHAVIOR_COLUMNS
    if col in raw.columns
]

print("\nBehavioral columns used:")
for col in available_columns:
    print(f"  {col}")

# ------------------------------------------------------------
# CREATE BEHAVIORAL PATTERN
# ------------------------------------------------------------

print("\nCreating behavioral patterns...")

behavior_data = raw[available_columns].copy()

# Normalize missing values so identical missing values
# are treated consistently.
behavior_data = behavior_data.fillna("<MISSING>")

# Convert to strings to create deterministic patterns.
behavior_data = behavior_data.astype(str)

patterns = behavior_data.agg("|".join, axis=1)

raw["_behavior_pattern"] = patterns

unique_patterns = raw["_behavior_pattern"].nunique()

print(f"\nUnique behavioral patterns : {unique_patterns:,}")
print(
    f"Duplicate rows             : "
    f"{len(raw) - unique_patterns:,}"
)

print(
    f"Duplicate percentage       : "
    f"{(1 - unique_patterns / len(raw)) * 100:.2f}%"
)

# ------------------------------------------------------------
# DUPLICATE-AWARE SAMPLING
#
# We preserve the FIRST occurrences.
# This is important because the training data is chronological.
# ------------------------------------------------------------

print(f"\nKeeping maximum {MAX_PER_PATTERN} alerts per pattern...")

keep_indices = (
    raw.groupby("_behavior_pattern", sort=False)
       .head(MAX_PER_PATTERN)
       .index
)

keep_indices = keep_indices.sort_values()

sampled_features = features.iloc[keep_indices].copy()

# ------------------------------------------------------------
# SAVE
# ------------------------------------------------------------

Path(OUTPUT_PATH).parent.mkdir(parents=True, exist_ok=True)

sampled_features.to_csv(
    OUTPUT_PATH,
    index=False
)

# ------------------------------------------------------------
# REPORT
# ------------------------------------------------------------

print("\n" + "=" * 70)
print("TRAINING SAMPLE COMPLETE")
print("=" * 70)

print(f"Original training rows : {len(features):,}")
print(f"Sampled training rows  : {len(sampled_features):,}")
print(
    f"Rows removed           : "
    f"{len(features) - len(sampled_features):,}"
)

print(
    f"Reduction              : "
    f"{(1 - len(sampled_features) / len(features)) * 100:.2f}%"
)

print("\nSaved to:")
print(OUTPUT_PATH)

print("\n" + "=" * 70)
print("LEAKAGE CHECK")
print("=" * 70)

print("Labels used           : NO")
print("Actual incidents used : NO")
print("Incident IDs used     : NO")
print("Attack labels used    : NO")
print("Test data used        : NO")
print("Ground truth used     : NO")
print("Rarity features used  : NO for grouping")
print("Future alerts used    : NO")

print("\nOriginal training dataset was NOT modified.")
print("Test dataset was NOT modified.")
print("Only a separate model-fitting sample was created.")

print("=" * 70)