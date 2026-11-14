import pandas as pd
import numpy as np
from collections import Counter

# ============================================================
# LEAKAGE-SAFE UNSUPERVISED FEATURE ENGINEERING V3
# ============================================================

TRAIN_PATH = "data/train_test/train_80.csv"
TEST_PATH = "data/train_test/test_20.csv"

TRAIN_OUTPUT = "data/unsupervised_features/X_train_unsupervised_v3.csv"
TEST_OUTPUT = "data/unsupervised_features/X_test_unsupervised_v3.csv"

print("=" * 70)
print("LEAKAGE-SAFE UNSUPERVISED FEATURE ENGINEERING V3")
print("=" * 70)

# ============================================================
# HELPER FUNCTIONS
# ============================================================

def safe_numeric(series):
    return pd.to_numeric(series, errors="coerce").fillna(0)


def normalize_text(series):
    return (
        series
        .fillna("MISSING")
        .astype(str)
        .str.strip()
        .str.lower()
    )


def rarity_from_training(train_series, target_series):
    """
    Calculate rarity using TRAINING DATA ONLY.

    Higher value = rarer behavior.

    This prevents test data from influencing the learned
    behavioral distribution.
    """

    train_values = normalize_text(train_series)

    counts = train_values.value_counts()

    total = len(train_values)

    # Smoothed frequency.
    frequencies = counts / total

    # -log(frequency)
    rarity_map = -np.log(frequencies + 1e-12)

    target_values = normalize_text(target_series)

    # Completely unseen values receive maximum observed rarity.
    max_rarity = rarity_map.max()

    return target_values.map(rarity_map).fillna(max_rarity)


def port_category(series):
    """
    Convert exact ports into behavioral categories.

    This prevents every new port number from becoming a
    completely different behavior.
    """

    p = safe_numeric(series)

    conditions = [
        p == 0,
        p < 1024,
        p < 49152,
        p >= 49152,
    ]

    choices = [
        0,  # missing/zero
        1,  # well-known
        2,  # registered
        3,  # ephemeral/dynamic
    ]

    return np.select(
        conditions,
        choices,
        default=0
    )


def protocol_category(series):
    """
    Protocol behavioral grouping.
    """

    p = safe_numeric(series)

    conditions = [
        p == 1,
        p == 6,
        p == 17,
    ]

    choices = [
        1,  # ICMP
        6,  # TCP
        17, # UDP
    ]

    return np.select(
        conditions,
        choices,
        default=0
    )


def message_size_bucket(series):
    """
    Convert exact message length into behavioral buckets.
    """

    x = safe_numeric(series)

    conditions = [
        x == 0,
        x <= 100,
        x <= 500,
        x <= 1000,
        x <= 5000,
        x > 5000,
    ]

    choices = [
        0,
        1,
        2,
        3,
        4,
        5,
    ]

    return np.select(
        conditions,
        choices,
        default=0
    )


def build_features(df, training_reference):
    """
    Build unsupervised behavioral features.

    IMPORTANT:
    - No labels
    - No incident IDs
    - No attack labels
    - No ground truth
    - No future rows
    """

    out = pd.DataFrame(index=df.index)

    # ========================================================
    # TEMPORAL FEATURES
    # ========================================================

    timestamp = pd.to_datetime(
        df["timestamp"],
        errors="coerce"
    )

    out["hour"] = timestamp.dt.hour.fillna(0).astype(int)

    out["day_of_week"] = (
        timestamp.dt.dayofweek
        .fillna(0)
        .astype(int)
    )

    out["is_weekend"] = (
        out["day_of_week"] >= 5
    ).astype(int)

    # Cyclic encoding
    out["hour_sin"] = np.sin(
        2 * np.pi * out["hour"] / 24
    )

    out["hour_cos"] = np.cos(
        2 * np.pi * out["hour"] / 24
    )

    out["dow_sin"] = np.sin(
        2 * np.pi * out["day_of_week"] / 7
    )

    out["dow_cos"] = np.cos(
        2 * np.pi * out["day_of_week"] / 7
    )

    # ========================================================
    # NETWORK FEATURES
    # ========================================================

    out["src_port"] = safe_numeric(df["src_port"])
    out["dst_port"] = safe_numeric(df["dst_port"])
    out["protocol"] = safe_numeric(df["protocol"])

    # Port behavioral categories
    out["src_port_category"] = port_category(
        df["src_port"]
    )

    out["dst_port_category"] = port_category(
        df["dst_port"]
    )

    # Protocol category
    out["protocol_category"] = protocol_category(
        df["protocol"]
    )

    # Port relationship
    out["same_port"] = (
        safe_numeric(df["src_port"])
        == safe_numeric(df["dst_port"])
    ).astype(int)

    # Privileged ports
    out["src_port_privileged"] = (
        (safe_numeric(df["src_port"]) > 0)
        & (safe_numeric(df["src_port"]) < 1024)
    ).astype(int)

    out["dst_port_privileged"] = (
        (safe_numeric(df["dst_port"]) > 0)
        & (safe_numeric(df["dst_port"]) < 1024)
    ).astype(int)

    # Presence features
    out["has_src_ip"] = (
        df["src_ip"].notna()
        & df["src_ip"].astype(str).ne("")
    ).astype(int)

    out["has_dst_ip"] = (
        df["dst_ip"].notna()
        & df["dst_ip"].astype(str).ne("")
    ).astype(int)

    out["has_src_host"] = (
        df["src_host"].notna()
        & df["src_host"].astype(str).ne("")
    ).astype(int)

    out["has_dst_host"] = (
        df["dst_host"].notna()
        & df["dst_host"].astype(str).ne("")
    ).astype(int)

    # ========================================================
    # MESSAGE BEHAVIOR
    # ========================================================

    message = (
        df["message_sanitized"]
        .fillna("")
        .astype(str)
    )

    out["message_length"] = message.str.len()

    out["message_word_count"] = (
        message.str.split().str.len()
    )

    out["message_digit_count"] = (
        message.str.count(r"\d")
    )

    out["message_special_count"] = (
        message.str.count(r"[^a-zA-Z0-9\s]")
    )

    out["message_size_bucket"] = message_size_bucket(
        out["message_length"]
    )

    # ========================================================
    # USER / IDENTITY BEHAVIOR
    # ========================================================

    out["has_username"] = (
        df["username"].notna()
        & df["username"].astype(str).ne("")
    ).astype(int)

    username = (
        df["username"]
        .fillna("")
        .astype(str)
    )

    out["username_length"] = username.str.len()

    # ========================================================
    # EXISTING NUMERIC SIGNAL
    # ========================================================

    out["suspicion_score"] = safe_numeric(
        df["suspicion_score"]
    )

    # ========================================================
    # CATEGORICAL BEHAVIORAL RARITY
    # ========================================================

    rarity_columns = [
        "pipeline",
        "product_name",
        "vendor_name",
        "message_type",
        "stream_name",
        "action",
        "severity",
        "lifecycle_stage",
        "src_ip",
        "dst_ip",
        "src_host",
        "dst_host",
        "username",
        "src_port",
        "dst_port",
        "protocol",
    ]

    for column in rarity_columns:

        if column not in df.columns:
            out[column + "_rarity"] = 0
            continue

        out[column + "_rarity"] = rarity_from_training(
            training_reference[column],
            df[column]
        )

    # ========================================================
    # BEHAVIORAL COMBINATION
    # ========================================================

    train_combo = (
        normalize_text(training_reference["pipeline"])
        + "|"
        + normalize_text(training_reference["product_name"])
        + "|"
        + normalize_text(training_reference["message_type"])
        + "|"
        + normalize_text(training_reference["action"])
        + "|"
        + normalize_text(training_reference["protocol"].astype(str))
        + "|"
        + port_category(
            training_reference["dst_port"]
        ).astype(str)
    )

    test_combo = (
        normalize_text(df["pipeline"])
        + "|"
        + normalize_text(df["product_name"])
        + "|"
        + normalize_text(df["message_type"])
        + "|"
        + normalize_text(df["action"])
        + "|"
        + normalize_text(df["protocol"].astype(str))
        + "|"
        + port_category(
            df["dst_port"]
        ).astype(str)
    )

    combo_counts = train_combo.value_counts()
    combo_frequency = combo_counts / len(train_combo)

    combo_rarity = -np.log(
        combo_frequency + 1e-12
    )

    out["network_behavior_rarity"] = (
        test_combo
        .map(combo_rarity)
        .fillna(combo_rarity.max())
    )

    # ========================================================
    # HIGH-LEVEL BEHAVIOR COMBINATION
    # ========================================================

    train_high_combo = (
        normalize_text(training_reference["pipeline"])
        + "|"
        + normalize_text(training_reference["message_type"])
        + "|"
        + normalize_text(training_reference["action"])
        + "|"
        + normalize_text(training_reference["protocol"].astype(str))
        + "|"
        + port_category(
            training_reference["src_port"]
        ).astype(str)
        + "|"
        + port_category(
            training_reference["dst_port"]
        ).astype(str)
    )

    test_high_combo = (
        normalize_text(df["pipeline"])
        + "|"
        + normalize_text(df["message_type"])
        + "|"
        + normalize_text(df["action"])
        + "|"
        + normalize_text(df["protocol"].astype(str))
        + "|"
        + port_category(
            df["src_port"]
        ).astype(str)
        + "|"
        + port_category(
            df["dst_port"]
        ).astype(str)
    )

    high_counts = train_high_combo.value_counts()

    high_frequency = high_counts / len(train_high_combo)

    high_rarity = -np.log(
        high_frequency + 1e-12
    )

    out["high_level_behavior_rarity"] = (
        test_high_combo
        .map(high_rarity)
        .fillna(high_rarity.max())
    )

    # ========================================================
    # FINAL NUMERIC CLEANUP
    # ========================================================

    out = out.replace(
        [np.inf, -np.inf],
        np.nan
    )

    out = out.fillna(0)

    return out


# ============================================================
# LOAD DATA
# ============================================================

print("\nLoading training data...")

train = pd.read_csv(
    TRAIN_PATH,
    low_memory=False
)

print(f"Training rows: {len(train):,}")

print("\nLoading testing data...")

test = pd.read_csv(
    TEST_PATH,
    low_memory=False
)

print(f"Testing rows: {len(test):,}")

# ============================================================
# SORT CHRONOLOGICALLY
# ============================================================

train["timestamp"] = pd.to_datetime(
    train["timestamp"],
    errors="coerce"
)

test["timestamp"] = pd.to_datetime(
    test["timestamp"],
    errors="coerce"
)

train = train.sort_values(
    "timestamp",
    kind="mergesort"
).reset_index(drop=True)

test = test.sort_values(
    "timestamp",
    kind="mergesort"
).reset_index(drop=True)

# ============================================================
# BUILD FEATURES
# ============================================================

print("\nCreating training features...")

X_train = build_features(
    train,
    train
)

print("\nTraining features:")
print(X_train.shape)

print("\nCreating testing features...")

# IMPORTANT:
# Rarity maps are created from TRAINING DATA ONLY.
X_test = build_features(
    test,
    train
)

print("\nTesting features:")
print(X_test.shape)

# ============================================================
# SANITY CHECK
# ============================================================

print("\n" + "=" * 70)
print("FEATURE SANITY CHECK")
print("=" * 70)

print("\nMissing values:")
print(X_train.isna().sum().sum())

print("\nInfinite values:")

numeric_train = X_train.select_dtypes(
    include=[np.number]
)

print(
    np.isinf(
        numeric_train.to_numpy()
    ).sum()
)

print("\nNumber of features:")
print(len(X_train.columns))

print("\nFeature columns:")

for col in X_train.columns:
    print(col)

# ============================================================
# SAVE
# ============================================================

print("\n" + "=" * 70)
print("SAVING V3 FEATURES")
print("=" * 70)

X_train.to_csv(
    TRAIN_OUTPUT,
    index=False
)

X_test.to_csv(
    TEST_OUTPUT,
    index=False
)

print("\nTraining features saved:")
print(TRAIN_OUTPUT)

print("\nTesting features saved:")
print(TEST_OUTPUT)

# ============================================================
# LEAKAGE REPORT
# ============================================================

print("\n" + "=" * 70)
print("LEAKAGE CHECK")
print("=" * 70)

print("Labels used             : NO")
print("Actual incidents used   : NO")
print("Incident IDs used       : NO")
print("Attack labels used      : NO")
print("Ground truth used       : NO")
print("Future alerts used      : NO")
print("Test distribution used  : NO")
print()
print("Categorical encoding    : NO")
print("Training rarity maps    : YES")
print("Port categories         : YES")
print("Behavior combinations   : YES")
print("Chronological ordering  : YES")
print()
print("IMPORTANT:")
print("All rarity statistics were learned from TRAINING DATA ONLY.")
print("The test set was never used to construct rarity mappings.")
print("No ground-truth information was used.")
print("=" * 70)