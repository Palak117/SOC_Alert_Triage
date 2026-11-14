import pandas as pd
import numpy as np

TRAIN_PATH = "data/train_test/train_80.csv"
TEST_PATH = "data/train_test/test_20.csv"

TRAIN_OUTPUT = "data/unsupervised_features/X_train_unsupervised_v4.csv"
TEST_OUTPUT = "data/unsupervised_features/X_test_unsupervised_v4.csv"

print("=" * 70)
print("LEAKAGE-SAFE UNSUPERVISED FEATURE ENGINEERING V4")
print("=" * 70)


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def safe_numeric(series):
    return pd.to_numeric(
        series,
        errors="coerce"
    ).fillna(0)


def normalize_text(series):
    return (
        series
        .fillna("MISSING")
        .astype(str)
        .str.strip()
        .str.lower()
    )


def apply_rarity(train_series, target_series):
    """
    Learn rarity from training data only.

    Output:
        0 = common
        1 = maximally rare
    """

    train_values = normalize_text(train_series)
    target_values = normalize_text(target_series)

    counts = train_values.value_counts()
    total = len(train_values)

    frequency = counts / total

    raw_rarity = -np.log(
        frequency + 1e-12
    )

    max_rarity = raw_rarity.max()

    if max_rarity > 0:
        rarity_map = raw_rarity / max_rarity
    else:
        rarity_map = raw_rarity

    return (
        target_values
        .map(rarity_map)
        .fillna(1.0)
    )


def port_category(series):
    """
    Convert ports into behavioral categories.
    """

    p = safe_numeric(series)

    return np.select(
        [
            p == 0,
            p < 1024,
            p < 49152,
            p >= 49152
        ],
        [
            0,
            1,
            2,
            3
        ],
        default=0
    )


def protocol_category(series):
    """
    Group common network protocols.
    """

    p = safe_numeric(series)

    return np.select(
        [
            p == 1,
            p == 6,
            p == 17
        ],
        [
            1,
            6,
            17
        ],
        default=0
    )


def message_size_bucket(series):
    """
    Convert exact message length into behavioral buckets.
    """

    x = safe_numeric(series)

    return np.select(
        [
            x == 0,
            x <= 100,
            x <= 500,
            x <= 1000,
            x <= 5000,
            x > 5000
        ],
        [
            0,
            1,
            2,
            3,
            4,
            5
        ],
        default=0
    )


def combination_rarity(train_combo, target_combo):
    """
    Calculate normalized behavioral rarity
    using training data only.
    """

    counts = train_combo.value_counts()

    frequency = (
        counts / len(train_combo)
    )

    raw_rarity = -np.log(
        frequency + 1e-12
    )

    max_rarity = raw_rarity.max()

    if max_rarity > 0:
        rarity_map = (
            raw_rarity / max_rarity
        )
    else:
        rarity_map = raw_rarity

    return (
        target_combo
        .map(rarity_map)
        .fillna(1.0)
    )


# ============================================================
# BUILD FEATURES
# ============================================================

def build_features(df, training_reference):

    out = pd.DataFrame(
        index=df.index
    )

    # ========================================================
    # TEMPORAL FEATURES
    # ========================================================

    timestamp = pd.to_datetime(
        df["timestamp"],
        errors="coerce"
    )

    out["hour"] = (
        timestamp.dt.hour
        .fillna(0)
        .astype(int)
    )

    out["day_of_week"] = (
        timestamp.dt.dayofweek
        .fillna(0)
        .astype(int)
    )

    out["is_weekend"] = (
        out["day_of_week"] >= 5
    ).astype(int)

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

    out["src_port"] = safe_numeric(
        df["src_port"]
    )

    out["dst_port"] = safe_numeric(
        df["dst_port"]
    )

    out["protocol"] = safe_numeric(
        df["protocol"]
    )

    out["src_port_category"] = port_category(
        df["src_port"]
    )

    out["dst_port_category"] = port_category(
        df["dst_port"]
    )

    out["protocol_category"] = protocol_category(
        df["protocol"]
    )

    out["same_port"] = (
        out["src_port"]
        ==
        out["dst_port"]
    ).astype(int)

    out["src_port_privileged"] = (
        (out["src_port"] > 0)
        &
        (out["src_port"] < 1024)
    ).astype(int)

    out["dst_port_privileged"] = (
        (out["dst_port"] > 0)
        &
        (out["dst_port"] < 1024)
    ).astype(int)

    # Presence features

    out["has_src_ip"] = (
        df["src_ip"].notna()
        &
        df["src_ip"].astype(str).ne("")
    ).astype(int)

    out["has_dst_ip"] = (
        df["dst_ip"].notna()
        &
        df["dst_ip"].astype(str).ne("")
    ).astype(int)

    out["has_src_host"] = (
        df["src_host"].notna()
        &
        df["src_host"].astype(str).ne("")
    ).astype(int)

    out["has_dst_host"] = (
        df["dst_host"].notna()
        &
        df["dst_host"].astype(str).ne("")
    ).astype(int)

    # ========================================================
    # MESSAGE FEATURES
    # ========================================================

    message = (
        df["message_sanitized"]
        .fillna("")
        .astype(str)
    )

    out["message_length"] = (
        message.str.len()
    )

    out["message_word_count"] = (
        message.str.split().str.len()
    )

    out["message_digit_count"] = (
        message.str.count(r"\d")
    )

    out["message_special_count"] = (
        message.str.count(
            r"[^a-zA-Z0-9\s]"
        )
    )

    out["message_size_bucket"] = (
        message_size_bucket(
            out["message_length"]
        )
    )

    # ========================================================
    # USER FEATURES
    # ========================================================

    out["has_username"] = (
        df["username"].notna()
        &
        df["username"].astype(str).ne("")
    ).astype(int)

    username = (
        df["username"]
        .fillna("")
        .astype(str)
    )

    out["username_length"] = (
        username.str.len()
    )

    # ========================================================
    # EXISTING NUMERIC SIGNAL
    # ========================================================

    out["suspicion_score"] = safe_numeric(
        df["suspicion_score"]
    )

    # ========================================================
    # INDIVIDUAL RARITY FEATURES
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
        "protocol"
    ]

    for column in rarity_columns:

        output_column = (
            column + "_rarity"
        )

        out[output_column] = apply_rarity(
            training_reference[column],
            df[column]
        )

    # ========================================================
    # NETWORK BEHAVIOR
    # ========================================================

    train_combo = (
        normalize_text(
            training_reference["pipeline"]
        )
        + "|"
        + normalize_text(
            training_reference["product_name"]
        )
        + "|"
        + normalize_text(
            training_reference["message_type"]
        )
        + "|"
        + normalize_text(
            training_reference["action"]
        )
        + "|"
        + normalize_text(
            training_reference["protocol"]
        )
        + "|"
        + port_category(
            training_reference["dst_port"]
        ).astype(str)
    )

    target_combo = (
        normalize_text(
            df["pipeline"]
        )
        + "|"
        + normalize_text(
            df["product_name"]
        )
        + "|"
        + normalize_text(
            df["message_type"]
        )
        + "|"
        + normalize_text(
            df["action"]
        )
        + "|"
        + normalize_text(
            df["protocol"]
        )
        + "|"
        + port_category(
            df["dst_port"]
        ).astype(str)
    )

    out["network_behavior_rarity"] = (
        combination_rarity(
            train_combo,
            target_combo
        )
    )

    # ========================================================
    # HIGH LEVEL BEHAVIOR
    # ========================================================

    train_high_combo = (
        normalize_text(
            training_reference["pipeline"]
        )
        + "|"
        + normalize_text(
            training_reference["message_type"]
        )
        + "|"
        + normalize_text(
            training_reference["action"]
        )
        + "|"
        + normalize_text(
            training_reference["protocol"]
        )
        + "|"
        + port_category(
            training_reference["src_port"]
        ).astype(str)
        + "|"
        + port_category(
            training_reference["dst_port"]
        ).astype(str)
    )

    target_high_combo = (
        normalize_text(
            df["pipeline"]
        )
        + "|"
        + normalize_text(
            df["message_type"]
        )
        + "|"
        + normalize_text(
            df["action"]
        )
        + "|"
        + normalize_text(
            df["protocol"]
        )
        + "|"
        + port_category(
            df["src_port"]
        ).astype(str)
        + "|"
        + port_category(
            df["dst_port"]
        ).astype(str)
    )

    out["high_level_behavior_rarity"] = (
        combination_rarity(
            train_high_combo,
            target_high_combo
        )
    )

    # ========================================================
    # CLEANUP
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

print(
    f"Training rows: {len(train):,}"
)

print("\nLoading testing data...")

test = pd.read_csv(
    TEST_PATH,
    low_memory=False
)

print(
    f"Testing rows: {len(test):,}"
)


# ============================================================
# CHRONOLOGICAL ORDER
# ============================================================

train["timestamp"] = pd.to_datetime(
    train["timestamp"],
    errors="coerce"
)

test["timestamp"] = pd.to_datetime(
    test["timestamp"],
    errors="coerce"
)

train = (
    train
    .sort_values(
        "timestamp",
        kind="mergesort"
    )
    .reset_index(drop=True)
)

test = (
    test
    .sort_values(
        "timestamp",
        kind="mergesort"
    )
    .reset_index(drop=True)
)


# ============================================================
# CREATE FEATURES
# ============================================================

print(
    "\nCreating V4 training features..."
)

X_train = build_features(
    train,
    train
)

print(
    f"Training features: {X_train.shape}"
)

print(
    "\nCreating V4 testing features..."
)

X_test = build_features(
    test,
    train
)

print(
    f"Testing features: {X_test.shape}"
)


# ============================================================
# SANITY CHECK
# ============================================================

print("\n" + "=" * 70)
print("V4 FEATURE SANITY CHECK")
print("=" * 70)

print(
    "\nMissing values:",
    X_train.isna().sum().sum()
)

numeric_train = (
    X_train.select_dtypes(
        include=[np.number]
    )
)

print(
    "\nInfinite values:",
    np.isinf(
        numeric_train.to_numpy()
    ).sum()
)

print(
    "\nNumber of features:",
    len(X_train.columns)
)


# ============================================================
# RARITY RANGE
# ============================================================

print("\n" + "=" * 70)
print("RARITY RANGE CHECK")
print("=" * 70)

rarity_columns = [
    c for c in X_train.columns
    if "rarity" in c
]

for column in rarity_columns:

    print(
        f"{column:<32}"
        f"min={X_train[column].min():.4f} "
        f"max={X_train[column].max():.4f} "
        f"mean={X_train[column].mean():.4f}"
    )


# ============================================================
# SAVE
# ============================================================

print("\n" + "=" * 70)
print("SAVING V4 FEATURES")
print("=" * 70)

X_train.to_csv(
    TRAIN_OUTPUT,
    index=False
)

X_test.to_csv(
    TEST_OUTPUT,
    index=False
)

print(
    "\nTraining features saved:"
)

print(TRAIN_OUTPUT)

print(
    "\nTesting features saved:"
)

print(TEST_OUTPUT)


# ============================================================
# LEAKAGE CHECK
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
print("Rarity statistics       : TRAINING ONLY")
print("Port categories         : YES")
print("Behavior combinations   : YES")
print("Chronological ordering  : YES")
print()
print("IMPORTANT:")
print("All rarity statistics were learned from TRAINING DATA ONLY.")
print("The test set was never used to construct rarity mappings.")
print("No ground-truth information was used.")
print("=" * 70)
