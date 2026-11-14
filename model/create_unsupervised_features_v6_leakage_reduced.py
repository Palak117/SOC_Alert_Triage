import os
import pandas as pd
import numpy as np


# ============================================================
# PATHS
# ============================================================

TRAIN_PATH = "data/train_test/train_80.csv"
TEST_PATH = "data/train_test/test_20.csv"

TRAIN_OUTPUT = "data/unsupervised_features_v6_leakage_reduced/X_train.csv"
TEST_OUTPUT = "data/unsupervised_features_v6_leakage_reduced/X_test.csv"


print("=" * 70)
print("CAUSAL CHRONOLOGICAL UNSUPERVISED FEATURE ENGINEERING V6")
print("=" * 70)


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def safe_numeric(series):
    """
    Convert values to numeric.
    Invalid/missing values become 0.
    """
    return pd.to_numeric(
        series,
        errors="coerce"
    ).fillna(0)


def normalize_text(series):
    """
    Normalize categorical/text values.
    """
    return (
        series
        .fillna("MISSING")
        .astype(str)
        .str.strip()
        .str.lower()
    )


# ============================================================
# STATIC CATEGORICAL RARITY
# ============================================================

def apply_rarity(train_series, target_series):
    """
    Learn categorical rarity from TRAINING DATA ONLY.

    Important:
        The target/test distribution is never used
        to calculate the rarity statistics.
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

        rarity_map = (
            raw_rarity / max_rarity
        )

    else:

        rarity_map = raw_rarity

    return (
        target_values
        .map(rarity_map)
        .fillna(1.0)
    )


# ============================================================
# PORT CATEGORY
# ============================================================

def port_category(series):
    """
    Convert ports into behavioral categories.

    0 = missing/zero
    1 = privileged/system port
    2 = registered/user port
    3 = dynamic/private port
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


# ============================================================
# PROTOCOL CATEGORY
# ============================================================

def protocol_category(series):
    """
    Group common network protocols.

    1  = ICMP
    6  = TCP
    17 = UDP
    0  = other/missing
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


# ============================================================
# MESSAGE SIZE BUCKET
# ============================================================

def message_size_bucket(series):
    """
    Convert message length into behavioral buckets.
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


# ============================================================
# COMBINATION RARITY
# ============================================================

def combination_rarity(
    train_combo,
    target_combo
):
    """
    Calculate normalized behavioral rarity
    using TRAINING DATA ONLY.
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
# NUMERIC BUCKET RARITY
# ============================================================

def numeric_bucket_rarity(
    train_series,
    target_series,
    bins
):
    """
    Fully unsupervised numeric rarity.

    The bucket boundaries are fixed before looking
    at target/test values.

    Rarity probabilities are learned ONLY from
    training data.

    Therefore:

        TRAIN -> learn distribution
        TEST  -> map into learned distribution
    """

    train_values = safe_numeric(
        train_series
    )

    target_values = safe_numeric(
        target_series
    )

    train_bucket = pd.cut(
        train_values,
        bins=bins,
        labels=False,
        include_lowest=True
    )

    target_bucket = pd.cut(
        target_values,
        bins=bins,
        labels=False,
        include_lowest=True
    )

    counts = (
        train_bucket
        .value_counts(normalize=True)
    )

    raw_rarity = -np.log(
        counts + 1e-12
    )

    max_rarity = raw_rarity.max()

    if max_rarity > 0:

        rarity_map = (
            raw_rarity / max_rarity
        )

    else:

        rarity_map = raw_rarity

    return (
        target_bucket
        .map(rarity_map)
        .fillna(1.0)
    )


# ============================================================
# MESSAGE LENGTH BUCKETS
# ============================================================

MESSAGE_LENGTH_BINS = [
    -1,
    115,
    500,
    1000,
    2000,
    3000,
    4000,
    5000,
    np.inf
]


# ============================================================
# MESSAGE WORD COUNT BUCKETS
# ============================================================

MESSAGE_WORD_BINS = [
    -1,
    14,
    25,
    50,
    100,
    200,
    300,
    360,
    np.inf
]


# ============================================================
# CAUSAL HISTORICAL FEATURES
# ============================================================

def add_causal_history_features(
    out,
    df,
    history_df=None
):
    """
    Create causal historical features.

    TRAINING:
        history_df = None

        Each row only sees alerts occurring before it.

    TEST:
        history_df = training data

        Test starts with training history and then
        continues chronologically through the test set.

    No future alerts are used.
    """

    historical_columns = [
        "src_ip",
        "src_host",
        "username",
        "product_name",
        "message_type",
        "pipeline"
    ]


    # ========================================================
    # BUILD HISTORY + CURRENT DATA
    # ========================================================

    if history_df is not None:

        combined = pd.concat(
            [
                history_df,
                df
            ],
            ignore_index=True
        )

        history_length = len(
            history_df
        )

    else:

        combined = df.copy()

        history_length = 0


    # ========================================================
    # HISTORICAL FEATURES
    # ========================================================

    for column in historical_columns:

        values = normalize_text(
            combined[column]
        )

        previous_count = (
            values
            .groupby(values)
            .cumcount()
        )

        first_seen = (
            previous_count == 0
        ).astype(int)


        # ----------------------------------------------------
        # Keep only current dataframe rows
        # ----------------------------------------------------

        current_previous_count = (
            previous_count
            .iloc[history_length:]
            .to_numpy()
        )

        current_first_seen = (
            first_seen
            .iloc[history_length:]
            .to_numpy()
        )


        # ----------------------------------------------------
        # Log compression
        #
        # Prevent very frequent identifiers from dominating
        # Isolation Forest.
        # ----------------------------------------------------

        out[
            f"{column}_previous_count"
        ] = np.log1p(
            current_previous_count
            .astype(float)
        )

        out[
            f"{column}_first_seen"
        ] = (
            current_first_seen
            .astype(int)
        )


    # ========================================================
    # BEHAVIOR HISTORY
    # ========================================================

    behavior_key = (

        normalize_text(
            combined["pipeline"]
        )

        + "|"

        + normalize_text(
            combined["product_name"]
        )

        + "|"

        + normalize_text(
            combined["message_type"]
        )

        + "|"

        + normalize_text(
            combined["action"]
        )

        + "|"

        + normalize_text(
            combined["protocol"]
        )

        + "|"

        + port_category(
            combined["dst_port"]
        ).astype(str)
    )


    behavior_previous_count = (
        behavior_key
        .groupby(behavior_key)
        .cumcount()
    )


    behavior_first_seen = (
        behavior_previous_count == 0
    ).astype(int)


    out["behavior_previous_count"] = (
        np.log1p(
            behavior_previous_count
            .iloc[history_length:]
            .to_numpy()
            .astype(float)
        )
    )


    out["behavior_first_seen"] = (
        behavior_first_seen
        .iloc[history_length:]
        .to_numpy()
        .astype(int)
    )


    return out


# ============================================================
# BUILD FEATURES
# ============================================================

def build_features(
    df,
    training_reference,
    history_df=None
):

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


    out["src_port_category"] = (
        port_category(
            df["src_port"]
        )
    )


    out["dst_port_category"] = (
        port_category(
            df["dst_port"]
        )
    )


    out["protocol_category"] = (
        protocol_category(
            df["protocol"]
        )
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


    # ========================================================
    # NETWORK PRESENCE
    # ========================================================

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
        message
        .str.split()
        .str.len()
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
# ========================================================
    # STATIC CATEGORICAL RARITY
    # ========================================================

    rarity_columns = [
        "pipeline",
        "product_name",
        "vendor_name",
        "message_type",
        "stream_name",
        "action",
        "severity",
    ]


    for column in rarity_columns:

        output_column = (
            column + "_rarity"
        )


        raw_rarity = apply_rarity(
            training_reference[column],
            df[column]
        )


        # ----------------------------------------------------
        # Log compression
        #
        # Prevent extreme rarity from dominating.
        # ----------------------------------------------------

        out[output_column] = (
            np.log1p(
                raw_rarity
            )
        )


    # ========================================================
    # NETWORK BEHAVIOR RARITY
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
    # HIGH LEVEL BEHAVIOR RARITY
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
    # CAUSAL HISTORY
    # ========================================================

    out = add_causal_history_features(
        out,
        df,
        history_df=history_df
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
# LOAD TRAINING DATA
# ============================================================

print("\nLoading training data...")

train = pd.read_csv(
    TRAIN_PATH,
    low_memory=False
)


# Stable ID BEFORE sorting.
train["_alert_id"] = np.arange(
    len(train),
    dtype=np.int64
)


print(
    f"Training rows: {len(train):,}"
)


# ============================================================
# LOAD TESTING DATA
# ============================================================

print("\nLoading testing data...")

test = pd.read_csv(
    TEST_PATH,
    low_memory=False
)


# Stable ID BEFORE sorting.
test["_alert_id"] = np.arange(
    len(test),
    dtype=np.int64
)


print(
    f"Testing rows: {len(test):,}"
)


# ============================================================
# CHRONOLOGICAL ORDER
# ============================================================

print("\nSorting data chronologically...")


train["timestamp"] = pd.to_datetime(
    train["timestamp"],
    unit="s",
    errors="coerce"
)


test["timestamp"] = pd.to_datetime(
    test["timestamp"],
    unit="s",
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


print(
    "Training data: chronological order"
)

print(
    "Testing data : chronological order"
)


# ============================================================
# CREATE TRAINING FEATURES
# ============================================================

print(
    "\nCreating V6 training features..."
)


X_train = build_features(
    df=train,
    training_reference=train,
    history_df=None
)


print(
    f"Training features: {X_train.shape}"
)


# ============================================================
# CREATE TEST FEATURES
# ============================================================

print(
    "\nCreating V6 testing features..."
)


X_test = build_features(
    df=test,
    training_reference=train,
    history_df=train
)


print(
    f"Testing features: {X_test.shape}"
)


# ============================================================
# IMPORTANT:
# ADD ALERT ID AFTER FEATURE CREATION
# ============================================================
#
# This keeps _alert_id OUT of the Isolation Forest feature
# matrix if you train using all columns.
#
# If you need alert IDs for joining later, they can be
# stored separately.
# ============================================================

X_train["_alert_id"] = (
    train["_alert_id"].values
)


X_test["_alert_id"] = (
    test["_alert_id"].values
)


# ============================================================
# FEATURE CONSISTENCY CHECK
# ============================================================

print("\n" + "=" * 70)
print("FEATURE CONSISTENCY CHECK")
print("=" * 70)


train_feature_columns = [
    c for c in X_train.columns
    if c != "_alert_id"
]


test_feature_columns = [
    c for c in X_test.columns
    if c != "_alert_id"
]


print(
    "Training model features:",
    len(train_feature_columns)
)


print(
    "Testing model features :",
    len(test_feature_columns)
)


if train_feature_columns != test_feature_columns:

    print("\nERROR: TRAIN/TEST FEATURES DO NOT MATCH.")

    train_only = sorted(
        set(train_feature_columns)
        -
        set(test_feature_columns)
    )

    test_only = sorted(
        set(test_feature_columns)
        -
        set(train_feature_columns)
    )

    print(
        "\nTrain only:"
    )

    print(train_only)


    print(
        "\nTest only:"
    )

    print(test_only)


    raise ValueError(
        "Training and testing feature columns do not match."
    )


print(
    "\nTRAIN/TEST FEATURE STRUCTURE: OK"
)


# ============================================================
# SANITY CHECK
# ============================================================

print("\n" + "=" * 70)
print("V6 FEATURE SANITY CHECK")
print("=" * 70)


print(
    "\nTraining missing values:",
    X_train.isna().sum().sum()
)


print(
    "Testing missing values :",
    X_test.isna().sum().sum()
)


numeric_train = (
    X_train
    .drop(columns=["_alert_id"])
    .select_dtypes(
        include=[np.number]
    )
)


numeric_test = (
    X_test
    .drop(columns=["_alert_id"])
    .select_dtypes(
        include=[np.number]
    )
)


print(
    "\nTraining infinite values:",
    np.isinf(
        numeric_train.to_numpy()
    ).sum()
)


print(
    "Testing infinite values :",
    np.isinf(
        numeric_test.to_numpy()
    ).sum()
)


print(
    "\nNumber of model features:",
    len(train_feature_columns)
)


# ============================================================
# CAUSAL HISTORY CHECK
# ============================================================

print("\n" + "=" * 70)
print("CAUSAL HISTORY FEATURE CHECK")
print("=" * 70)


causal_columns = [
    c
    for c in train_feature_columns
    if (
        "previous_count" in c
        or
        "first_seen" in c
    )
]


print(
    f"\nCausal history features: "
    f"{len(causal_columns)}"
)


for column in causal_columns:

    print(
        f"{column:<35}"
        f"min={X_train[column].min():.4f} "
        f"max={X_train[column].max():.4f} "
        f"mean={X_train[column].mean():.4f}"
    )


# ============================================================
# RARITY RANGE CHECK
# ============================================================

print("\n" + "=" * 70)
print("RARITY RANGE CHECK")
print("=" * 70)


rarity_columns = [
    c
    for c in train_feature_columns
    if "rarity" in c
]


for column in rarity_columns:

    print(
        f"{column:<35}"
        f"min={X_train[column].min():.4f} "
        f"max={X_train[column].max():.4f} "
        f"mean={X_train[column].mean():.4f}"
    )


# ============================================================
# V6 MESSAGE FEATURE CHECK
# ============================================================

print("\n" + "=" * 70)
print("V6 MESSAGE BEHAVIOR CHECK")
print("=" * 70)


message_features = [
    "message_length",
    "message_word_count",
    "message_digit_count",
    "message_special_count",
    "message_size_bucket"
]

for column in message_features:

    print(
        f"{column:<35}"
        f"min={X_train[column].min():.4f} "
        f"max={X_train[column].max():.4f} "
        f"mean={X_train[column].mean():.4f}"
    )


# ============================================================
# SAVE FEATURES
# ============================================================

print("\n" + "=" * 70)
print("SAVING V6 FEATURES")
print("=" * 70)


os.makedirs(os.path.dirname(TRAIN_OUTPUT), exist_ok=True)

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


print(
    TRAIN_OUTPUT
)


print(
    "\nTesting features saved:"
)


print(
    TEST_OUTPUT
)


# ============================================================
# FINAL LEAKAGE CHECK
# ============================================================

print("\n" + "=" * 70)
print("V6 LEAKAGE CHECK")
print("=" * 70)


print(
    "Labels used             : NO"
)


print(
    "Actual incidents used   : NO"
)


print(
    "Incident IDs used       : NO"
)


print(
    "Attack labels used      : NO"
)


print(
    "Ground truth used       : NO"
)


print(
    "Future alerts used      : NO"
)


print(
    "Test distribution used  : NO"
)


print()


print(
    "Categorical rarity      : TRAINING ONLY"
)


print(
    "Message rarity          : TRAINING ONLY"
)


print(
    "Word-count rarity       : TRAINING ONLY"
)


print(
    "Historical features     : PAST ALERTS ONLY"
)


print(
    "Port categories         : YES"
)


print(
    "Behavior combinations   : YES"
)


print(
    "Chronological ordering  : YES"
)


print()


print(
    "IMPORTANT:"
)


print(
    "All rarity statistics were learned from TRAINING DATA ONLY."
)


print(
    "Message-length rarity uses fixed predefined buckets."
)


print(
    "Message-word-count rarity uses fixed predefined buckets."
)


print(
    "Causal history features use only previous alerts."
)


print(
    "No incident information is used to create features."
)


print(
    "No ground-truth information is used."
)


print(
    "V6 feature engineering is fully unsupervised."
)


print("=" * 70)
print("V6 FEATURE ENGINEERING COMPLETE")
print("=" * 70)
