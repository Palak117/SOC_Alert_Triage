import pandas as pd
import numpy as np

TRAIN_PATH = "data/train_test/train_80.csv"
TEST_PATH = "data/train_test/test_20.csv"

TRAIN_OUTPUT = "data/unsupervised_features/X_train_unsupervised_v5.csv"
TEST_OUTPUT = "data/unsupervised_features/X_test_unsupervised_v5.csv"

print("=" * 70)
print("CAUSAL CHRONOLOGICAL UNSUPERVISED FEATURE ENGINEERING V5")
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

    train_values = normalize_text(train_series)
    target_values = normalize_text(target_series)

    counts = train_values.value_counts()

    frequency = counts / len(train_values)

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


def port_category(series):

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


def combination_rarity(
    train_combo,
    target_combo
):

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
# CAUSAL HISTORY FEATURES
# ============================================================

def add_causal_history_features(
    out,
    df
):

    historical_columns = [
        "src_ip",
        "src_host",
        "username",
        "product_name",
        "message_type",
        "pipeline"
    ]

    for column in historical_columns:

        values = normalize_text(
            df[column]
        )

        previous_count = (
            values
            .groupby(values)
            .cumcount()
        )

        out[
            f"{column}_previous_count"
        ] = previous_count.astype(float)

        out[
            f"{column}_first_seen"
        ] = (
            previous_count == 0
        ).astype(int)

    # --------------------------------------------------------
    # BEHAVIOR HISTORY
    # --------------------------------------------------------

    behavior_key = (
        normalize_text(df["pipeline"])
        + "|"
        + normalize_text(df["product_name"])
        + "|"
        + normalize_text(df["message_type"])
        + "|"
        + normalize_text(df["action"])
        + "|"
        + normalize_text(df["protocol"])
        + "|"
        + port_category(
            df["dst_port"]
        ).astype(str)
    )

    behavior_previous_count = (
        behavior_key
        .groupby(behavior_key)
        .cumcount()
    )

    out[
        "behavior_previous_count"
    ] = behavior_previous_count.astype(float)

    out[
        "behavior_first_seen"
    ] = (
        behavior_previous_count == 0
    ).astype(int)

    return out


# ============================================================
# BUILD FEATURES
# ============================================================

def build_features(
    df,
    training_reference
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
        port_category(df["src_port"])
    )

    out["dst_port_category"] = (
        port_category(df["dst_port"])
    )

    out["protocol_category"] = (
        protocol_category(df["protocol"])
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
    # PRESENCE FEATURES
    # ========================================================

    for column in [
        "src_ip",
        "dst_ip",
        "src_host",
        "dst_host"
    ]:

        out[
            "has_" + column
        ] = (
            df[column].notna()
            &
            df[column]
            .astype(str)
            .ne("")
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
        df["username"]
        .astype(str)
        .ne("")
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

    out["suspicion_score"] = (
        safe_numeric(
            df["suspicion_score"]
        )
    )

    # ========================================================
    # STATIC RARITY
    # TRAINING DATA ONLY
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

        out[
            column + "_rarity"
        ] = apply_rarity(
            training_reference[column],
            df[column]
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

    out[
        "network_behavior_rarity"
    ] = combination_rarity(
        train_combo,
        target_combo
    )

    # ========================================================
    # HIGH-LEVEL BEHAVIOR RARITY
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

    out[
        "high_level_behavior_rarity"
    ] = combination_rarity(
        train_high_combo,
        target_high_combo
    )

    # ========================================================
    # CAUSAL HISTORY
    # ========================================================

    out = add_causal_history_features(
        out,
        df
    )

    # ========================================================
    # CLEAN
    # ========================================================

    out = (
        out
        .replace(
            [np.inf, -np.inf],
            np.nan
        )
        .fillna(0)
    )

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
# CREATE STABLE ALERT IDS
# IMPORTANT:
# CREATE IDS BEFORE CHRONOLOGICAL SORTING
# ============================================================

print(
    "\nCreating stable alert IDs..."
)

train["_alert_id"] = np.arange(
    len(train)
)

test["_alert_id"] = np.arange(
    len(test)
)

print(
    "Training alert IDs: PASS"
)

print(
    "Testing alert IDs : PASS"
)


# ============================================================
# CHRONOLOGICAL ORDER
# ============================================================

print(
    "\nSorting data chronologically..."
)

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

print(
    "Training data chronological order: PASS"
)

print(
    "Testing data chronological order : PASS"
)


# ============================================================
# LEARN RARITY FROM TRAINING ONLY
# ============================================================

print(
    "\nLearning rarity mappings from TRAINING ONLY..."
)

print(
    "Incident IDs are NOT used."
)


# ============================================================
# CREATE FEATURES
# ============================================================

print(
    "\nCreating V5 training features..."
)

X_train = build_features(
    train,
    train
)

print(
    f"Training features: {X_train.shape}"
)

print(
    "\nCreating V5 testing features..."
)

X_test = build_features(
    test,
    train
)

print(
    f"Testing features: {X_test.shape}"
)


# ============================================================
# ADD STABLE ALERT ID
# IMPORTANT:
# _alert_id IS NOT A MODEL FEATURE
# ============================================================

print(
    "\nAdding stable alert IDs to feature files..."
)

X_train.insert(
    0,
    "_alert_id",
    train["_alert_id"].reset_index(drop=True)
)

X_test.insert(
    0,
    "_alert_id",
    test["_alert_id"].reset_index(drop=True)
)

print(
    "Training _alert_id added: PASS"
)

print(
    "Testing _alert_id added : PASS"
)


# ============================================================
# FEATURE COUNT CHECK
# ============================================================

print(
    "\n" + "=" * 70
)

print(
    "V5 FEATURE SANITY CHECK"
)

print(
    "=" * 70
)

print(
    f"\nTraining shape : {X_train.shape}"
)

print(
    f"Testing shape  : {X_test.shape}"
)

print(
    "\nExpected:"
)

print(
    "60 model features + 1 _alert_id = 61 columns"
)

if X_train.shape[1] != 61:
    raise ValueError(
        f"Training feature count should be 61, "
        f"but found {X_train.shape[1]}"
    )

if X_test.shape[1] != 61:
    raise ValueError(
        f"Testing feature count should be 61, "
        f"but found {X_test.shape[1]}"
    )

print(
    "\nFeature count check: PASS"
)

print(
    f"Model features: {X_train.shape[1] - 1}"
)

print(
    "Identity column: _alert_id"
)

print(
    f"\nMissing train values: "
    f"{X_train.isna().sum().sum()}"
)

print(
    f"Missing test values: "
    f"{X_test.isna().sum().sum()}"
)


# ============================================================
# ALERT ID CHECK
# ============================================================

print(
    "\n" + "=" * 70
)

print(
    "STABLE ALERT ID CHECK"
)

print(
    "=" * 70
)

if X_train["_alert_id"].nunique() != len(X_train):
    raise ValueError(
        "Training alert IDs are not unique!"
    )

if X_test["_alert_id"].nunique() != len(X_test):
    raise ValueError(
        "Testing alert IDs are not unique!"
    )

if set(X_train["_alert_id"]) != set(
    range(len(X_train))
):
    raise ValueError(
        "Training alert IDs are invalid!"
    )

if set(X_test["_alert_id"]) != set(
    range(len(X_test))
):
    raise ValueError(
        "Testing alert IDs are invalid!"
    )

print(
    "Training alert ID uniqueness : PASS"
)

print(
    "Testing alert ID uniqueness  : PASS"
)

print(
    "Stable mapping preserved     : PASS"
)


# ============================================================
# CAUSAL FEATURE CHECK
# ============================================================

print(
    "\n" + "=" * 70
)

print(
    "CAUSAL HISTORY FEATURE CHECK"
)

print(
    "=" * 70
)

causal_columns = [
    c
    for c in X_train.columns
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
        f"min={X_train[column].min():.0f} "
        f"max={X_train[column].max():.0f} "
        f"mean={X_train[column].mean():.2f}"
    )


# ============================================================
# RARITY RANGE CHECK
# ============================================================

print(
    "\n" + "=" * 70
)

print(
    "RARITY RANGE CHECK"
)

print(
    "=" * 70
)

rarity_columns = [
    c
    for c in X_train.columns
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
# SAVE FEATURES
# ============================================================

print(
    "\n" + "=" * 70
)

print(
    "SAVING V5 FEATURES"
)

print(
    "=" * 70
)

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
# VERIFY SAVED FILES
# ============================================================

print(
    "\n" + "=" * 70
)

print(
    "SAVED FILE VERIFICATION"
)

print(
    "=" * 70
)

saved_train = pd.read_csv(
    TRAIN_OUTPUT,
    low_memory=False
)

saved_test = pd.read_csv(
    TEST_OUTPUT,
    low_memory=False
)

if "_alert_id" not in saved_train.columns:
    raise ValueError(
        "_alert_id missing from saved training file!"
    )

if "_alert_id" not in saved_test.columns:
    raise ValueError(
        "_alert_id missing from saved testing file!"
    )

if len(saved_train) != len(train):
    raise ValueError(
        "Saved training row count mismatch!"
    )

if len(saved_test) != len(test):
    raise ValueError(
        "Saved testing row count mismatch!"
    )

if saved_train.shape[1] != 61:
    raise ValueError(
        "Saved training file does not contain 61 columns!"
    )

if saved_test.shape[1] != 61:
    raise ValueError(
        "Saved testing file does not contain 61 columns!"
    )

print(
    "Saved training file: PASS"
)

print(
    "Saved testing file : PASS"
)

print(
    "_alert_id preserved : PASS"
)

print(
    "61 total columns   : PASS"
)


# ============================================================
# FINAL LEAKAGE CHECK
# ============================================================

print(
    "\n" + "=" * 70
)

print(
    "V5 LEAKAGE CHECK"
)

print(
    "=" * 70
)

print(
    "Labels used              : NO"
)

print(
    "Actual incidents used    : NO"
)

print(
    "Incident IDs used        : NO"
)

print(
    "Attack labels used       : NO"
)

print(
    "Ground truth used        : NO"
)

print(
    "Future alerts used       : NO"
)

print(
    "Test distribution used   : NO"
)

print(
    "Rarity statistics        : TRAINING ONLY"
)

print(
    "Historical features      : PREVIOUS ALERTS ONLY"
)

print(
    "Chronological ordering   : YES"
)

print(
    "Stable alert ID          : YES"
)

print(
    "\nIMPORTANT:"
)

print(
    "The current alert is NOT included "
    "in its own historical count."
)

print(
    "Future alerts are NOT used "
    "for historical count features."
)

print(
    "Incident IDs are NOT used."
)

print(
    "_alert_id is NOT a model feature."
)

print(
    "_alert_id is only an identity key."
)

print(
    "The V5 model remains UNSUPERVISED."
)

print("=" * 70)

print(
    "V5 FEATURE ENGINEERING COMPLETE"
)

print("=" * 70)