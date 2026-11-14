import pandas as pd
import numpy as np
import json
import os
from collections import defaultdict

# ============================================================
# PATHS
# ============================================================

TRAIN_PATH = "data/train_test/train_80.csv"
TEST_PATH = "data/train_test/test_20.csv"

OUTPUT_DIR = "data/unsupervised_features"

TRAIN_OUTPUT = os.path.join(
    OUTPUT_DIR,
    "X_train_unsupervised_v2.csv"
)

TEST_OUTPUT = os.path.join(
    OUTPUT_DIR,
    "X_test_unsupervised_v2.csv"
)

os.makedirs(OUTPUT_DIR, exist_ok=True)


# ============================================================
# CONFIGURATION
# ============================================================

# Columns that contain ground-truth / post-hoc information.
# NEVER use these for model features.

LEAKAGE_COLUMNS = {
    "label_binary",
    "label_confidence",
    "actual_incident",
    "incident_ids",
    "attack_techniques",
    "attack_tactics",
    "defense_techniques",
    "mo_name",
    "is_false_positive",
    "disposition",
    "disposition_category",
    "set_roles",
    "matched_rules",
    "status_name",
}


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def safe_numeric(series, default=0.0):
    return pd.to_numeric(
        series,
        errors="coerce"
    ).fillna(default)


def string_length(series):
    return (
        series
        .fillna("")
        .astype(str)
        .str.len()
        .astype(float)
    )


def binary_present(series):
    return (
        series
        .fillna("")
        .astype(str)
        .str.strip()
        .ne("")
        .astype(float)
    )


# ============================================================
# CREATE FEATURES
# ============================================================

def create_features(df, historical_state=None):
    """
    Create leakage-safe unsupervised behavioral features.

    IMPORTANT:
    - No labels are used.
    - No incident information is used.
    - No future alerts are used.
    - Historical frequency features are calculated from alerts
      that appeared before the current alert.
    """

    df = df.copy()

    features = pd.DataFrame(index=df.index)

    # ========================================================
    # TIMESTAMP
    # ========================================================

    timestamp = pd.to_datetime(
        df["timestamp"],
        errors="coerce",
        unit="s"
    )

    # If timestamp is already datetime-like, retry normally.
    if timestamp.isna().mean() > 0.5:
        timestamp = pd.to_datetime(
            df["timestamp"],
            errors="coerce"
        )

    features["hour"] = (
        timestamp.dt.hour
        .fillna(0)
        .astype(float)
    )

    features["day_of_week"] = (
        timestamp.dt.dayofweek
        .fillna(0)
        .astype(float)
    )

    features["is_weekend"] = (
        timestamp.dt.dayofweek
        .isin([5, 6])
        .astype(float)
    )

    # Cyclic representation of time.
    features["hour_sin"] = np.sin(
        2 * np.pi * features["hour"] / 24
    )

    features["hour_cos"] = np.cos(
        2 * np.pi * features["hour"] / 24
    )

    features["dow_sin"] = np.sin(
        2 * np.pi * features["day_of_week"] / 7
    )

    features["dow_cos"] = np.cos(
        2 * np.pi * features["day_of_week"] / 7
    )

    # ========================================================
    # NETWORK FEATURES
    # ========================================================

    features["src_port"] = safe_numeric(
        df.get("src_port", pd.Series(index=df.index))
    )

    features["dst_port"] = safe_numeric(
        df.get("dst_port", pd.Series(index=df.index))
    )

    features["protocol"] = safe_numeric(
        df.get("protocol", pd.Series(index=df.index))
    )

    # Useful network transformations.
    features["src_port_privileged"] = (
        (features["src_port"] > 0) &
        (features["src_port"] < 1024)
    ).astype(float)

    features["dst_port_privileged"] = (
        (features["dst_port"] > 0) &
        (features["dst_port"] < 1024)
    ).astype(float)

    features["same_port"] = (
        features["src_port"] == features["dst_port"]
    ).astype(float)

    # ========================================================
    # IP / HOST BEHAVIOR
    # ========================================================

    src_ip = (
        df.get(
            "src_ip",
            pd.Series("", index=df.index)
        )
        .fillna("")
        .astype(str)
    )

    dst_ip = (
        df.get(
            "dst_ip",
            pd.Series("", index=df.index)
        )
        .fillna("")
        .astype(str)
    )

    src_host = (
        df.get(
            "src_host",
            pd.Series("", index=df.index)
        )
        .fillna("")
        .astype(str)
    )

    dst_host = (
        df.get(
            "dst_host",
            pd.Series("", index=df.index)
        )
        .fillna("")
        .astype(str)
    )

    features["has_src_ip"] = binary_present(src_ip)
    features["has_dst_ip"] = binary_present(dst_ip)
    features["has_src_host"] = binary_present(src_host)
    features["has_dst_host"] = binary_present(dst_host)

    # ========================================================
    # MESSAGE BEHAVIOR
    # ========================================================

    message = (
        df.get(
            "message_sanitized",
            pd.Series("", index=df.index)
        )
        .fillna("")
        .astype(str)
    )

    features["message_length"] = message.str.len().astype(float)

    features["message_word_count"] = (
        message.str.split().str.len()
        .fillna(0)
        .astype(float)
    )

    features["message_digit_count"] = (
        message.str.count(r"\d")
        .astype(float)
    )

    features["message_special_count"] = (
        message.str.count(r"[^A-Za-z0-9\s]")
        .astype(float)
    )

    # ========================================================
    # USERNAME BEHAVIOR
    # ========================================================

    username = (
        df.get(
            "username",
            pd.Series("", index=df.index)
        )
        .fillna("")
        .astype(str)
    )

    features["has_username"] = binary_present(username)

    features["username_length"] = (
        username.str.len()
        .astype(float)
    )

    # ========================================================
    # SUSPICION SCORE
    # ========================================================

    features["suspicion_score"] = safe_numeric(
        df.get(
            "suspicion_score",
            pd.Series(index=df.index)
        )
    )

    # ========================================================
    # CATEGORICAL RARITY
    # ========================================================
    #
    # IMPORTANT:
    # We do NOT encode categories as arbitrary numbers.
    #
    # Instead we calculate whether a category is rare.
    #
    # For training:
    #   frequency comes from previous training observations.
    #
    # For testing:
    #   frequency comes from training + previous test observations.
    #
    # Therefore no future information is used.
    # ========================================================

    categorical_columns = [
        "pipeline",
        "product_name",
        "vendor_name",
        "message_type",
        "stream_name",
        "action",
        "severity",
        "lifecycle_stage",
    ]

    if historical_state is None:

        historical_state = {
            col: defaultdict(int)
            for col in categorical_columns
        }

    for col in categorical_columns:

        values = (
            df.get(
                col,
                pd.Series("", index=df.index)
            )
            .fillna("")
            .astype(str)
        )

        rarity_values = []

        for value in values:

            previous_count = historical_state[col][value]

            # Log-scaled previous frequency.
            rarity = 1.0 / np.log1p(
                previous_count + 1
            )

            rarity_values.append(rarity)

            # Update only AFTER calculating this row.
            historical_state[col][value] += 1

        features[f"{col}_rarity"] = rarity_values

    # ========================================================
    # SOURCE / DESTINATION FREQUENCY
    # ========================================================

    frequency_columns = [
        ("src_ip", src_ip),
        ("dst_ip", dst_ip),
        ("src_host", src_host),
        ("dst_host", dst_host),
        ("username", username),
    ]

    for col_name, values in frequency_columns:

        state_key = f"freq_{col_name}"

        if state_key not in historical_state:
            historical_state[state_key] = defaultdict(int)

        rarity_values = []

        for value in values:

            previous_count = (
                historical_state[state_key][value]
                if value != ""
                else 0
            )

            rarity = 1.0 / np.log1p(
                previous_count + 1
            )

            rarity_values.append(rarity)

            if value != "":
                historical_state[state_key][value] += 1

        features[f"{col_name}_rarity"] = rarity_values

    # ========================================================
    # PORT FREQUENCY
    # ========================================================

    for col_name in ["src_port", "dst_port"]:

        state_key = f"freq_{col_name}"

        if state_key not in historical_state:
            historical_state[state_key] = defaultdict(int)

        rarity_values = []

        for value in features[col_name]:

            key = int(value)

            previous_count = (
                historical_state[state_key][key]
            )

            rarity = 1.0 / np.log1p(
                previous_count + 1
            )

            rarity_values.append(rarity)

            historical_state[state_key][key] += 1

        features[f"{col_name}_rarity"] = rarity_values

    # ========================================================
    # PROTOCOL FREQUENCY
    # ========================================================

    if "freq_protocol" not in historical_state:
        historical_state["freq_protocol"] = defaultdict(int)

    protocol_rarity = []

    for value in features["protocol"]:

        key = int(value)

        previous_count = (
            historical_state["freq_protocol"][key]
        )

        rarity = 1.0 / np.log1p(
            previous_count + 1
        )

        protocol_rarity.append(rarity)

        historical_state["freq_protocol"][key] += 1

    features["protocol_rarity"] = protocol_rarity

    # ========================================================
    # PORT + PROTOCOL COMBINATION RARITY
    # ========================================================

    if "freq_network_combo" not in historical_state:
        historical_state["freq_network_combo"] = defaultdict(int)

    combo_rarity = []

    for src, dst, protocol in zip(
        features["src_port"],
        features["dst_port"],
        features["protocol"]
    ):

        key = (
            int(src),
            int(dst),
            int(protocol)
        )

        previous_count = (
            historical_state["freq_network_combo"][key]
        )

        rarity = 1.0 / np.log1p(
            previous_count + 1
        )

        combo_rarity.append(rarity)

        historical_state["freq_network_combo"][key] += 1

    features["network_combo_rarity"] = combo_rarity

    return features, historical_state


# ============================================================
# LOAD TRAINING DATA
# ============================================================

print("=" * 70)
print("LEAKAGE-SAFE UNSUPERVISED FEATURE ENGINEERING V2")
print("=" * 70)

print()
print("Loading training data...")

train = pd.read_csv(
    TRAIN_PATH,
    low_memory=False
)

print(f"Training rows: {len(train):,}")

print()
print("Creating training features...")

# Sort chronologically before calculating historical behavior.
train["_original_order"] = np.arange(len(train))

train["_timestamp_sort"] = pd.to_datetime(
    train["timestamp"],
    errors="coerce"
)

train = train.sort_values(
    "_timestamp_sort",
    kind="stable"
).reset_index(drop=True)

train_features, historical_state = create_features(
    train
)

print()
print("Training features:")
print(train_features.shape)


# ============================================================
# LOAD TEST DATA
# ============================================================

print()
print("Loading testing data...")

test = pd.read_csv(
    TEST_PATH,
    low_memory=False
)

print(f"Testing rows: {len(test):,}")

print()
print("Creating testing features...")

# Test data must also be chronological.
test["_timestamp_sort"] = pd.to_datetime(
    test["timestamp"],
    errors="coerce"
)

test = test.sort_values(
    "_timestamp_sort",
    kind="stable"
).reset_index(drop=True)

test_features, historical_state = create_features(
    test,
    historical_state
)

print()
print("Testing features:")
print(test_features.shape)


# ============================================================
# SANITY CHECK
# ============================================================

print()
print("=" * 70)
print("FEATURE SANITY CHECK")
print("=" * 70)

print()
print("Missing values:")

missing = train_features.isna().sum()

print(
    missing[missing > 0]
    if missing.sum() > 0
    else "None"
)

print()
print(
    "Infinite values:",
    np.isinf(
        train_features.select_dtypes(
            include=[np.number]
        )
    ).sum().sum()
)

print()
print("Number of features:", len(train_features.columns))

print()
print("Feature columns:")

for col in train_features.columns:
    print(col)


# ============================================================
# SAVE
# ============================================================

print()
print("=" * 70)
print("SAVING FEATURES")
print("=" * 70)

train_features.to_csv(
    TRAIN_OUTPUT,
    index=False
)

test_features.to_csv(
    TEST_OUTPUT,
    index=False
)

print()
print("Training features saved:")
print(TRAIN_OUTPUT)

print()
print("Testing features saved:")
print(TEST_OUTPUT)

print()
print("=" * 70)
print("FEATURE ENGINEERING COMPLETE")
print("=" * 70)

print()
print("LEAKAGE CHECK:")
print("Labels used                 : NO")
print("Actual incidents used      : NO")
print("Incident IDs used          : NO")
print("Attack labels used         : NO")
print("Future alerts used         : NO")
print("Test labels used           : NO")
print()
print("Categorical values encoded : NO")
print("Categorical rarity used    : YES")
print("Historical behavior used  : YES")
print("Chronological processing   : YES")