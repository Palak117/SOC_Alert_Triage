import pandas as pd

TRAIN_PATH = "data/train_test/train_80.csv"

print("=" * 70)
print("TRAINING DATA BEHAVIOR ANALYSIS")
print("=" * 70)

print("\nLoading training dataset...")
df = pd.read_csv(TRAIN_PATH, low_memory=False)

print("\nTotal training rows:", len(df))

# ------------------------------------------------------------
# IMPORTANT:
# This script is ONLY a diagnostic.
# It does not train the model.
# It does not modify scores.
# ------------------------------------------------------------

def show_distribution(column):

    print("\n" + "-" * 70)
    print(column.upper())
    print("-" * 70)

    if column not in df.columns:
        print("Column not found.")
        return

    print(df[column].value_counts(dropna=False).head(20))


# ------------------------------------------------------------
# BASIC DISTRIBUTIONS
# ------------------------------------------------------------

show_distribution("pipeline")
show_distribution("product_name")
show_distribution("vendor_name")
show_distribution("message_type")
show_distribution("action")
show_distribution("lifecycle_stage")
show_distribution("severity")
show_distribution("protocol")

# ------------------------------------------------------------
# NUMERIC FEATURES
# ------------------------------------------------------------

print("\n" + "=" * 70)
print("NUMERIC FEATURE RANGES")
print("=" * 70)

numeric_columns = [
    "suspicion_score",
    "src_port",
    "dst_port",
    "protocol"
]

for column in numeric_columns:

    if column not in df.columns:
        continue

    s = pd.to_numeric(
        df[column],
        errors="coerce"
    )

    print(f"\n--- {column} ---")
    print("Count :", s.notna().sum())
    print("Mean  :", s.mean())
    print("Min   :", s.min())
    print("Max   :", s.max())
    print("Unique:", s.nunique())

# ------------------------------------------------------------
# COMBINATION PATTERNS
# ------------------------------------------------------------

print("\n" + "=" * 70)
print("IMPORTANT BEHAVIORAL COMBINATIONS")
print("=" * 70)

combos = [
    [
        "pipeline",
        "product_name"
    ],
    [
        "pipeline",
        "message_type"
    ],
    [
        "pipeline",
        "action"
    ],
    [
        "product_name",
        "message_type"
    ],
    [
        "pipeline",
        "product_name",
        "message_type"
    ]
]

for columns in combos:

    missing = [
        c for c in columns
        if c not in df.columns
    ]

    if missing:
        continue

    print("\n--- " + " + ".join(columns) + " ---")

    result = (
        df.groupby(
            columns,
            dropna=False
        )
        .size()
        .sort_values(
            ascending=False
        )
        .head(15)
    )

    print(result)

# ------------------------------------------------------------
# RARE COMBINATIONS
# ------------------------------------------------------------

print("\n" + "=" * 70)
print("RARE BEHAVIORAL COMBINATIONS")
print("=" * 70)

rare_columns = [
    "pipeline",
    "product_name",
    "vendor_name",
    "message_type",
    "action"
]

available = [
    c for c in rare_columns
    if c in df.columns
]

if len(available) > 0:

    pattern_counts = (
        df.groupby(
            available,
            dropna=False
        )
        .size()
        .sort_values(
            ascending=True
        )
    )

    print(
        pattern_counts.head(30)
    )

# ------------------------------------------------------------
# TEMPORAL DISTRIBUTION
# ------------------------------------------------------------

print("\n" + "=" * 70)
print("TEMPORAL DISTRIBUTION")
print("=" * 70)

if "timestamp" in df.columns:

    timestamp = pd.to_numeric(
        df["timestamp"],
        errors="coerce"
    )

    dt = pd.to_datetime(
        timestamp,
        unit="s",
        errors="coerce"
    )

    print("\nTime range:")
    print("Start:", dt.min())
    print("End  :", dt.max())

    print("\nAlerts by hour:")

    print(
        dt.dt.hour
        .value_counts()
        .sort_index()
    )

    print("\nAlerts by day of week:")

    print(
        dt.dt.day_name()
        .value_counts()
    )

# ------------------------------------------------------------
# DUPLICATE ANALYSIS
# ------------------------------------------------------------

print("\n" + "=" * 70)
print("TRAINING DUPLICATE ANALYSIS")
print("=" * 70)

feature_columns = [
    "hour",
    "day_of_week",
    "src_port",
    "dst_port",
    "protocol",
    "suspicion_score",
    "pipeline",
    "product_name",
    "vendor_name",
    "message_type",
    "action",
    "lifecycle_stage"
]

available_features = [
    c for c in feature_columns
    if c in df.columns
]

if available_features:

    unique_patterns = (
        df[available_features]
        .drop_duplicates()
        .shape[0]
    )

    duplicate_rows = (
        len(df) - unique_patterns
    )

    print(
        "Unique behavioral patterns:",
        unique_patterns
    )

    print(
        "Duplicate rows:",
        duplicate_rows
    )

    print(
        "Duplicate percentage:",
        f"{duplicate_rows / len(df) * 100:.2f}%"
    )

# ------------------------------------------------------------
# COMPLETION
# ------------------------------------------------------------

print("\n" + "=" * 70)
print("TRAINING BEHAVIOR ANALYSIS COMPLETE")
print("=" * 70)

print("\nIMPORTANT:")
print("This script did NOT train a model.")
print("This script did NOT use labels for learning.")
print("This script did NOT modify the dataset.")
print("This script is only a diagnostic.")