import pandas as pd

DATA_PATH = "data/precinct6_cybersecurity.parquet"

print("Loading dataset...")
df = pd.read_parquet(DATA_PATH)

print("\n==============================")
print("DATASET INFORMATION")
print("==============================")

print(f"Rows    : {len(df):,}")
print(f"Columns : {len(df.columns)}")

print("\n==============================")
print("COLUMN NAMES")
print("==============================")

for i, column in enumerate(df.columns, 1):
    print(f"{i}. {column}")

print("\n==============================")
print("DATA TYPES")
print("==============================")

print(df.dtypes)

print("\n==============================")
print("MISSING VALUES")
print("==============================")

print(df.isnull().sum())

print("\n==============================")
print("FIRST 5 ROWS")
print("==============================")

print(df.head())

print("\n==============================")
print("INSPECTION COMPLETE")
print("==============================")

print("\n==============================")
print("IMPORTANT COLUMNS")
print("==============================")

important_columns = [
    "label_binary",
    "label_confidence",
    "suspicion_score",
    "disposition",
    "disposition_category",
    "is_false_positive",
    "incident_ids",
    "severity",
    "status_name",
    "action",
    "lifecycle_stage"
]

for column in important_columns:
    print(f"\n--- {column} ---")
    print(df[column].value_counts(dropna=False).head(15))


print("\n==============================")
print("TIMESTAMP ANALYSIS")
print("==============================")

# Convert Unix timestamp to datetime
df["timestamp_datetime"] = pd.to_datetime(
    df["timestamp"],
    unit="s",
    errors="coerce"
)

print("\nEarliest timestamp:")
print(df["timestamp_datetime"].min())

print("\nLatest timestamp:")
print(df["timestamp_datetime"].max())

print("\nFirst 10 timestamps:")
print(df["timestamp_datetime"].head(10))

print("\nLast 10 timestamps:")
print(df["timestamp_datetime"].tail(10))

# Check whether the dataset is already chronologically ordered
is_sorted = df["timestamp_datetime"].is_monotonic_increasing

print("\nIs dataset already chronologically sorted?")
print(is_sorted)
