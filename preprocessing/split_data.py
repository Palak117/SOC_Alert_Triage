import pandas as pd
import os

DATA_PATH = "data/precinct6_cybersecurity.parquet"

print("Loading dataset...")
df = pd.read_parquet(DATA_PATH)

# Convert Unix timestamp to datetime
df["timestamp_datetime"] = pd.to_datetime(
    df["timestamp"],
    unit="s",
    errors="coerce"
)

# Sort chronologically
print("Sorting dataset chronologically...")
df = df.sort_values("timestamp_datetime").reset_index(drop=True)

# 80/20 chronological split
split_index = int(len(df) * 0.80)

df_train = df.iloc[:split_index].copy()
df_test = df.iloc[split_index:].copy()

# Create folder for split data
os.makedirs("data/train_test", exist_ok=True)

# Save paths
train_path = "data/train_test/train_80.csv"
test_path = "data/train_test/test_20.csv"

# Save with escape character
print("Saving training data...")
df_train.to_csv(
    train_path,
    index=False,
    escapechar="\\"
)

print("Saving testing data...")
df_test.to_csv(
    test_path,
    index=False,
    escapechar="\\"
)

print("\n==============================")
print("CHRONOLOGICAL SPLIT COMPLETE")
print("==============================")

print(f"Total records : {len(df):,}")
print(f"Training 80%  : {len(df_train):,}")
print(f"Testing 20%   : {len(df_test):,}")

print("\nTraining period:")
print(df_train["timestamp_datetime"].min())
print("to")
print(df_train["timestamp_datetime"].max())

print("\nTesting period:")
print(df_test["timestamp_datetime"].min())
print("to")
print(df_test["timestamp_datetime"].max())

print("\nSaved:")
print(train_path)
print(test_path)