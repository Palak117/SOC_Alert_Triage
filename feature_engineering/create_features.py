import pandas as pd
import os

TRAIN_PATH = "data/train_test/train_80.csv"
TEST_PATH = "data/train_test/test_20.csv"

OUTPUT_DIR = "data/features"

os.makedirs(OUTPUT_DIR, exist_ok=True)

print("Loading training data...")
train_df = pd.read_csv(TRAIN_PATH, low_memory=False)

print("Loading testing data...")
test_df = pd.read_csv(TEST_PATH, low_memory=False)

print("\n==============================")
print("CREATING FEATURES")
print("==============================")


# --------------------------------------------------
# 1. Convert timestamp into useful time features
# --------------------------------------------------

def create_time_features(df):

    timestamp = pd.to_datetime(
        df["timestamp"],
        unit="s",
        errors="coerce"
    )

    df["hour"] = timestamp.dt.hour
    df["day_of_week"] = timestamp.dt.dayofweek
    df["is_weekend"] = (timestamp.dt.dayofweek >= 5).astype(int)

    return df


print("Creating time features...")

train_df = create_time_features(train_df)
test_df = create_time_features(test_df)


# --------------------------------------------------
# 2. Select numerical features
# --------------------------------------------------

numerical_features = [
    "src_port",
    "dst_port",
    "protocol",
    "suspicion_score",
    "hour",
    "day_of_week",
    "is_weekend"
]


# --------------------------------------------------
# 3. Select categorical features
# --------------------------------------------------

categorical_features = [
    "severity",
    "action",
    "lifecycle_stage",
    "product_name",
    "vendor_name",
    "message_type",
    "stream_name",
    "pipeline"
]


# --------------------------------------------------
# 4. Prepare categorical values
# --------------------------------------------------

print("Encoding categorical features...")

for column in categorical_features:

    train_df[column] = train_df[column].fillna("").astype(str)
    test_df[column] = test_df[column].fillna("").astype(str)


# --------------------------------------------------
# 5. Combine train + test for consistent encoding
# --------------------------------------------------

combined = pd.concat(
    [
        train_df[numerical_features + categorical_features],
        test_df[numerical_features + categorical_features]
    ],
    axis=0
)

combined = pd.get_dummies(
    combined,
    columns=categorical_features,
    dtype="int8"
)


# --------------------------------------------------
# 6. Split them back
# --------------------------------------------------

X_train = combined.iloc[:len(train_df)].copy()
X_test = combined.iloc[len(train_df):].copy()


# --------------------------------------------------
# 7. Handle missing numerical values
# --------------------------------------------------

X_train[numerical_features] = X_train[numerical_features].fillna(0)
X_test[numerical_features] = X_test[numerical_features].fillna(0)


# --------------------------------------------------
# 8. Save feature datasets
# --------------------------------------------------

train_output = os.path.join(
    OUTPUT_DIR,
    "X_train.csv"
)

test_output = os.path.join(
    OUTPUT_DIR,
    "X_test.csv"
)

print("Saving training features...")
X_train.to_csv(
    train_output,
    index=False
)

print("Saving testing features...")
X_test.to_csv(
    test_output,
    index=False
)


# --------------------------------------------------
# 9. Final information
# --------------------------------------------------

print("\n==============================")
print("FEATURE ENGINEERING COMPLETE")
print("==============================")

print(f"Training rows  : {len(X_train):,}")
print(f"Testing rows   : {len(X_test):,}")
print(f"Total features : {X_train.shape[1]}")

print("\nTraining features:")
print(train_output)

print("\nTesting features:")
print(test_output)