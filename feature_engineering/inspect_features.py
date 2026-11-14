import pandas as pd

FEATURE_PATH = "data/features/X_train.csv"

print("Loading training features...")
df = pd.read_csv(FEATURE_PATH)

print("\n==============================")
print("FEATURE INSPECTION")
print("==============================")

print(f"Rows    : {len(df):,}")
print(f"Features: {len(df.columns):,}")

print("\n==============================")
print("FEATURE TYPES")
print("==============================")

print(df.dtypes.value_counts())

print("\n==============================")
print("MISSING VALUES")
print("==============================")

missing = df.isnull().sum()
print(missing[missing > 0])

print("\n==============================")
print("CONSTANT FEATURES")
print("==============================")

constant = []

for col in df.columns:
    if df[col].nunique() <= 1:
        constant.append(col)

print(f"Constant features: {len(constant)}")

if constant:
    print(constant)

print("\n==============================")
print("LOW-VARIANCE FEATURES")
print("==============================")

low_variance = []

for col in df.columns:
    if df[col].nunique() <= 2:
        low_variance.append(col)

print(f"Features with <= 2 unique values: {len(low_variance)}")

if low_variance:
    print(low_variance[:100])

print("\n==============================")
print("FEATURE RANGE")
print("==============================")

numeric_cols = df.select_dtypes(include=["number"]).columns

for col in numeric_cols[:30]:
    print(
        f"{col:35} "
        f"min={df[col].min():.4f} "
        f"max={df[col].max():.4f} "
        f"unique={df[col].nunique():,}"
    )

print("\n==============================")
print("INSPECTION COMPLETE")
print("==============================")