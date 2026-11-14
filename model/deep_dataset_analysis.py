import pandas as pd
import ast

TEST_PATH = "data/train_test/test_20.csv"

print("Loading test dataset...")
df = pd.read_csv(TEST_PATH, low_memory=False)

print("\n==============================")
print("DEEP DATASET ANALYSIS")
print("==============================")

print(f"Total rows: {len(df):,}")

# --------------------------------------------------
# ACTUAL INCIDENT
# --------------------------------------------------

df["actual_incident"] = df["incident_ids"].apply(
    lambda x: x != "[]" and pd.notna(x)
)

print("\n==============================")
print("INCIDENT DISTRIBUTION")
print("==============================")

print(df["actual_incident"].value_counts())

# --------------------------------------------------
# LABEL DISTRIBUTION
# --------------------------------------------------

print("\n==============================")
print("LABEL vs INCIDENT")
print("==============================")

print(
    pd.crosstab(
        df["label_binary"],
        df["actual_incident"],
        margins=True
    )
)

# --------------------------------------------------
# NUMERIC FEATURES
# --------------------------------------------------

numeric_columns = [
    "suspicion_score",
    "label_confidence",
    "src_port",
    "dst_port",
    "protocol",
    "timestamp"
]

print("\n==============================")
print("NUMERIC FEATURES")
print("==============================")

for col in numeric_columns:

    if col not in df.columns:
        continue

    print(f"\n--- {col} ---")

    print(
        df.groupby("actual_incident")[col]
        .agg(["count", "mean", "min", "max"])
    )

# --------------------------------------------------
# CATEGORICAL FEATURES
# --------------------------------------------------

categorical_columns = [
    "severity",
    "action",
    "lifecycle_stage",
    "product_name",
    "vendor_name",
    "pipeline",
    "message_type",
    "stream_name",
    "matched_rules",
    "set_roles",
    "attack_techniques",
    "attack_tactics",
    "mo_name"
]

print("\n==============================")
print("CATEGORICAL FEATURE ANALYSIS")
print("==============================")

for col in categorical_columns:

    if col not in df.columns:
        continue

    print(f"\n--- {col} ---")

    temp = (
        df.groupby([col, "actual_incident"])
        .size()
        .unstack(fill_value=0)
    )

    if True in temp.columns:
        temp["incident_rate"] = (
            temp[True] /
            temp.sum(axis=1) * 100
        )

        temp = temp.sort_values(
            "incident_rate",
            ascending=False
        )

    print(temp.head(15))

# --------------------------------------------------
# MISSING VALUES
# --------------------------------------------------

print("\n==============================")
print("MISSING VALUES")
print("==============================")

missing = df.isna().sum()

print(
    missing[missing > 0]
    .sort_values(ascending=False)
)

# --------------------------------------------------
# UNIQUE VALUES
# --------------------------------------------------

print("\n==============================")
print("UNIQUE VALUES")
print("==============================")

for col in df.columns:

    print(
        f"{col:25s} : "
        f"{df[col].nunique(dropna=False):,}"
    )

# --------------------------------------------------
# INCIDENT SCORE ANALYSIS
# --------------------------------------------------

print("\n==============================")
print("SUSPICION SCORE BY LABEL")
print("==============================")

print(
    df.groupby("label_binary")["suspicion_score"]
    .agg(["count", "mean", "min", "max"])
)

# --------------------------------------------------
# MALICIOUS EVENTS
# --------------------------------------------------

print("\n==============================")
print("MALICIOUS EVENTS")
print("==============================")

malicious = df[df["label_binary"] == "malicious"]

print(f"Malicious rows: {len(malicious):,}")

print("\nMalicious severity:")
print(malicious["severity"].value_counts())

print("\nMalicious lifecycle:")
print(malicious["lifecycle_stage"].value_counts())

print("\nMalicious products:")
print(malicious["product_name"].value_counts().head(15))

print("\nMalicious vendors:")
print(malicious["vendor_name"].value_counts().head(15))

print("\nMalicious pipelines:")
print(malicious["pipeline"].value_counts())

print("\n==============================")
print("DEEP ANALYSIS COMPLETE")
print("==============================")