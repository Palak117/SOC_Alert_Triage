import pandas as pd

INPUT_PATH = "data/scored/test_unsupervised_v3_scored.csv"

print("=" * 70)
print("V3 RANKING BEHAVIOR ANALYSIS")
print("=" * 70)

print("\nLoading V3 scored results...")

df = pd.read_csv(INPUT_PATH)

print(f"Total records : {len(df):,}")
print(f"Unique scores : {df['anomaly_score'].nunique():,}")

# ---------------------------------------------------------
# SCORE DISTRIBUTION
# ---------------------------------------------------------

print("\n" + "=" * 70)
print("SCORE DISTRIBUTION")
print("=" * 70)

print(f"Minimum anomaly score : {df['anomaly_score'].min():.6f}")
print(f"Maximum anomaly score : {df['anomaly_score'].max():.6f}")
print(f"Mean anomaly score    : {df['anomaly_score'].mean():.6f}")
print(f"Median anomaly score  : {df['anomaly_score'].median():.6f}")

print("\nScore quantiles:")
print(
    df["anomaly_score"].quantile(
        [0.001, 0.01, 0.05, 0.10, 0.25,
         0.50, 0.75, 0.90, 0.95, 0.99]
    )
)

# ---------------------------------------------------------
# TOP-K TIE ANALYSIS
# ---------------------------------------------------------

print("\n" + "=" * 70)
print("TOP-K TIE ANALYSIS")
print("=" * 70)

for k in [100, 500, 1000, 5000, 10000]:

    top_k = df.head(k)

    score_counts = top_k["anomaly_score"].value_counts()

    largest_tie = score_counts.max()

    number_of_tied_scores = (score_counts > 1).sum()

    print(f"\nTOP-{k}")
    print("-" * 50)
    print(
        f"Score range : "
        f"{top_k['anomaly_score'].min():.6f} "
        f"to "
        f"{top_k['anomaly_score'].max():.6f}"
    )
    print(
        f"Unique scores : "
        f"{top_k['anomaly_score'].nunique():,}"
    )
    print(
        f"Largest tie group : "
        f"{largest_tie:,}"
    )
    print(
        f"Scores appearing more than once : "
        f"{number_of_tied_scores:,}"
    )

# ---------------------------------------------------------
# TOP 20
# ---------------------------------------------------------

print("\n" + "=" * 70)
print("TOP 20 PRIORITY ALERTS")
print("=" * 70)

print(
    df[
        [
            "priority_rank",
            "anomaly_score",
            "priority_score"
        ]
    ].head(20).to_string(index=False)
)

# ---------------------------------------------------------
# RANK ORDER CHECK
# ---------------------------------------------------------

print("\n" + "=" * 70)
print("RANK ORDER CHECK")
print("=" * 70)

expected = df["priority_score"].values

is_descending = all(
    expected[i] >= expected[i + 1]
    for i in range(len(expected) - 1)
)

print(f"Priority score descending : {is_descending}")

# ---------------------------------------------------------
# SCORE-TO-PRIORITY CHECK
# ---------------------------------------------------------

difference = (
    df["priority_score"] + df["anomaly_score"]
).abs().max()

print(
    f"Priority = -anomaly score : "
    f"{difference < 1e-12}"
)

# ---------------------------------------------------------
# NEGATIVE SCORE ANALYSIS
# ---------------------------------------------------------

negative_count = (
    df["anomaly_score"] < 0
).sum()

positive_count = (
    df["anomaly_score"] >= 0
).sum()

print("\n" + "=" * 70)
print("ANOMALY SCORE SIGN")
print("=" * 70)

print(f"Negative anomaly scores : {negative_count:,}")
print(f"Non-negative scores     : {positive_count:,}")

print("\n" + "=" * 70)
print("ANALYSIS COMPLETE")
print("=" * 70)

print("\nIMPORTANT:")
print("This analysis does NOT modify model scores.")
print("No labels were used.")
print("No incident IDs were used.")
print("No ground truth was used.")
print("No ranking information from incidents was used.")