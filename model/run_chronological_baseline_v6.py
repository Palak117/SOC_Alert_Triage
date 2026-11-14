import pandas as pd
import numpy as np
import os

print("=" * 80)
print("CAUSAL CHRONOLOGICAL BASELINE vs V6 UNSUPERVISED RANKING")
print("=" * 80)

# ============================================================
# PATHS
# ============================================================

ORIGINAL_TEST_PATH = (
    "data/train_test/test_20.csv"
)

V6_SCORED_PATH = (
    "data/scored/test_unsupervised_v6_scored.csv"
)

BASELINE_OUTPUT_PATH = (
    "data/scored/chronological_baseline_v6_test.csv"
)

COMPARISON_OUTPUT_PATH = (
    "data/scored/v6_vs_chronological_comparison.csv"
)

UNIQUE_COMPARISON_OUTPUT_PATH = (
    "data/scored/incident_discovery_comparison.csv"
)


# ============================================================
# 1. LOAD ORIGINAL TEST DATA
# ============================================================

print("\nLoading original chronological test data...")

original = pd.read_csv(
    ORIGINAL_TEST_PATH,
    low_memory=False
)

print(
    f"Original test rows: {len(original):,}"
)


# ============================================================
# 2. LOAD V6 SCORED DATA
# ============================================================

print("\nLoading V6 scored results...")

v6 = pd.read_csv(
    V6_SCORED_PATH,
    low_memory=False
)

print(
    f"V6 scored rows: {len(v6):,}"
)


# ============================================================
# 3. BASIC SAFETY CHECKS
# ============================================================

print("\n" + "=" * 80)
print("BASIC SAFETY CHECKS")
print("=" * 80)

if len(original) != len(v6):
    raise ValueError(
        f"Row count mismatch!\n"
        f"Original: {len(original):,}\n"
        f"V6: {len(v6):,}"
    )

print("Row count match: PASS")


required_v6_columns = [
    "_alert_id",
    "anomaly_score",
    "priority_score",
    "priority_rank"
]

for column in required_v6_columns:

    if column not in v6.columns:
        raise ValueError(
            f"Required V6 column missing: {column}"
        )

    print(
        f"V6 column '{column}': PASS"
    )


if "incident_ids" not in original.columns:
    raise ValueError(
        "incident_ids column missing from original test data."
    )

print(
    "Original 'incident_ids': PASS"
)


if "timestamp" not in original.columns:
    raise ValueError(
        "timestamp column missing from original test data."
    )

print(
    "Original 'timestamp': PASS"
)


# ============================================================
# 4. ALERT ID SAFETY
# ============================================================

print("\n" + "=" * 80)
print("ALERT ID SAFETY")
print("=" * 80)

expected_ids = np.arange(
    len(original)
)

actual_ids = np.sort(
    v6["_alert_id"].to_numpy()
)

if np.array_equal(
    actual_ids,
    expected_ids
):
    print(
        "V6 _alert_id values cover 0 -> N-1: PASS"
    )
else:
    raise ValueError(
        "V6 _alert_id values do not cover "
        "0 -> N-1."
    )


if v6["_alert_id"].nunique() != len(v6):
    raise ValueError(
        "V6 _alert_id values are not unique."
    )

print(
    "V6 _alert_id uniqueness: PASS"
)


# ============================================================
# 5. CREATE POST-HOC INCIDENT FLAG
# ============================================================

print("\n" + "=" * 80)
print("POST-HOC EVALUATION DATA")
print("=" * 80)


def has_incident(value):

    if pd.isna(value):
        return False

    text = str(value).strip()

    if text == "":
        return False

    if text.lower() in {
        "nan",
        "none",
        "null",
        "[]",
        "{}"
    }:
        return False

    return True


original["actual_incident"] = (
    original["incident_ids"]
    .apply(has_incident)
)


total_incident_alerts = int(
    original["actual_incident"].sum()
)


print(
    f"Total incident alerts: "
    f"{total_incident_alerts:,}"
)


# ============================================================
# 6. CHRONOLOGICAL ORDER
# ============================================================

print("\n" + "=" * 80)
print("CHRONOLOGICAL BASELINE")
print("=" * 80)


original["timestamp_parsed"] = pd.to_datetime(
    original["timestamp"],
    errors="coerce"
)


if original["timestamp_parsed"].isna().any():

    missing_timestamps = int(
        original["timestamp_parsed"]
        .isna()
        .sum()
    )

    raise ValueError(
        f"{missing_timestamps:,} timestamps "
        f"could not be parsed."
    )


print(
    "Timestamp parsing: PASS"
)


# IMPORTANT:
#
# The chronological baseline uses the original
# chronological test order.
#
# Stable mergesort preserves original order
# when timestamps are equal.

chronological = (
    original
    .assign(
        _original_order=np.arange(
            len(original)
        )
    )
    .sort_values(
        by=[
            "timestamp_parsed",
            "_original_order"
        ],
        ascending=[
            True,
            True
        ],
        kind="mergesort"
    )
    .reset_index(drop=True)
)


print(
    "Chronological sorting: PASS"
)


if chronological["timestamp_parsed"].is_monotonic_increasing:

    print(
        "Chronological queue order: PASS"
    )

else:

    raise ValueError(
        "Chronological queue is not actually chronological."
    )


# ============================================================
# 7. CREATE BASELINE RANK
# ============================================================

chronological["baseline_rank"] = (
    np.arange(
        1,
        len(chronological) + 1
    )
)


# ============================================================
# 8. CREATE BASELINE OUTPUT
# ============================================================

baseline_columns = [
    "baseline_rank",
    "_original_order",
    "timestamp",
    "incident_ids",
    "actual_incident"
]


# Include useful alert-identification columns if available.

optional_columns = [
    "alert_id",
    "id",
    "event_id",
    "alert_type",
    "severity",
    "source_ip",
    "destination_ip",
    "src_ip",
    "dst_ip",
    "protocol"
]


for column in optional_columns:

    if column in chronological.columns:

        baseline_columns.append(column)


baseline = chronological[
    baseline_columns
].copy()


baseline.to_csv(
    BASELINE_OUTPUT_PATH,
    index=False
)


print("\nChronological baseline saved:")
print(BASELINE_OUTPUT_PATH)


# ============================================================
# 9. TOP-K EVALUATION SETTINGS
# ============================================================

top_ks = [
    100,
    500,
    1000,
    5000,
    10000,
    25000,
    50000,
    100000
]


# ============================================================
# 10. CHRONOLOGICAL BASELINE METRICS
# ============================================================

print("\n" + "=" * 80)
print("CHRONOLOGICAL BASELINE RESULTS")
print("=" * 80)


baseline_results = []


for k in top_ks:

    k = min(
        k,
        len(baseline)
    )

    top_k = baseline.head(k)

    incidents_found = int(
        top_k["actual_incident"].sum()
    )

    precision = (
        incidents_found / k
    )

    recall = (
        incidents_found / total_incident_alerts
        if total_incident_alerts > 0
        else 0.0
    )

    alerts_avoided = (
        len(baseline) - k
    )

    review_percentage = (
        k / len(baseline) * 100
    )

    avoided_percentage = (
        alerts_avoided / len(baseline) * 100
    )

    baseline_results.append({
        "review_budget": k,
        "baseline_incident_alerts_found": incidents_found,
        "baseline_precision": precision,
        "baseline_recall": recall,
        "baseline_alerts_reviewed": k,
        "baseline_review_percentage": review_percentage,
        "baseline_alerts_avoided": alerts_avoided,
        "baseline_alerts_avoided_percentage":
            avoided_percentage
    })

    print(
        f"Top-{k:<6} | "
        f"Incidents: {incidents_found:<6} | "
        f"Precision: {precision:.4f} "
        f"({precision * 100:.2f}%) | "
        f"Recall: {recall:.4f} "
        f"({recall * 100:.2f}%) | "
        f"Alerts avoided: {alerts_avoided:,} "
        f"({avoided_percentage:.2f}%)"
    )


baseline_results_df = pd.DataFrame(
    baseline_results
)


# ============================================================
# 11. V6 METRICS
# ============================================================

print("\n" + "=" * 80)
print("V6 UNSUPERVISED RESULTS")
print("=" * 80)


# Map incident truth from the original data using
# _alert_id = original row position.

v6_eval = v6.copy()


v6_eval["actual_incident"] = (
    v6_eval["_alert_id"]
    .astype(int)
    .map(
        original["actual_incident"]
    )
)


if v6_eval["actual_incident"].isna().any():

    raise ValueError(
        "Some V6 alerts could not be mapped "
        "to original incident information."
    )


v6_results = []


for k in top_ks:

    k = min(
        k,
        len(v6_eval)
    )

    top_k = (
        v6_eval
        .sort_values(
            "priority_rank",
            ascending=True
        )
        .head(k)
    )

    incidents_found = int(
        top_k["actual_incident"].sum()
    )

    precision = (
        incidents_found / k
    )

    recall = (
        incidents_found / total_incident_alerts
        if total_incident_alerts > 0
        else 0.0
    )

    alerts_avoided = (
        len(v6_eval) - k
    )

    review_percentage = (
        k / len(v6_eval) * 100
    )

    avoided_percentage = (
        alerts_avoided / len(v6_eval) * 100
    )

    v6_results.append({
        "review_budget": k,
        "v6_incident_alerts_found": incidents_found,
        "v6_precision": precision,
        "v6_recall": recall,
        "v6_alerts_reviewed": k,
        "v6_review_percentage": review_percentage,
        "v6_alerts_avoided": alerts_avoided,
        "v6_alerts_avoided_percentage":
            avoided_percentage
    })

    print(
        f"Top-{k:<6} | "
        f"Incidents: {incidents_found:<6} | "
        f"Precision: {precision:.4f} "
        f"({precision * 100:.2f}%) | "
        f"Recall: {recall:.4f} "
        f"({recall * 100:.2f}%) | "
        f"Alerts avoided: {alerts_avoided:,} "
        f"({avoided_percentage:.2f}%)"
    )


v6_results_df = pd.DataFrame(
    v6_results
)


# ============================================================
# 12. DIRECT COMPARISON
# ============================================================

print("\n" + "=" * 80)
print("V6 vs CHRONOLOGICAL BASELINE")
print("=" * 80)


comparison = baseline_results_df.merge(
    v6_results_df,
    on="review_budget",
    how="inner"
)


comparison["precision_difference"] = (
    comparison["v6_precision"]
    -
    comparison["baseline_precision"]
)


comparison["recall_difference"] = (
    comparison["v6_recall"]
    -
    comparison["baseline_recall"]
)


comparison["incident_alerts_found_difference"] = (
    comparison["v6_incident_alerts_found"]
    -
    comparison["baseline_incident_alerts_found"]
)


comparison["relative_review_budget_percentage"] = (
    comparison["review_budget"]
    /
    len(original)
    *
    100
)


comparison.to_csv(
    COMPARISON_OUTPUT_PATH,
    index=False
)


# ============================================================
# 13. PRINT COMPARISON
# ============================================================

print(
    "\n"
    f"{'K':>8} | "
    f"{'Chron Inc':>10} | "
    f"{'V6 Inc':>8} | "
    f"{'Chron Prec':>11} | "
    f"{'V6 Prec':>9} | "
    f"{'Chron Recall':>13} | "
    f"{'V6 Recall':>10}"
)

print("-" * 80)


for _, row in comparison.iterrows():

    print(
        f"{int(row['review_budget']):>8,} | "
        f"{int(row['baseline_incident_alerts_found']):>10,} | "
        f"{int(row['v6_incident_alerts_found']):>8,} | "
        f"{row['baseline_precision'] * 100:>10.2f}% | "
        f"{row['v6_precision'] * 100:>8.2f}% | "
        f"{row['baseline_recall'] * 100:>12.2f}% | "
        f"{row['v6_recall'] * 100:>9.2f}%"
    )


# ============================================================
# 14. UNIQUE INCIDENT FUNCTIONS
# ============================================================

print("\n" + "=" * 80)
print("UNIQUE INCIDENT DISCOVERY")
print("=" * 80)


def extract_incident_ids(value):

    if pd.isna(value):
        return []

    text = str(value).strip()

    if text == "":
        return []

    if text.lower() in {
        "nan",
        "none",
        "null",
        "[]",
        "{}"
    }:
        return []

    if (
        text.startswith("[")
        and
        text.endswith("]")
    ):

        text = text[1:-1].strip()

        if text == "":
            return []

        parts = text.split(",")

        ids = []

        for part in parts:

            part = (
                part
                .strip()
                .strip("'")
                .strip('"')
            )

            if part:
                ids.append(part)

        return ids

    if ";" in text:

        return [
            x.strip()
            for x in text.split(";")
            if x.strip()
        ]

    return [text]


original_incident_lists = (
    original["incident_ids"]
    .apply(extract_incident_ids)
)


all_incidents = set()

for ids in original_incident_lists:

    for incident_id in ids:

        all_incidents.add(
            incident_id
        )


total_unique_incidents = len(
    all_incidents
)


print(
    f"Total unique incidents: "
    f"{total_unique_incidents:,}"
)


# ============================================================
# 15. BASELINE UNIQUE INCIDENT DISCOVERY
# ============================================================

unique_results = []


for k in top_ks:

    k = min(
        k,
        len(baseline)
    )

    discovered = set()

    for original_position in (
        baseline
        .head(k)
        ["_original_order"]
    ):

        ids = original_incident_lists.iloc[
            int(original_position)
        ]

        for incident_id in ids:

            discovered.add(
                incident_id
            )


    unique_found = len(
        discovered
    )


    recall = (
        unique_found / total_unique_incidents
        if total_unique_incidents > 0
        else 0.0
    )


    unique_results.append({
        "review_budget": k,
        "chronological_unique_incidents_found":
            unique_found,
        "chronological_unique_incident_recall":
            recall
    })


# ============================================================
# 16. V6 UNIQUE INCIDENT DISCOVERY
# ============================================================

for k in top_ks:

    k = min(
        k,
        len(v6_eval)
    )

    top_k = (
        v6_eval
        .sort_values(
            "priority_rank",
            ascending=True
        )
        .head(k)
    )

    discovered = set()

    for alert_id in top_k["_alert_id"]:

        ids = original_incident_lists.iloc[
            int(alert_id)
        ]

        for incident_id in ids:

            discovered.add(
                incident_id
            )


    unique_found = len(
        discovered
    )


    recall = (
        unique_found / total_unique_incidents
        if total_unique_incidents > 0
        else 0.0
    )


    for result in unique_results:

        if result["review_budget"] == k:

            result[
                "v6_unique_incidents_found"
            ] = unique_found

            result[
                "v6_unique_incident_recall"
            ] = recall


unique_comparison = pd.DataFrame(
    unique_results
)


unique_comparison[
    "unique_incident_difference"
] = (
    unique_comparison[
        "v6_unique_incidents_found"
    ]
    -
    unique_comparison[
        "chronological_unique_incidents_found"
    ]
)


unique_comparison[
    "unique_recall_difference"
] = (
    unique_comparison[
        "v6_unique_incident_recall"
    ]
    -
    unique_comparison[
        "chronological_unique_incident_recall"
    ]
)


unique_comparison.to_csv(
    UNIQUE_COMPARISON_OUTPUT_PATH,
    index=False
)


# ============================================================
# 17. PRINT UNIQUE INCIDENT COMPARISON
# ============================================================

print(
    "\n"
    f"{'K':>8} | "
    f"{'Chron Unique':>13} | "
    f"{'V6 Unique':>10} | "
    f"{'Chron Recall':>13} | "
    f"{'V6 Recall':>10}"
)

print("-" * 70)


for _, row in unique_comparison.iterrows():

    print(
        f"{int(row['review_budget']):>8,} | "
        f"{int(row['chronological_unique_incidents_found']):>13} | "
        f"{int(row['v6_unique_incidents_found']):>10} | "
        f"{row['chronological_unique_incident_recall'] * 100:>12.2f}% | "
        f"{row['v6_unique_incident_recall'] * 100:>9.2f}%"
    )


# ============================================================
# 18. FIRST INCIDENT DISCOVERY
# ============================================================

print("\n" + "=" * 80)
print("FIRST INCIDENT DISCOVERY RANK")
print("=" * 80)


# Chronological baseline

chronological_first_rank = {}


for rank, original_position in enumerate(
    baseline["_original_order"],
    start=1
):

    ids = original_incident_lists.iloc[
        int(original_position)
    ]

    for incident_id in ids:

        if incident_id not in chronological_first_rank:

            chronological_first_rank[
                incident_id
            ] = rank


# V6

v6_first_rank = {}


v6_sorted = (
    v6_eval
    .sort_values(
        "priority_rank",
        ascending=True
    )
)


for rank, alert_id in enumerate(
    v6_sorted["_alert_id"],
    start=1
):

    ids = original_incident_lists.iloc[
        int(alert_id)
    ]

    for incident_id in ids:

        if incident_id not in v6_first_rank:

            v6_first_rank[
                incident_id
            ] = rank


print(
    f"Chronological incidents discovered: "
    f"{len(chronological_first_rank):,}"
)

print(
    f"V6 incidents discovered: "
    f"{len(v6_first_rank):,}"
)


if v6_first_rank:

    v6_ranks = list(
        v6_first_rank.values()
    )

    print(
        f"\nV6 minimum first incident rank: "
        f"{min(v6_ranks):,}"
    )

    print(
        f"V6 mean first incident rank: "
        f"{np.mean(v6_ranks):,.2f}"
    )

    print(
        f"V6 median first incident rank: "
        f"{np.median(v6_ranks):,.2f}"
    )

    print(
        f"V6 maximum first incident rank: "
        f"{max(v6_ranks):,}"
    )


if chronological_first_rank:

    chronological_ranks = list(
        chronological_first_rank.values()
    )

    print(
        f"\nChronological minimum first incident rank: "
        f"{min(chronological_ranks):,}"
    )

    print(
        f"Chronological mean first incident rank: "
        f"{np.mean(chronological_ranks):,.2f}"
    )

    print(
        f"Chronological median first incident rank: "
        f"{np.median(chronological_ranks):,.2f}"
    )

    print(
        f"Chronological maximum first incident rank: "
        f"{max(chronological_ranks):,}"
    )


# ============================================================
# 19. FINAL SAFETY CHECKS
# ============================================================

print("\n" + "=" * 80)
print("FINAL SAFETY CHECKS")
print("=" * 80)


# V6 ranking must remain unchanged.

v6_rank_check = (
    v6_eval
    .sort_values(
        "priority_rank"
    )[
        "priority_rank"
    ]
    .to_numpy()
)


expected_v6_ranks = np.arange(
    1,
    len(v6_eval) + 1
)


if np.array_equal(
    v6_rank_check,
    expected_v6_ranks
):

    print(
        "V6 ranking unchanged: PASS"
    )

else:

    raise ValueError(
        "V6 ranking integrity check failed."
    )


# Verify V6 scores remain unchanged.

v6_score_order = (
    v6_eval
    .sort_values(
        "priority_rank"
    )[
        "priority_score"
    ]
    .to_numpy()
)


if np.all(
    v6_score_order[:-1]
    >=
    v6_score_order[1:]
):

    print(
        "V6 priority-score ordering: PASS"
    )

else:

    raise ValueError(
        "V6 priority-score ordering failed."
    )


# Verify baseline has every original row.

if len(baseline) == len(original):

    print(
        "Chronological baseline row count: PASS"
    )

else:

    raise ValueError(
        "Chronological baseline row count mismatch."
    )


# Verify baseline positions are unique.

if (
    baseline["_original_order"]
    .nunique()
    ==
    len(baseline)
):

    print(
        "Chronological baseline row identity: PASS"
    )

else:

    raise ValueError(
        "Duplicate original positions in baseline."
    )


# ============================================================
# 20. SAVE FINAL COMPARISON
# ============================================================

print("\n" + "=" * 80)
print("FILES CREATED")
print("=" * 80)

print(
    f"\n1. {BASELINE_OUTPUT_PATH}"
)

print(
    f"2. {COMPARISON_OUTPUT_PATH}"
)

print(
    f"3. {UNIQUE_COMPARISON_OUTPUT_PATH}"
)


# ============================================================
# 21. FINAL SUMMARY
# ============================================================

print("\n" + "=" * 80)
print("CHRONOLOGICAL BASELINE EXPERIMENT COMPLETE")
print("=" * 80)

print(
    f"""
Total test alerts        : {len(original):,}
Incident alerts          : {total_incident_alerts:,}
Unique incidents         : {total_unique_incidents:,}

V6 model ranking:
    Isolation Forest
    Unsupervised
    300 trees
    Random state = 42

Chronological baseline:
    Original timestamp order
    Stable tie-breaking
    No model involved

Ground truth:
    incident_ids
    POST-HOC evaluation ONLY

Ground truth was NOT used for:
    - feature engineering
    - model training
    - anomaly scoring
    - priority scoring
    - priority ranking

The V6 ranking was not modified.

The chronological queue is an independent
baseline for comparison.

This experiment is now ready for the
SIH baseline-vs-model evaluation.
"""
)

print("=" * 80)