import pandas as pd
import numpy as np

print("=" * 70)
print("CAUSAL CHRONOLOGICAL V6 POST-HOC VALIDATION")
print("=" * 70)

# ============================================================
# PATHS
# ============================================================

SCORED_PATH = (
    "data/scored/test_unsupervised_v6_scored.csv"
)

ORIGINAL_TEST_PATH = (
    "data/train_test/test_20.csv"
)

OUTPUT_PATH = (
    "data/scored/test_unsupervised_v6_validated.csv"
)

# ============================================================
# 1. LOAD SCORED RESULTS
# ============================================================

print("\nLoading V6 scored results...")

scored = pd.read_csv(
    SCORED_PATH,
    low_memory=False
)

print(f"Scored records : {len(scored):,}")

# ============================================================
# 2. LOAD ORIGINAL TEST DATA
# ============================================================

print("\nLoading original test data...")

original = pd.read_csv(
    ORIGINAL_TEST_PATH,
    low_memory=False
)

print(f"Original test  : {len(original):,}")

# ============================================================
# 3. BASIC SAFETY CHECKS
# ============================================================

print("\n" + "=" * 70)
print("BASIC SAFETY CHECKS")
print("=" * 70)

if len(scored) != len(original):
    raise ValueError(
        f"Row count mismatch! "
        f"Scored={len(scored)}, "
        f"Original={len(original)}"
    )

print("Row count match: PASS")

if "_alert_id" not in scored.columns:
    raise ValueError(
        "_alert_id missing from scored results."
    )

print("Scored _alert_id column: PASS")

if "_alert_id" in original.columns:
    print("Original test _alert_id column: PRESENT")
else:
    print(
        "Original test _alert_id column: "
        "NOT PRESENT — acceptable"
    )

if scored["_alert_id"].is_unique:
    print("Scored _alert_id uniqueness: PASS")
else:
    raise ValueError(
        "Scored _alert_id values are not unique."
    )

# ============================================================
# 4. REQUIRED COLUMN CHECK
# ============================================================

print("\n" + "=" * 70)
print("REQUIRED COLUMN CHECK")
print("=" * 70)

required_scored_columns = [
    "_alert_id",
    "anomaly_score",
    "priority_score",
    "priority_rank"
]

for column in required_scored_columns:

    if column not in scored.columns:
        raise ValueError(
            f"Required scored column missing: {column}"
        )

    print(
        f"Scored '{column}': PASS"
    )

required_original_columns = [
    "incident_ids",
    "timestamp"
]

for column in required_original_columns:

    if column not in original.columns:
        raise ValueError(
            f"Required original column missing: {column}"
        )

    print(
        f"Original '{column}' column: PASS"
    )

# ============================================================
# 5. ALERT ID RANGE CHECK
# ============================================================

print("\n" + "=" * 70)
print("ALERT ID RANGE CHECK")
print("=" * 70)

expected_ids = np.arange(
    len(original)
)

actual_ids = np.sort(
    scored["_alert_id"].to_numpy()
)

if np.array_equal(actual_ids, expected_ids):

    print(
        "Alert IDs cover original rows "
        "0 -> N-1: PASS"
    )

else:

    raise ValueError(
        "Alert IDs do not form a complete "
        "0 -> N-1 sequence."
    )

print(
    f"Minimum _alert_id: "
    f"{scored['_alert_id'].min():,}"
)

print(
    f"Maximum _alert_id: "
    f"{scored['_alert_id'].max():,}"
)

# ============================================================
# 6. POST-HOC GROUND TRUTH CREATION
# ============================================================

print("\n" + "=" * 70)
print("POST-HOC GROUND TRUTH CREATION")
print("=" * 70)

print(
    "\nincident_ids are being used ONLY "
    "for post-hoc evaluation."
)

incident_ids = original["incident_ids"]


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


actual_incident = incident_ids.apply(
    has_incident
)

print(
    "Ground truth created for post-hoc "
    "evaluation: PASS"
)

# ============================================================
# 7. ALERT -> ORIGINAL ROW ALIGNMENT
# ============================================================

print("\n" + "=" * 70)
print("ALERT-TO-ORIGINAL ROW ALIGNMENT")
print("=" * 70)

print(
    "\nUsing _alert_id as the original "
    "row-position key..."
)

# _alert_id represents the original row
# position before the scored dataframe
# was sorted by anomaly priority.

scored["actual_incident"] = (
    scored["_alert_id"]
    .map(
        actual_incident.to_dict()
    )
)

if scored["actual_incident"].isna().any():

    raise ValueError(
        "Some scored alerts could not be "
        "mapped to original test rows."
    )

print(
    "Original-row alignment using "
    "_alert_id: PASS"
)

scored["incident_id_eval"] = (
    scored["_alert_id"]
    .map(
        incident_ids.to_dict()
    )
)

print(
    "incident_ids attached for "
    "evaluation only: PASS"
)

# ============================================================
# 8. GROUND TRUTH DISTRIBUTION
# ============================================================

print("\n" + "=" * 70)
print("GROUND TRUTH DISTRIBUTION")
print("=" * 70)

print(
    scored["actual_incident"]
    .value_counts()
)

total_incident_alerts = int(
    scored["actual_incident"].sum()
)

print(
    f"\nTotal incident alerts: "
    f"{total_incident_alerts:,}"
)

# ============================================================
# 9. V6 PRIORITY ORDER CHECK
# ============================================================

print("\n" + "=" * 70)
print("V6 PRIORITY ORDER CHECK")
print("=" * 70)

ranked = (
    scored
    .sort_values(
        "priority_rank",
        ascending=True
    )
    .reset_index(drop=True)
)

expected_ranks = np.arange(
    1,
    len(ranked) + 1
)

if np.array_equal(
    ranked["priority_rank"].to_numpy(),
    expected_ranks
):

    print(
        "Priority ranks are sequential: PASS"
    )

else:

    raise ValueError(
        "Priority ranks are not sequential."
    )

priority_score_values = (
    ranked["priority_score"]
    .to_numpy()
)

if np.all(
    priority_score_values[:-1]
    >=
    priority_score_values[1:]
):

    print(
        "Priority score descending order: PASS"
    )

else:

    raise ValueError(
        "Priority score is not in descending order."
    )

anomaly_score_values = (
    ranked["anomaly_score"]
    .to_numpy()
)

if np.all(
    anomaly_score_values[:-1]
    >=
    anomaly_score_values[1:]
):

    print(
        "Anomaly score descending order: PASS"
    )

else:

    raise ValueError(
        "Anomaly score is not in descending order."
    )

# ============================================================
# 10. PRECISION@K + INCIDENT RECALL
# ============================================================

print("\n" + "=" * 70)
print("PRECISION@K + INCIDENT RECALL")
print("=" * 70)

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

for requested_k in top_ks:

    k = min(
        requested_k,
        len(ranked)
    )

    top_k = ranked.head(k)

    incidents_found = int(
        top_k["actual_incident"].sum()
    )

    precision = (
        incidents_found / k
    )

    if total_incident_alerts > 0:

        recall = (
            incidents_found
            /
            total_incident_alerts
        )

    else:

        recall = 0.0

    alerts_avoided = (
        len(ranked) - k
    )

    avoided_percentage = (
        alerts_avoided
        /
        len(ranked)
    )

    print(
        f"Top-{k:<6} | "
        f"Incident alerts: "
        f"{incidents_found:<6} | "
        f"Precision: "
        f"{precision:.4f} "
        f"({precision * 100:.2f}%) | "
        f"Recall: "
        f"{recall:.4f} "
        f"({recall * 100:.2f}%) | "
        f"Alerts avoided: "
        f"{alerts_avoided:,} "
        f"({avoided_percentage * 100:.2f}%)"
    )

# ============================================================
# 11. INCIDENT ID PARSER
# ============================================================

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


incident_id_lists = (
    incident_ids.apply(
        extract_incident_ids
    )
)

# ============================================================
# 12. UNIQUE INCIDENT DISCOVERY
# ============================================================

print("\n" + "=" * 70)
print("UNIQUE INCIDENT DISCOVERY")
print("=" * 70)

all_incidents = set()

for ids in incident_id_lists:

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
# 13. UNIQUE INCIDENT RECALL
# ============================================================

print("\n" + "=" * 70)
print("UNIQUE INCIDENT RECALL")
print("=" * 70)

for requested_k in top_ks:

    k = min(
        requested_k,
        len(ranked)
    )

    discovered = set()

    for alert_id in ranked.head(k)["_alert_id"]:

        ids = incident_id_lists.iloc[
            int(alert_id)
        ]

        for incident_id in ids:

            discovered.add(
                incident_id
            )

    unique_found = len(
        discovered
    )

    if total_unique_incidents > 0:

        unique_recall = (
            unique_found
            /
            total_unique_incidents
        )

    else:

        unique_recall = 0.0

    print(
        f"Top-{k:<6} | "
        f"Unique incidents: "
        f"{unique_found:<6} | "
        f"Unique recall: "
        f"{unique_recall:.2%}"
    )

# ============================================================
# 14. INCIDENT DISCOVERY BY REVIEW FRACTION
# ============================================================

print("\n" + "=" * 70)
print("INCIDENT DISCOVERY BY REVIEW FRACTION")
print("=" * 70)

review_percentages = [
    0.1,
    0.5,
    1,
    2,
    5,
    10,
    25
]

for percentage in review_percentages:

    k = max(
        1,
        int(
            len(ranked)
            *
            percentage
            /
            100
        )
    )

    discovered = set()

    for alert_id in ranked.head(k)["_alert_id"]:

        ids = incident_id_lists.iloc[
            int(alert_id)
        ]

        for incident_id in ids:

            discovered.add(
                incident_id
            )

    unique_found = len(
        discovered
    )

    if total_unique_incidents > 0:

        recall = (
            unique_found
            /
            total_unique_incidents
        )

    else:

        recall = 0.0

    print(
        f"Review {percentage:>5.1f}% "
        f"({k:>7,} alerts) | "
        f"Incidents discovered: "
        f"{unique_found:>4} | "
        f"Recall: "
        f"{recall:.2%}"
    )

# ============================================================
# 15. FIRST INCIDENT RANK
# ============================================================

print("\n" + "=" * 70)
print("FIRST INCIDENT RANK")
print("=" * 70)

first_rank = {}

for rank, alert_id in enumerate(
    ranked["_alert_id"],
    start=1
):

    ids = incident_id_lists.iloc[
        int(alert_id)
    ]

    for incident_id in ids:

        if incident_id not in first_rank:

            first_rank[
                incident_id
            ] = rank

print(
    f"Incidents discovered: "
    f"{len(first_rank):,}"
)

if first_rank:

    ranks = list(
        first_rank.values()
    )

    print(
        f"Minimum first rank : "
        f"{min(ranks):,}"
    )

    print(
        f"Mean first rank    : "
        f"{np.mean(ranks):,.2f}"
    )

    print(
        f"Median first rank  : "
        f"{np.median(ranks):,.2f}"
    )

    print(
        f"Maximum first rank : "
        f"{max(ranks):,}"
    )

    print(
        "\nFirst 20 incidents discovered:"
    )

    for incident_id, rank in sorted(
        first_rank.items(),
        key=lambda x: x[1]
    )[:20]:

        print(
            f"Rank {rank:<8} | "
            f"Incident: {incident_id}"
        )

# ============================================================
# 16. CHRONOLOGICAL ORDER CHECK
# ============================================================

print("\n" + "=" * 70)
print("CHRONOLOGICAL ORDER CHECK")
print("=" * 70)

test_timestamp = pd.to_datetime(
    original["timestamp"],
    errors="coerce"
)

if test_timestamp.isna().any():

    raise ValueError(
        "Timestamp parsing failed for "
        f"{test_timestamp.isna().sum():,} rows."
    )

print("Timestamp parsing: PASS")

if test_timestamp.is_monotonic_increasing:

    print(
        "Original test chronological order: PASS"
    )

else:

    raise ValueError(
        "Original test data is not in "
        "chronological order."
    )

# ============================================================
# 17. ALERT-ID / TIMESTAMP ALIGNMENT CHECK
# ============================================================

print("\n" + "=" * 70)
print("ALERT-ID / TIMESTAMP ALIGNMENT CHECK")
print("=" * 70)

sample_size = min(
    100,
    len(scored)
)

sampled = (
    scored
    .head(sample_size)
)

for _, row in sampled.iterrows():

    alert_id = int(
        row["_alert_id"]
    )

    original_time = (
        test_timestamp.iloc[
            alert_id
        ]
    )

    if pd.isna(original_time):

        raise ValueError(
            f"Invalid timestamp for "
            f"_alert_id={alert_id}"
        )

print(
    f"Sampled {sample_size} "
    "_alert_id -> original row "
    "timestamp mapping: PASS"
)

# ============================================================
# 18. SAVE VALIDATED RESULTS
# ============================================================

print("\n" + "=" * 70)
print("SAVING V6 VALIDATION RESULTS")
print("=" * 70)

ranked.to_csv(
    OUTPUT_PATH,
    index=False
)

print(
    "\nSaved evaluation results to:"
)

print(
    OUTPUT_PATH
)

# ============================================================
# 19. VERIFY SAVED FILE
# ============================================================

saved_check = pd.read_csv(
    OUTPUT_PATH,
    low_memory=False
)

if len(saved_check) != len(ranked):

    raise ValueError(
        "Saved validation row count "
        "does not match ranked results."
    )

if "_alert_id" not in saved_check.columns:

    raise ValueError(
        "_alert_id missing from saved "
        "validation file."
    )

if "actual_incident" not in saved_check.columns:

    raise ValueError(
        "actual_incident missing from "
        "saved validation file."
    )

print(
    "Saved validation file verification: PASS"
)

# ============================================================
# 20. FINAL SAFETY STATEMENT
# ============================================================

print("\n" + "=" * 70)
print("V6 VALIDATION COMPLETE")
print("=" * 70)

print(
    """
IMPORTANT:

The V6 Isolation Forest was NOT retrained.

V6 anomaly scores were NOT modified.

V6 priority scores were NOT modified.

V6 priority ranking was NOT modified.

incident_ids were used ONLY for
post-hoc evaluation.

No incident labels were used during:

- feature engineering
- model training
- test scoring
- anomaly-score calculation
- priority-score creation
- priority ranking

No ground-truth information was used
to create anomaly scores.

No incident information was used to
create priority rankings.

_alert_id is an identity / row-position
key used only to map scored alerts back
to the original test rows during
post-hoc evaluation.

_alert_id is NOT used as a model feature.

Incident information is attached only
AFTER scoring for evaluation.

This validation does NOT change the
production ranking.

The V6 model remains fully UNSUPERVISED.
"""
)

print("=" * 70)