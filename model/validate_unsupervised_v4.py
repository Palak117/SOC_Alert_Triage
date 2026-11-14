import pandas as pd
import numpy as np

print("=" * 70)
print("UNSUPERVISED V4 POST-HOC VALIDATION")
print("=" * 70)

# ============================================================
# 1. LOAD V4 SCORED RESULTS
# ============================================================

print("\nLoading V4 scored results...")

scored = pd.read_csv(
    "data/scored/test_unsupervised_v4_scored.csv",
    low_memory=False
)

print(f"Scored records : {len(scored):,}")

# ============================================================
# 2. LOAD ORIGINAL TEST DATA
# ============================================================

print("\nLoading original test data...")

original = pd.read_csv(
    "data/train_test/test_20.csv",
    low_memory=False
)

print(f"Original test  : {len(original):,}")

# ============================================================
# 3. SAFETY CHECK
# ============================================================

if len(scored) != len(original):
    raise ValueError(
        f"Row mismatch! Scored={len(scored)}, "
        f"Original={len(original)}"
    )

# ============================================================
# 4. CREATE GROUND TRUTH ONLY FOR EVALUATION
# ============================================================

print("\nCreating ground truth ONLY for evaluation...")

if "incident_ids" not in original.columns:
    raise ValueError(
        "incident_ids column not found in test dataset."
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


actual_incident = incident_ids.apply(has_incident)

# Attach evaluation-only information BEFORE ranking.
scored["actual_incident"] = actual_incident.values
scored["incident_id_eval"] = incident_ids.values

# ============================================================
# 5. GROUND TRUTH DISTRIBUTION
# ============================================================

print("\n" + "=" * 70)
print("GROUND TRUTH DISTRIBUTION")
print("=" * 70)

print(
    scored["actual_incident"].value_counts()
)

total_incident_alerts = int(
    scored["actual_incident"].sum()
)

print(
    f"\nTotal incident alerts: "
    f"{total_incident_alerts:,}"
)

# ============================================================
# 6. ENSURE CORRECT PRIORITY ORDER
# ============================================================

if "priority_rank" in scored.columns:

    ranked = (
        scored
        .sort_values(
            "priority_rank",
            ascending=True,
            kind="mergesort"
        )
        .reset_index(drop=True)
    )

else:

    ranked = (
        scored
        .sort_values(
            "anomaly_score",
            ascending=True,
            kind="mergesort"
        )
        .reset_index(drop=True)
    )

# ============================================================
# 7. PRECISION@K + INCIDENT RECALL
# ============================================================

print("\n" + "=" * 70)
print("PRECISION@K + INCIDENT RECALL")
print("=" * 70)

top_ks = [
    100,
    500,
    1000,
    5000,
    10000
]

for k in top_ks:

    top_k = ranked.head(k)

    incidents_found = int(
        top_k["actual_incident"].sum()
    )

    precision = incidents_found / k

    if total_incident_alerts > 0:
        recall = (
            incidents_found /
            total_incident_alerts
        )
    else:
        recall = 0.0

    alerts_avoided = (
        len(ranked) - k
    )

    avoided_percentage = (
        alerts_avoided /
        len(ranked)
    )

    print(
        f"Top-{k:<5} | "
        f"Incident alerts: {incidents_found:<5} | "
        f"Precision: {precision:.4f} "
        f"({precision * 100:.2f}%) | "
        f"Recall: {recall:.4f} "
        f"({recall * 100:.2f}%) | "
        f"Alerts avoided: {alerts_avoided:,} "
        f"({avoided_percentage * 100:.2f}%)"
    )

# ============================================================
# 8. UNIQUE INCIDENT DISCOVERY
# ============================================================

print("\n" + "=" * 70)
print("UNIQUE INCIDENT DISCOVERY")
print("=" * 70)


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

    # List-like format:
    # ['id1', 'id2']
    if text.startswith("[") and text.endswith("]"):

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

    # Semicolon-separated IDs
    if ";" in text:

        return [
            x.strip()
            for x in text.split(";")
            if x.strip()
        ]

    # Single incident ID
    return [text]


# IMPORTANT:
# Create these lists directly from ranked rows.
# This keeps incident IDs attached to their scored alerts.

ranked["incident_id_list_eval"] = (
    ranked["incident_id_eval"]
    .apply(extract_incident_ids)
)

# ------------------------------------------------------------
# All unique incidents
# ------------------------------------------------------------

all_incidents = set()

for ids in ranked["incident_id_list_eval"]:

    for incident_id in ids:
        all_incidents.add(incident_id)

total_unique_incidents = len(all_incidents)

print(
    f"Total unique incidents: "
    f"{total_unique_incidents:,}"
)

# ------------------------------------------------------------
# Unique incident recall @ K
# ------------------------------------------------------------

for k in top_ks:

    top_k = ranked.head(k)

    discovered = set()

    for ids in top_k["incident_id_list_eval"]:

        for incident_id in ids:
            discovered.add(incident_id)

    unique_found = len(discovered)

    if total_unique_incidents > 0:

        unique_recall = (
            unique_found /
            total_unique_incidents
        )

    else:

        unique_recall = 0.0

    print(
        f"Top-{k:<5} | "
        f"Unique incidents: {unique_found:<5} | "
        f"Unique recall: {unique_recall:.2%}"
    )

# ============================================================
# 9. FIRST INCIDENT RANK
# ============================================================

print("\n" + "=" * 70)
print("FIRST INCIDENT RANK")
print("=" * 70)

first_rank = {}

for rank, ids in enumerate(
    ranked["incident_id_list_eval"],
    start=1
):

    for incident_id in ids:

        if incident_id not in first_rank:

            first_rank[incident_id] = rank

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
        f"Maximum first rank : "
        f"{max(ranks):,}"
    )

    print("\nFirst 20 incidents discovered:")

    for incident_id, rank in sorted(
        first_rank.items(),
        key=lambda x: x[1]
    )[:20]:

        print(
            f"Rank {rank:<8} | "
            f"Incident: {incident_id}"
        )

# ============================================================
# 10. INCIDENT DISCOVERY AT IMPORTANT RANKS
# ============================================================

print("\n" + "=" * 70)
print("INCIDENT DISCOVERY SUMMARY")
print("=" * 70)

for threshold in [
    1000,
    5000,
    10000,
    25000,
    50000,
    100000
]:

    discovered = sum(
        1
        for rank in first_rank.values()
        if rank <= threshold
    )

    recall = (
        discovered / total_unique_incidents
        if total_unique_incidents > 0
        else 0.0
    )

    print(
        f"Rank <= {threshold:<6} | "
        f"Incidents discovered: "
        f"{discovered:<4} | "
        f"Recall: {recall:.2%}"
    )

# ============================================================
# 11. SAVE VALIDATED RESULTS
# ============================================================

print("\n" + "=" * 70)
print("SAVING VALIDATION RESULTS")
print("=" * 70)

# Do not need the temporary Python list column in CSV.
ranked_to_save = ranked.drop(
    columns=["incident_id_list_eval"],
    errors="ignore"
)

output_path = (
    "data/scored/"
    "test_unsupervised_v4_validated.csv"
)

ranked_to_save.to_csv(
    output_path,
    index=False
)

print(
    f"\nSaved evaluation results to:\n"
    f"{output_path}"
)

# ============================================================
# 12. FINAL SAFETY STATEMENT
# ============================================================

print("\n" + "=" * 70)
print("VALIDATION COMPLETE")
print("=" * 70)

print("""
IMPORTANT:

The Isolation Forest was NOT retrained.
V4 anomaly scores were NOT modified.
V4 ranking was NOT modified.

incident_ids were used ONLY for post-hoc evaluation.

No labels were used during:
- feature engineering
- model training
- test scoring

Ground-truth incidents were NOT used to create
anomaly scores or priority rankings.

The incident IDs remain attached to their original
scored records during ranking to ensure correct
post-hoc incident discovery calculations.
""")

print("=" * 70)