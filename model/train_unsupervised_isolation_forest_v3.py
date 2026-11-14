import pandas as pd
import numpy as np
from pathlib import Path

print("=" * 70)
print("UNSUPERVISED V3 POST-HOC VALIDATION")
print("=" * 70)

# ============================================================
# PATHS
# ============================================================

SCORED_PATH = Path("data/scored/test_unsupervised_v3_scored.csv")
TEST_PATH = Path("data/train_test/test_20.csv")
OUTPUT_PATH = Path("data/scored/test_unsupervised_v3_validated.csv")


# ============================================================
# LOAD DATA
# ============================================================

print("\nLoading V3 scored results...")

scored = pd.read_csv(SCORED_PATH, low_memory=False)

print(f"Scored records : {len(scored):,}")

print("\nLoading original test data...")

original = pd.read_csv(TEST_PATH, low_memory=False)

print(f"Original test  : {len(original):,}")


# ============================================================
# ROW COUNT CHECK
# ============================================================

if len(scored) != len(original):
    raise ValueError(
        f"Row mismatch: scored={len(scored):,}, "
        f"original={len(original):,}"
    )


# ============================================================
# POST-HOC GROUND TRUTH
# ============================================================

print("\nCreating ground truth ONLY for evaluation...")

if "incident_ids" not in original.columns:
    raise ValueError(
        "incident_ids column not found in original test dataset."
    )

incident_ids = original["incident_ids"]


# ------------------------------------------------------------
# Convert missing/empty incident IDs to non-incident
# ------------------------------------------------------------

def has_incident(value):

    if pd.isna(value):
        return False

    value = str(value).strip()

    if value == "":
        return False

    if value.lower() in {
        "nan",
        "none",
        "null",
        "[]",
        "{}",
        "no incident",
        "no_incident"
    }:
        return False

    return True


actual_incident = incident_ids.apply(has_incident)


# ============================================================
# GROUND TRUTH DISTRIBUTION
# ============================================================

print("\n" + "=" * 70)
print("GROUND TRUTH DISTRIBUTION")
print("=" * 70)

distribution = actual_incident.value_counts()

print(distribution)

total_incidents = int(actual_incident.sum())
total_alerts = len(actual_incident)

print(f"\nTotal incident alerts: {total_incidents:,}")


# ============================================================
# ATTACH ONLY FOR EVALUATION
# ============================================================

result = scored.copy()

result["actual_incident"] = actual_incident.to_numpy()


# ============================================================
# PRECISION@K + INCIDENT RECALL
# ============================================================

print("\n" + "=" * 70)
print("PRECISION@K + INCIDENT RECALL")
print("=" * 70)

TOP_K_VALUES = [100, 500, 1000, 5000, 10000]

validation_rows = []

for k in TOP_K_VALUES:

    top_k = result.head(k)

    incident_count = int(top_k["actual_incident"].sum())

    precision = incident_count / k

    if total_incidents > 0:
        recall = incident_count / total_incidents
    else:
        recall = 0.0

    alerts_avoided = total_alerts - k

    avoided_percentage = alerts_avoided / total_alerts

    print(
        f"Top-{k:<5} | "
        f"Incident alerts: {incident_count:<6} | "
        f"Precision: {precision:.4f} ({precision * 100:.2f}%) | "
        f"Recall: {recall:.4f} ({recall * 100:.2f}%) | "
        f"Alerts avoided: {alerts_avoided:,} "
        f"({avoided_percentage * 100:.2f}%)"
    )

    validation_rows.append({
        "top_k": k,
        "incident_alerts": incident_count,
        "precision": precision,
        "recall": recall,
        "alerts_avoided": alerts_avoided,
        "alerts_avoided_percentage": avoided_percentage
    })


# ============================================================
# UNIQUE INCIDENT DISCOVERY
# ============================================================

print("\n" + "=" * 70)
print("UNIQUE INCIDENT DISCOVERY")
print("=" * 70)


def normalize_incident_id(value):

    if pd.isna(value):
        return []

    text = str(value).strip()

    if text == "":
        return []

    # Handle common list-like representation
    if text.startswith("[") and text.endswith("]"):

        text = text[1:-1].strip()

        if text == "":
            return []

        parts = text.split(",")

        cleaned = []

        for part in parts:
            part = part.strip().strip("'").strip('"')

            if part:
                cleaned.append(part)

        return cleaned

    # Handle semicolon-separated IDs
    if ";" in text:
        return [
            x.strip()
            for x in text.split(";")
            if x.strip()
        ]

    return [text]


incident_sets = incident_ids.apply(normalize_incident_id)

all_incidents = set()

for ids in incident_sets:
    for incident_id in ids:
        all_incidents.add(incident_id)


total_unique_incidents = len(all_incidents)

print(f"Total unique incidents: {total_unique_incidents:,}")


for k in TOP_K_VALUES:

    top_original_indices = result.head(k).index

    discovered = set()

    for idx in top_original_indices:

        for incident_id in incident_sets.iloc[idx]:
            discovered.add(incident_id)

    unique_recall = (
        len(discovered) / total_unique_incidents
        if total_unique_incidents > 0
        else 0.0
    )

    print(
        f"Top-{k:<5} | "
        f"Unique incidents: {len(discovered):<6} | "
        f"Unique recall: {unique_recall:.2%}"
    )


# ============================================================
# FIRST INCIDENT RANK
# ============================================================

print("\n" + "=" * 70)
print("FIRST INCIDENT RANK")
print("=" * 70)

first_rank = {}

for rank, idx in enumerate(result.index, start=1):

    ids = incident_sets.iloc[idx]

    for incident_id in ids:

        if incident_id not in first_rank:
            first_rank[incident_id] = rank


print(f"Incidents discovered: {len(first_rank):,}")

if first_rank:

    ranks = list(first_rank.values())

    print(f"Minimum first rank : {min(ranks):,}")
    print(f"Mean first rank    : {np.mean(ranks):,.2f}")
    print(f"Maximum first rank : {max(ranks):,}")

    print("\nFirst 20 incidents discovered:")

    for incident_id, rank in list(first_rank.items())[:20]:

        print(
            f"Rank {rank:<8} | Incident: {incident_id}"
        )


# ============================================================
# SAVE VALIDATED RESULTS
# ============================================================

print("\n" + "=" * 70)
print("SAVING VALIDATED RESULTS")
print("=" * 70)

result.to_csv(
    OUTPUT_PATH,
    index=False
)

print(f"\nSaved evaluation results to:")
print(OUTPUT_PATH)


# ============================================================
# FINAL SAFETY CHECK
# ============================================================

print("\n" + "=" * 70)
print("VALIDATION COMPLETE")
print("=" * 70)

print("""
IMPORTANT:
The Isolation Forest was NOT retrained.
Scores were NOT modified.
Ranking was NOT modified.

The incident_ids column was used ONLY for post-hoc evaluation.

No labels were used during:
- feature engineering
- model training
- test scoring

Ground-truth incidents were NOT used to create anomaly scores.
""")

print("=" * 70)