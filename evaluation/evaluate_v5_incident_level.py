import os
import pandas as pd
import numpy as np

print("=" * 70)
print("V5 INCIDENT-LEVEL POST-HOC EVALUATION")
print("=" * 70)

CANDIDATES = [
    "data/scored/test_unsupervised_v5_scored.csv",
    "data/scored/test_unsupervised_v6_scored.csv",
    "data/scored/test_v6_leakage_reduced_scored.csv",
    "data/scored/final_v6_sih_dashboard_alerts.csv",
]

SCORED_FILE = None
for cand in CANDIDATES:
    if os.path.exists(cand):
        SCORED_FILE = cand
        break

if SCORED_FILE is None:
    raise FileNotFoundError(f"Scored file not found in candidates: {CANDIDATES}")

TEST_FILE = "data/train_test/test_20.csv"
OUTPUT_DIR = "data/evaluation"

os.makedirs(OUTPUT_DIR, exist_ok=True)

# ----------------------------------------------------------------
# LOAD DATA
# ----------------------------------------------------------------

print(f"\nLoading scored results from {SCORED_FILE}...")
scored = pd.read_csv(
    SCORED_FILE,
    low_memory=False
)

print("Scored rows:", len(scored))

print("\nLoading original test data...")
test = pd.read_csv(
    TEST_FILE,
    low_memory=False
)

print("Test rows:", len(test))

# ----------------------------------------------------------------
# BASIC CHECKS
# ----------------------------------------------------------------

print("\n" + "=" * 70)
print("BASIC CHECKS")
print("=" * 70)

required_scored = [
    "_alert_id",
    "priority_rank",
    "anomaly_score"
]

for col in required_scored:
    if col not in scored.columns:
        raise ValueError(
            f"{col} missing from scored results."
        )

if "incident_ids" not in test.columns:
    raise ValueError(
        "incident_ids missing from original test data."
    )

print("Required columns: PASS")

# ----------------------------------------------------------------
# CREATE STABLE ALERT ID
# ----------------------------------------------------------------

test["_alert_id"] = np.arange(len(test))

if test["_alert_id"].duplicated().any():
    raise ValueError(
        "_alert_id is not unique."
    )

# ----------------------------------------------------------------
# NORMALIZE INCIDENT IDS
# ----------------------------------------------------------------

def extract_incident_ids(value):

    if pd.isna(value):
        return []

    value = str(value).strip()

    if value in ["", "[]", "nan", "None"]:
        return []

    # Handle list-like values such as:
    # ['INC001', 'INC002']
    try:
        parsed = eval(
            value,
            {"__builtins__": {}},
            {}
        )

        if isinstance(parsed, list):
            return [
                str(x).strip()
                for x in parsed
                if str(x).strip()
            ]

        if isinstance(parsed, str):
            return [parsed.strip()]

    except Exception:
        pass

    # Fallback: treat the value as one incident ID
    return [value]

# ----------------------------------------------------------------
# CREATE POST-HOC INCIDENT INFORMATION
# ----------------------------------------------------------------

test["incident_id_list"] = (
    test["incident_ids"]
    .apply(extract_incident_ids)
)

# ----------------------------------------------------------------
# ATTACH INCIDENT IDS TO SCORED ALERTS
# ----------------------------------------------------------------

incident_mapping = test.set_index(
    "_alert_id"
)["incident_id_list"]

scored["incident_id_list"] = (
    scored["_alert_id"]
    .map(incident_mapping)
)

if scored["incident_id_list"].isna().any():
    raise ValueError(
        "Some alerts could not be mapped to incident IDs."
    )

print("Alert-to-incident mapping: PASS")

# ----------------------------------------------------------------
# SORT BY V5 PRIORITY
# ----------------------------------------------------------------

scored = scored.sort_values(
    "priority_rank",
    ascending=True
).reset_index(drop=True)

# ----------------------------------------------------------------
# ALL UNIQUE INCIDENTS
# ----------------------------------------------------------------

all_incidents = set()

for incident_list in scored["incident_id_list"]:

    for incident_id in incident_list:

        if incident_id:
            all_incidents.add(incident_id)

total_unique_incidents = len(all_incidents)

print("\n" + "=" * 70)
print("INCIDENT DATASET SUMMARY")
print("=" * 70)

print(
    f"Unique incident IDs : {total_unique_incidents:,}"
)

# ----------------------------------------------------------------
# TOP-K INCIDENT-LEVEL EVALUATION
# ----------------------------------------------------------------

K_VALUES = [100, 500, 1000, 5000, 10000]

results = []

print("\n" + "=" * 70)
print("INCIDENT-LEVEL TOP-K EVALUATION")
print("=" * 70)

for k in K_VALUES:

    if k > len(scored):
        continue

    top_k = scored.head(k)

    found_incidents = set()

    for incident_list in top_k["incident_id_list"]:

        for incident_id in incident_list:

            if incident_id:
                found_incidents.add(incident_id)

    unique_found = len(found_incidents)

    incident_recall = (
        unique_found / total_unique_incidents
        if total_unique_incidents > 0
        else 0
    )

    results.append({
        "K": k,
        "Unique_Incidents_Found": unique_found,
        "Total_Unique_Incidents": total_unique_incidents,
        "Incident_Level_Recall": incident_recall,
        "Incident_Level_Recall_Percent":
            incident_recall * 100
    })

    print(f"\nTop-{k:,}")
    print(
        f"  Unique incidents found : {unique_found:,}"
    )
    print(
        f"  Total unique incidents: "
        f"{total_unique_incidents:,}"
    )
    print(
        f"  Incident recall       : "
        f"{incident_recall:.6f}"
    )
    print(
        f"  Incident recall (%)   : "
        f"{incident_recall * 100:.2f}%"
    )

# ----------------------------------------------------------------
# ALERTS PER INCIDENT
# ----------------------------------------------------------------

print("\n" + "=" * 70)
print("ALERTS PER INCIDENT")
print("=" * 70)

incident_alert_counts = {}

for incident_list in scored["incident_id_list"]:

    for incident_id in incident_list:

        if incident_id:

            incident_alert_counts[incident_id] = (
                incident_alert_counts.get(
                    incident_id,
                    0
                ) + 1
            )

if incident_alert_counts:

    counts = list(
        incident_alert_counts.values()
    )

    print(
        f"Minimum alerts/incident : "
        f"{min(counts)}"
    )

    print(
        f"Maximum alerts/incident : "
        f"{max(counts)}"
    )

    print(
        f"Average alerts/incident : "
        f"{sum(counts) / len(counts):.2f}"
    )

# ----------------------------------------------------------------
# SAVE RESULTS
# ----------------------------------------------------------------

output_file = os.path.join(
    OUTPUT_DIR,
    "v5_incident_level_evaluation.csv"
)

pd.DataFrame(results).to_csv(
    output_file,
    index=False
)

print("\n" + "=" * 70)
print("RESULTS SAVED")
print("=" * 70)

print(output_file)

print("\n" + "=" * 70)
print("POST-HOC SAFETY")
print("=" * 70)

print(
    "incident_ids were NOT used during:"
)

print("- Isolation Forest training")
print("- anomaly score calculation")
print("- priority score calculation")
print("- priority ranking")
print("- Top-K selection")

print(
    "\nincident_ids were used ONLY "
    "for post-hoc evaluation."
)

print("\nV5 INCIDENT-LEVEL EVALUATION COMPLETE")