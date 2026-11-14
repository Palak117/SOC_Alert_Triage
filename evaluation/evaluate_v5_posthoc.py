import pandas as pd
import numpy as np
import os

# ================================================================
# V5 POST-HOC EVALUATION
# ================================================================

print("=" * 70)
print("CAUSAL CHRONOLOGICAL UNSUPERVISED V5 POST-HOC EVALUATION")
print("=" * 70)

# ----------------------------------------------------------------
# FILE PATHS
# ----------------------------------------------------------------

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

# Change this path ONLY if your original test file has a different name.
TEST_FILE = "data/train_test/test_20.csv"

OUTPUT_DIR = "data/evaluation"

os.makedirs(OUTPUT_DIR, exist_ok=True)

# ----------------------------------------------------------------
# LOAD DATA
# ----------------------------------------------------------------

print(f"\nLoading scored results from {SCORED_FILE}...")

scored = pd.read_csv(SCORED_FILE, low_memory=False)

print("Scored rows:", len(scored))

print("\nLoading original test data...")

test = pd.read_csv(TEST_FILE)

print("Test rows:", len(test))

# ----------------------------------------------------------------
# BASIC CHECKS
# ----------------------------------------------------------------

print("\n" + "=" * 70)
print("BASIC DATA CHECKS")
print("=" * 70)

if "_alert_id" not in scored.columns:
    raise ValueError("_alert_id missing from scored results.")

if "priority_rank" not in scored.columns:
    raise ValueError("priority_rank missing from scored results.")

if "anomaly_score" not in scored.columns:
    raise ValueError("anomaly_score missing from scored results.")

# ---------------------------------------------------------------
# CREATE POST-HOC GROUND TRUTH FROM INCIDENT IDS
# ---------------------------------------------------------------

if "incident_ids" not in test.columns:
    raise ValueError(
        "incident_ids missing from original test data."
    )

print("incident_ids column found: PASS")


def is_incident(value):

    if pd.isna(value):
        return False

    value = str(value).strip()

    if value in ["", "[]", "nan", "None"]:
        return False

    return True


test["actual_incident"] = (
    test["incident_ids"]
    .apply(is_incident)
)

print("actual_incident created from incident_ids: PASS")

# ----------------------------------------------------------------
# CHECK ROW COUNTS
# ----------------------------------------------------------------

if len(scored) != len(test):
    raise ValueError(
        f"Row count mismatch: scored={len(scored)}, test={len(test)}"
    )

print("Row count check: PASS")

# ----------------------------------------------------------------
# ATTACH GROUND TRUTH
# ----------------------------------------------------------------

print("\nAttaching actual_incident for POST-HOC evaluation...")

# ---------------------------------------------------------------
# MAP GROUND TRUTH USING STABLE ALERT ID
# ---------------------------------------------------------------

# ---------------------------------------------------------------
# CREATE STABLE ALERT ID
# ---------------------------------------------------------------

# The original test CSV does not store _alert_id.
# V5 creates it deterministically from chronological row order,
# using the same method as inspect_v5_top_alerts.py.

test["_alert_id"] = np.arange(len(test))

# Safety check
if test["_alert_id"].duplicated().any():
    raise ValueError(
        "_alert_id is not unique in original test data."
    )

# Create alert_id -> actual_incident mapping
ground_truth = test.set_index("_alert_id")["actual_incident"]

# Attach ground truth using stable alert identity
scored["actual_incident"] = (
    scored["_alert_id"]
    .map(ground_truth)
)

# Verify every scored alert received ground truth
if scored["actual_incident"].isna().any():
    missing = scored["actual_incident"].isna().sum()
    raise ValueError(
        f"Ground truth mapping failed for {missing} alerts."
    )

scored["actual_incident"] = (
    scored["actual_incident"].astype(bool)
)

print("Stable _alert_id ground-truth mapping: PASS")
print(
    "Ground-truth incidents attached:",
    int(scored["actual_incident"].sum())
)

# ----------------------------------------------------------------
# SORT BY PRIORITY
# ----------------------------------------------------------------

scored = scored.sort_values(
    "priority_rank",
    ascending=True
).reset_index(drop=True)

# ----------------------------------------------------------------
# TOTAL INCIDENTS
# ----------------------------------------------------------------

total_alerts = len(scored)

total_incidents = scored["actual_incident"].sum()

total_non_incidents = total_alerts - total_incidents

print("\n" + "=" * 70)
print("DATASET SUMMARY")
print("=" * 70)

print(f"Total alerts       : {total_alerts:,}")
print(f"Actual incidents   : {total_incidents:,}")
print(f"Non-incidents      : {total_non_incidents:,}")

# ----------------------------------------------------------------
# TOP-K EVALUATION
# ----------------------------------------------------------------

K_VALUES = [100, 500, 1000, 5000, 10000]

results = []

print("\n" + "=" * 70)
print("TOP-K POST-HOC EVALUATION")
print("=" * 70)

for k in K_VALUES:

    if k > total_alerts:
        continue

    top_k = scored.head(k)

    incidents_found = int(top_k["actual_incident"].sum())

    precision = incidents_found / k

    recall = (
        incidents_found / total_incidents
        if total_incidents > 0
        else 0
    )

    review_fraction = k / total_alerts

    alerts_avoided = total_alerts - k

    results.append({
        "K": k,
        "Incidents_Found": incidents_found,
        "Precision_at_K": precision,
        "Precision_at_K_Percent": precision * 100,
        "Incident_Recall_at_K": recall,
        "Incident_Recall_at_K_Percent": recall * 100,
        "Review_Fraction": review_fraction,
        "Review_Fraction_Percent": review_fraction * 100,
        "Alerts_Avoided": alerts_avoided
    })

    print(f"\nTop-{k:,}")
    print(f"  Incidents found       : {incidents_found:,}")
    print(f"  Precision@{k:,}       : {precision:.6f}")
    print(f"  Precision@{k:,} (%)   : {precision * 100:.2f}%")
    print(f"  Incident Recall@{k:,} : {recall:.6f}")
    print(f"  Incident Recall (%)   : {recall * 100:.2f}%")
    print(f"  Alerts reviewed       : {k:,}")
    print(f"  Review fraction       : {review_fraction * 100:.4f}%")
    print(f"  Alerts avoided        : {alerts_avoided:,}")

# ----------------------------------------------------------------
# SAVE RESULTS
# ----------------------------------------------------------------

results_df = pd.DataFrame(results)

output_file = os.path.join(
    OUTPUT_DIR,
    "v5_posthoc_evaluation.csv"
)

results_df.to_csv(
    output_file,
    index=False
)

print("\n" + "=" * 70)
print("SAVING EVALUATION RESULTS")
print("=" * 70)

print(f"\nSaved to:")
print(output_file)

# ----------------------------------------------------------------
# BEST RANKED INCIDENT
# ----------------------------------------------------------------

first_incident = scored[
    scored["actual_incident"] == True
].iloc[0]

print("\n" + "=" * 70)
print("FIRST ACTUAL INCIDENT")
print("=" * 70)

print(f"Priority rank : {int(first_incident['priority_rank'])}")
print(f"Anomaly score : {first_incident['anomaly_score']:.6f}")

# ----------------------------------------------------------------
# FINAL SAFETY STATEMENT
# ----------------------------------------------------------------

print("\n" + "=" * 70)
print("POST-HOC EVALUATION SAFETY")
print("=" * 70)

print("""
Incident information was NOT used to:

- train the Isolation Forest
- create anomaly scores
- create priority scores
- create priority rankings
- select the Top-K alerts

actual_incident is used ONLY after scoring
for POST-HOC VALIDATION.

No model retraining was performed.

The V5 model remains UNSUPERVISED.
""")

print("=" * 70)
print("V5 POST-HOC EVALUATION COMPLETE")
print("=" * 70)