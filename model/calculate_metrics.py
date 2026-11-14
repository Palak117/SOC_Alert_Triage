import os
import pandas as pd

CANDIDATES = [
    "data/scored/test_validated.csv",
    "data/scored/test_unsupervised_v6_validated.csv",
    "data/scored/test_v6_leakage_reduced_scored.csv",
    "data/scored/final_v6_sih_dashboard_alerts.csv",
]

PATH = None
for candidate in CANDIDATES:
    if os.path.exists(candidate):
        PATH = candidate
        break

if PATH is None:
    raise FileNotFoundError(f"No validated or scored results found among candidates: {CANDIDATES}")

print(f"Loading validated results from: {PATH}")
df = pd.read_csv(PATH, low_memory=False)

# --------------------------------------------------
# Precision@K
# --------------------------------------------------

def precision_at_k(df, k):
    top_k = df.head(k)
    incidents_found = top_k["actual_incident"].sum()
    precision = incidents_found / k
    return incidents_found, precision


# --------------------------------------------------
# Incident Recall
# --------------------------------------------------

def incident_recall_at_k(df, k, total_incidents):
    top_k = df.head(k)
    incidents_found = top_k["actual_incident"].sum()
    recall = incidents_found / total_incidents
    return incidents_found, recall


total_incidents = df["actual_incident"].sum()
total_alerts = len(df)

print("\n==============================")
print("MODEL VALIDATION METRICS")
print("==============================")

print(f"Total alerts     : {total_alerts:,}")
print(f"Total incidents   : {total_incidents:,}")

# Different review sizes
k_values = [100, 500, 1000, 5000, 10000]

print("\n==============================")
print("PRECISION@K")
print("==============================")

for k in k_values:
    found, precision = precision_at_k(df, k)

    print(
        f"Top-{k:<5} | "
        f"Incidents found: {found:<5} | "
        f"Precision: {precision:.4f} "
        f"({precision * 100:.2f}%)"
    )


print("\n==============================")
print("INCIDENT RECALL")
print("==============================")

for k in k_values:
    found, recall = incident_recall_at_k(
        df,
        k,
        total_incidents
    )

    print(
        f"Top-{k:<5} | "
        f"Incidents found: {found:<5} | "
        f"Recall: {recall:.4f} "
        f"({recall * 100:.2f}%)"
    )


# --------------------------------------------------
# Alerts avoided
# --------------------------------------------------

print("\n==============================")
print("ALERTS AVOIDED")
print("==============================")

for k in k_values:
    alerts_avoided = total_alerts - k
    percentage = alerts_avoided / total_alerts

    print(
        f"Review Top-{k:<5} | "
        f"Alerts avoided: {alerts_avoided:,} | "
        f"Reduction: {percentage * 100:.2f}%"
    )


# --------------------------------------------------
# Where are the incidents?
# --------------------------------------------------

incident_rows = df[df["actual_incident"] == True]

print("\n==============================")
print("INCIDENT RANK ANALYSIS")
print("==============================")

print(
    incident_rows["priority_rank"].describe()
)

print("\nFirst 20 actual incidents in ranked queue:")

disp_cols = [
    c for c in [
        "priority_rank",
        "anomaly_score",
        "label_binary",
        "incident_ids",
        "origin",
        "severity"
    ] if c in incident_rows.columns
]
print(
    incident_rows[disp_cols]
    .head(20)
    .to_string(index=False)
)

print("\n==============================")
print("METRIC CALCULATION COMPLETE")
print("==============================")