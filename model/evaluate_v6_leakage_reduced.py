import os
import numpy as np
import pandas as pd

SCORED = "data/scored/test_v6_leakage_reduced_scored.csv"
OUTPUT = "data/scored/v6_leakage_reduced_evaluation.txt"

df = pd.read_csv(SCORED, low_memory=False)

if "incident_ids" not in df.columns:
    raise ValueError("incident_ids is missing; cannot evaluate incident recall.")

def get_incidents(value):
    if pd.isna(value) or str(value).strip() in ("", "[]", "nan", "None"):
        return set()
    import re
    return set(x for x in re.split(r"[,;|]\s*|\s+", str(value).strip(" []'\"")) if x)

incident_sets = df["incident_ids"].apply(get_incidents)
is_incident = incident_sets.apply(bool)
df["_incident"] = is_incident

total = len(df)
incident_alerts = int(is_incident.sum())
all_incidents = set().union(*incident_sets) if total else set()

lines = []
lines.append("LEAKAGE-REDUCED MODEL — POST-HOC EVALUATION")
lines.append("=" * 65)
lines.append(f"Test alerts: {total:,}")
lines.append(f"Incident alerts: {incident_alerts:,}")
lines.append(f"Unique incidents: {len(all_incidents):,}")
lines.append("")
lines.append("TOP-K RANKING")
lines.append(f"{'K':>10} {'Incident alerts':>18} {'Precision@K':>15} {'Unique incidents':>18} {'Unique recall':>15}")

for k in [100, 500, 1000, 5000, 10000, 25000, 50000, 100000]:
    top = df.nsmallest(min(k, total), "priority_rank")
    found = set().union(*incident_sets.loc[top.index]) if len(top) else set()
    count = int(top["_incident"].sum())
    precision = count / len(top) * 100 if len(top) else 0
    recall = len(found) / len(all_incidents) * 100 if all_incidents else 0
    lines.append(f"{k:>10,} {count:>18,} {precision:>14.2f}% {len(found):>18,} {recall:>14.2f}%")

lines.append("")
lines.append("REVIEW EFFORT")
lines.append(f"{'Review %':>10} {'Alerts reviewed':>18} {'Unique incidents':>18} {'Alerts avoided':>17}")
for fraction in [0.001, 0.005, 0.01, 0.02, 0.05, 0.10, 0.25]:
    k = max(1, int(np.ceil(total * fraction)))
    top = df.nsmallest(k, "priority_rank")
    found = set().union(*incident_sets.loc[top.index]) if len(top) else set()
    lines.append(f"{fraction*100:>9.1f}% {k:>18,} {len(found):>18,} {(total-k)/total*100:>16.2f}%")

report = "\n".join(lines)
os.makedirs("data/scored", exist_ok=True)
with open(OUTPUT, "w", encoding="utf-8") as f:
    f.write(report)

print(report)
print("\nSaved report:", OUTPUT)
