
from pathlib import Path

base_dir = Path(__file__).resolve().parent.parent
data_dir = base_dir / "data" / "scored"

print("Project folder:", base_dir)
print("Expected data folder:", data_dir)
print("Data folder exists:", data_dir.exists())

print("\nCSV files found in data/scored:")
if data_dir.exists():
    for file in sorted(data_dir.glob("*.csv")):
        print(" -", file.name)

print("\nChecking expected files:")
expected = [
    "final_v6_sih_dashboard_alerts.csv",
    "final_v6_sih_dashboard_summary.csv",
    "final_v6_sih_dashboard_review_fractions.csv",
    "final_v6_sih_dashboard_incidents.csv",
    "dashboard_consolidated.parquet",
    "dashboard_consolidated_leakage_reduced.parquet",
    "test_v6_leakage_reduced_scored.csv",
]

for name in expected:
    path = data_dir / name
    print(f"{name}: {'FOUND' if path.exists() else 'MISSING'}")
