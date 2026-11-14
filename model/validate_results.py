import pandas as pd
import ast

SCORED_PATH = "data/scored/test_scored.csv"
TEST_PATH = "data/train_test/test_20.csv"

print("Loading scored results...")
scored = pd.read_csv(SCORED_PATH)

print("Loading original test data...")
test = pd.read_csv(TEST_PATH, low_memory=False)

print("\n==============================")
print("VALIDATION")
print("==============================")

print("Scored records :", len(scored))
print("Original test  :", len(test))

# Check that both datasets have the same number of rows
if len(scored) != len(test):
    raise ValueError("Number of rows does not match!")

# Add actual incident information to scored results
scored["incident_ids"] = test["incident_ids"].values
scored["label_binary"] = test["label_binary"].values

# An alert is considered associated with a recorded incident
def has_incident(value):
    try:
        incidents = ast.literal_eval(value)
        return isinstance(incidents, list) and len(incidents) > 0
    except:
        return False

scored["actual_incident"] = scored["incident_ids"].apply(has_incident)

print("\nActual incident distribution:")
print(scored["actual_incident"].value_counts())

print("\nLabel distribution:")
print(scored["label_binary"].value_counts())

print("\n==============================")
print("TOP RANKED ALERTS")
print("==============================")

print(
    scored[
        [
            "priority_rank",
            "anomaly_score",
            "actual_incident",
            "label_binary",
            "incident_ids"
        ]
    ].head(20).to_string(index=False)
)

# Save validation data
output_path = "data/scored/test_validated.csv"
scored.to_csv(output_path, index=False, escapechar="\\")

print("\nSaved:")
print(output_path)

print("\n==============================")
print("VALIDATION PREPARATION COMPLETE")
print("==============================")