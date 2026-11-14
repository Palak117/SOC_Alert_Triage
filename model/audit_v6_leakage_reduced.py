from pathlib import Path
import pandas as pd

ROOT = Path(".")
FEATURE_SCRIPT = ROOT / "model/create_unsupervised_features_v6_leakage_reduced.py"
FEATURES = ROOT / "data/unsupervised_features_v6_leakage_reduced/X_train.csv"
REPORT = ROOT / "data/scored/v6_leakage_reduced_feature_audit.txt"

# Fields that require particular scrutiny in an unsupervised alert-ranking pipeline.
sensitive_terms = [
    "label_binary", "label_confidence", "incident_ids",
    "actual_incident", "ground_truth", "suspicion_score",
    "lifecycle_stage", "is_false_positive", "disposition",
    "disposition_category", "status_name", "attack_techniques",
    "attack_tactics", "defense_techniques", "matched_rules"
]

if not FEATURE_SCRIPT.exists():
    raise FileNotFoundError(f"Feature script not found: {FEATURE_SCRIPT}")
if not FEATURES.exists():
    raise FileNotFoundError(f"Training features not found: {FEATURES}")

source = FEATURE_SCRIPT.read_text(encoding="utf-8", errors="replace")
lines = source.splitlines()
feature_names = list(pd.read_csv(FEATURES, nrows=0).columns)

findings = []
for term in sensitive_terms:
    hits = [(i, line.strip()) for i, line in enumerate(lines, 1)
            if term.lower() in line.lower()]
    if hits:
        findings.append((term, hits))

out = []
out.append("LEAKAGE-REDUCED FEATURE PROVENANCE AUDIT")
out.append("=" * 68)
out.append(f"Script reviewed: {FEATURE_SCRIPT}")
out.append(f"Training feature file: {FEATURES}")
out.append(f"Generated model features: {len(feature_names)}")
out.append("")
out.append("GENERATED FEATURES")
out.extend(f"{i:02d}. {name}" for i, name in enumerate(feature_names, 1))
out.append("")
out.append("SENSITIVE-FIELD SOURCE SCAN")
out.append("A match means the term occurs in source text; it does not alone prove leakage.")
out.append("No match is not proof that every transformation is safe.")
out.append("")

if not findings:
    out.append("No searched sensitive terms were found in the feature-generation source.")
else:
    for term, hits in findings:
        out.append(f"\n{term}: {len(hits)} matching source line(s)")
        for line_no, line in hits[:12]:
            out.append(f"  line {line_no}: {line[:240]}")
        if len(hits) > 12:
            out.append(f"  ... {len(hits)-12} additional matching lines")

out.append("")
out.append("KNOWN SAFEGUARDS")
out.append("- The separate feature script removes suspicion_score and lifecycle_stage rarity.")
out.append("- The new model was fitted only on the generated numeric feature matrix.")
out.append("- Incident IDs are used for post-hoc evaluation, not model.fit().")
out.append("- The experiment uses separate files and does not overwrite the original V6 model.")
out.append("")
out.append("LIMITATIONS / REQUIRED MANUAL REVIEW")
out.append("- Review each matching source line and the function that creates its feature.")
out.append("- Verify every feature is available at alert triage time, not only after investigation or closure.")
out.append("- Historical counts and rarity statistics must use only prior alerts or training-derived statistics.")
out.append("- Static text scanning cannot establish full data lineage or prove leakage-free behavior.")
out.append("- Treat this as a leakage-reduced experiment, not a certified leakage-free model.")

REPORT.parent.mkdir(parents=True, exist_ok=True)
REPORT.write_text("\n".join(out), encoding="utf-8")
print("\n".join(out))
print(f"\nAudit saved to: {REPORT}")
