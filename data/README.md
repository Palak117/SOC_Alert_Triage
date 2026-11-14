# SAT-SA Data Architecture & Dataset Guide

**Supervisory Analytics Tool for SOC Assessment (SAT-SA)**  
**Problem Statement:** SIH26157 — NTRO / NCIIPC

---

## 1. Out-of-the-Box Operation

SAT-SA is engineered to operate immediately upon cloning without requiring multi-gigabyte dataset downloads. The repository includes high-performance, compressed Apache Parquet datasets and supervisory metadata summaries:

- `data/scored/dashboard_consolidated.parquet` (54.4 MB): Consolidated 402,335 test alerts with V6 54-feature scores, supervisory context signals, peer audit metrics, and incident alignments.
- `data/scored/dashboard_consolidated_leakage_reduced.parquet` (54.7 MB): Scored alerts under the strict 50-feature leakage-reduced candidate model.
- `data/scored/dashboard_multientity_sample.parquet` (14.8 MB): Multi-entity regulatory evaluation sample representing 4 Critical Sector Entities (Power & Energy, Banking & Financial, Telecom & ISP, Transportation & Rail).
- `data/scored/multientity_supervisory_summary.json`: Multi-CSE statutory governance scorecards, telemetry matrices, cohort robust Z-scores, and regulatory compliance ratings.
- `data/scored/*_summary.csv` and `data/scored/*_incidents.csv`: Exact KPI tables, incident discovery distributions, and review-fraction tradeoff benchmarks.
- `data/soc_features/category_mappings.json`: Categorical encoders for SOC telemetry fields.
- `data/submissions/`: Audit trail and live prediction submissions log.

---

## 2. Raw Training Dataset (Precinct 6)

For researchers and engineers wishing to reproduce model training from scratch, the full raw telemetry dataset is the **Precinct 6 Cybersecurity Dataset** (~343 MB compressed Parquet, expanding to ~4.5 GB of training/testing CSV splits).

### Downloading Raw Data
Run the included download script:
```bash
python download_dataset.py
```
This script downloads `precinct6_cybersecurity.parquet` directly from the official Hugging Face repository (`siddhant-tiwari/precinct6_cybersecurity`).

---

## 3. Data Pipeline & Reproduction Workflow

To re-run the entire pipeline from raw data to final dashboard artifacts:

1. **Split Data (80% Train, 20% Test):**
   ```bash
   python preprocessing/split_data.py
   ```
   Generates `data/train_test/train_80.csv` and `data/train_test/test_20.csv`.

2. **Feature Engineering:**
   - For V6 Baseline (54 features):
     ```bash
     python model/create_unsupervised_features_v6.py
     ```
   - For Leakage-Reduced Candidate (50 features):
     ```bash
     python model/create_unsupervised_features_v6_leakage_reduced.py
     ```

3. **Model Training:**
   - Train V6 Baseline Isolation Forest:
     ```bash
     python model/train_isolation_forest_v6.py
     ```
   - Train Leakage-Reduced Isolation Forest:
     ```bash
     python model/train_isolation_forest_v6_leakage_reduced.py
     ```

4. **Model Scoring & Context Enrichment:**
   ```bash
   python model/score_unsupervised_test_v6.py
   python model/score_v6_leakage_reduced.py
   python model/create_sih_context_layer_v6.py
   python model/add_supervisory_peer_audit_v6.py
   ```

5. **Parquet Consolidation & Multi-Entity Sample Generation:**
   ```bash
   python scratch/run_consolidation.py
   python scratch/build_multientity_data.py
   ```
   Rebuilds `dashboard_consolidated.parquet` and `dashboard_multientity_sample.parquet`.

---

## 4. Evaluation & Verification

To verify evaluation metrics and ground-truth safeguards:
```bash
python model/validate_unsupervised_v6.py
python model/evaluate_v6_leakage_reduced.py
pytest tests/
```
