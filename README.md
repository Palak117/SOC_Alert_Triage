# Supervisory Analytics Tool for SOC Assessment (SAT-SA)

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.42+-red.svg)](https://streamlit.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests: 45 Passed](https://img.shields.io/badge/Pytest-45%20Passed-brightgreen.svg)](tests/)
[![SIH Problem](https://img.shields.io/badge/SIH%20Problem-SIH26157-orange.svg)]()
[![Organization](https://img.shields.io/badge/Organization-NTRO%20%2F%20NCIIPC-blueviolet.svg)]()

> **SIH Problem Statement:** SIH26157  
> **Organization:** National Technical Research Organisation (NTRO) / National Critical Information Infrastructure Protection Centre (NCIIPC)  
> **System Name:** Supervisory Analytics Tool for SOC Assessment (SAT-SA)

---

## 1. Executive Summary

**Supervisory Analytics Tool for SOC Assessment (SAT-SA)** is an air-gapped, sovereign, high-throughput supervisory analytics platform designed to solve the critical alert fatigue crisis in Security Operations Centres (SOCs) protecting Critical Sector Entities (CSEs).

SAT-SA provides dual-layer intelligence:
1. **Machine Learning Anomaly Prioritization:** High-speed unsupervised anomaly detection (Isolation Forest) prioritizing security-critical alerts with **zero data leakage**, achieving **79.00% Top-100 Precision**, **94.28% Top-5,000 Incident Recall**, and **100.00% Unique Incident Discovery (44/44 incidents captured)** within the top 2% review budget.
2. **Supervisory Governance & Regulatory Oversight:** Cross-entity peer benchmarking, statutory 8-domain compliance scoring, telemetry gap detection, and automated supervisory dossier generation across multiple Critical Sector Entities.

---

## 2. Key Architecture & Capabilities

### A. Dual Machine Learning Pipelines
- **V6 Baseline Model (54 Features):** Production baseline with high-fidelity behavioral, frequency, and SOC categorical features.
- **Leakage-Reduced Candidate Model (50 Features):** Strictly audited variant removing all high-cardinality and potential post-hoc identifiers (`alert_category`, `rule_name`, `entity_id`, etc.) to eliminate target leakage and overfitting risks.
- **Rarity Priors & Empirical Frequency:** Robust Laplace-smoothed frequency tables precalculated strictly from historical training distributions.

### B. Eight Mission Dashboard Pages
The Streamlit application delivers 8 specialized operational and supervisory views:
1. **Executive Mission Overview:** Real-time alert volume, triage velocity, critical incident discovery KPIs, and multi-CSE entity scoping.
2. **Operational Priority Queue:** Actionable alert investigation feed with multi-factor filtering, priority tagging, and CSV export.
3. **Incident Discovery & Recall:** Tradeoff curves between analyst review effort and incident recall, proving 100% incident discovery in the top 2% review budget.
4. **Deep Alert Investigation:** Single-alert forensic viewer with telemetry evidence breakdown, Mitre ATT&CK alignment, and analyst notes.
5. **Context & Telemetry Gaps:** Identification of investigation-without-evidence, low telemetry visibility, repetitive investigations, and execution blind spots.
6. **Batch Alert Scoring & Triage:** High-throughput batch inference pipeline supporting CSV and JSON uploads with cryptographic duplicate hashing and submission manifest audit trails.
7. **Live Alert Prediction Engine:** Real-time single-alert triage engine with automatic field sanitization, ground-truth label stripping, and interactive scoring.
8. **CSE Regulatory Assessment:** Cross-entity compliance scorecards across 8 statutory domains, cohort robust Z-scores, telemetry coverage heatmaps, and downloadable supervisory dossiers.

### C. Multi-Entity Supervisory Governance
Simulates and evaluates 4 Critical Sector Entities (CSEs):
- **ORG-0001:** Northern Grid Regional Load Despatch Centre (Power & Energy)
- **ORG-0003:** State Financial Clearing Corporation (Banking & Financial)
- **ORG-0004:** National Backbone Telecom Exchange (Telecom & ISP)
- **ORG-0005:** Western Railway Traffic Control Network (Transportation & Rail)

---

## 3. Verified Performance & Evaluation Metrics

Evaluated on the full held-out test split of **402,335 alerts** containing **3,113 incident alerts** across **44 unique incidents**:

| Review Cutoff | Incident Alerts Captured | Triage Precision | Incident Recall | Unique Incidents Discovered | Cumulative Workload Avoided |
|:---|---:|---:|---:|---:|---:|
| **Top 100** | 79 | **79.00%** | 2.54% | **24 / 44** (54.5%) | 99.98% |
| **Top 500** | 414 | **82.80%** | 13.30% | **33 / 44** (75.0%) | 99.88% |
| **Top 1,000** | 774 | **77.40%** | 24.86% | **38 / 44** (86.4%) | 99.75% |
| **Top 5,000** | 2,935 | **58.70%** | 94.28% | **44 / 44** (100.0%) | 98.76% |
| **Top 10,000** | 3,075 | **30.75%** | 98.78% | **44 / 44** (100.0%) | 97.51% |
| **Top 25,000** | 3,113 | **12.45%** | **100.00%** | **44 / 44** (100.0%) | 93.79% |

*Key Takeaway: Security analysts reviewing only the top 2.0% of alerts (8,046 alerts) discover 100% of all confirmed security incidents, reducing alert fatigue by 98.0%.*

---

## Dataset Source & Attribution

SAT-SA is evaluated using the **WitFoo Precinct6 Cybersecurity Dataset**, an open corpus of cybersecurity telemetry and Security Operations Center (SOC) events.

* **Dataset Name:** [WitFoo Precinct6 Cybersecurity Dataset](https://huggingface.co/datasets/witfoo/precinct6-cybersecurity)
* **Dataset Publisher:** WitFoo
* **Official Repository:** [https://huggingface.co/datasets/witfoo/precinct6-cybersecurity](https://huggingface.co/datasets/witfoo/precinct6-cybersecurity)
* **License:** Apache License 2.0 (as stated by the dataset publisher)
* **Dataset Size:** 2,011,674 security events, as documented by the source
* **Description:** Diverse cybersecurity telemetry and SOC security events across multiple infrastructure pipelines, security appliances, network flows, and endpoint sensor feeds.

### Evaluation Scoping in SAT-SA
* **Held-Out Evaluation Entity:** SAT-SA utilizes **ORG-0004** (Defense & National Telecommunications) as its strictly held-out evaluation entity, representing 402,335 alerts in the final 20% chronological test partition (containing 3,113 incident-associated alerts linked to 44 confirmed incidents).
* **Framework Utilization:** The dataset is used for alert analysis, unsupervised Isolation Forest anomaly detection, operational triage prioritization, and empirical recall/precision evaluation.
* **Provenance & Mirror Verification:** The primary dataset download pipeline ([download_dataset.py](download_dataset.py)) pulls the `signals` partition directly from the official repository `witfoo/precinct6-cybersecurity` (with historical repository documentation also noting mirror availability at `siddhant-tiwari/precinct6_cybersecurity`). Pre-consolidated, compressed test parquets are bundled in `data/scored/` for immediate out-of-the-box execution.

---

## 4. Repository Structure

```text
SOC_Alert_Triage/
├── dashboard/                     # Streamlit User Interface
│   ├── app.py                     # Main dashboard entrypoint & router
│   ├── check_alerts.py            # Dashboard healthcheck & validation script
│   ├── ui_theme.py                # Sovereign styling, zero CDN fonts, strict CSS
│   └── views/                     # Eight individual dashboard page modules
│       ├── overview.py            # 1. Executive Mission Overview
│       ├── priority_queue.py      # 2. Priority Queue
│       ├── incident_discovery.py  # 3. Incident Discovery & Tradeoff
│       ├── alert_investigation.py # 4. Alert Investigation & Forensics
│       ├── context_gaps.py        # 5. Context & Telemetry Gaps
│       ├── batch_prediction.py    # 6. Batch Inference & Queue Ingestion
│       ├── live_prediction.py     # 7. Live Single-Alert Scoring Engine
│       └── regulatory_assessment.py # 8. CSE Regulatory & Multi-Entity Assessment
├── backend/                       # Core Backend Services & Business Logic
│   ├── config.py                  # Path configuration & environment constants
│   ├── data_service.py            # Fast Parquet data access & query engine
│   ├── model_service.py           # Isolation Forest inference & score mapping
│   ├── evaluation_service.py      # Dual ground-truth ranking evaluation metrics
│   ├── batch_prediction.py        # Batch scoring, deduplication & audit trail
│   ├── live_prediction.py         # Real-time inference & validation
│   └── multientity_service.py     # Regulatory compliance, Z-scores & dossier export
├── model/                         # Machine Learning Pipeline & Artifacts
│   ├── isolation_forest_unsupervised_v6.pkl      # Production V6 Model (300 estimators)
│   ├── isolation_forest_v6_leakage_reduced.pkl   # Leakage-Reduced Model (300 estimators)
│   ├── v6_rarity_priors.json                     # Precomputed Laplace rarity priors
│   ├── train_isolation_forest_v6.py              # Baseline training pipeline
│   ├── train_isolation_forest_v6_leakage_reduced.py # Leakage-reduced training pipeline
│   ├── create_unsupervised_features_v6.py        # 54-feature engineering pipeline
│   ├── create_unsupervised_features_v6_leakage_reduced.py # 50-feature engineering pipeline
│   ├── score_unsupervised_test_v6.py             # Inference pipeline
│   └── validate_unsupervised_v6.py               # Rigorous 10-point audit validator
├── data/                          # Bundled Datasets & Metadata
│   ├── README.md                  # Dataset documentation & reproduction guide
│   ├── scored/                    # Consolidated parquets & evaluation summaries
│   │   ├── dashboard_consolidated.parquet
│   │   ├── dashboard_consolidated_leakage_reduced.parquet
│   │   ├── dashboard_multientity_sample.parquet
│   │   └── multientity_supervisory_summary.json
│   ├── soc_features/              # Categorical encoders
│   └── submissions/               # Audit manifests & prediction logs
├── tests/                         # Comprehensive Automated Test Suite (Pytest)
│   ├── test_batch_prediction.py   # Batch processing & schema validation tests
│   ├── test_dashboard_app.py      # Streamlit AppTest page switching tests
│   ├── test_data_service.py       # Data querying & filtering tests
│   ├── test_evaluation.py         # Evaluation logic & metric tests
│   ├── test_live_prediction.py    # Live inference & label stripping tests
│   ├── test_model_pipeline.py     # Model inference & integrity tests
│   ├── test_multientity.py        # Regulatory assessment & dossier tests
│   └── test_regression_audit_fixes.py # 14-phase forensic audit regression tests
├── audit_reports/                 # Independent 14-Phase Forensic Audit Reports
├── requirements.txt               # Locked, verified dependencies
└── pytest.ini                     # Pytest configuration
```

---

## 5. Quick Start & Installation

### Step 1: Clone Repository
```bash
git clone https://github.com/Palak117/SOC_Alert_Triage.git
cd SOC_Alert_Triage
```

### Step 2: Set Up Python Virtual Environment
Requires **Python 3.10+**:
```bash
# Windows
python -m venv .venv
.venv\Scripts\activate

# Linux / macOS
python3 -m venv .venv
source .venv/bin/activate
```

### Step 3: Install Verified Dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### Step 4: Run Automated Tests
Verify all 45 automated tests pass:
```bash
pytest
```
*Expected: `45 passed in ~36s`*

### Step 5: Launch Streamlit Dashboard
```bash
streamlit run dashboard/app.py
```
Open your browser at `http://localhost:8501`.

---

## 6. Raw Data Reproduction (Optional)

SAT-SA comes with all necessary pre-consolidated datasets bundled for instant execution. To reproduce the raw dataset from scratch:

```bash
# 1. Download raw Precinct 6 dataset from Hugging Face
python download_dataset.py

# 2. Split into 80% train and 20% test
python preprocessing/split_data.py

# 3. Generate unsupervised features
python model/create_unsupervised_features_v6.py

# 4. Train Isolation Forest model
python model/train_isolation_forest_v6.py

# 5. Score test dataset
python model/score_unsupervised_test_v6.py

# 6. Rebuild consolidated parquets
python scratch/run_consolidation.py
python scratch/build_multientity_data.py
```

---

## 7. Security, Sovereignty & Compliance Safeguards

- **Strict Ground-Truth Isolation:** Target labels (`incident_alert_flag`, `incident_id`) are physically excluded from feature engineering and inference, and only used for post-hoc validation.
- **Air-Gapped Sovereign Design:** Zero external Google Fonts or CDN dependencies. All UI fonts fallback to standard system typography (`Segoe UI`, system sans-serif).
- **Stored XSS Prevention:** All user-supplied fields and external parameters rendered in HTML are strictly sanitized via `html.escape()`.
- **Zero Secrets / Credentials:** Strict `.gitignore` policy preventing credentials, `.env` files, or proprietary logs from exposure.

---

## 8. License & Acknowledgements

Developed for **Smart India Hackathon (SIH 2026)** under Problem Statement **SIH26157** for **NTRO / NCIIPC**.

Released under the **MIT License**.
