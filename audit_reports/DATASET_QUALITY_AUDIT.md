# DATASET QUALITY & DATA PIPELINE FORENSIC AUDIT — SAT-SA (SIH26157)

**Audit Date:** 2026-11-14  
**Auditor:** Independent Technical Forensic Audit  
**Scope:** Phase 3 — Complete forensic inspection of all raw, intermediate, feature, scored, consolidated, and submission datasets across `data/`, `preprocessing/`, `model/`, and `backend/`.

---

## 1. Complete Dataset Inventory & Schema Profile

| File Path | Format | Rows | Columns | Purpose & Provenance |
|---|---|---:|---:|---|
| `data/precinct6_cybersecurity.parquet` | Parquet | `2,011,674` | `38` | Raw dataset downloaded from Hugging Face (`WitFoo/precinct6-cybersecurity-dataset`) via `download_dataset.py` |
| `data/train_test/train_80.csv` | CSV | `1,609,339` | `38` | First 80% chronological split (`2024-07-26 11:10:23` to `2024-07-29 19:54:37` UTC) |
| `data/train_test/test_20.csv` | CSV | `402,335` | `38` | Final 20% chronological split (`2024-07-29 19:54:37` to `2024-08-01 06:00:03` UTC; 100% `ORG-0004`) |
| `data/unsupervised_features/X_train_unsupervised_v6.csv` | CSV | `1,609,339` | `54` | Offline V6 training feature matrix (`create_unsupervised_features_v6.py`) |
| `data/unsupervised_features/X_test_unsupervised_v6.csv` | CSV | `402,335` | `55` | Offline V6 test feature matrix (`54` features + `_alert_id`) |
| `data/unsupervised_features/X_train_v6_leakage_reduced.csv` | CSV | `1,609,339` | `50` | Offline Leakage-Reduced training feature matrix (`create_unsupervised_features_v6_leakage_reduced.py`) |
| `data/unsupervised_features/X_test_v6_leakage_reduced.csv` | CSV | `402,335` | `51` | Offline Leakage-Reduced test feature matrix (`50` features + `_alert_id`) |
| `data/scored/dashboard_consolidated.parquet` | Parquet | `402,335` | `95` | Primary dashboard dataset (Baseline V6 scores + context layer + peer audit) |
| `data/scored/dashboard_consolidated_leakage_reduced.parquet` | Parquet | `402,335` | `95` | Candidate dashboard dataset (Leakage-Reduced V6 scores + context layer + peer audit) |
| `data/scored/dashboard_multientity_sample.parquet` | Parquet | `64,968` | `95` | Sampled multi-CSE dataset (`20,000` each for `ORG-0004`, `ORG-0003`, `ORG-0005` + `4,968` for `ORG-0001`); **never loaded by dashboard** |
| `data/scored/multientity_supervisory_summary.json` | JSON | `4 entities` | — | Cross-CSE summary & 8-domain scores loaded by Page 1 and Page 8 |
| `data/scored/final_v6_sih_dashboard_summary.csv` | CSV | `8` | `12` | Top-K evaluation summary (`K = 100..100,000`) for Baseline V6 |
| `data/scored/leakage_reduced_dashboard_summary.csv` | CSV | `8` | `12` | Top-K evaluation summary (`K = 100..100,000`) for Leakage-Reduced V6 |
| `data/scored/final_v6_sih_dashboard_incidents.csv` | CSV | `44` | `5` | Per-incident discovery rank ledger (`44` unique incidents) for Baseline V6 |
| `data/scored/leakage_reduced_dashboard_incidents.csv` | CSV | `44` | `5` | Per-incident discovery rank ledger (`44` unique incidents) for Leakage-Reduced V6 |
| `data/scored/final_v6_sih_dashboard_review_fractions.csv` | CSV | `7` | `4` | Review fraction summary (`0.1%..25%`) for Baseline V6 |
| `data/scored/leakage_reduced_review_fractions.csv` | CSV | `7` | `4` | Review fraction summary (`0.1%..25%`) for Leakage-Reduced V6 |

---

## 2. Raw Dataset (`precinct6_cybersecurity.parquet`) Organization & Label Breakdown

Direct inspection of `data/precinct6_cybersecurity.parquet` (`2,011,674` rows, `38` columns) across its 4 `org_id` segments revealed significant structural and temporal asymmetry:

| `org_id` | Total Rows | % of Dataset | Exact UTC Timestamp Range (`unit="s"`) | Duration | `label_binary == 'benign'` | `label_binary == 'suspicious'` | `label_binary == 'malicious'` | Rows with `incident_ids` | Rows with MITRE Tactics/Tech | Mean `suspicion_score` |
|---|---:|---:|---|---|---:|---:|---:|---:|---:|---:|
| **`ORG-0004`** | `995,985` | `49.51%` | `2024-07-26 11:10:25` $\to$ `2024-08-01 06:00:03` | `138.8 hrs` (`5.78 d`) | `976,694` | `15,115` | `4,176` | `4,176` | `19,291` | `0.4004` |
| **`ORG-0005`** | `576,817` | `28.67%` | `2024-07-26 11:10:40` $\to$ `2024-07-27 06:00:06` | `18.8 hrs` (`0.78 d`) | `481,726` | `91,555` | `3,536` | `3,536` | `95,091` | `2.6517` |
| **`ORG-0003`** | `433,904` | `21.57%` | `2024-07-26 11:10:23` $\to$ `2024-07-27 06:00:04` | `18.8 hrs` (`0.78 d`) | `433,775` | `113` | `16` | `16` | `129` | `0.0080` |
| **`ORG-0001`** | `4,968` | `0.25%` | `2024-07-26 11:10:23` $\to$ `2024-07-27 05:59:43` | `18.8 hrs` (`0.78 d`) | `4,958` | `10` | `0` | `0` | `10` | `0.0322` |
| **TOTAL** | **`2,011,674`** | **`100.00%`** | `2024-07-26 11:10:23` $\to$ `2024-08-01 06:00:03` | `138.8 hrs` | **`1,897,153`** | **`106,793`** | **`7,728`** | **`7,728`** | **`114,521`** | — |

### Key Dataset Findings:
1. **`label_binary` is a 3-Class String Column (`'benign'`, `'suspicious'`, `'malicious'`), Not Binary `0/1`:**
   - Across the entire `2,011,674`-row dataset, `label_binary == 'malicious'` (`7,728` rows) matches `incident_ids != ""` (`7,728` rows) with **100% identity**, and `label_binary.isin(['suspicious', 'malicious'])` (`106,793 + 7,728 = 114,521` rows) matches non-empty MITRE ATT&CK `attack_tactics`/`attack_techniques` (`114,521` rows) with **100% identity**.
2. **Global Chronological Split (`preprocessing/split_data.py`) Puts Only `ORG-0004` in `test_20.csv`:**
   - Because `ORG-0001`, `ORG-0003`, and `ORG-0005` all terminate on `2024-07-27 06:00 UTC`, sorting all `2,011,674` rows globally by timestamp and taking the final 20% (`402,335` rows, `2024-07-29 19:54:37` to `2024-08-01 06:00:03`) places **100% of `ORG-0001`, `ORG-0003`, and `ORG-0005` inside `train_80.csv`** and leaves **only `ORG-0004` in `test_20.csv`**.
   - Consequently, the Isolation Forest was trained on a mixture of 4 organizations (`593,650` rows of `ORG-0004` + `576,817` rows of `ORG-0005` + `433,904` rows of `ORG-0003` + `4,968` rows of `ORG-0001`), while all historical test evaluations (`test_20.csv`) measure performance on a single organization (`ORG-0004`).

---

## 3. Missing-Value & Data-Type Hazards Across Pipeline Stages

### 3.1 Empty Strings (`""`) in Parquet vs. `NaN` in CSV
In `data/precinct6_cybersecurity.parquet`, missing values in string columns are stored as empty strings `""` rather than `null`/`NaN`:

| Organization | Empty `src_ip` (`""`) | Empty `dst_ip` (`""`) | Empty `username` (`""`) | Empty `action` (`""`) | Zero `src_port` (`"0"`) |
|---|---:|---:|---:|---:|---:|
| `ORG-0001` | `1.39%` | `83.96%` | `97.28%` | `19.34%` | `1.39%` |
| `ORG-0003` | `0.15%` | `95.36%` | `99.90%` | `11.81%` | `0.15%` |
| `ORG-0004` | `7.34%` | `64.61%` | `99.13%` | `12.66%` | `20.11%` |
| `ORG-0005` | `19.72%` | `63.61%` | `81.61%` | `15.56%` | `25.12%` |

- **Hazard 1 (`scratch/build_multientity_data.py:97-105`):** When `build_multientity_data.py` reads `precinct6_cybersecurity.parquet` directly via `pd.read_parquet()`, empty strings remain `""` (not `NaN`). Checking `df_clean["src_ip"].isna()` and `df_clean["src_port"] == 0` (when `src_port` is string `"0"`) produces `0` for every row, zeroing out `evidence_gap_rate` for `ORG-0001`, `ORG-0003`, and `ORG-0005`.
- **Hazard 2 (`backend/batch_prediction.py:147-172`):** Conversely, when `pd.read_csv()` reads `test_20.csv` or user-uploaded CSVs, empty strings become `np.nan`. Calling `.astype(str)` before `.fillna("")` converts `np.nan` into the literal string `"nan"`, causing `extract_arrival_time_features()` to treat missing IPs, hosts, usernames, and messages as present!

### 3.2 Unmapped Integer `severity` (`1, 2, 3`) Breaks `critical_missing_context_signal`
- In `precinct6_cybersecurity.parquet` and `test_20.csv`, the raw `severity` column contains integer-coded strings:
  - `'1'`: `384,335` rows (`95.53%`) in `test_20.csv`
  - `'3'`: `16,800` rows (`4.18%`)
  - `'2'`: `1,200` rows (`0.30%`)
- In `model/create_sih_context_layer_v6.py:1098`, `critical_severity_signal` checks:
  ```python
  context["critical_severity_signal"] = context["severity_context"].str.lower().isin(["critical", "high", "4", "5", "sev4", "sev5", "p1", "p2"])
  ```
  Because the raw `severity` values in `test_20.csv` are `'1'`, `'2'`, and `'3'` (none of which are in `["critical", "high", "4", "5", ...]`), **`critical_severity_signal` and `critical_missing_context_signal` evaluate to `False` (`0` rows) across all `402,335` alerts in `dashboard_consolidated.parquet`!**

### 3.3 Four Redundant Timestamp Columns in `dashboard_consolidated.parquet`
`dashboard_consolidated.parquet` (`95` columns) carries **4 separate timestamp columns**:
1. `timestamp` (float Unix epoch seconds, e.g., `1722282877.182`)
2. `event_time` (ISO string)
3. `timestamp_datetime` (datetime64[ns])
4. `Timestamp` (formatted display string)
Meanwhile, `scratch/build_multientity_data.py:194` parses `df["timestamp"]` using `pd.to_datetime(df["timestamp"], errors="coerce")` without `unit="s"`, turning `1722282877` into `1970-01-01 00:00:01.722282877` (`"1970-01-01 to 1970-01-01"` in `multientity_supervisory_summary.json`).
