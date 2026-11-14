# MACHINE LEARNING, MODEL & INFERENCE FORENSIC AUDIT — SAT-SA (SIH26157)

**Audit Date:** 2026-11-14  
**Auditor:** Independent Technical Forensic Audit  
**Scope:** Phases 4 and 8 — Forensic inspection of all 9 model artifacts in `model/*.pkl`, training and feature-engineering scripts (`model/create_unsupervised_features_v6*.py`, `model/train_isolation_forest_v6*.py`), independent recalculation of all ranking and classification metrics on `test_20.csv` ($N = 402,335$), and audit of live/batch inference (`backend/batch_prediction.py`, `backend/live_prediction.py`).

---

## 1. Inventory of All Saved Model Artifacts (`model/*.pkl`)

All 9 serialized scikit-learn `IsolationForest` artifacts in `model/` were loaded via `joblib` and inspected directly:

| Artifact Filename | Size (Bytes) | `n_features_in_` | `n_estimators` | `max_samples` | `contamination` | `random_state` | `offset_` | Status in Project |
|---|---:|---:|---:|---|---|---:|---:|---|
| `isolation_forest_unsupervised_v6.pkl` | `2,994,929` | **54** | `300` | `256` | `'auto'` (`0.02`) | `42` | `-0.580484` | **Active Primary Model (Baseline V6)** |
| `isolation_forest_v6_leakage_reduced.pkl` | `2,994,769` | **50** | `300` | `256` | `'auto'` (`0.02`) | `42` | `-0.574471` | **Active Candidate Model (Leakage-Reduced V6)** |
| `isolation_forest_unsupervised_v5.pkl` | `2,953,241` | `53` | `300` | `256` | `'auto'` | `42` | `-0.500000` | Legacy Historical Artifact |
| `isolation_forest_unsupervised_v4.pkl` | `2,894,793` | `46` | `300` | `256` | `'auto'` | `42` | `-0.500000` | Legacy Historical Artifact |
| `isolation_forest_unsupervised_v3.pkl` | `2,882,505` | `46` | `300` | `256` | `'auto'` | `42` | `-0.500000` | Legacy Historical Artifact |
| `isolation_forest_unsupervised_v2.pkl` | `2,849,737` | `41` | `300` | `256` | `'auto'` | `42` | `-0.500000` | Legacy Historical Artifact |
| `isolation_forest_behavioral.pkl` | `1,355,609` | `19` | `200` | `256` | `'auto'` | `42` | `-0.500000` | Legacy Historical Artifact |
| `isolation_forest_soc.pkl` | `1,310,553` | `18` | `200` | `256` | `'auto'` | `42` | `-0.500000` | Legacy Historical Artifact |
| `isolation_forest.pkl` | `1,568,401` | `776` | `200` | `256` | `'auto'` | `42` | `-0.500000` | Initial Prototype Artifact |

---

## 2. Feature Engineering & Target Proxy Leakage Audit

### 2.1 Ground-Truth Exclusion vs. Proxy Leakage (`suspicion_score` Correlation $r = 0.9618$)
- **Direct Ground-Truth Exclusion (VERIFIED):** Neither `isolation_forest_unsupervised_v6.pkl` (54 features) nor `isolation_forest_v6_leakage_reduced.pkl` (50 features) includes direct label columns (`incident_ids`, `actual_incident`, `label_binary`, `label_confidence`, `attack_tactics`, `attack_techniques`).
- **Critical Proxy Leakage in Baseline V6 (`isolation_forest_unsupervised_v6.pkl`):**
  - The 54-feature Baseline V6 model includes 4 features that were removed in the 50-feature Leakage-Reduced model (`model/create_unsupervised_features_v6_leakage_reduced.py`):
    1. `suspicion_score` (WitFoo vendor-assigned suspicion score)
    2. `lifecycle_stage_rarity` (derived from `lifecycle_stage`, which records post-triage workflow states such as `complete-mission`)
    3. `message_length_rarity`
    4. `message_word_count_rarity`
  - **Independent Correlation Verification on `test_20.csv` ($N = 402,335$):**
    - Pearson correlation between `suspicion_score` and `actual_incident` (`3,113` confirmed incident alerts): **`r = 0.9618`**!
    - Pearson correlation between `suspicion_score` and `security_relevant` (`13,390` alerts): **`r = 0.4577`**.
    - Pearson correlation between `suspicion_score` and V6 Baseline `anomaly_score`: **`r = 0.3278`**.
- **Forensic Conclusion:** `suspicion_score` is an almost-exact linear proxy (`r = 0.9618`) for `actual_incident` in the WitFoo dataset. Including `suspicion_score` in the 54-feature V6 Baseline model explains why its Top-100 Incident Precision is `79.0%` (`24/44` unique incidents) compared to `29.0%` (`5/44` unique incidents) when `suspicion_score` and `lifecycle_stage_rarity` are removed in the 50-feature Leakage-Reduced model.

---

## 3. Independent Recalculation of Model Performance on `test_20.csv` ($N = 402,335$)

All metrics below were recalculated directly from `data/scored/dashboard_consolidated.parquet`, `data/scored/dashboard_consolidated_leakage_reduced.parquet`, and `data/train_test/test_20.csv`.

### 3.1 Ground-Truth Provenance Verification
In `test_20.csv` (`402,335` rows, 100% belonging to `ORG-0004` from `2024-07-29 19:54:37` to `2024-08-01 06:00:03` UTC):
- `label_binary` contains **3 string classes** in the raw WitFoo dataset:
  - `'benign'`: **`388,945`** alerts (`96.67%`)
  - `'suspicious'`: **`10,277`** alerts (`2.55%`)
  - `'malicious'`: **`3,113`** alerts (`0.77%`)
- **Layer 1 — Confirmed Incident Alerts (`actual_incident == True`):** Exactly **`3,113` alerts** (`0.7737%`), identical to `label_binary == 'malicious'`, spanning **`44` unique `incident_ids`**.
- **Layer 2 — Security-Relevant Alerts (`security_relevant == True`):** Defined as `actual_incident == True` OR non-empty MITRE ATT&CK `attack_tactics`/`attack_techniques`. All `3,113` confirmed incident alerts also carry MITRE tags, and all `10,277` `'suspicious'` alerts carry MITRE tags (`3,113 + 10,277 = 13,390`, `3.3281%`). Thus, the `13,390` security-relevant label count is **100% genuine and verified** from raw WitFoo fields (`label_binary != 'benign'`).

---

### 3.2 Ranking & Triage Performance: Baseline V6 (54 Features) vs. Leakage-Reduced V6 (50 Features) vs. Chronological Baseline

| Review Horizon ($K$) | Review % | Alerts Avoided (Workload Red. %) | Model / Baseline | Confirmed Incident Alerts Found (of 3,113) | Incident Precision@K | Incident Alert Recall@K | Unique Incidents Found (of 44) | Unique Incident Recall@K | Security-Relevant Alerts Found (of 13,390) | Security-Relevant Precision@K | Security-Relevant Recall@K |
|---:|---:|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| **100** | `0.025%` | `402,235` (`99.98%`) | **V6 Baseline (54 feat)**<br>**Leakage-Reduced (50 feat)**<br>*Chronological Baseline* | `79`<br>`29`<br>*`0`* | **`79.00%`**<br>**`29.00%`**<br>*`0.00%`* | `2.54%`<br>`0.93%`<br>*`0.00%`* | **`24 / 44`**<br>**`5 / 44`**<br>*`0 / 44`* | **`54.55%`**<br>**`11.36%`**<br>*`0.00%`* | `99`<br>`97`<br>*`3`* | **`99.00%`**<br>**`97.00%`**<br>*`3.00%`* | `0.74%`<br>`0.72%`<br>*`0.02%`* |
| **500** | `0.124%` | `401,835` (`99.88%`) | **V6 Baseline (54 feat)**<br>**Leakage-Reduced (50 feat)**<br>*Chronological Baseline* | `414`<br>`165`<br>*`4`* | **`82.80%`**<br>**`33.00%`**<br>*`0.80%`* | `13.30%`<br>`5.30%`<br>*`0.13%`* | **`33 / 44`**<br>**`13 / 44`**<br>*`2 / 44`* | **`75.00%`**<br>**`29.55%`**<br>*`4.55%`* | `492`<br>`482`<br>*`17`* | **`98.40%`**<br>**`96.40%`**<br>*`3.40%`* | `3.67%`<br>`3.60%`<br>*`0.13%`* |
| **1,000** | `0.249%` | `401,335` (`99.75%`) | **V6 Baseline (54 feat)**<br>**Leakage-Reduced (50 feat)**<br>*Chronological Baseline* | `774`<br>`329`<br>*`8`* | **`77.40%`**<br>**`32.90%`**<br>*`0.80%`* | `24.86%`<br>`10.57%`<br>*`0.26%`* | **`38 / 44`**<br>**`22 / 44`**<br>*`5 / 44`* | **`86.36%`**<br>**`50.00%`**<br>*`11.36%`* | `975`<br>`980`<br>*`35`* | **`97.50%`**<br>**`98.00%`**<br>*`3.50%`* | `7.28%`<br>`7.32%`<br>*`0.26%`* |
| **5,000** | `1.243%` | `397,335` (`98.76%`) | **V6 Baseline (54 feat)**<br>**Leakage-Reduced (50 feat)**<br>*Chronological Baseline* | `2,935`<br>`1,221`<br>*`37`* | **`58.70%`**<br>**`24.42%`**<br>*`0.74%`* | `94.28%`<br>`39.22%`<br>*`1.19%`* | **`44 / 44`**<br>**`34 / 44`**<br>*`12 / 44`* | **`100.00%`**<br>**`77.27%`**<br>*`27.27%`* | `4,874`<br>`4,922`<br>*`167`* | **`97.48%`**<br>**`98.44%`**<br>*`3.34%`* | `36.40%`<br>`36.76%`<br>*`1.25%`* |
| **10,000** | `2.485%` | `392,335` (`97.51%`) | **V6 Baseline (54 feat)**<br>**Leakage-Reduced (50 feat)**<br>*Chronological Baseline* | `3,075`<br>`2,537`<br>*`84`* | **`30.75%`**<br>**`25.37%`**<br>*`0.84%`* | `98.78%`<br>`81.50%`<br>*`2.70%`* | **`44 / 44`**<br>**`39 / 44`**<br>*`14 / 44`* | **`100.00%`**<br>**`88.64%`**<br>*`31.82%`* | `9,858`<br>`9,890`<br>*`347`* | **`98.58%`**<br>**`98.90%`**<br>*`3.47%`* | `73.62%`<br>`73.86%`<br>*`2.59%`* |
| **25,000** | `6.214%` | `377,335` (`93.79%`) | **V6 Baseline (54 feat)**<br>**Leakage-Reduced (50 feat)**<br>*Chronological Baseline* | `3,113`<br>`3,113`<br>*`202`* | **`12.45%`**<br>**`12.45%`**<br>*`0.81%`* | **`100.00%`**<br>**`100.00%`**<br>*`6.49%`* | **`44 / 44`**<br>**`44 / 44`**<br>*`21 / 44`* | **`100.00%`**<br>**`100.00%`**<br>*`47.73%`* | `13,387`<br>`13,387`<br>*`847`* | **`53.55%`**<br>**`53.55%`**<br>*`3.39%`* | `99.98%`<br>`99.98%`<br>*`6.33%`* |
| **50,000** | `12.427%` | `352,335` (`87.57%`) | **V6 Baseline (54 feat)**<br>**Leakage-Reduced (50 feat)**<br>*Chronological Baseline* | `3,113`<br>`3,113`<br>*`372`* | **`6.23%`**<br>**`6.23%`**<br>*`0.74%`* | **`100.00%`**<br>**`100.00%`**<br>*`11.95%`* | **`44 / 44`**<br>**`44 / 44`**<br>*`28 / 44`* | **`100.00%`**<br>**`100.00%`**<br>*`63.64%`* | `13,390`<br>`13,390`<br>*`1,636`* | **`26.78%`**<br>**`26.78%`**<br>*`3.27%`* | **`100.00%`**<br>**`100.00%`**<br>*`12.22%`* |

#### Key Forensic Takeaways on Ranking Performance:
1. **Both models achieve 97%–99% Security-Relevant Precision across the Top 10,000 alerts** and capture **100% of all 3,113 confirmed incident alerts and all 44 unique incidents within the Top 25,000 alerts** (`6.21%` of dataset, `93.79%` workload reduction).
2. **At tight review budgets ($K = 100$ to $K = 5,000$), the 54-feature Baseline V6 model's superior incident recall (`100%` of 44 unique incidents at Top 5,000 vs. `77.27%` [34/44] for Leakage-Reduced) is directly driven by `suspicion_score` (`r = 0.9618` with `actual_incident`).** In the Leakage-Reduced model (without `suspicion_score`), `'suspicious'` MITRE alerts and `'malicious'` incident alerts rank together based on structural/behavioral rarity, so discovering all 44 unique incidents requires reviewing up to Rank `14,625` (`3.63%` of the queue) instead of Rank `4,955` (`1.23%` of the queue).

---

### 3.3 Binary Classification Metrics Across Thresholds ($N = 402,335$)

Because Isolation Forest is an unsupervised anomaly ranking algorithm, binary classification metrics depend entirely on the chosen decision threshold and ground-truth definition:

| Model | Decision Threshold | Ground-Truth Definition | TP | FP | FN | TN | Accuracy | Precision | Recall | F1-Score |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| **V6 Baseline (54 feat)** | **Top 1% (`K = 4,023`)** | Confirmed Incident (`3,113`)<br>Security-Relevant (`13,390`) | `2,694`<br>`3,913` | `1,329`<br>`110` | `419`<br>`9,477` | `397,893`<br>`388,835` | `99.57%`<br>`97.62%` | `66.96%`<br>`97.27%` | `86.54%`<br>`29.22%` | **`75.50%`**<br>`44.94%` |
| **V6 Baseline (54 feat)** | **Top 5% (`K = 20,116`)** | Confirmed Incident (`3,113`)<br>Security-Relevant (`13,390`) | `3,113`<br>`13,342` | `17,003`<br>`6,774` | `0`<br>`48` | `382,219`<br>`382,171` | `95.77%`<br>`98.30%` | `15.48%`<br>`66.33%` | `100.00%`<br>`99.64%` | `26.80%`<br>**`79.64%`** |
| **V6 Baseline (54 feat)** | **Top 10% (`K = 40,233`)** | Confirmed Incident (`3,113`)<br>Security-Relevant (`13,390`) | `3,113`<br>`13,390` | `37,120`<br>`26,843` | `0`<br>`0` | `362,102`<br>`362,102` | `90.77%`<br>`93.33%` | `7.74%`<br>`33.28%` | `100.00%`<br>`100.00%` | `14.36%`<br>`49.94%` |
| **V6 Baseline (54 feat)** | **Top 20% (`K = 80,467`)** | Confirmed Incident (`3,113`)<br>Security-Relevant (`13,390`) | `3,113`<br>`13,390` | `77,354`<br>`67,077` | `0`<br>`0` | `321,868`<br>`321,868` | `80.77%`<br>`83.33%` | `3.87%`<br>`16.64%` | `100.00%`<br>`100.00%` | `7.45%`<br>`28.53%` |
| **V6 Baseline (54 feat)** | **`anomaly_score > 0` (`35,554` pos)** | Confirmed Incident (`3,113`)<br>Security-Relevant (`13,390`) | `3,113`<br>`13,390` | `32,441`<br>`22,164` | `0`<br>`0` | `366,781`<br>`366,781` | `91.94%`<br>`94.49%` | `8.76%`<br>`37.66%` | `100.00%`<br>`100.00%` | `16.10%`<br>`54.72%` |
| **Leakage-Reduced (50 feat)** | **Top 1% (`K = 4,023`)** | Confirmed Incident (`3,113`)<br>Security-Relevant (`13,390`) | `992`<br>`3,949` | `3,031`<br>`74` | `2,121`<br>`9,441` | `396,191`<br>`388,871` | `98.72%`<br>`97.64%` | `24.66%`<br>`98.16%` | `31.87%`<br>`29.49%` | `27.80%`<br>`45.36%` |
| **Leakage-Reduced (50 feat)** | **Top 5% (`K = 20,116`)** | Confirmed Incident (`3,113`)<br>Security-Relevant (`13,390`) | `3,104`<br>`13,353` | `17,012`<br>`6,763` | `9`<br>`37` | `382,210`<br>`382,182` | `95.77%`<br>`98.31%` | `15.43%`<br>`66.38%` | `99.71%`<br>`99.72%` | `26.73%`<br>**`79.71%`** |
| **Leakage-Reduced (50 feat)** | **`anomaly_score > 0` (`36,142` pos)** | Confirmed Incident (`3,113`)<br>Security-Relevant (`13,390`) | `3,113`<br>`13,390` | `33,029`<br>`22,752` | `0`<br>`0` | `366,193`<br>`366,193` | `91.79%`<br>`94.35%` | `8.61%`<br>`37.05%` | `100.00%`<br>`100.00%` | `15.86%`<br>`54.07%` |

---

## 4. Phase 8 — Forensic Audit of Live & Batch Inference (`backend/batch_prediction.py` & `backend/live_prediction.py`)

### 4.1 CRITICAL DEFECT: Severe Training-vs-Inference Feature Mismatch (`backend/batch_prediction.py:93-181`)
Both `process_new_submission()` (`backend/batch_prediction.py`) and `predict_single_alert()` (`backend/live_prediction.py`) call `extract_arrival_time_features(raw_df, expected_features)` to build the feature vector fed into `model.decision_function()`.

When we tested `extract_arrival_time_features()` on the **first 100 rows of `test_20.csv`** and compared its output against the actual offline feature matrix `data/unsupervised_features/X_test_unsupervised_v6.csv` for the exact same 100 rows:
- **26 out of 50 features differed** between the offline pipeline and `extract_arrival_time_features()`!
- The offline pipeline produced a mean anomaly score of **`-0.0546`** (correctly classifying most alerts as normal background traffic), whereas `extract_arrival_time_features()` shifted the mean anomaly score to **`+0.0749`** (**MAE = `0.1295`**).

#### Breakdown of the 6 Feature Engineering Bugs in `extract_arrival_time_features()` (`backend/batch_prediction.py:132-178`):

1. **23 of 50 Features (27 of 54 in Baseline V6) Are Hardcoded to `0.0` (`lines 175-177`):**
   - `for f in expected_features: if f not in features_df.columns: features_df[f] = 0.0`
   - **All 7 static rarity features** (`pipeline_rarity`, `product_name_rarity`, `vendor_name_rarity`, `message_type_rarity`, `stream_name_rarity`, `action_rarity`, `severity_rarity`) and **both composite rarity features** (`network_behavior_rarity`, `high_level_behavior_rarity`) are hardcoded to **`0.0`** because the training rarity lookup tables from `train_80.csv` were never saved to disk!
   - **All 14 causal historical frequency features** (`src_ip_previous_count`, `src_ip_first_seen`, `src_host_previous_count`, `src_host_first_seen`, `username_previous_count`, `username_first_seen`, `product_name_previous_count`, `product_name_first_seen`, `message_type_previous_count`, `message_type_first_seen`, `pipeline_previous_count`, `pipeline_first_seen`, `behavior_previous_count`, `behavior_first_seen`) are hardcoded to **`0.0`**. Note that `previous_count == 0` AND `first_seen == 0` is **mathematically impossible** in training (`create_unsupervised_features_v6.py:553`), where `previous_count == 0` always implies `first_seen == 1`.
   - In Baseline V6, `suspicion_score`, `lifecycle_stage_rarity`, `message_length_rarity`, and `message_word_count_rarity` are also set to `0.0`.

2. **`.astype(str)` Before `.fillna("")` Turns Missing CSV Values (`NaN`) into `"nan"` (`lines 147-172`):**
   - Lines `147-150`: `(df["src_ip"] ...).astype(str).str.strip().ne("").astype(int)`. When `df["src_ip"]` is `np.nan` (from `pd.read_csv`), `.astype(str)` converts `np.nan` to `"nan"`, which is non-empty! Thus every missing IP/host in a CSV upload gets `has_src_ip = 1`, `has_dst_ip = 1`, `has_dst_host = 1`!
   - Lines `170-172`: `user = (df["username"] ...).astype(str).fillna("")`. Calling `.astype(str)` before `.fillna("")` converts `np.nan` to `"nan"`, falsely setting `has_username = 1` and `username_length = 3` for every missing username!
   - Lines `159-161`: `msg = msg.astype(str).fillna("")` converts missing messages into `"nan"` (`message_length = 3`, `message_word_count = 1`).

3. **`src_port_privileged` and `dst_port_privileged` Invert Missing Ports (`lines 143-144`):**
   - Training (`create_unsupervised_features_v6.py:648-659`): `((src_port > 0) & (src_port < 1024)).astype(int)` (`0` when port is `0`/missing).
   - Inference (`batch_prediction.py:143-144`): `(src_p < 1024).astype(int)` (sets **`1`** when port is `0`/missing!).

4. **`src_port_category` and `dst_port_category` Use Binary `0/1` Instead of `0..3` (`lines 139-140`):**
   - Training (`lines 99-125`): `0` (`<=0`), `1` (`<1024`), `2` (`<49152`), `3` (`>=49152`).
   - Inference (`batch_prediction.py:139-140`): `(src_p > 1024).astype(int)` (`0` or `1` only).

5. **`protocol_category` Uses Raw Protocol Number Instead of `{0, 1, 6, 17}` (`line 141`):**
   - Training (`lines 132-156`): Keeps `{1, 6, 17}` and maps all other protocols to `0`.
   - Inference (`batch_prediction.py:141`): `features_df["protocol_category"] = proto` (unmapped).

6. **`message_size_bucket` Uses Sample-Relative `pd.qcut` Instead of Fixed Thresholds (`line 165`):**
   - Training (`lines 163-188`): Fixed character thresholds `<=0 -> 0`, `<=100 -> 1`, `<=500 -> 2`, `<=1000 -> 3`, `<=5000 -> 4`, `>5000 -> 5`.
   - Inference (`batch_prediction.py:165`): `pd.qcut(features_df["message_length"], q=5, labels=False, duplicates="drop")` (returns `0..4` relative to the uploaded batch, and always collapses to **`0`** on single-alert live prediction!).
