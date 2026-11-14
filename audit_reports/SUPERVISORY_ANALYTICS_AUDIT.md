# SUPERVISORY ANALYTICS, MULTI-CSE & 8-DOMAIN RISK AUDIT — SAT-SA (SIH26157)

**Audit Date:** 2026-11-14  
**Auditor:** Independent Technical Forensic Audit  
**Scope:** Phases 5, 6, and 7 — Forensic verification of Multi-CSE architecture (`scratch/build_multientity_data.py`, `backend/multientity_service.py`, `data/scored/multientity_supervisory_summary.json`), 8-Domain Supervisory Risk Scoring, Intra-Entity Peer Benchmarking (`model/add_supervisory_peer_audit_v6.py`, `model/complete_supervisory_analytics_v6.py`), and Alert-Level Supervisory Context Signals (`model/create_sih_context_layer_v6.py`).

---

## 1. Phase 5 — Multi-CSE & Cross-Entity Benchmarking Audit

### 1.1 Entity Provenance: Real `org_id` Segments Mapped to Synthetic NCIIPC Personas
In `data/precinct6_cybersecurity.parquet` (`2,011,674` total rows), there are **4 distinct `org_id` values** (`ORG-0004`, `ORG-0001`, `ORG-0005`, `ORG-0003`) originating from WitFoo Precinct 6 telemetry. In `scratch/build_multientity_data.py:34-63`, these 4 anonymous organization IDs are mapped to synthetic Indian Critical Sector Entity (CSE) personas:

| Raw `org_id` | Assigned CSE Persona (`build_multientity_data.py:34-63`) | Assigned Sector | Raw Parquet Volume | Alert Volume Evaluated (`multientity_supervisory_summary.json`) |
|---|---|---|---|---|
| `ORG-0004` | Apex Financial Services — Core Banking SOC | BFSI (Banking & Financial) | `995,985` | `402,335` (`test_20.csv` slice from `dashboard_consolidated.parquet`) |
| `ORG-0001` | Bharat Power Grid Corp — SCADA/OT Security | Power & Energy | `4,968` | `4,968` (`100%` of raw parquet for `ORG-0001`) |
| `ORG-0005` | National Telecom Backbone — NOC/SOC | Telecommunications | `576,817` | `20,000` (downsampled via `df_raw.sample(n=20000, random_state=42)` at `build_multientity_data.py:85`) |
| `ORG-0003` | National Rail Logistics — Signalling Telemetry | Transport & Railways | `433,904` | `20,000` (downsampled via `df_raw.sample(n=20000, random_state=42)` at `build_multientity_data.py:85`) |

---

### 1.2 Critical Defect 1: Incompatible Scoring Pipelines Across Entities (`scratch/build_multientity_data.py:66-124`)
The cross-entity pipeline does **not** score all 4 entities with the same feature engineering pipeline:
1. **`ORG-0004` (`lines 66-73`):** Loaded directly from `data/scored/dashboard_consolidated.parquet` (`402,335` rows of `test_20.csv`), which was scored using the offline 54-feature pipeline (`model/create_unsupervised_features_v6.py`) with full historical frequency tracking (`*_previous_count`, `*_first_seen`), training rarity maps (`*_rarity`), and `suspicion_score`. Its resulting `mean_anomaly_score` is **`-0.0798`**.
2. **`ORG-0001`, `ORG-0003`, `ORG-0005` (`lines 75-115`):** Loaded from `data/precinct6_cybersecurity.parquet`, passed through `sanitize_and_validate_upload()` and `extract_arrival_time_features()` (`backend/batch_prediction.py:93-181`), which computes only **27 basic features** and fills the remaining **27 features with `0.0`**! Because 27 features are zeroed out, the Isolation Forest assigns positive anomaly scores to almost every alert (`mean_anomaly_score` of **`+0.0185`** for `ORG-0001`, **`+0.0218`** for `ORG-0003`, and **`+0.0223`** for `ORG-0005`).

**Forensic Conclusion:** Comparing `mean_anomaly_score` across `ORG-0004` (`-0.0798`) and `ORG-0001/0003/0005` (`+0.0185` to `+0.0223`) compares two incompatible feature extraction pipelines rather than genuine differences in entity threat posture.

---

### 1.3 Critical Defect 2: Broken Empty-String vs `NaN` Logic Zeroes Out Multi-CSE Gap Rates (`scratch/build_multientity_data.py:97-105, 149-151`)
In `data/precinct6_cybersecurity.parquet`, missing string fields (`src_ip`, `dst_ip`, `username`, `action`) are stored as **empty strings `""`** (not `NaN`), and missing `src_port` is stored as the string **`"0"`** (not integer `0`).
However, `scratch/build_multientity_data.py:97-105` computes `evidence_gap_count` for `ORG-0001`, `ORG-0003`, and `ORG-0005` as:
```python
df_clean["evidence_gap_count"] = (
    df_clean["src_ip"].isna().astype(int)
    + df_clean["dst_ip"].isna().astype(int)
    + df_clean["username"].isna().astype(int)
    + df_clean["action"].isna().astype(int)
    + (df_clean["src_port"] == 0).astype(int)
)
```
Because `df_clean["src_ip"]` is `""` (not `NaN`) and `df_clean["src_port"]` is `"0"` (not `0`), **`evidence_gap_count` evaluates to `0` for 100% of rows in `ORG-0001`, `ORG-0003`, and `ORG-0005`**!

Even worse, lines `149-151` compute `evidence_gap_rate` and `execution_gap_rate` for **all 4 entities** (including `ORG-0004`) using `.gt(1)`:
```python
ev_gap = float((df["evidence_gap_count"].gt(1).sum() / total) * 100.0) if "evidence_gap_count" in df.columns else 0.0
neg_space = float((df["negative_space_signal"].astype(bool).sum() / total) * 100.0) if "negative_space_signal" in df.columns else 0.0
exec_gap = float((df["execution_gap_count"].gt(1).sum() / total) * 100.0) if "execution_gap_count" in df.columns else 0.0
```
- In `dashboard_consolidated.parquet` (`ORG-0004`), both `evidence_gap_count` and `execution_gap_count` only take values `0` (`381,670` rows) or `1` (`20,665` rows, `5.14%`)—neither column is **ever `> 1`**! Thus `df["evidence_gap_count"].gt(1).sum()` and `df["execution_gap_count"].gt(1).sum()` both evaluate to **`0`** (`0.0%`) for `ORG-0004`!
- For `ORG-0001`, `ORG-0003`, and `ORG-0005`, `df_clean["evidence_gap_count"]` is `0` for every row due to the `""` vs `NaN` and `"0"` vs `0` bug (`lines 97-105`), and `df_clean["execution_gap_count"]` is `0` or `1` (`lines 106-110`), so `.gt(1)` also evaluates to **`0.0%`** for all three entities!

**Resulting Corrupt Values in `data/scored/multientity_supervisory_summary.json`:**

| Metric in `multientity_supervisory_summary.json` | `ORG-0004` | `ORG-0001` | `ORG-0003` | `ORG-0005` | Forensic Reality |
|---|---|---|---|---|---|
| `execution_gap_rate` | `0.0%` | `0.0%` | `0.0%` | `0.0%` | **BROKEN (`0.0%` for all 4 CSEs due to `.gt(1)` bug; actual `ORG-0004` `.gt(0)` rate is `5.14%` [20,665 rows])** |
| `evidence_gap_rate` | `0.0%` | `0.0%` | `0.0%` | `0.0%` | **BROKEN (`0.0%` for all 4 CSEs due to `.gt(1)` bug & `""` vs `NaN` bug)** |
| `negative_space_rate` | `5.14%` | `0.0%` | `0.0%` | `0.0%` | **BROKEN for `ORG-0001/0003/0005` (`negative_space_signal` depends on `evidence_gap_count >= 2` which is always `0`)** |
| `critical_high_pct` | `5.0%` | `5.03%` | `5.0%` | `5.0%` | **TAUTOLOGICAL (`vectorize_priority_label` assigns Critical+High to top 5% rank cutoff)** |

---

### 1.4 Critical Defect 3: Mathematically Degenerate Cross-Entity Robust Z-Scores (`scratch/build_multientity_data.py:224-243`)
Lines `226-236` compute Cross-Entity Robust Z-scores across the $N=4$ entities:
```python
med = float(np.median(vals))
mad = float(np.median(np.abs(vals - med)))
if mad == 0:
    mad = 0.01
rz = (val - med) / (1.4826 * mad)
```
When 3 out of 4 entities have `0.0` (as in `negative_space_rate = [5.1407, 0.0, 0.0, 0.0]`), both `median` and `MAD` are `0.0`. Substituting `mad = 0.01` divides `5.1407` by `0.014826`, producing a nonsensical Robust Z-score of **`+346.44`** (`multientity_supervisory_summary.json:197`)! Similarly, `mean_anomaly_score` for `ORG-0004` gets a Robust Z-score of **`-37.02`** (`multientity_supervisory_summary.json:189`).

---

### 1.5 Non-Comparable Temporal Windows & Broken Epoch Parsing (`scratch/build_multientity_data.py:189-203`)
- **Broken Timestamp Parsing (`1970-01-01 to 1970-01-01`):** In `precinct6_cybersecurity.parquet`, `timestamp` is a float Unix epoch in **seconds** (`1721992223.7` = `2024-07-26`). However, `build_multientity_data.py:194` calls `pd.to_datetime(df["timestamp"], errors="coerce")` **without `unit="s"`**, which interprets `1721992223` as nanoseconds (`1.72` seconds after the Unix epoch). Consequently, `multientity_supervisory_summary.json` records `"time_window_days": 1.0` and `"date_range": "1970-01-01 to 1970-01-01"` for all 4 entities!
- **Actual Non-Overlapping Temporal Windows (Verified with `unit="s"`):**
  - `ORG-0001`: `2024-07-26 11:10:23` to `2024-07-27 05:59:43` (`18.8` hours, `4,968` alerts).
  - `ORG-0003`: `2024-07-26 11:10:23` to `2024-07-27 06:00:04` (`18.8` hours, `433,904` alerts in raw parquet; downsampled to `20,000`).
  - `ORG-0005`: `2024-07-26 11:10:40` to `2024-07-27 06:00:06` (`18.8` hours, `576,817` alerts in raw parquet; downsampled to `20,000`).
  - `ORG-0004` (`test_20.csv`): `2024-07-29 19:54:37` to `2024-08-01 06:00:03` (`58.1` hours, `402,335` alerts).
- **Finding:** There is **zero temporal overlap** between `ORG-0004`'s evaluation slice (`July 29 – Aug 1, 2024`) and the other three organizations (`July 26–27, 2024`). That is why `split_data.py`'s global chronological 80/20 split put 100% of `ORG-0001`, `ORG-0003`, and `ORG-0005` into `train_80.csv` and left only `ORG-0004` in `test_20.csv`.

---

## 2. Phase 6 — 8-Domain Supervisory Risk Scoring Audit

All 8 domain scores are computed in `scratch/build_multientity_data.py:160-182`. Below is the forensic audit of every domain formula, its inputs, its actual computed values across the 4 CSEs in `multientity_supervisory_summary.json`, and its validity classification.

| # | Domain Name | Code Formula (`scratch/build_multientity_data.py:162-177`) | Computed Scores (`ORG-0004` / `0001` / `0005` / `0003`) | Classification | Forensic Finding |
|---|---|---|---|---|---|
| 1 | **Threat Detection** | `max(20.0, min(95.0, 100.0 - (crit_high_pct * 1.5) + (mean_score * 20.0)))` | `90.9` / `92.8` / `92.9` / `92.9` | **HEURISTIC PROXY (Degenerate)** | `crit_high_pct` is tautologically `5.0%` for all CSEs due to rank-percentile labeling; `mean_score` difference is an artifact of 54-feature vs 27-feature scoring. Also, higher `mean_anomaly_score` *increases* the health score (`+ mean_score * 20.0`), which is backwards if higher anomaly score means higher risk. |
| 2 | **Triage Quality** | `max(25.0, min(95.0, 92.0 - (ev_gap * 0.6)))` | `92.0` / `92.0` / `92.0` / `92.0` | **UNSUPPORTED / CONSTANT** | Because `ev_gap == 0.0%` for all 4 CSEs (Section 1.3), every entity receives an identical hardcoded **`92.0`**. |
| 3 | **Escalation** | `max(20.0, min(95.0, 100.0 - (exec_gap * 0.8)))` | `95.0` / `95.0` / `95.0` / `95.0` | **UNSUPPORTED / CONSTANT** | Because `exec_gap == 0.0%` for all 4 CSEs (`.gt(1)` bug), `100.0 - 0` is capped by `min(95.0, ...)` to an identical **`95.0`** across all 4 entities. |
| 4 | **Evidence Adequacy** | `max(20.0, min(95.0, avg_coverage * 0.95))` | `51.7` / `65.1` / `64.5` / `66.1` | **PARTIALLY SUPPORTED** | Driven by `avg_coverage` across 9 telemetry columns (`src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, `username`, `action`, `src_host`, `dst_host`). However, `build_multientity_data.py:130-139` checks `df[col].notna()` without checking for `"0"` on ports, inflating port coverage to `100%` for `ORG-0001/0003/0005`. |
| 5 | **Monitoring Coverage** | `max(20.0, min(95.0, avg_coverage))` | `54.5` / `68.5` / `67.9` / `69.6` | **PARTIALLY SUPPORTED (Collinear with #4)** | Exact linear multiple of Domain 4 (`Domain 4 = 0.95 * Domain 5`), double-counting `avg_coverage` in the composite mean. |
| 6 | **Governance & Oversight** | `max(25.0, min(95.0, 100.0 - (neg_space * 1.2)))` | `93.8` / `95.0` / `95.0` / `95.0` | **HEURISTIC PROXY (Broken for 3 CSEs)** | Uses `negative_space_rate`, which is only computed for `ORG-0004` (`5.14%` -> `93.8`) and is `0.0%` (`95.0`) for the other 3 CSEs. |
| 7 | **Operational Discipline** | `max(25.0, min(95.0, 100.0 - (exec_gap * 0.5 + ev_gap * 0.5)))` | `95.0` / `95.0` / `95.0` / `95.0` | **UNSUPPORTED / CONSTANT** | Both `exec_gap` and `ev_gap` are `0.0%` for all 4 CSEs, producing an identical **`95.0`** for every entity. |
| 8 | **Remediation** | `max(15.0, min(95.0, action_cov * 0.9 + 10.0))` | `88.7` / `82.6` / `86.2` / `89.4` | **HEURISTIC PROXY** | Uses non-empty `action` field coverage (`action_cov`) as a proxy for remediation completion. Note that `create_sih_context_layer_v6.py:1441` explicitly documented `remediation_completion_supported = False` because `action` is firewall/sensor action (`allow`/`deny`), not SOC case remediation. |

---

## 3. Phase 7 — Alert-Level Supervisory Context & Intra-Entity Peer Audit

Unlike the faulty Multi-CSE aggregation script (`scratch/build_multientity_data.py`), the single-entity alert-level supervisory pipeline (`model/create_sih_context_layer_v6.py`, `model/add_supervisory_peer_audit_v6.py`, and `model/complete_supervisory_analytics_v6.py`) is substantially better engineered and transparent about dataset boundaries:

### 3.1 Verified Alert-Level Supervisory Signals (`dashboard_consolidated.parquet`, $N=402,335$)

| Signal / Column | Code Implementation | Verified Distribution ($N=402,335$) | Assessment |
|---|---|---|---|
| **Evidence Sufficiency (`investigation_evidence_count`, `investigation_evidence_level`)** | `create_sih_context_layer_v6.py:675-720`: Sums 9 boolean field-presence indicators (`has_source_ip`, `has_destination_ip`, `has_source_host`, `has_destination_host`, `has_username`, `has_protocol`, `has_action`, `has_matched_rule`, `has_investigation_role`). Categorized into `Sufficient (>=6)`, `Moderate (3-5)`, `Limited (0-2)`. | `Limited`: `226,410` (`56.27%`)<br>`Moderate`: `170,567` (`42.39%`)<br>`Sufficient`: `5,358` (`1.33%`) | **GENUINE & DATA-DRIVEN** |
| **Execution Gap Signals (`execution_gap_count`, `execution_gap_level`)** | `create_sih_context_layer_v6.py:1080-1150`: Sums `investigation_without_evidence_signal` (`21,601`), `no_escalation_context_signal` (`5,358`), and `critical_missing_context_signal` (`0`, because raw `severity` in `test_20.csv` is integer `1..4` rather than string `"critical"`). | `execution_gap_count > 0`: `26,959` (`6.70%`) | **PARTIALLY SUPPORTED** (`critical_missing_context_signal` is always `False` on `test_20.csv` because `create_sih_context_layer_v6.py:1098` checks `severity_context.isin(["critical", "high", "4", "5"])`, whereas raw `severity` values are `1` [`384,335`], `2` [`1,200`], `3` [`16,800`]). |
| **Negative Space Signal (`negative_space_signal`, `low_telemetry_signal`)** | `create_sih_context_layer_v6.py:1030-1195`: Flags alerts with `telemetry_evidence_count <= 1` (`low_telemetry_signal`: `20,683` rows, `5.14%`). | `20,683` alerts (`5.14%`) | **GENUINE HEURISTIC PROXY** |
| **Intra-Entity Peer Deviation (`peer_deviation_review_signal`, `peer_robust_z_*`)** | `add_supervisory_peer_audit_v6.py:1-520`: Hierarchically groups alerts into peer cohorts (minimum cohort size `>= 30`) by `(alert_source, alert_type)` -> `alert_source` -> `alert_pipeline` -> `GLOBAL_FALLBACK`. Computes Median + MAD Robust Z-scores (`z = (x - median) / (1.4826 * MAD)`) for anomaly score, entity alert frequency, and evidence deficit. Flags outliers with `|Z| >= 3.0`. | `peer_deviation_review_signal == True`: `19,528` alerts (`4.85%`)<br>`supervisory_review_recommended == True`: `46,356` alerts (`11.52%`) | **GENUINE & MATHEMATICALLY SOUND** (unlike the 4-entity cross-CSE Z-score, intra-entity peer cohorts have $N \ge 30$ and valid non-zero MAD handling). |
| **Unsupported Signals Explicitly Flagged (`rapid_closure_supported`, `remediation_completion_supported`)** | `create_sih_context_layer_v6.py:1431-1446`: Explicitly sets `rapid_closure_supported = False` and `remediation_completion_supported = False` because case-open/close timestamps and remediation fields do not exist in the WitFoo dataset. | `False` across all `402,335` rows | **HONEST & DEFENSIBLE** (though later contradicted by `build_multientity_data.py` Domain 8). |
