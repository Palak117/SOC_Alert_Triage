# FRONTEND & UX FORENSIC AUDIT — SAT-SA (SIH26157)

**Audit Date:** 2026-11-14  
**Auditor:** Independent Technical Forensic Audit  
**Scope:** Phase 9 — Complete line-by-line inspection of `dashboard/app.py`, `dashboard/ui_theme.py`, `dashboard/check_alerts.py`, and all 8 modular views in `dashboard/views/*.py`.

---

## 1. Executive Summary of Frontend Architecture

The SAT-SA frontend is built on **Streamlit** (`dashboard/app.py`, 1,015 lines) with a custom dark-mode CSS design system ("Sovereign Sentinel", defined in `dashboard/ui_theme.py`, 392 lines) and 8 modular view files under `dashboard/views/`:

| # | Navigation Label | View Module | Lines | Primary Data Source Passed |
|---|---|---|---|---|
| 1 | `01 // Executive Overview` | `dashboard/views/overview.py` | 225 | `alerts`, `summary`, `incidents`, `review`, `multi_summary` |
| 2 | `02 // Priority Triage Queue` | `dashboard/views/priority_queue.py` | 150 | `alerts` |
| 3 | `03 // Incident Discovery` | `dashboard/views/incident_discovery.py` | 179 | `alerts`, `incidents`, `review`, `summary` |
| 4 | `04 // Alert Forensics` | `dashboard/views/alert_investigation.py` | 290 | `alerts` |
| 5 | `05 // Supervisory Gaps` | `dashboard/views/context_gaps.py` | 154 | `alerts`, `summary` |
| 6 | `06 // Batch Ingestion` | `dashboard/views/batch_prediction.py` | 148 | `model_choice` |
| 7 | `07 // Live Probe Sandbox` | `dashboard/views/live_prediction.py` | 222 | `model_choice` |
| 8 | `08 // Multi-CSE Command` | `dashboard/views/regulatory_assessment.py` | 269 | `multi_summary` |

### High-Level Assessment
While the visual styling (`dashboard/ui_theme.py`) achieves a dark cybersecurity aesthetic (`#060911` canvas, `#0B111E` cards, `Inter` + `JetBrains Mono` typography, KPI strip components, and Plotly dark templates), forensic inspection of the view logic and data bindings revealed **15 verified frontend defects**, including **4 Critical** data-Disconnect / broken-chart bugs and **6 High-severity** hardcoded/misleading metric bugs.

---

## 2. Global Shell, State & Navigation Audit (`dashboard/app.py` & `dashboard/ui_theme.py`)

### 2.1 CRITICAL: Sidebar CSE Selector Is Disconnected From Pages 1–5 (`dashboard/app.py:489, 875-890, 958-997`)
- **Evidence:**
  - In `dashboard/app.py:875-890`, the sidebar renders a `st.selectbox("Select Entity Scope", cse_options, ...)` containing `All CSEs (4 Entities)`, `ORG-0004 (Apex Financial Services — Core Banking SOC)`, `ORG-0001 (Bharat Power Grid Corp — SCADA/OT Security)`, `ORG-0005 (National Telecom Backbone — NOC/SOC)`, and `ORG-0003 (National Rail Logistics — Signalling Telemetry)`.
  - Selecting an entity updates `st.session_state["global_cse_selector"]` and changes the `active_cse` badge displayed in `render_command_header()` (`app.py:948`).
  - **However**, `alerts, summary, incidents, review = load_data(model_choice)` (`app.py:489`) loads `dashboard_consolidated.parquet` (or `dashboard_consolidated_leakage_reduced.parquet`), which contains **exclusively `ORG-0004`'s 402,335 test alerts** (`test_20.csv`).
  - Neither `app.py` nor any of Pages 1–5 (`overview.py`, `priority_queue.py`, `incident_discovery.py`, `alert_investigation.py`, `context_gaps.py`) filters `alerts` by `org_id` or loads `data/scored/dashboard_multientity_sample.parquet`.
- **Impact:** When a supervisor selects `ORG-0001 (Power/Energy)` or `ORG-0003 (Transport)` in the sidebar, the top command bar claims the active scope is `ORG-0001` or `ORG-0003`, while Pages 1–5 continue displaying `ORG-0004`'s 402,335 alerts, incidents, and metrics.

### 2.2 CRITICAL: Model Switcher Updates `alerts` Parquet But Never Switches `summary`, `incidents`, or `review` CSVs (`dashboard/app.py:489-495`)
- **Evidence:**
  - `load_data(model_choice: str)` (`app.py:489-504`) switches the main alert dataframe between `CONSOLIDATED_PARQUET` (`dashboard_consolidated.parquet`) and `LEAKAGE_REDUCED_PARQUET` (`dashboard_consolidated_leakage_reduced.parquet`).
  - However, lines `493-495` unconditionally load:
    ```python
    summary = pd.read_csv(SUMMARY_FILE)
    incidents = pd.read_csv(INCIDENT_FILE)
    review = pd.read_csv(REVIEW_FILE)
    ```
    where `SUMMARY_FILE`, `INCIDENT_FILE`, and `REVIEW_FILE` point to `final_v6_sih_dashboard_summary.csv`, `final_v6_sih_dashboard_incidents.csv`, and `final_v6_sih_dashboard_review_fractions.csv` (the Baseline V6 54-feature model outputs).
  - Even though `data/scored/leakage_reduced_dashboard_summary.csv`, `leakage_reduced_dashboard_incidents.csv`, and `leakage_reduced_review_fractions.csv` exist on disk, they are never loaded when `"Leakage-Reduced Candidate (50 Clean Features)"` is selected.
- **Impact:** Selecting the Leakage-Reduced model in the sidebar still passes Baseline V6 summary, incident discovery, and review-fraction tables to Pages 1, 3, and 5.

### 2.3 MEDIUM: Structural HTML Wrapper Anti-Pattern Across 6 Views (`<div class="cyber-card">` Empty Box Bug)
- **Evidence:**
  - Streamlit's `st.markdown('<div class="cyber-card">', unsafe_allow_html=True)` followed by native Streamlit calls (`st.plotly_chart`, `st.dataframe`, `st.columns`) and a later `st.markdown('</div>', unsafe_allow_html=True)` does **not** wrap the intermediate Streamlit components inside the `<div>`. Because each `st.markdown()` call is mounted inside its own isolated React `element-container` DOM node, the browser auto-closes the unclosed `<div class="cyber-card">` immediately, rendering an empty styled `<div class="cyber-card"></div>` bar above the chart/table, and discarding the stray `</div>` below it.
  - Affected locations verified:
    - `dashboard/views/overview.py`: lines `93 & 133`, `145 & 190`, `193 & 224`
    - `dashboard/views/priority_queue.py`: lines `81 & 108`
    - `dashboard/views/incident_discovery.py`: lines `79 & 119`
    - `dashboard/views/batch_prediction.py`: lines `34 & 62`
    - `dashboard/views/live_prediction.py`: lines `145 & 168`
    - `dashboard/views/regulatory_assessment.py`: lines `161 & 173`

### 2.4 LOW: 515 Lines of Dead Legacy Code Retained in `dashboard/app.py` (`lines 500-1015`)
- **Evidence:**
  - `dashboard/app.py` routes to modular views at lines `956-999` and calls `st.stop()` at line `1000`.
  - However, legacy inline view functions (`render_overview`, `render_priority_queue`, `render_incident_discovery`, `render_alert_investigation`, `render_context_and_gaps`) remain defined in `dashboard/app.py:552-849` (~300 lines of unreachable dead code).

---

## 3. Page-by-Page Forensic Audit

### Page 1: `01 // Executive Overview` (`dashboard/views/overview.py`)

| Check | Status | Evidence & Technical Finding |
|---|---|---|
| **KPI Ribbon (`lines 55-82`)** | **PARTIAL (Hardcoded)** | `total_alerts` (`402,335`), `total_incidents` (`3,113`), `unique_incidents` (`44`), `exec_gaps` (`26,959`), and `neg_space` (`20,683`) are computed from `alerts`. However, sub-labels and deltas are **hardcoded strings from the V6 Baseline model**: `"100% full recall at Top 5k"` (`line 64`), `"Sec-Relevant: 99.0%"` (`line 65`), `"98.76%"` (`line 69`), `"397,335 alerts avoided"` (`line 70`). They do **not** update when switching to the Leakage-Reduced model (where Top-5k recall is `77.3%`, not `100%`). |
| **Contradictory Hardcoded Metrics on the Same Page (`lines 59-81` vs `101-108`)** | **HIGH DEFECT** | While the top KPI ribbon (`lines 64-70`) hardcodes **Baseline V6** performance (`100% recall at Top 5k`, `79.0% Precision@100`), the "Multi-Layer Benchmark Matrix" directly below it (`lines 101-108`) hardcodes **Leakage-Reduced** model performance (`"5 / 44 Incidents"`, `"11.4% Recall (29% Prec)"` at Top 100 and `"34 / 44 Incidents"`, `"77.3% Recall (24% Prec)"` at Top 5,000) regardless of which model is active in the sidebar! |
| **Discovery Trajectory Chart (`lines 154-184`)** | **CRITICAL BUG (Broken Chart)** | Line `154` checks `if not review.empty and "V6_Unique_Incidents" in review.columns:`. In `final_v6_sih_dashboard_review_fractions.csv` (and `leakage_reduced_review_fractions.csv`), the actual columns are `Review_Percentage,Alerts_Reviewed,Unique_Incidents_Found,Unique_Incident_Recall`. Because `"V6_Unique_Incidents"` does not exist, the `if` condition is **always `False`**, and the chart never renders—always displaying the fallback `st.info("Discovery trajectory telemetry unavailable.")` (`line 186`). |
| **National Cross-CSE Posture Matrix (`lines 193-224`)** | **PASS (Display) / FAIL (Underlying Data)** | Renders a 4-row table from `multi_summary["entities"]`. However, because `multientity_supervisory_summary.json` has `0.0%` for `execution_gap_rate` and `evidence_gap_rate` across all 4 entities, the displayed table shows `0.0%` execution gaps for every CSE. |

---

### Page 2: `02 // Priority Triage Queue` (`dashboard/views/priority_queue.py`)

| Check | Status | Evidence & Technical Finding |
|---|---|---|
| **Filter Controls (`lines 32-76`)** | **PASS** | 6 filters work cleanly on `alerts`: Priority Tier (`Critical`, `High`, `Medium`, `Low`), Alert Source, Execution Gap Level, Evidence Sufficiency Level, Peer Deviation Signal (`All`, `Outliers Only (> 3σ)`, `Within Peer Norm`), and Top-K Horizon slider (`100` to `25,000`). Reset button clears session keys properly (`lines 69-75`). |
| **KPI Strip (`lines 85-96`)** | **PASS** | Dynamically reflects filtered count, top priority rank, peak anomaly score, and active execution gap count in the filtered slice. |
| **Paginated Queue Table (`lines 110-149`)** | **PASS** | Server-side slicing (`100` rows per page) over `filtered` dataframe keeps rendering fast (`<50 ms`). CSV export downloads up to 10,000 filtered rows (`lines 118-124`). |

---

### Page 3: `03 // Incident Discovery` (`dashboard/views/incident_discovery.py`)

| Check | Status | Evidence & Technical Finding |
|---|---|---|
| **KPI Strip (`lines 37-67`)** | **HIGH DEFECT (Hardcoded)** | All 5 KPI cards (`"44 / 44"`, `"100.0% Recall"`, `"Rank #2"`, `"98.76%"`, `"79.0%"`, `"99.0% Sec-Relevant"`, `"3.67x"`) are hardcoded strings in `incident_discovery.py:39-65` and never change when switching models. |
| **Cumulative Incident Discovery Curve (`lines 79-119`)** | **CRITICAL BUG (Plots Flat Zeros)** | Lines `83-84` compute: `v6_y = rev_df.get("V6_Unique_Incidents", pd.Series(0, index=rev_df.index))` and `chrono_y = rev_df.get("Chronological_Unique_Incidents", pd.Series(0, index=rev_df.index))`. Neither `"V6_Unique_Incidents"` nor `"Chronological_Unique_Incidents"` exists in `review` (`final_v6_sih_dashboard_review_fractions.csv`, which has `Unique_Incidents_Found`). Consequently, **both lines on the Plotly chart plot flat horizontal lines at `Y = 0` across all X values**, while only the static red dashed horizontal target line at `Y = 44` appears! |
| **Top-K Evaluation Milestones Table (`lines 138-159`)** | **HIGH BUG (100x Percentage Error)** | In `final_v6_sih_dashboard_summary.csv`, `V6_Precision`, `Chronological_Precision`, `V6_Incident_Alert_Recall`, and `Chronological_Recall` are stored as decimals in `[0, 1]` (e.g., `0.79`, `1.0`). Lines `148-151` apply `st.column_config.NumberColumn(..., format="%.2f%%")` directly without multiplying by `100`. As a result, `79.0%` precision is displayed to the user as **`0.79%`**, and `100.0%` recall is displayed as **`1.00%`**! |
| **Unique Incident Discovery Ledger (`lines 161-178`)** | **HIGH BUG (Missing Columns)** | Lines `168-174` select `col_order = [c for c in ["incident_ids", "earliest_discovery_rank", "earliest_alert_timestamp", "associated_alert_count", "highest_severity"] if c in inc_df.columns]`. However, `final_v6_sih_dashboard_incidents.csv` has columns `["incident_id", "first_priority_rank", "first_timestamp", "associated_alert_count", "highest_severity"]`. Because the first 3 column names do not match, **the table omits Incident ID, First Priority Rank, and First Timestamp**, rendering only `associated_alert_count` and `highest_severity`! |

---

### Page 4: `04 // Alert Forensics` (`dashboard/views/alert_investigation.py`)

| Check | Status | Evidence & Technical Finding |
|---|---|---|
| **Quick-Jump Preset Buttons (`lines 55-74`)** | **MEDIUM BUG (Non-Persistent State)** | Clicking `"⚡ Top #1 Threat"`, `"🔥 Highest Gap Alert"`, `"📡 Peer Outlier #1"`, or `"🎯 Confirmed Incident #1"` sets local variable `search_id = int(...)` for that single render cycle (`lines 60-74`) without updating `st.session_state["ai_search_id_input"]`. Any subsequent interaction on the page immediately reverts to whatever text is in `ai_search_id_input` (default `"292691"`). |
| **Stored HTML/XSS Injection (`lines 139-145, 227-239`)** | **HIGH SECURITY BUG** | Raw fields from the alert record (`row.get('message_sanitized')`, `row.get('username')`, `row.get('src_host')`, `row.get('dst_host')`, `row.get('matched_rules')`) are interpolated via Python f-strings directly into `st.markdown(..., unsafe_allow_html=True)` without `html.escape()`. A crafted alert payload containing `<script>` or `<img onerror=...>` executes arbitrary HTML/JS in the supervisor's browser. |
| **Peer-Group Robust Z-Score Bars (`lines 171-220`)** | **PASS** | Correctly displays `peer_group_type`, `peer_group_value`, `peer_group_size`, `peer_anomaly_explanation`, and visual Z-score bars for `peer_robust_z_anomaly`, `peer_robust_z_entity_freq`, and `peer_robust_z_evidence`. |

---

### Page 5: `05 // Supervisory Gaps` (`dashboard/views/context_gaps.py`)

| Check | Status | Evidence & Technical Finding |
|---|---|---|
| **KPI Strip (`lines 32-55`)** | **PASS** | Dynamically computes `exec_gaps` (`26,959`), `neg_space` (`20,683`), `low_ev` (`226,410`), `no_esc` (`5,358`), and `peer_dev` (`19,528`) from `alerts`. |
| **Charts (`lines 58-123`)** | **PASS** | Plots Execution Gap Breakdown bar chart and Evidence Sufficiency donut chart using `apply_cyber_plotly_theme`. |
| **Peer Deviation Outlier Registry (`lines 125-153`)** | **HIGH DEFECT (Misleading Table Filter)** | Section is titled `"Peer Deviation Outlier Registry (> 3σ Anomaly Signals)"` (`line 125`). However, line `127` filters `outliers = alerts[alerts["priority_label"].isin(["Critical", "High"])].head(25)`—it **never filters by `peer_deviation_review_signal == True`** and **never displays any `peer_robust_z_*` or `peer_group_*` columns** (`disp_cols` at lines `130-135` only shows rank, ID, timestamp, source, type, severity, score, execution gap, evidence level, and context reason). |

---

### Page 6: `06 // Batch Ingestion` (`dashboard/views/batch_prediction.py`)

| Check | Status | Evidence & Technical Finding |
|---|---|---|
| **File Upload & Scoring Flow (`lines 25-115`)** | **PARTIAL** | Supports CSV/JSON upload, SHA-256 deduplication check, and download of scored CSV. However, it invokes `process_batch_submission()` (`backend/batch_prediction.py`), which computes only **27 of 50/54 features** and zeroes out the remaining **23/27 features** (see `ML_MODEL_FORENSIC_AUDIT.md`). |
| **Submission Audit Ledger (`lines 122-148`)** | **LOW DEFECT (Polluted by Tests)** | Displays `data/submissions/submission_manifest.json`. Because `tests/test_batch_prediction.py` writes directly to the production `data/submissions/` directory, test runs pollute the user-facing ledger with synthetic test entries (`test_upload.csv`). |

---

### Page 7: `07 // Live Probe Sandbox` (`dashboard/views/live_prediction.py`)

| Check | Status | Evidence & Technical Finding |
|---|---|---|
| **Preset Payloads & Form (`lines 28-137`)** | **LOW DEFECT (Wrong Feature Count Label)** | Line `35` displays `f"{'Leakage-Reduced (21 Features)' if is_lr else 'Baseline V6 (23 Features)'}"`. The actual models have **50** and **54** features respectively (`21` and `23` are stale numbers from an older prototype). |
| **Single-Alert Inference (`lines 139-203`)** | **HIGH DEFECT (Degraded Feature Vector)** | Calls `predict_single_alert()` (`backend/live_prediction.py`), which delegates to `extract_arrival_time_features()`—zeroing out all rarity and historical frequency features (`23/50` or `27/54` features) and causing `pd.qcut` on `message_size_bucket` to collapse to `0` because a 1-row DataFrame has 0 quantile spread. |

---

### Page 8: `08 // Multi-CSE Command` (`dashboard/views/regulatory_assessment.py`)

| Check | Status | Evidence & Technical Finding |
|---|---|---|
| **Audit Priority Queue Cards (`lines 38-88`)** | **PASS (UI) / FAIL (Backend Scores)** | Renders 4 cards sorted by `composite_risk_score`. However, because 3 of 8 domains are constant across CSEs and 3 CSEs have `0.0%` gap rates in `multientity_supervisory_summary.json`, the rankings and scores (`82.7` to `86.7`) are driven almost entirely by synthetic telemetry coverage differences. |
| **8-Domain Radar & Bar Chart (`lines 94-156`)** | **PASS (UI)** | Renders interactive Plotly `Scatterpolar` radar chart and horizontal bar comparison across the 4 CSEs. |
| **Cross-CSE Benchmarking Matrix (`lines 159-189`)** | **FAIL (Corrupted Z-Scores Displayed)** | Displays `multientity_supervisory_summary.json` benchmark metrics and Robust Z-scores, including the mathematically degenerate **`+346.44σ`** Z-score for `ORG-0004`'s `negative_space_rate` and **`-37.02σ`** for `mean_anomaly_score`. |
| **Exportable Audit Dossier (`lines 234-268`)** | **PASS** | Exports Markdown (`.md`) and JSON (`.json`) supervisory assessment reports via `st.download_button`. |
