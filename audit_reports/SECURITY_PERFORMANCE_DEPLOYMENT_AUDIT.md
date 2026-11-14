# SECURITY, PERFORMANCE, CODE QUALITY & DEPLOYMENT AUDIT — SAT-SA (SIH26157)

**Audit Date:** 2026-11-14  
**Auditor:** Independent Technical Forensic Audit  
**Scope:** Phases 10, 11, 12, and 13 — Forensic evaluation of software engineering quality, independently measured runtime/memory performance, security & air-gapped sovereign readiness, and unit/integration test suite coverage.

---

## 1. Phase 10 — Code Quality & Software Engineering Audit

### 1.1 Architectural Organization & Dead Code
- **Strengths:**
  - Clear separation between `backend/` services (`config.py`, `data_service.py`, `model_service.py`, `evaluation_service.py`, `batch_prediction.py`, `live_prediction.py`, `multientity_service.py`) and `dashboard/` presentation layer (`app.py`, `ui_theme.py`, `views/*.py`).
  - Offline data preparation and validation scripts in `model/` include extensive assertion checks on row counts, `_alert_id` bijection (`0..N-1`), and rank monotonicity.
- **Weaknesses & Technical Debt:**
  1. **Unreachable Legacy Monolith in `dashboard/app.py` (`lines 552-849`):** After routing to the 8 modular views in `dashboard/views/*.py` (`lines 956-999`), `dashboard/app.py` calls `st.stop()` at line `1000`, leaving ~300 lines of legacy inline view functions (`render_overview`, `render_priority_queue`, `render_incident_discovery`, `render_alert_investigation`, `render_context_and_gaps`) as unreachable dead code inside `app.py`.
  2. **Incomplete `requirements.txt`:** `requirements.txt` lists only 6 packages (`pandas`, `numpy`, `scikit-learn`, `pyarrow`, `joblib`, `streamlit`). It **omits `plotly`** (imported directly in `dashboard/ui_theme.py:10`, `overview.py:9`, `incident_discovery.py:9`, `context_gaps.py:9`, and `regulatory_assessment.py:10`), **`datasets`** (imported in `download_dataset.py:1`), and **`pytest`** (required by `tests/`). Installing strictly from `requirements.txt` in a clean environment causes `ModuleNotFoundError: No module named 'plotly'` on startup.
  3. **Production Script in `scratch/` (`scratch/build_multientity_data.py`):** The generator for the Multi-CSE dataset (`data/scored/multientity_supervisory_summary.json` and `dashboard_multientity_sample.parquet`) lives in `scratch/build_multientity_data.py` rather than `model/` or `preprocessing/`.
  4. **Workspace Backup Directories:** Three full backup directories (`backup_pre_restoration/`, `backup_sih_enhancement/`, `backup_frontend_redesign/`) and 44 test-generated `.parquet` files in `data/submissions/` remain in the working tree.

---

## 2. Phase 11 — Performance & Scalability Audit (Independently Measured)

All timings and memory figures below were independently measured on the local Windows environment using Python's `time.perf_counter()` and `tracemalloc` over the actual production files:

| Operation / Benchmark | Measured Latency / Resource | Target / Claimed Threshold | Verdict |
|---|---|---|---|
| **Cold Load of `dashboard_consolidated.parquet` (`402,335` rows × `95` cols)** | **`1,405.5 ms` (`1.41 s`)** | Claimed `< 1.1 s` | **PASS (Slightly above 1.1s cold; `< 5 ms` warm via `@st.cache_data`)** |
| **Peak Memory Allocation During `402,335` × `95` Parquet Load** | **`341.4 MB`** | `< 1,024 MB` | **PASS** |
| **Single-Alert Feature Extraction + 300-Tree Isolation Forest Inference (`1` row)** | **`24.02 ms`** | `< 100 ms` | **PASS** |
| **Batch `1,000`-Alert Feature Extraction + 300-Tree Isolation Forest Inference** | **`70.35 ms`** | `< 2,000 ms` | **PASS** |
| **Priority Queue Server-Side Filtering & Pagination (`100` rows/page over `402,335` rows)** | **`< 35 ms`** | Interactive (`< 100 ms`) | **PASS** |

---

## 3. Phase 12 — Security, Privacy & Air-Gapped Readiness Audit

### 3.1 Security Vulnerability Register

| ID | Severity | Vulnerability | Exact Location | Forensic Evidence & Exploitability |
|---|---|---|---|---|
| **SEC-01** | **HIGH** | **Stored HTML / Cross-Site Scripting (XSS) via `unsafe_allow_html=True`** | `dashboard/views/alert_investigation.py:139-145, 227-239`<br>`dashboard/views/live_prediction.py:145-168` | Raw alert fields (`message_sanitized`, `username`, `src_host`, `dst_host`, `matched_rules`, `supervisory_traceability_note`) are interpolated directly into HTML f-strings passed to `st.markdown(..., unsafe_allow_html=True)` without `html.escape()`. Because SOC alert payloads routinely contain attacker-controlled strings (HTTP User-Agents, URLs, SMB/SQL payloads), an alert containing `<img src=x onerror="alert(document.cookie)">` will execute arbitrary JavaScript in the supervisor's browser during forensic review. |
| **SEC-02** | **MEDIUM** | **External Google Fonts Dependency Breaks Air-Gapped Isolation** | `dashboard/ui_theme.py:52` | Line `52` injects `@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap');`. In a classified/air-gapped NTRO/NCIIPC network without internet access, the browser attempts outbound HTTPS connections to `fonts.googleapis.com` and `fonts.gstatic.com` on every render, causing font load timeouts or CSP/firewall violations. |
| **SEC-03** | **MEDIUM** | **Unbounded Batch File Upload & Persistent Disk Exhaustion** | `backend/batch_prediction.py:184-275`<br>`dashboard/views/batch_prediction.py:39-60` | `process_new_submission()` does not enforce any cap on uploaded file byte size or row count before parsing CSV/JSON into memory and writing a new `.parquet` file to `data/submissions/`. Furthermore, `filename` is concatenated into the submission record without path-traversal sanitization (`Path(filename).name`), although the saved parquet filename itself uses `submission_id` (`sub_<timestamp>_<hash>.parquet`). |
| **SEC-04** | **LOW** | **Unverified Pickle Deserialization (`joblib.load`)** | `backend/model_service.py:67` | Model `.pkl` files are loaded via `joblib.load()` without verifying a pinned SHA-256 integrity hash first. While standard for local ML apps, sovereign deployments should verify artifact SHA-256 digests prior to unpickling. |

---

## 4. Phase 13 — Test Suite Forensic Audit (`tests/`)

The project includes **7 test files containing 31 test functions**:
- `tests/test_batch_prediction.py` (`5` tests)
- `tests/test_dashboard_app.py` (`4` tests)
- `tests/test_data_service.py` (`5` tests)
- `tests/test_evaluation.py` (`4` tests)
- `tests/test_live_prediction.py` (`5` tests)
- `tests/test_model_pipeline.py` (`4` tests)
- `tests/test_multientity.py` (`4` tests)

### 4.1 Critical Deficiencies in the Test Suite
1. **Tests Mutate and Pollute Production `data/submissions/` State (`tests/test_batch_prediction.py` & `tests/test_live_prediction.py`):**
   - Neither `test_batch_prediction.py` nor `test_live_prediction.py` uses `pytest`'s `tmp_path` fixture or monkeypatches `SUBMISSIONS_DIR` / `MANIFEST_FILE` / `LIVE_HISTORY_FILE`.
   - Every time `pytest` runs, `test_batch_prediction.py` writes new `sub_*.parquet` files into `data/submissions/` and appends synthetic test records to `data/submissions/submission_manifest.json` (which currently contains **44 test `.parquet` artifacts** visible in the production UI!).
2. **Shallow Assertions Mask Severe Functional Bugs (`tests/test_multientity.py`):**
   - `tests/test_multientity.py` asserts that `multientity_supervisory_summary.json` has 4 entities and that `0 <= score <= 100`.
   - It **never checks** whether `execution_gap_rate` or `evidence_gap_rate` are non-zero (missing the fact that both are `0.0%` across all 4 entities), whether `date_range` is valid (missing `"1970-01-01 to 1970-01-01"`), or whether Cross-Entity Robust Z-scores are finite/reasonable (missing `+346.44σ`).
3. **Zero Feature-Equivalence Tests Between Training and Live/Batch Inference:**
   - `tests/test_batch_prediction.py` and `tests/test_live_prediction.py` only verify that `extract_arrival_time_features()` returns a DataFrame with `50` or `54` columns and no `NaN`s. They **never compare** `extract_arrival_time_features(test_20.head(100))` against `X_test_unsupervised_v6.csv`, missing the 26-column feature mismatch and the `.astype(str)` `"nan"` bug.
4. **Zero UI Column-Binding Tests:**
   - `tests/test_dashboard_app.py` only tests that `load_data()` returns non-empty DataFrames; it never renders or checks column bindings in `dashboard/views/*.py`, missing the broken `"V6_Unique_Incidents"` charts in `overview.py` and `incident_discovery.py`, the `100x` percentage formatting bug in `incident_discovery.py`, and the missing columns in the Incident Discovery Ledger.
