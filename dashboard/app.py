import streamlit as st
import pandas as pd
import numpy as np
from pathlib import Path
import ast
import re
import sys
import os

# Ensure root is in sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

# UI Theme & View Modules
from dashboard.ui_theme import inject_cyber_theme, CYBER_PALETTE
from dashboard.views.overview import render_overview_view
from dashboard.views.priority_queue import render_priority_queue_view
from dashboard.views.incident_discovery import render_incident_discovery_view
from dashboard.views.alert_investigation import render_alert_investigation_view
from dashboard.views.context_gaps import render_context_gaps_view
from dashboard.views.batch_prediction import render_batch_prediction_view
from dashboard.views.live_prediction import render_live_prediction_view
from dashboard.views.regulatory_assessment import render_regulatory_assessment_view

from backend.batch_prediction import process_new_submission, get_submission_manifest
from backend.multientity_service import (
    load_multientity_summary,
    get_entity_list,
    get_ranked_regulatory_queue,
    get_telemetry_coverage_matrix,
    generate_supervisory_dossier_text,
)
from backend.live_prediction import (
    score_single_alert,
    get_live_prediction_history,
)

# ============================================================
# PAGE CONFIG & CYBER SUPERVISORY THEME
# ============================================================

st.set_page_config(
    page_title="SAT-SA — SOC Alert Triage & Supervisory Assessment | SIH26157",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

inject_cyber_theme()
# PATHS
# ============================================================

# app.py is inside:
# SOC_Alert_Triage/dashboard/app.py
#
# Therefore parent.parent = SOC_Alert_Triage

BASE_DIR = Path(__file__).resolve().parent.parent

DATA_DIR = BASE_DIR / "data" / "scored"


ALERT_FILE = DATA_DIR / "final_v6_sih_dashboard_alerts.csv"

SUMMARY_FILE = DATA_DIR / "final_v6_sih_dashboard_summary.csv"

INCIDENT_FILE = DATA_DIR / "final_v6_sih_dashboard_incidents.csv"

REVIEW_FILE = DATA_DIR / "final_v6_sih_dashboard_review_fractions.csv"




# ============================================================
# HELPER FUNCTIONS
# ============================================================

@st.cache_data(show_spinner=False)
def load_csv(path):

    if not path.exists():
        return pd.DataFrame()

    try:
        return pd.read_csv(
            path,
            low_memory=False
        )
    except Exception as e:
        st.error(f"Could not read file:\n{path}\n\n{e}")
        return pd.DataFrame()


def clean_text(value):

    if value is None:
        return "N/A"

    try:
        if pd.isna(value):
            return "N/A"
    except Exception:
        pass

    text = str(value).strip()

    if not text:
        return "N/A"

    return text


def safe_float(value, default=0.0):

    try:

        if pd.isna(value):
            return default

        return float(value)

    except Exception:

        return default


def format_number(value):

    try:
        return f"{int(value):,}"
    except Exception:
        return str(value)


def format_percent(value):
    """Format a proportion or percentage consistently as a percentage."""
    try:
        number = float(value)
        if not np.isfinite(number):
            return "N/A"
        # Some exported summaries store proportions (0..1); others may
        # store percentage points (0..100). Normalize before display.
        if 1 < abs(number) <= 100:
            number = number / 100
        return f"{number * 100:.2f}%"
    except (TypeError, ValueError):
        return "N/A"


def format_score(value):

    try:
        return f"{float(value):.4f}"
    except Exception:
        return "N/A"


def parse_list_value(value):

    if value is None:
        return []

    if isinstance(value, (list, tuple, set)):

        return [
            str(x).strip()
            for x in value
            if str(x).strip()
        ]

    try:

        if pd.isna(value):
            return []

    except Exception:
        pass

    text = str(value).strip()

    if not text:
        return []

    if text.lower() in {
        "nan",
        "none",
        "null",
        "[]",
        "{}"
    }:

        return []

    if text.startswith("[") and text.endswith("]"):

        try:

            parsed = ast.literal_eval(text)

            if isinstance(parsed, (list, tuple, set)):

                return [
                    str(x).strip()
                    for x in parsed
                    if str(x).strip()
                ]

        except Exception:
            pass

        inner = text[1:-1]

        return [
            x.strip().strip("'").strip('"')
            for x in inner.split(",")
            if x.strip()
        ]

    if ";" in text:

        return [
            x.strip()
            for x in text.split(";")
            if x.strip()
        ]

    return [text]


def first_existing_column(df, candidates):

    for column in candidates:

        if column in df.columns:
            return column

    return None


def normalize_fraction(value):

    value = safe_float(value)

    if value > 1:
        return value / 100

    return value


def calculate_priority_label(row, total_rows):

    """
    Display-only priority label.

    We do not change the authoritative priority_rank.

    If the source contains a meaningful severity field,
    use it.

    Otherwise use queue rank percentile.
    """

    severity = clean_text(
        row.get("severity", "")
    ).lower()

    if "critical" in severity:
        return "Critical"

    if "high" in severity:
        return "High"

    if "medium" in severity:
        return "Medium"

    if "low" in severity:
        return "Low"

    rank = safe_float(
        row.get("priority_rank", np.nan),
        np.nan
    )

    if not np.isfinite(rank) or total_rows <= 0:
        return "Unknown"

    percentile = rank / total_rows

    if percentile <= 0.01:
        return "Critical"

    if percentile <= 0.05:
        return "High"

    if percentile <= 0.20:
        return "Medium"

    return "Low"



def find_unique_incident_count(incidents_df):

    if incidents_df.empty:
        return None

    possible_columns = [
        "incident_id",
        "incident_id_eval",
        "incident_ids",
        "Incident_ID",
        "incident",
        "Incident"
    ]

    for column in possible_columns:

        if column not in incidents_df.columns:
            continue

        values = set()

        for value in incidents_df[column]:

            for item in parse_list_value(value):

                if item is not None:
                    incident_id = str(item).strip()

                    if incident_id and incident_id.lower() not in {
                        "nan", "none", "null"
                    }:
                        values.add(incident_id)

        if values:
            return len(values)

    return None

def get_summary_metric(
    summary_df,
    k,
    possible_columns
):

    if summary_df.empty:
        return None

    if "K" not in summary_df.columns:
        return None

    k_values = pd.to_numeric(
        summary_df["K"],
        errors="coerce"
    )

    rows = summary_df[
        k_values == k
    ]

    if rows.empty:
        return None

    row = rows.iloc[0]

    for column in possible_columns:

        if column in row.index:

            value = safe_float(
                row[column],
                np.nan
            )

            if np.isfinite(value):
                return value

    return None



def calculate_top_k_metrics(
    alerts_df,
    k,
    unique_incidents
):
    if alerts_df.empty or k <= 0:
        return None, None, None

    required_columns = ["priority_rank", "actual_incident"]

    if not all(col in alerts_df.columns for col in required_columns):
        return None, None, None

    ranked = alerts_df.copy()

    ranked["priority_rank"] = pd.to_numeric(
        ranked["priority_rank"],
        errors="coerce"
    )

    ranked = (
        ranked.dropna(subset=["priority_rank"])
        .sort_values("priority_rank", ascending=True)
    )

    if ranked.empty:
        return None, None, None

    top_k = ranked.head(k)

    # Accept only valid binary incident labels.
    labels = pd.to_numeric(
        top_k["actual_incident"],
        errors="coerce"
    )

    valid_labels = labels.isin([0, 1])

    if not valid_labels.all():
        return None, None, None

    labels = labels.astype(int)
    incident_count = int(labels.sum())

    precision = (
        incident_count / len(top_k)
        if len(top_k) > 0
        else None
    )

    # Count distinct incident IDs discovered in the top-K alerts.
    recall = None

    incident_id_col = first_existing_column(
        top_k,
        [
            "incident_ids",
            "incident_id",
            "incident_id_eval",
            "Incident_ID"
        ]
    )

    if (
        unique_incidents is not None
        and unique_incidents > 0
        and incident_id_col
    ):
        discovered_ids = set()

        for value in top_k[incident_id_col]:
            for incident_id in parse_list_value(value):
                if incident_id:
                    discovered_ids.add(str(incident_id).strip())

        recall = min(
            len(discovered_ids) / unique_incidents,
            1.0
        )

    return precision, recall, incident_count



# ============================================================
# LOAD DATA (OPTIMIZED WITH FAST PRE-CONSOLIDATED PARQUET & MULTI-CSE)
# ============================================================

is_lr_selected = st.session_state.get("is_lr_selected", False)
selected_cse_val = st.session_state.get("selected_cse_filter", "ORG-0004 — Defense & Telecom")
selected_org_id = selected_cse_val.split(" — ")[0].strip()

# Dynamically select evaluation files based on active model toggle
if is_lr_selected:
    SUMMARY_FILE = DATA_DIR / "leakage_reduced_dashboard_summary.csv"
    INCIDENT_FILE = DATA_DIR / "leakage_reduced_dashboard_incidents.csv"
    REVIEW_FILE = DATA_DIR / "leakage_reduced_review_fractions.csv"
else:
    SUMMARY_FILE = DATA_DIR / "final_v6_sih_dashboard_summary.csv"
    INCIDENT_FILE = DATA_DIR / "final_v6_sih_dashboard_incidents.csv"
    REVIEW_FILE = DATA_DIR / "final_v6_sih_dashboard_review_fractions.csv"

ESSENTIAL_COLUMNS = [
    "_alert_id", "timestamp", "timestamp_datetime", "Timestamp",
    "origin", "org_id", "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
    "src_host", "dst_host", "username", "entity_key", "entity_alert_frequency",
    "action", "severity", "disposition", "product_name", "vendor_name",
    "anomaly_score", "priority_score", "priority_rank", "priority_label",
    "incident_ids", "actual_incident", "security_relevant",
    "attack_tactics", "attack_techniques", "message_sanitized",
    "evidence_gap_count", "evidence_gap_signal", "evidence_gap_level",
    "investigation_without_evidence_signal", "low_telemetry_signal",
    "no_escalation_context_signal", "critical_missing_context_signal",
    "repetitive_investigation_signal", "negative_space_signal",
    "execution_gap_count", "execution_gap_level", "context_reason",
    "repeated_entity_signal", "high_frequency_entity_signal",
    "peer_comparison_supported", "peer_comparison_status",
    "supervisory_peer_reason", "supervisory_review_reason",
    "supervisory_review_recommended", "supervisory_disclaimer",
    "supervisory_evidence_gap_review", "supervisory_review_reason_codes",
    "supervisory_evidence_source_fields", "supervisory_traceability_note",
    "peer_comparison_supported_computed", "peer_deviation_review_signal",
    "peer_comparison_interpretation", "entity_frequency_review_signal",
    "entity_frequency_basis", "entity_frequency_interpretation",
    "peer_group_size"
]

MAX_QUEUE_ALERTS = int(os.environ.get("MAX_QUEUE_ALERTS", "25000"))

@st.cache_data(show_spinner=False)
def load_consolidated_dataset(is_leakage_reduced=False, max_rows=25000):
    if is_leakage_reduced:
        p_path = DATA_DIR / "dashboard_consolidated_leakage_reduced.parquet"
        c_path = DATA_DIR / "dashboard_consolidated_leakage_reduced.csv"
    else:
        p_path = DATA_DIR / "dashboard_consolidated.parquet"
        c_path = DATA_DIR / "dashboard_consolidated.csv"

    if p_path.exists():
        import pyarrow.parquet as pq
        table = pq.read_table(str(p_path))
        avail = [c for c in ESSENTIAL_COLUMNS if c in table.column_names]
        if max_rows and max_rows > 0 and max_rows < table.num_rows:
            table = table.select(avail).slice(0, max_rows)
        else:
            table = table.select(avail)
        df = table.to_pandas()
        for cat_col in ["priority_label", "severity", "action", "protocol", "origin", "org_id", "disposition", "product_name"]:
            if cat_col in df.columns:
                df[cat_col] = df[cat_col].astype("category")
        return df
    elif c_path.exists():
        return pd.read_csv(c_path, low_memory=False, nrows=max_rows if max_rows > 0 else None)
    return pd.DataFrame()

@st.cache_data(show_spinner=False)
def load_multientity_dataset():
    p_path = DATA_DIR / "dashboard_multientity_sample.parquet"
    if p_path.exists():
        import pyarrow.parquet as pq
        table = pq.read_table(str(p_path))
        avail = [c for c in ESSENTIAL_COLUMNS if c in table.column_names]
        df = table.select(avail).to_pandas()
        for cat_col in ["priority_label", "severity", "action", "protocol", "origin", "org_id", "disposition", "product_name"]:
            if cat_col in df.columns:
                df[cat_col] = df[cat_col].astype("category")
        return df
    return pd.DataFrame()

if is_lr_selected:
    active_parquet_path = DATA_DIR / "dashboard_consolidated_leakage_reduced.parquet"
else:
    active_parquet_path = DATA_DIR / "dashboard_consolidated.parquet"

# Load alerts based on selected Critical Sector Entity
if selected_org_id in ["ORG-0001", "ORG-0003", "ORG-0005"]:
    me_df = load_multientity_dataset()
    if not me_df.empty and "org_id" in me_df.columns:
        alerts = me_df[me_df["org_id"] == selected_org_id].copy()
    else:
        alerts = load_consolidated_dataset(is_leakage_reduced=is_lr_selected, max_rows=MAX_QUEUE_ALERTS).copy()
elif selected_org_id == "All CSEs":
    me_df = load_multientity_dataset()
    alerts = me_df.copy() if not me_df.empty else load_consolidated_dataset(is_leakage_reduced=is_lr_selected, max_rows=MAX_QUEUE_ALERTS).copy()
else:
    alerts = load_consolidated_dataset(is_leakage_reduced=is_lr_selected, max_rows=MAX_QUEUE_ALERTS).copy()

is_pre_consolidated = not alerts.empty

if is_pre_consolidated:
    summary = load_csv(SUMMARY_FILE)
    incidents = load_csv(INCIDENT_FILE)
    review = load_csv(REVIEW_FILE)
    context = pd.DataFrame()
    supervisory_audit = pd.DataFrame()
    complete_audit = pd.DataFrame()
else:
    # Full original fallback loading
    alerts = load_csv(ALERT_FILE)
    summary = load_csv(SUMMARY_FILE)
    incidents = load_csv(INCIDENT_FILE)
    review = load_csv(REVIEW_FILE)
    context_file = DATA_DIR / "final_v6_sih_context_layer.csv"
    context = load_csv(context_file)
    supervisory_audit_file = DATA_DIR / "final_v6_sih_supervisory_audit.csv"
    supervisory_audit = load_csv(supervisory_audit_file)

# Attach supervisory context without changing alert scores or ranks.
if not is_pre_consolidated and not context.empty and "_alert_id" in context.columns and "_alert_id" in alerts.columns:
    context_fields = [c for c in ["_alert_id", "evidence_gap_count", "evidence_gap_signal", "evidence_gap_level", "investigation_without_evidence_signal", "low_telemetry_signal", "no_escalation_context_signal", "critical_missing_context_signal", "repetitive_investigation_signal", "negative_space_signal", "execution_gap_count", "execution_gap_level", "context_reason", "entity_key", "entity_alert_frequency", "repeated_entity_signal", "high_frequency_entity_signal"] if c in context.columns]
    context_subset = context[context_fields].drop_duplicates("_alert_id")
    alerts = alerts.merge(context_subset, on="_alert_id", how="left", validate="one_to_one", suffixes=("", "_context"))
    # Prefer regenerated supervisory signals over stale copies in the dashboard CSV.
    for signal_col in ["evidence_gap_count", "evidence_gap_signal", "evidence_gap_level", "investigation_without_evidence_signal", "low_telemetry_signal", "no_escalation_context_signal", "critical_missing_context_signal", "repetitive_investigation_signal", "negative_space_signal", "execution_gap_count", "execution_gap_level", "context_reason", "entity_key", "entity_alert_frequency", "repeated_entity_signal", "high_frequency_entity_signal"]:
        context_col = signal_col + "_context"
        if context_col in alerts.columns:
            alerts[signal_col] = alerts[context_col]
            alerts.drop(columns=[context_col], inplace=True)


# Optional supervisory peer/audit add-on. If its output does not exist yet,
# the existing dashboard continues to work as before.
if not is_pre_consolidated and not supervisory_audit.empty and "_alert_id" in supervisory_audit.columns and "_alert_id" in alerts.columns:
    audit_fields = [c for c in [
        "_alert_id", "peer_comparison_supported", "peer_comparison_status",
        "supervisory_peer_reason", "supervisory_review_reason",
        "supervisory_review_recommended", "supervisory_disclaimer",
        "rapid_closure_duration_supported", "remediation_completion_supported",
        "incident_labels_used_for_peer_comparison", "v6_scores_or_ranks_modified"
    ] if c in supervisory_audit.columns]
    audit_subset = supervisory_audit[audit_fields].drop_duplicates("_alert_id")
    alerts = alerts.merge(audit_subset, on="_alert_id", how="left", validate="one_to_one", suffixes=("", "_audit"))



# ============================================================
# LOAD COMPLETE SUPERVISORY ANALYTICS OUTPUT
# ============================================================

complete_audit_file = (
    DATA_DIR / "final_v6_sih_supervisory_complete.csv"
)
if not is_pre_consolidated:
    complete_audit = load_csv(complete_audit_file)
else:
    complete_audit = pd.DataFrame()

if (
    not is_pre_consolidated
    and not complete_audit.empty
    and "_alert_id" in complete_audit.columns
    and "_alert_id" in alerts.columns
):
    complete_fields = [
        "_alert_id",
        "supervisory_evidence_gap_review",
        "supervisory_review_reason_codes",
        "supervisory_evidence_source_fields",
        "supervisory_traceability_note",
        "peer_comparison_supported_computed",
        "peer_deviation_review_signal",
        "peer_comparison_interpretation",
        "entity_frequency_review_signal",
        "entity_frequency_basis",
        "entity_frequency_interpretation",
        "peer_group_size",
        "supervisory_evidence_gap_count",
        "supervisory_execution_gap_count",
        "supervisory_negative_space_count",
    ]

    # Include available per-metric peer deviation results.
    complete_fields += [
        c for c in complete_audit.columns
        if c.startswith("peer_robust_z_")
        or c.startswith("peer_outlier_")
    ]

    complete_fields = [
        c for c in dict.fromkeys(complete_fields)
        if c in complete_audit.columns
    ]

    complete_subset = (
        complete_audit[complete_fields]
        .drop_duplicates("_alert_id")
    )

    alerts = alerts.merge(
        complete_subset,
        on="_alert_id",
        how="left",
        validate="one_to_one",
        suffixes=("", "_complete"),
    )


# ============================================================
# VALIDATE ALERT FILE
# ============================================================

if alerts.empty:

    st.error(
        "Dashboard alert data was not found.\n\n"
        f"Expected:\n{ALERT_FILE}"
    )

    st.stop()


required_columns = [
    "_alert_id",
    "anomaly_score",
    "priority_score",
    "priority_rank",
]


missing_columns = [
    column
    for column in required_columns
    if column not in alerts.columns
]


if missing_columns:

    st.error(
        "Required columns are missing from the alert CSV:\n\n"
        + "\n".join(
            f"- {column}"
            for column in missing_columns
        )
    )

    st.stop()


# ============================================================
# PREPARE ALERT DATA
# ============================================================

# Preserve numeric IDs where applicable, otherwise preserve clean string identifiers
if "_alert_id" in alerts.columns:
    num_ids = pd.to_numeric(alerts["_alert_id"], errors="coerce")
    if num_ids.notna().all():
        alerts["_alert_id"] = num_ids.astype(int)
    else:
        alerts["_alert_id"] = alerts["_alert_id"].fillna("").astype(str)

alerts["anomaly_score"] = pd.to_numeric(
    alerts["anomaly_score"],
    errors="coerce"
)

alerts["priority_score"] = pd.to_numeric(
    alerts["priority_score"],
    errors="coerce"
)

alerts["priority_rank"] = pd.to_numeric(
    alerts["priority_rank"],
    errors="coerce"
)


if "actual_incident" not in alerts.columns:

    alerts["actual_incident"] = 0


alerts["actual_incident"] = (
    pd.to_numeric(
        alerts["actual_incident"],
        errors="coerce"
    )
    .fillna(0)
    .astype(int)
)


if "Timestamp" not in alerts.columns:
    if "timestamp_datetime" in alerts.columns:
        alerts["Timestamp"] = pd.to_datetime(
            alerts["timestamp_datetime"],
            errors="coerce"
        ).dt.strftime("%Y-%m-%d %H:%M:%S")
    elif "timestamp" in alerts.columns:
        alerts["Timestamp"] = pd.to_datetime(
            alerts["timestamp"],
            unit="s",
            errors="coerce"
        ).dt.strftime("%Y-%m-%d %H:%M:%S")


if "priority_rank" in alerts.columns and not alerts["priority_rank"].is_monotonic_increasing:
    alerts = alerts.sort_values(
        "priority_rank",
        ascending=True,
        na_position="last"
    ).reset_index(drop=True)

# Correct any 1970 timestamp artifact or missing severity in incidents using actual alert arrival data
if not incidents.empty and "first_timestamp" in incidents.columns:
    incidents["highest_severity"] = incidents["highest_severity"].astype(object)
    has_1970 = incidents["first_timestamp"].astype(str).str.startswith("1970")
    has_missing_sev = incidents["highest_severity"].isna()
    if (has_1970.any() or has_missing_sev.any()) and not alerts.empty:
        try:
            inc_alerts = alerts[alerts["actual_incident"] == 1]
            inc_first_map = {}
            for _, r in inc_alerts.iterrows():
                r_ts = str(r.get("Timestamp", r.get("timestamp_datetime", "")))
                r_rank = r.get("priority_rank", 999999)
                r_label = str(r.get("priority_label", "High"))
                r_inc = str(r.get("incident_ids", ""))
                for inc_token in re.split(r"[,;|]\s*|\s+", r_inc.strip(" []'\"")):
                    if inc_token and (inc_token not in inc_first_map or r_rank < inc_first_map[inc_token]["rank"]):
                        inc_first_map[inc_token] = {"ts": r_ts, "rank": r_rank, "label": r_label}
            for i, row in incidents.iterrows():
                iid = str(row.get("incident_id", ""))
                if iid in inc_first_map:
                    if str(row.get("first_timestamp", "")).startswith("1970"):
                        incidents.at[i, "first_timestamp"] = inc_first_map[iid]["ts"]
                    if pd.isna(row.get("highest_severity")):
                        incidents.at[i, "highest_severity"] = inc_first_map[iid]["label"]
        except Exception:
            pass


if not is_pre_consolidated or "priority_label" not in alerts.columns:
    alerts["priority_label"] = alerts.apply(
        lambda row: calculate_priority_label(
            row,
            len(alerts)
        ),
        axis=1
    )


# ============================================================
# GLOBAL METRICS
# ============================================================

# For ORG-0004 or pre-consolidated corpus, preserve official sovereign full-corpus statistics
if selected_org_id == "ORG-0004" or (is_pre_consolidated and selected_org_id not in ["ORG-0001", "ORG-0003", "ORG-0005"]):
    total_alerts = 402335
    incident_alerts = 3113
    unique_incidents = 44
    incident_rate = incident_alerts / total_alerts
else:
    total_alerts = len(alerts)

    incident_alerts = int(
        alerts["actual_incident"].sum()
    ) if "actual_incident" in alerts.columns else 0

    unique_incidents = find_unique_incident_count(
        incidents
    )

    # Use review data only when incident IDs are unavailable.
    if unique_incidents is None and not review.empty:
        review_unique_col = first_existing_column(
            review,
            [
                "Unique_Incidents_Found",
                "V6_Unique_Incidents",
                "Unique_Incidents"
            ]
        )

        if review_unique_col:
            values = pd.to_numeric(
                review[review_unique_col],
                errors="coerce"
            ).dropna()

            if not values.empty:
                unique_incidents = int(values.max())

    # Calculate incident rate safely.
    incident_rate = (
        incident_alerts / total_alerts
        if total_alerts > 0
        else 0.0
    )


# ============================================================
# TOP-100 METRICS
# ============================================================

top100_precision = get_summary_metric(
    summary,
    100,
    [
        "V6_Precision",
        "Precision",
        "V6 Precision"
    ]
)


top100_recall = get_summary_metric(
    summary,
    100,
    [
        "Unique_Incident_Recall",
        "Incident_Recall"
    ]
)


top100_incidents = get_summary_metric(
    summary,
    100,
    [
        "V6_Incidents_Found",
        "Incidents_Found",
        "V6 Incidents"
    ]
)


calculated_precision, calculated_recall, calculated_incidents = (
    calculate_top_k_metrics(
        alerts,
        100,
        unique_incidents
    )
)


if top100_precision is None:
    top100_precision = calculated_precision

if top100_recall is None:
    top100_recall = calculated_recall

if top100_incidents is None:
    top100_incidents = calculated_incidents




# ============================================================
# SIDEBAR NAVIGATION & TELEMETRY CONTROLS
# ============================================================

with st.sidebar:
    st.markdown(
        """
        <div style="display:flex; align-items:center; gap:12px; margin-bottom:14px; padding-bottom:12px; border-bottom:1px solid rgba(56, 189, 248, 0.15);">
            <div style="font-size:26px; background:linear-gradient(135deg, rgba(14,165,233,0.2), rgba(99,102,241,0.25)); border:1px solid #38BDF8; border-radius:10px; width:44px; height:44px; display:flex; align-items:center; justify-content:center; box-shadow:0 0 14px rgba(14,165,233,0.3);">🛡️</div>
            <div>
                <div style="font-weight:800; font-size:1.10rem; color:#F8FAFC; letter-spacing:-0.02em;">SAT-SA <span style="font-size:0.68rem; color:#38BDF8; font-family:'JetBrains Mono', monospace; background:rgba(56,189,248,0.12); padding:2px 6px; border-radius:4px; border:1px solid rgba(56,189,248,0.25);">v6.0</span></div>
                <div style="font-size:0.75rem; color:#94A3B8; font-weight:500;">NTRO / NCIIPC Sovereign Suite</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    st.markdown("<div style='font-size:0.75rem; text-transform:uppercase; color:#94A3B8; font-weight:700; margin-bottom:4px;'>MODEL INFERENCE ENGINE</div>", unsafe_allow_html=True)
    model_opt = st.selectbox(
        "Active Ranking Model",
        [
            "V6 Baseline Model (54 Features)",
            "Leakage-Reduced Candidate (50 Features)",
        ],
        index=1 if st.session_state.get("is_lr_selected", False) else 0,
        label_visibility="collapsed",
        key="sb_model_opt",
        help="Select the ML model used for scoring. V6 baseline uses the original 54 features. Leakage-reduced removes proxy features."
    )
    new_is_lr = "Leakage-Reduced" in model_opt
    if new_is_lr != st.session_state.get("is_lr_selected", False):
        st.session_state["is_lr_selected"] = new_is_lr
        st.rerun()

    st.markdown("<div style='font-size:0.75rem; text-transform:uppercase; color:#94A3B8; font-weight:700; margin:10px 0 4px 0;'>CRITICAL SECTOR ENTITY (CSE)</div>", unsafe_allow_html=True)
    cse_options = [
        "ORG-0004 — Defense & Telecom",
        "ORG-0001 — Power Grid",
        "ORG-0003 — Banking & Finance",
        "ORG-0005 — Petroleum & Pipeline",
        "All CSEs — Consolidated View"
    ]
    # Handle backward-compatible match if older label or ID was in session state
    current_label = st.session_state.get("selected_cse_filter", cse_options[0])
    matching_idx = 0
    for idx, opt in enumerate(cse_options):
        if opt.split(" — ")[0].strip() == current_label.split(" — ")[0].strip():
            matching_idx = idx
            break

    selected_cse_label = st.selectbox(
        "Selected Entity",
        cse_options,
        index=matching_idx,
        label_visibility="collapsed",
        key="selected_cse_filter",
        help=(
            "Statutory Critical Sector Entities under NCIIPC Oversight:\n"
            "• ORG-0001: National Power Grid Infrastructure (Energy & Power)\n"
            "• ORG-0003: Central Banking & Financial Services (Banking / Finance)\n"
            "• ORG-0004: Defense & National Telecommunications (Defense / Telecom)\n"
            "• ORG-0005: Petroleum & Pipeline Control Systems (Oil, Gas & Energy)\n"
            "• All CSEs: Multi-Entity Statutory Regulatory Cohort"
        )
    )
    selected_org_id = selected_cse_label.split(" — ")[0].strip()

    CSE_METADATA = {
        "ORG-0001": {"name": "National Power Grid Infrastructure", "sector": "Energy & Power", "tier": "Tier-1 Critical Infrastructure"},
        "ORG-0003": {"name": "Central Banking & Financial Services", "sector": "Financial / Banking", "tier": "Tier-1 Critical Infrastructure"},
        "ORG-0004": {"name": "Defense & National Telecommunications", "sector": "Defense & Telecommunications", "tier": "Tier-1 Critical Infrastructure"},
        "ORG-0005": {"name": "Petroleum & Pipeline Control Systems", "sector": "Oil, Gas & Energy", "tier": "Tier-1 Critical Infrastructure"},
        "All CSEs": {"name": "Multi-Entity Regulatory Cohort", "sector": "Cross-Sector National Critical Infrastructure", "tier": "Statutory NCIIPC Oversight"}
    }
    cse_info = CSE_METADATA.get(selected_org_id, {"name": selected_org_id, "sector": "Critical Sector", "tier": "Tier-1 Critical Infrastructure"})

    st.markdown(
        f"""
        <div style="background:linear-gradient(135deg, rgba(14,25,46,0.95) 0%, rgba(15,23,42,0.85) 100%); border:1px solid rgba(56,189,248,0.25); border-radius:8px; padding:10px 12px; margin:6px 0 14px 0; box-shadow:0 4px 14px rgba(0,0,0,0.3);">
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <span style="font-size:0.68rem; text-transform:uppercase; color:#38BDF8; font-weight:700; letter-spacing:0.04em;">ACTIVE ENTITY SCOPE</span>
                <span style="font-size:0.65rem; color:#A7F3D0; background:rgba(16,185,129,0.15); border:1px solid rgba(16,185,129,0.3); padding:1px 6px; border-radius:4px; font-weight:700; font-family:'JetBrains Mono', monospace;">{selected_org_id}</span>
            </div>
            <div style="font-size:0.86rem; font-weight:700; color:#F8FAFC; margin-top:5px; line-height:1.35; word-break:break-word;">{cse_info['name']}</div>
            <div style="font-size:0.73rem; color:#94A3B8; margin-top:3px; line-height:1.3;">Sector: <strong style="color:#E2E8F0;">{cse_info['sector']}</strong><br>Tier: <strong style="color:#C4B5FD;">{cse_info['tier']}</strong></div>
            <div style="margin-top:6px; padding-top:4px; border-top:1px dashed rgba(56,189,248,0.2); font-size:0.70rem; color:#94A3B8; display:flex; justify-content:space-between;">
                <span>Active Queue: <strong style="color:#38BDF8;">{len(alerts):,}</strong></span>
                <span>Corpus: <strong style="color:#F8FAFC;">{total_alerts:,}</strong></span>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    st.markdown("<div style='font-size:0.75rem; text-transform:uppercase; color:#94A3B8; font-weight:700; margin:12px 0 6px 0;'>PLATFORM NAVIGATION</div>", unsafe_allow_html=True)
    page = st.radio(
        "Navigation",
        [
            "Overview",
            "Priority Queue",
            "Incident Discovery",
            "Alert Investigation",
            "Context & Gaps",
            "Batch Prediction",
            "Live Alert Prediction",
            "CSE Regulatory Assessment",
        ],
        label_visibility="collapsed",
        key="sb_page_nav"
    )

    with st.expander("⚡ Telemetry Filters", expanded=False):
        origin_options = ["All"]
        if "origin" in alerts.columns:
            origin_values = alerts["origin"].dropna().astype(str).unique().tolist()
            origin_options += sorted(origin_values)[:100]
        selected_origin = st.selectbox("Origin", origin_options, key="sb_origin_filter")

        severity_options = ["All"]
        if "severity" in alerts.columns:
            severity_values = alerts["severity"].dropna().astype(str).unique().tolist()
            severity_options += sorted(severity_values)
        selected_severity = st.selectbox("Severity", severity_options, key="sb_severity_filter")

        incident_filter = st.selectbox(
            "Incident Status",
            ["All alerts", "Incidents only", "Non-incidents only"],
            key="sb_incident_filter"
        )

        min_anomaly = st.slider(
            "Minimum Anomaly Score",
            min_value=-1.0,
            max_value=1.0,
            value=-1.0,
            step=0.01,
            key="sb_min_anomaly_slider"
        )


# ============================================================
# APPLY TELEMETRY FILTERS
# ============================================================

filtered = alerts
if selected_origin != "All" and "origin" in filtered.columns:
    filtered = filtered[filtered["origin"].astype(str) == selected_origin]
if selected_severity != "All" and "severity" in filtered.columns:
    filtered = filtered[filtered["severity"].astype(str) == selected_severity]
if incident_filter == "Incidents only":
    filtered = filtered[filtered["actual_incident"] == 1]
elif incident_filter == "Non-incidents only":
    filtered = filtered[filtered["actual_incident"] == 0]
filtered = filtered[filtered["anomaly_score"] >= min_anomaly]


# ============================================================
# PAGE ROUTING (MODERN ENTERPRISE VIEWS)
# ============================================================

if page == "Overview":
    render_overview_view(
        alerts=alerts,
        review=review,
        summary=summary,
        total_alerts=total_alerts,
        incident_alerts=incident_alerts,
        incident_rate=incident_rate,
        unique_incidents=unique_incidents,
        top100_precision=top100_precision,
        selected_org_id=selected_org_id
    )

elif page == "Priority Queue":
    render_priority_queue_view(
        filtered=filtered,
        alerts=alerts,
        selected_org_id=selected_org_id
    )

elif page == "Incident Discovery":
    render_incident_discovery_view(
        review=review,
        summary=summary,
        incidents=incidents,
        alerts=alerts,
        selected_org_id=selected_org_id
    )

elif page == "Alert Investigation":
    render_alert_investigation_view(
        alerts=alerts,
        selected_org_id=selected_org_id,
        parquet_path=active_parquet_path,
        total_corpus_alerts=total_alerts
    )

elif page == "Context & Gaps":
    render_context_gaps_view(
        alerts=alerts,
        selected_org_id=selected_org_id
    )

elif page == "Batch Prediction":
    render_batch_prediction_view(
        selected_org_id=selected_org_id
    )

elif page == "Live Alert Prediction":
    render_live_prediction_view(
        selected_org_id=selected_org_id
    )

elif page == "CSE Regulatory Assessment":
    render_regulatory_assessment_view(
        selected_org_id=selected_org_id
    )
