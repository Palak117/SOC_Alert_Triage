import pandas as pd
import numpy as np
from pathlib import Path


print("=" * 90)
print("V6 SIH CONTEXT SUMMARY / DASHBOARD-READY DATA")
print("=" * 90)


# ============================================================
# 1. PATHS
# ============================================================

ORIGINAL_TEST_FILE = (
    "data/train_test/test_20.csv"
)

V6_FILE = (
    "data/scored/test_unsupervised_v6_validated.csv"
)

CONTEXT_FILE = (
    "data/scored/final_v6_sih_context_layer.csv"
)

OUTPUT_FILE = (
    "data/scored/final_v6_sih_dashboard_alerts.csv"
)

SUMMARY_FILE = (
    "data/scored/final_v6_sih_dashboard_summary.csv"
)

INCIDENT_FILE = (
    "data/scored/final_v6_sih_dashboard_incidents.csv"
)

REVIEW_FILE = (
    "data/scored/final_v6_sih_dashboard_review_fractions.csv"
)

REPORT_FILE = (
    "data/scored/final_v6_sih_dashboard_report.txt"
)


# ============================================================
# 2. LOAD AUTHORITATIVE DATA
# ============================================================

print("\nLoading original test data...")

original = pd.read_csv(
    ORIGINAL_TEST_FILE,
    low_memory=False
)

print(
    f"Original test records: {len(original):,}"
)


print("\nLoading authoritative V6 validated results...")

v6 = pd.read_csv(
    V6_FILE,
    low_memory=False
)

print(
    f"V6 records: {len(v6):,}"
)


print("\nLoading SIH context layer...")

context = pd.read_csv(
    CONTEXT_FILE,
    low_memory=False
)

print(
    f"Context records: {len(context):,}"
)


# ============================================================
# 3. BASIC FILE SAFETY
# ============================================================

print("\n" + "=" * 90)
print("BASIC FILE SAFETY")
print("=" * 90)


if len(original) != len(v6):
    raise ValueError(
        "Original test and V6 row counts do not match."
    )

print("Original / V6 row count: PASS")


if len(original) != len(context):
    raise ValueError(
        "Original test and context layer row counts do not match."
    )

print("Original / context row count: PASS")


required_v6 = [
    "_alert_id",
    "anomaly_score",
    "priority_score",
    "priority_rank",
    "actual_incident"
]


for column in required_v6:

    if column not in v6.columns:

        raise ValueError(
            f"Missing required V6 column: {column}"
        )

    print(
        f"V6 '{column}': PASS"
    )


if not v6["_alert_id"].is_unique:

    raise ValueError(
        "V6 _alert_id is not unique."
    )

print("V6 _alert_id uniqueness: PASS")


# ============================================================
# 4. CREATE ORIGINAL ROW ID
# ============================================================

print("\nCreating authoritative original-row identity...")


original = original.reset_index(
    drop=True
)

original["_alert_id"] = np.arange(
    len(original)
)


if not original["_alert_id"].is_unique:

    raise ValueError(
        "Generated original _alert_id is not unique."
    )

print(
    "Original _alert_id: PASS"
)


# ============================================================
# 5. VERIFY V6 ALERT ID RANGE
# ============================================================

print("\nVerifying V6 alert ID range...")


expected_ids = np.arange(
    len(original)
)

actual_ids = (
    v6["_alert_id"]
    .astype(int)
    .to_numpy()
)

if not np.array_equal(
    np.sort(actual_ids),
    expected_ids
):

    raise ValueError(
        "V6 _alert_id values do not cover "
        "the original rows exactly."
    )

print(
    "V6 _alert_id range: PASS"
)


# ============================================================
# 6. VERIFY CONTEXT ID
# ============================================================

if "_alert_id" in context.columns:

    context_ids = (
        context["_alert_id"]
        .astype(int)
        .to_numpy()
    )

    if not np.array_equal(
        np.sort(context_ids),
        expected_ids
    ):

        raise ValueError(
            "Context _alert_id values do not "
            "cover the original rows exactly."
        )

    print(
        "Context _alert_id range: PASS"
    )

else:

    print(
        "Context _alert_id not present."
    )

    print(
        "Context will be aligned by row position."
    )

    context["_alert_id"] = np.arange(
        len(context)
    )


# ============================================================
# 7. VERIFY V6 RANKING INTEGRITY
# ============================================================

print("\n" + "=" * 90)
print("V6 RANKING INTEGRITY")
print("=" * 90)


v6_check = (
    v6
    .sort_values(
        "priority_rank",
        ascending=True
    )
    .reset_index(drop=True)
)


expected_ranks = np.arange(
    1,
    len(v6) + 1
)


if not np.array_equal(
    v6_check["priority_rank"]
    .astype(int)
    .to_numpy(),
    expected_ranks
):

    raise ValueError(
        "V6 priority ranks are not sequential."
    )

print(
    "V6 priority ranks: PASS"
)


priority_scores = (
    v6_check["priority_score"]
    .to_numpy()
)


if not np.all(
    priority_scores[:-1]
    >=
    priority_scores[1:]
):

    raise ValueError(
        "V6 priority scores are not "
        "descending."
    )

print(
    "V6 priority-score order: PASS"
)


anomaly_scores = (
    v6_check["anomaly_score"]
    .to_numpy()
)


if not np.all(
    anomaly_scores[:-1]
    >=
    anomaly_scores[1:]
):

    raise ValueError(
        "V6 anomaly scores are not "
        "descending."
    )

print(
    "V6 anomaly-score order: PASS"
)


# ============================================================
# 8. VERIFY ORIGINAL SIH COLUMNS
# ============================================================

print("\n" + "=" * 90)
print("ORIGINAL SIH DATA COLUMNS")
print("=" * 90)


required_original = [

    "timestamp",
    "event_time",
    "timestamp_source",

    "origin",
    "org_id",
    "artifact_id",

    "message_type",
    "stream_name",
    "pipeline",

    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",

    "src_host",
    "dst_host",
    "username",

    "action",
    "severity",

    "vendor_code",
    "message_sanitized",

    "label_binary",
    "label_confidence",

    "attack_techniques",
    "attack_tactics",
    "defense_techniques",

    "mo_name",
    "suspicion_score",

    "lifecycle_stage",
    "disposition",
    "disposition_category",

    "is_false_positive",
    "status_name",

    "incident_ids",
    "matched_rules",
    "set_roles",

    "product_name",
    "vendor_name",

    "timestamp_datetime"
]


for column in required_original:

    if column not in original.columns:

        raise ValueError(
            f"Missing original SIH column: {column}"
        )

    print(
        f"{column}: PASS"
    )


# ============================================================
# 9. MERGE ORIGINAL + V6
# ============================================================

print("\n" + "=" * 90)
print("BUILDING AUTHORITATIVE ALERT TABLE")
print("=" * 90)


# ------------------------------------------------------------
# Only bring authoritative V6 fields.
# This prevents accidental replacement of original fields.
# ------------------------------------------------------------

v6_fields = [
    "_alert_id",
    "anomaly_score",
    "priority_score",
    "priority_rank",
    "actual_incident"
]


v6_authoritative = (
    v6[v6_fields]
    .copy()
)


# ------------------------------------------------------------
# Remove any duplicate V6-derived columns from original
# if they somehow exist.
# ------------------------------------------------------------

duplicate_columns = [

    "anomaly_score",
    "priority_score",
    "priority_rank",
    "actual_incident"
]


for column in duplicate_columns:

    if column in original.columns:

        original = original.drop(
            columns=[column]
        )


# ------------------------------------------------------------
# Merge using _alert_id
# ------------------------------------------------------------

alerts = original.merge(
    v6_authoritative,
    on="_alert_id",
    how="inner",
    validate="one_to_one"
)


if len(alerts) != len(original):

    raise ValueError(
        "Original / V6 merge lost rows."
    )


print(
    "Original + V6 merge: PASS"
)

print(
    f"Combined alert records: {len(alerts):,}"
)


# ============================================================
# 10. MERGE CONTEXT LAYER
# ============================================================

print("\nMerging SIH context layer...")


context_columns = [
    column
    for column in context.columns
    if column != "_alert_id"
]


# ------------------------------------------------------------
# Avoid duplicate columns.
# Original data remains authoritative.
# ------------------------------------------------------------

safe_context_columns = []


for column in context_columns:

    if column in alerts.columns:

        # Do not overwrite authoritative fields.
        continue

    safe_context_columns.append(
        column
    )


context_for_merge = context[
    ["_alert_id"] + safe_context_columns
].copy()


alerts = alerts.merge(
    context_for_merge,
    on="_alert_id",
    how="left",
    validate="one_to_one"
)


print(
    "Context merge: PASS"
)


# ============================================================
# 11. TIMESTAMP PREPARATION
# ============================================================

print("\nPreparing timestamps...")


alerts["timestamp_parsed"] = pd.to_datetime(
    alerts["timestamp"],
    errors="coerce"
)


alerts["event_time_parsed"] = pd.to_datetime(
    alerts["event_time"],
    errors="coerce"
)


alerts["timestamp_datetime_parsed"] = pd.to_datetime(
    alerts["timestamp_datetime"],
    errors="coerce"
)


if alerts["timestamp_parsed"].isna().any():

    raise ValueError(
        "Invalid timestamps found."
    )


print(
    "Timestamp parsing: PASS"
)


# ============================================================
# 12. POST-HOC INCIDENT EXTRACTION
# ============================================================

print("\nPreparing post-hoc incident information...")


def extract_incident_ids(value):

    if value is None:
        return []

    if isinstance(
        value,
        (list, tuple, set, np.ndarray)
    ):

        result = []

        for item in value:

            if item is None:
                continue

            if isinstance(
                item,
                (list, tuple, set, np.ndarray)
            ):

                for nested in item:

                    if nested is None:
                        continue

                    text = str(
                        nested
                    ).strip()

                    if text:
                        result.append(text)

            else:

                text = str(
                    item
                ).strip()

                if text:
                    result.append(text)

        return result

    try:

        missing = pd.isna(
            value
        )

        if isinstance(
            missing,
            (bool, np.bool_)
        ):

            if missing:
                return []

    except (
        TypeError,
        ValueError
    ):

        pass

    text = str(
        value
    ).strip()


    if text == "":
        return []


    if text.lower() in {
        "nan",
        "none",
        "null",
        "[]",
        "{}"
    }:

        return []


    # --------------------------------------------------------
    # Python-list style string
    # --------------------------------------------------------

    if (
        text.startswith("[")
        and
        text.endswith("]")
    ):

        text = text[1:-1].strip()

        if not text:
            return []

        parts = text.split(",")

        result = []

        for part in parts:

            part = (
                part
                .strip()
                .strip("'")
                .strip('"')
            )

            if part:
                result.append(part)

        return result


    # --------------------------------------------------------
    # Semicolon-separated
    # --------------------------------------------------------

    if ";" in text:

        return [
            x.strip()
            for x in text.split(";")
            if x.strip()
        ]


    return [text]


alerts["incident_id_list"] = (
    alerts["incident_ids"]
    .apply(extract_incident_ids)
)


alerts["actual_incident_posthoc"] = (
    alerts["incident_id_list"]
    .apply(
        lambda x: len(x) > 0
    )
)


# ------------------------------------------------------------
# Verify post-hoc ground truth against V6 validation
# ------------------------------------------------------------

if not np.array_equal(
    alerts["actual_incident_posthoc"]
    .astype(bool)
    .to_numpy(),

    alerts["actual_incident"]
    .astype(bool)
    .to_numpy()
):

    raise ValueError(
        "Post-hoc incident ground truth "
        "does not match V6 validated results."
    )


print(
    "Post-hoc incident alignment: PASS"
)


# ============================================================
# 13. INCIDENT COUNTS
# ============================================================

total_alerts = len(alerts)


incident_alerts = int(
    alerts["actual_incident"].sum()
)


incident_rate = (
    incident_alerts
    /
    total_alerts
)


all_incidents = set()


for ids in alerts["incident_id_list"]:

    for incident_id in ids:

        all_incidents.add(
            incident_id
        )


total_unique_incidents = len(
    all_incidents
)


print("\n" + "=" * 90)
print("DATASET SUMMARY")
print("=" * 90)


print(
    f"Total alerts       : {total_alerts:,}"
)

print(
    f"Incident alerts    : {incident_alerts:,}"
)

print(
    f"Incident rate      : {incident_rate:.4%}"
)

print(
    f"Unique incidents   : {total_unique_incidents:,}"
)


# ============================================================
# 14. REVIEW-FRACTION FIELDS
# ============================================================

print("\nBuilding review-fraction fields...")


alerts["review_fraction"] = (
    alerts["priority_rank"]
    /
    total_alerts
)


alerts["alerts_avoided_if_reviewed"] = (
    total_alerts
    -
    alerts["priority_rank"]
)


alerts["alerts_avoided_percentage"] = (
    alerts["alerts_avoided_if_reviewed"]
    /
    total_alerts
)


# ============================================================
# 15. ENTITY / TELEMETRY CONTEXT
# ============================================================

print("\nBuilding dashboard context fields...")


# ------------------------------------------------------------
# Entity presence
# ------------------------------------------------------------

entity_columns = [
    "src_ip",
    "dst_ip",
    "src_host",
    "dst_host",
    "username",
    "org_id",
    "artifact_id",
    "product_name",
    "vendor_name"
]


for column in entity_columns:

    alerts[f"has_{column}"] = (
        alerts[column]
        .fillna("")
        .astype(str)
        .str.strip()
        .ne("")
    )


alerts["entity_context_count"] = (
    alerts[
        [
            f"has_{column}"
            for column in entity_columns
        ]
    ]
    .sum(axis=1)
)


# ------------------------------------------------------------
# Telemetry completeness
# ------------------------------------------------------------

telemetry_columns = [
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "src_host",
    "dst_host",
    "username",
    "action",
    "product_name",
    "vendor_name",
    "message_type"
]


for column in telemetry_columns:

    alerts[f"has_telemetry_{column}"] = (
        alerts[column]
        .fillna("")
        .astype(str)
        .str.strip()
        .ne("")
    )


alerts["telemetry_fields_available"] = (
    alerts[
        [
            f"has_telemetry_{column}"
            for column in telemetry_columns
        ]
    ]
    .sum(axis=1)
)


alerts["low_telemetry_context"] = (
    alerts["telemetry_fields_available"]
    <= 3
)


# ============================================================
# 16. INVESTIGATION / CLOSURE CONTEXT
# ============================================================

print(
    "Building investigation and closure context..."
)


def nonempty_series(series):

    return (
        series
        .fillna("")
        .astype(str)
        .str.strip()
        .ne("")
    )


alerts["has_action"] = nonempty_series(
    alerts["action"]
)


alerts["has_disposition"] = nonempty_series(
    alerts["disposition"]
)


alerts["has_disposition_category"] = (
    nonempty_series(
        alerts["disposition_category"]
    )
)


alerts["has_lifecycle_stage"] = (
    nonempty_series(
        alerts["lifecycle_stage"]
    )
)


alerts["has_status"] = nonempty_series(
    alerts["status_name"]
)


alerts["has_matched_rules"] = (
    nonempty_series(
        alerts["matched_rules"]
    )
)


alerts["has_set_roles"] = nonempty_series(
    alerts["set_roles"]
)


alerts["has_attack_techniques"] = (
    nonempty_series(
        alerts["attack_techniques"]
    )
)


alerts["has_attack_tactics"] = (
    nonempty_series(
        alerts["attack_tactics"]
    )
)


alerts["investigation_context_count"] = (
    alerts[
        [
            "has_action",
            "has_disposition",
            "has_disposition_category",
            "has_lifecycle_stage",
            "has_status",
            "has_matched_rules",
            "has_set_roles",
            "has_attack_techniques",
            "has_attack_tactics"
        ]
    ]
    .sum(axis=1)
)


# ============================================================
# 17. SEVERITY NORMALIZATION
# ============================================================

severity_text = (
    alerts["severity"]
    .fillna("")
    .astype(str)
    .str.lower()
    .str.strip()
)


alerts["severity_normalized"] = (
    severity_text
)


severity_map = {
    "critical": 4,
    "crit": 4,
    "high": 3,
    "medium": 2,
    "moderate": 2,
    "low": 1,
    "info": 0,
    "informational": 0
}


alerts["severity_numeric"] = (
    severity_text
    .map(severity_map)
)


# ============================================================
# 18. DISPOSITION / STATUS NORMALIZATION
# ============================================================

alerts["disposition_normalized"] = (
    alerts["disposition"]
    .fillna("")
    .astype(str)
    .str.lower()
    .str.strip()
)


alerts["status_normalized"] = (
    alerts["status_name"]
    .fillna("")
    .astype(str)
    .str.lower()
    .str.strip()
)


alerts["lifecycle_normalized"] = (
    alerts["lifecycle_stage"]
    .fillna("")
    .astype(str)
    .str.lower()
    .str.strip()
)


# ============================================================
# 19. DASHBOARD PRIORITY BUCKET
# ============================================================

alerts["priority_bucket"] = pd.cut(
    alerts["priority_rank"],
    bins=[
        0,
        100,
        500,
        1000,
        5000,
        10000,
        25000,
        100000,
        total_alerts
    ],
    labels=[
        "Top-100",
        "Top-500",
        "Top-1,000",
        "Top-5,000",
        "Top-10,000",
        "Top-25,000",
        "Top-100,000",
        "Remaining"
    ],
    include_lowest=True
)


# ============================================================
# 20. FINAL DATA QUALITY CHECKS
# ============================================================

print("\n" + "=" * 90)
print("FINAL DATA QUALITY CHECKS")
print("=" * 90)


if len(alerts) != total_alerts:

    raise ValueError(
        "Final alert count changed."
    )

print(
    "Final row count: PASS"
)


if not alerts["_alert_id"].is_unique:

    raise ValueError(
        "Final _alert_id is not unique."
    )

print(
    "Alert identity uniqueness: PASS"
)


# ------------------------------------------------------------
# V6 scores must remain identical.
# ------------------------------------------------------------

original_v6 = (
    v6
    .set_index("_alert_id")
    .sort_index()
)


final_v6 = (
    alerts
    .set_index("_alert_id")
    .sort_index()
)


for column in [
    "anomaly_score",
    "priority_score",
    "priority_rank"
]:

    if not np.allclose(
        original_v6[column].to_numpy(),
        final_v6[column].to_numpy(),
        equal_nan=True
    ):

        raise ValueError(
            f"V6 {column} changed during "
            "dashboard preparation."
        )

    print(
        f"V6 {column}: UNCHANGED / PASS"
    )


# ============================================================
# 21. BUILD TOP-K SUMMARY
# ============================================================

print("\n" + "=" * 90)
print("TOP-K DASHBOARD SUMMARY")
print("=" * 90)


top_ks = [
    100,
    500,
    1000,
    5000,
    10000,
    25000,
    50000,
    100000
]


top_k_rows = []


for k in top_ks:

    k_actual = min(
        k,
        total_alerts
    )


    top = (
        alerts
        .sort_values(
            "priority_rank",
            ascending=True
        )
        .head(k_actual)
    )


    found_incidents = int(
        top["actual_incident"].sum()
    )


    precision = (
        found_incidents
        /
        k_actual
    )


    recall = (
        found_incidents
        /
        incident_alerts
        if incident_alerts > 0
        else 0
    )


    unique_found = set()


    for ids in top["incident_id_list"]:

        for incident_id in ids:

            unique_found.add(
                incident_id
            )


    unique_recall = (
        len(unique_found)
        /
        total_unique_incidents
        if total_unique_incidents > 0
        else 0
    )


    alerts_avoided = (
        total_alerts
        -
        k_actual
    )


    top_k_rows.append({

        "K": k_actual,

        "Incidents_Found":
            found_incidents,

        "Precision":
            precision,

        "Incident_Recall":
            recall,

        "Unique_Incidents_Found":
            len(unique_found),

        "Unique_Incident_Recall":
            unique_recall,

        "Alerts_Avoided":
            alerts_avoided,

        "Alerts_Avoided_Percentage":
            alerts_avoided
            /
            total_alerts
    })


top_k_summary = pd.DataFrame(
    top_k_rows
)


# ============================================================
# 22. PRINT TOP-K SUMMARY
# ============================================================

print(
    "\nK       | Incidents | Precision | Recall | "
    "Unique Incidents | Unique Recall | Alerts Avoided"
)

print(
    "-" * 100
)


for _, row in top_k_summary.iterrows():

    print(

        f"{int(row['K']):<7} | "

        f"{int(row['Incidents_Found']):<9} | "

        f"{row['Precision'] * 100:>8.2f}% | "

        f"{row['Incident_Recall'] * 100:>6.2f}% | "

        f"{int(row['Unique_Incidents_Found']):<15} | "

        f"{row['Unique_Incident_Recall'] * 100:>11.2f}% | "

        f"{int(row['Alerts_Avoided']):,}"
    )


# ============================================================
# 23. REVIEW FRACTION SUMMARY
# ============================================================

print("\n" + "=" * 90)
print("REVIEW FRACTION SUMMARY")
print("=" * 90)


review_fractions = [
    0.001,
    0.005,
    0.01,
    0.02,
    0.05,
    0.10,
    0.25
]


review_rows = []


ranked = (
    alerts
    .sort_values(
        "priority_rank",
        ascending=True
    )
    .reset_index(drop=True)
)


for fraction in review_fractions:

    k = max(
        1,
        int(
            total_alerts
            *
            fraction
        )
    )


    top = ranked.head(k)


    found_incidents = int(
        top["actual_incident"].sum()
    )


    unique_found = set()


    for ids in top["incident_id_list"]:

        for incident_id in ids:

            unique_found.add(
                incident_id
            )


    unique_recall = (
        len(unique_found)
        /
        total_unique_incidents
        if total_unique_incidents > 0
        else 0
    )


    review_rows.append({

        "Review_Fraction":
            fraction,

        "Alerts_Reviewed":
            k,

        "Incidents_Found":
            found_incidents,

        "Unique_Incidents_Found":
            len(unique_found),

        "Unique_Incident_Recall":
            unique_recall,

        "Alerts_Avoided":
            total_alerts - k,

        "Alerts_Avoided_Percentage":
            (total_alerts - k)
            /
            total_alerts
    })


review_summary = pd.DataFrame(
    review_rows
)


print(
    "\nReview % | Alerts | Unique Incidents | "
    "Unique Recall | Alerts Avoided"
)

print(
    "-" * 85
)


for _, row in review_summary.iterrows():

    print(

        f"{row['Review_Fraction'] * 100:>7.1f}% | "

        f"{int(row['Alerts_Reviewed']):>7,} | "

        f"{int(row['Unique_Incidents_Found']):>16} | "

        f"{row['Unique_Incident_Recall'] * 100:>11.2f}% | "

        f"{int(row['Alerts_Avoided']):>14,}"
    )


# ============================================================
# 24. INCIDENT-LEVEL DASHBOARD TABLE
# ============================================================

print("\n" + "=" * 90)
print("BUILDING INCIDENT-LEVEL DASHBOARD TABLE")
print("=" * 90)


incident_rows = []


for incident_id in sorted(
    all_incidents
):

    incident_alerts_df = alerts[
        alerts["incident_id_list"]
        .apply(
            lambda ids:
            incident_id in ids
        )
    ]


    if len(incident_alerts_df) == 0:

        continue


    best_row = (
        incident_alerts_df
        .sort_values(
            "priority_rank",
            ascending=True
        )
        .iloc[0]
    )


    incident_rows.append({

        "incident_id":
            incident_id,

        "alert_count":
            len(incident_alerts_df),

        "first_priority_rank":
            int(
                incident_alerts_df[
                    "priority_rank"
                ].min()
            ),

        "best_anomaly_score":
            float(
                incident_alerts_df[
                    "anomaly_score"
                ].max()
            ),

        "best_priority_score":
            float(
                incident_alerts_df[
                    "priority_score"
                ].max()
            ),

        "first_timestamp":
            incident_alerts_df[
                "timestamp_parsed"
            ].min(),

        "highest_severity":
            incident_alerts_df[
                "severity_numeric"
            ].max(),

        "origin":
            str(
                best_row["origin"]
            ),

        "product_name":
            str(
                best_row["product_name"]
            ),

        "vendor_name":
            str(
                best_row["vendor_name"]
            ),

        "lifecycle_stage":
            str(
                best_row["lifecycle_stage"]
            ),

        "disposition":
            str(
                best_row["disposition"]
            ),

        "status_name":
            str(
                best_row["status_name"]
            )
    })


incident_summary = pd.DataFrame(
    incident_rows
)


if len(incident_summary) > 0:

    incident_summary = (
        incident_summary
        .sort_values(
            "first_priority_rank",
            ascending=True
        )
        .reset_index(drop=True)
    )


print(
    f"Incident dashboard rows: "
    f"{len(incident_summary):,}"
)


# ============================================================
# 25. SAVE FILES
# ============================================================

print("\n" + "=" * 90)
print("SAVING DASHBOARD-READY FILES")
print("=" * 90)


Path(
    "data/scored"
).mkdir(
    parents=True,
    exist_ok=True
)


# ------------------------------------------------------------
# Main alert-level dashboard file
# ------------------------------------------------------------

alerts_to_save = alerts.copy()


# Lists are converted to strings for CSV compatibility.

alerts_to_save[
    "incident_id_list"
] = (
    alerts_to_save[
        "incident_id_list"
    ]
    .apply(
        lambda x:
        ";".join(x)
    )
)


alerts_to_save.to_csv(
    OUTPUT_FILE,
    index=False
)


print(
    f"1. Alert dashboard file:\n"
    f"   {OUTPUT_FILE}"
)


# ------------------------------------------------------------
# Top-K summary
# ------------------------------------------------------------

top_k_summary.to_csv(
    SUMMARY_FILE,
    index=False
)


print(
    f"2. Top-K summary:\n"
    f"   {SUMMARY_FILE}"
)


# ------------------------------------------------------------
# Incident summary
# ------------------------------------------------------------

incident_summary.to_csv(
    INCIDENT_FILE,
    index=False
)


print(
    f"3. Incident summary:\n"
    f"   {INCIDENT_FILE}"
)


# ------------------------------------------------------------
# Review fraction
# ------------------------------------------------------------

review_summary.to_csv(
    REVIEW_FILE,
    index=False
)


print(
    f"4. Review-fraction summary:\n"
    f"   {REVIEW_FILE}"
)


# ============================================================
# 26. HUMAN-READABLE REPORT
# ============================================================

with open(
    REPORT_FILE,
    "w",
    encoding="utf-8"
) as report:

    report.write(
        "FINAL V6 SIH DASHBOARD-READY REPORT\n"
    )

    report.write(
        "=" * 90
        +
        "\n\n"
    )


    report.write(
        "DATASET\n"
    )

    report.write(
        f"Total alerts: "
        f"{total_alerts:,}\n"
    )

    report.write(
        f"Incident alerts: "
        f"{incident_alerts:,}\n"
    )

    report.write(
        f"Incident rate: "
        f"{incident_rate:.4%}\n"
    )

    report.write(
        f"Unique incidents: "
        f"{total_unique_incidents:,}\n\n"
    )


    report.write(
        "MODEL\n"
    )

    report.write(
        "Isolation Forest\n"
    )

    report.write(
        "Unsupervised learning\n"
    )

    report.write(
        "300 trees\n"
    )

    report.write(
        "Random state = 42\n\n"
    )


    report.write(
        "GROUND TRUTH POLICY\n"
    )

    report.write(
        "Incident information was used only "
        "for post-hoc evaluation.\n"
    )

    report.write(
        "No incident information was used "
        "during model training, anomaly "
        "scoring, priority scoring, or "
        "priority ranking.\n\n"
    )


    report.write(
        "TOP-K RESULTS\n"
    )

    for _, row in top_k_summary.iterrows():

        report.write(

            f"Top-{int(row['K']):,}: "

            f"incidents="
            f"{int(row['Incidents_Found']):,}, "

            f"precision="
            f"{row['Precision'] * 100:.2f}%, "

            f"recall="
            f"{row['Incident_Recall'] * 100:.2f}%, "

            f"unique incidents="
            f"{int(row['Unique_Incidents_Found']):,}, "

            f"unique recall="
            f"{row['Unique_Incident_Recall'] * 100:.2f}%\n"
        )


    report.write(
        "\nREVIEW FRACTIONS\n"
    )


    for _, row in review_summary.iterrows():

        report.write(

            f"{row['Review_Fraction'] * 100:.1f}% review: "

            f"{int(row['Alerts_Reviewed']):,} alerts reviewed, "

            f"{int(row['Unique_Incidents_Found']):,} unique incidents, "

            f"unique recall="
            f"{row['Unique_Incident_Recall'] * 100:.2f}%, "

            f"alerts avoided="
            f"{int(row['Alerts_Avoided']):,}\n"
        )


    report.write(
        "\nSAFETY\n"
    )

    report.write(
        "V6 anomaly scores unchanged.\n"
    )

    report.write(
        "V6 priority scores unchanged.\n"
    )

    report.write(
        "V6 priority ranks unchanged.\n"
    )

    report.write(
        "No model retraining performed.\n"
    )

    report.write(
        "Ground truth remains post-hoc only.\n"
    )

    report.write(
        "Original SIH context fields remain "
        "available for dashboard investigation.\n"
    )


# ============================================================
# 27. FINAL CONSOLE OUTPUT
# ============================================================

print("\n" + "=" * 90)
print("FINAL SIH DASHBOARD-READY LAYER COMPLETE")
print("=" * 90)


print(
    f"\nAlerts available for dashboard : "
    f"{total_alerts:,}"
)

print(
    f"Incident alerts                : "
    f"{incident_alerts:,}"
)

print(
    f"Unique incidents               : "
    f"{total_unique_incidents:,}"
)


print(
    "\nV6 anomaly scores              : UNCHANGED"
)

print(
    "V6 priority scores             : UNCHANGED"
)

print(
    "V6 priority ranking            : UNCHANGED"
)

print(
    "Model retrained                : NO"
)

print(
    "Ground truth usage             : POST-HOC ONLY"
)


print(
    "\nDashboard-ready files created:"
)

print(
    f"1. {OUTPUT_FILE}"
)

print(
    f"2. {SUMMARY_FILE}"
)

print(
    f"3. {INCIDENT_FILE}"
)

print(
    f"4. {REVIEW_FILE}"
)

print(
    f"5. {REPORT_FILE}"
)


print(
    "\nNext stage: dashboard implementation."
)

print("=" * 90)