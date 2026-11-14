import ast
import json
from pathlib import Path

import numpy as np
import pandas as pd


# ============================================================================
# V6 SIH CONTEXT + EXECUTION-GAP + NEGATIVE-SPACE LAYER
# ============================================================================
#
# IMPORTANT:
#
# This script DOES NOT:
#   - retrain the Isolation Forest
#   - modify anomaly_score
#   - modify priority_score
#   - modify priority_rank
#   - use incident_ids for scoring
#   - use label_binary for scoring
#   - use label_confidence for scoring
#
# It creates a separate SIH supervisory/context layer AFTER V6 scoring.
#
# Ground truth remains post-hoc only.
# ============================================================================


print("=" * 90)
print("V6 SIH CONTEXT / EXECUTION-GAP / NEGATIVE-SPACE LAYER")
print("=" * 90)


# ============================================================================
# 1. PATHS
# ============================================================================

ORIGINAL_TEST = Path(
    "data/train_test/test_20.csv"
)

V6_VALIDATED = Path(
    "data/scored/test_unsupervised_v6_validated.csv"
)

OUTPUT_FILE = Path(
    "data/scored/final_v6_sih_context_layer.csv"
)

REPORT_FILE = Path(
    "data/scored/final_v6_sih_context_report.txt"
)


OUTPUT_FILE.parent.mkdir(
    parents=True,
    exist_ok=True
)


# ============================================================================
# 2. LOAD DATA
# ============================================================================

print("\nLoading original test data...")

original = pd.read_csv(
    ORIGINAL_TEST,
    low_memory=False
)

print(
    f"Original test records: {len(original):,}"
)


print("\nLoading V6 validated results...")

v6 = pd.read_csv(
    V6_VALIDATED,
    low_memory=False
)

print(
    f"V6 validated records: {len(v6):,}"
)


# ============================================================================
# 3. BASIC SAFETY CHECKS
# ============================================================================

print("\n" + "=" * 90)
print("SAFETY CHECKS")
print("=" * 90)


required_original = [
    "timestamp",
    "event_time",
    "origin",
    "message_type",
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
    "lifecycle_stage",
    "disposition",
    "disposition_category",
    "status_name",
    "incident_ids",
    "matched_rules",
    "set_roles",
    "product_name",
    "vendor_name",
    "org_id",
    "artifact_id",
]


required_v6 = [
    "_alert_id",
    "anomaly_score",
    "priority_score",
    "priority_rank",
]


for column in required_original:

    if column not in original.columns:

        raise ValueError(
            f"Missing original test column: {column}"
        )

    print(
        f"Original '{column}': PASS"
    )


for column in required_v6:

    if column not in v6.columns:

        raise ValueError(
            f"Missing V6 column: {column}"
        )

    print(
        f"V6 '{column}': PASS"
    )


if len(original) != len(v6):

    raise ValueError(
        "Original test and V6 row counts do not match."
    )


print(
    "Original / V6 row count match: PASS"
)


if not v6["_alert_id"].is_unique:

    raise ValueError(
        "V6 _alert_id is not unique."
    )


print(
    "V6 _alert_id uniqueness: PASS"
)


expected_ids = np.arange(
    len(original)
)


actual_ids = np.sort(
    v6["_alert_id"].astype(int).to_numpy()
)


if not np.array_equal(
    expected_ids,
    actual_ids
):

    raise ValueError(
        "V6 _alert_id values do not cover 0 -> N-1."
    )


print(
    "V6 _alert_id range: PASS"
)


# ============================================================================
# 4. PRESERVE V6 RANKING
# ============================================================================

print("\nVerifying V6 ranking integrity...")


v6_rank_check = (
    v6
    .sort_values(
        "priority_rank",
        ascending=True
    )
    .reset_index(drop=True)
)


expected_rank = np.arange(
    1,
    len(v6_rank_check) + 1
)


if not np.array_equal(
    v6_rank_check["priority_rank"].astype(int).to_numpy(),
    expected_rank
):

    raise ValueError(
        "V6 priority ranks are not sequential."
    )


print(
    "V6 priority ranks: PASS"
)


priority_values = (
    v6_rank_check["priority_score"]
    .to_numpy()
)


if not np.all(
    priority_values[:-1]
    >=
    priority_values[1:]
):

    raise ValueError(
        "V6 priority-score ordering changed."
    )


print(
    "V6 priority-score ordering: PASS"
)


# ============================================================================
# 5. MAP ORIGINAL ROWS TO V6 USING _alert_id
# ============================================================================

print("\nMapping original rows to V6 results...")


original = original.reset_index(
    drop=True
)

original["_alert_id"] = np.arange(
    len(original)
)


# Merge only for context creation.
# V6 scores themselves are copied unchanged.

v6_context_columns = [
    "_alert_id",
    "anomaly_score",
    "priority_score",
    "priority_rank",
]

context = original.merge(
    v6[
        v6_context_columns
    ],
    on="_alert_id",
    how="left",
    validate="one_to_one"
)


if context["priority_rank"].isna().any():

    raise ValueError(
        "Some original rows could not be mapped to V6 ranking."
    )


print(
    "Original -> V6 alignment: PASS"
)


# ============================================================================
# 6. TIMESTAMP NORMALIZATION
# ============================================================================

print("\nPreparing timestamps...")


context["timestamp_datetime"] = pd.to_datetime(
    context["timestamp"],
    errors="coerce"
)


if context["timestamp_datetime"].isna().any():

    # Try event_time for rows where timestamp failed.
    fallback = pd.to_datetime(
        context["event_time"],
        errors="coerce"
    )

    context.loc[
        context["timestamp_datetime"].isna(),
        "timestamp_datetime"
    ] = fallback[
        context["timestamp_datetime"].isna()
    ]


if context["timestamp_datetime"].isna().any():

    raise ValueError(
        "Unable to parse timestamps."
    )


context = (
    context
    .sort_values(
        [
            "timestamp_datetime",
            "_alert_id"
        ],
        kind="mergesort"
    )
    .reset_index(drop=True)
)


print(
    "Timestamp parsing: PASS"
)


print(
    "Chronological context order: PASS"
)


# ============================================================================
# 7. SAFE TEXT HELPERS
# ============================================================================

def safe_text(value):

    if value is None:

        return ""

    if isinstance(
        value,
        float
    ) and np.isnan(value):

        return ""

    text = str(value).strip()

    if text.lower() in {
        "",
        "nan",
        "none",
        "null",
        "[]",
        "{}"
    }:

        return ""

    return text


def parse_collection(value):

    """
    Convert common dataset representations into a list.

    Supports:
      - actual Python lists
      - tuples
      - numpy arrays
      - strings like ['a', 'b']
      - strings like a;b
      - single values

    This is used ONLY for context/evidence creation.
    """

    if value is None:

        return []


    if isinstance(
        value,
        (list, tuple, set, np.ndarray)
    ):

        result = []

        for item in value:

            text = safe_text(item)

            if text:

                result.append(text)

        return result


    text = safe_text(value)


    if not text:

        return []


    if (
        text.startswith("[")
        and
        text.endswith("]")
    ):

        try:

            parsed = ast.literal_eval(
                text
            )

            if isinstance(
                parsed,
                (list, tuple, set)
            ):

                return [
                    safe_text(x)
                    for x in parsed
                    if safe_text(x)
                ]

        except Exception:

            pass


        inner = text[1:-1].strip()

        if not inner:

            return []


        result = []

        for part in inner.split(","):

            part = (
                part
                .strip()
                .strip("'")
                .strip('"')
            )

            if part:

                result.append(part)

        return result


    if ";" in text:

        return [
            x.strip()
            for x in text.split(";")
            if x.strip()
        ]


    return [text]


# ============================================================================
# 8. BASIC CONTEXT COLUMNS
# ============================================================================

print("\nBuilding SIH context fields...")


context["alert_source"] = (
    context["origin"]
    .map(safe_text)
)


context["alert_type"] = (
    context["message_type"]
    .map(safe_text)
)


context["alert_stream"] = (
    context["stream_name"]
    .map(safe_text)
)


context["alert_pipeline"] = (
    context["pipeline"]
    .map(safe_text)
)


context["severity_context"] = (
    context["severity"]
    .map(safe_text)
)


context["network_context"] = (
    context["protocol"]
    .map(safe_text)
)


context["source_host_context"] = (
    context["src_host"]
    .map(safe_text)
)


context["destination_host_context"] = (
    context["dst_host"]
    .map(safe_text)
)


context["product_context"] = (
    context["product_name"]
    .map(safe_text)
)


context["vendor_context"] = (
    context["vendor_name"]
    .map(safe_text)
)


# ============================================================================
# 9. EVIDENCE AVAILABILITY
# ============================================================================

print("Calculating evidence availability...")


context["has_source_ip"] = (
    context["src_ip"]
    .map(safe_text)
    .ne("")
)


context["has_destination_ip"] = (
    context["dst_ip"]
    .map(safe_text)
    .ne("")
)


context["has_source_host"] = (
    context["src_host"]
    .map(safe_text)
    .ne("")
)


context["has_destination_host"] = (
    context["dst_host"]
    .map(safe_text)
    .ne("")
)


context["has_username"] = (
    context["username"]
    .map(safe_text)
    .ne("")
)


context["has_protocol"] = (
    context["protocol"]
    .map(safe_text)
    .ne("")
)


context["has_action"] = (
    context["action"]
    .map(safe_text)
    .ne("")
)


context["has_matched_rule"] = (
    context["matched_rules"]
    .map(
        lambda x:
        len(parse_collection(x)) > 0
    )
)


context["has_investigation_role"] = (
    context["set_roles"]
    .map(
        lambda x:
        len(parse_collection(x)) > 0
    )
)


context["has_disposition"] = (
    context["disposition"]
    .map(safe_text)
    .ne("")
)


context["has_status"] = (
    context["status_name"]
    .map(safe_text)
    .ne("")
)


context["has_lifecycle"] = (
    context["lifecycle_stage"]
    .map(safe_text)
    .ne("")
)


# ============================================================================
# 10. INVESTIGATION EVIDENCE SCORE
# ============================================================================

context["investigation_evidence_count"] = (
    context[
        [
            "has_source_ip",
            "has_destination_ip",
            "has_source_host",
            "has_destination_host",
            "has_username",
            "has_protocol",
            "has_action",
            "has_matched_rule",
            "has_investigation_role",
        ]
    ]
    .sum(axis=1)
)


context["investigation_evidence_level"] = (
    pd.cut(
        context["investigation_evidence_count"],
        bins=[
            -1,
            2,
            5,
            7,
            20
        ],
        labels=[
            "LOW",
            "MEDIUM",
            "HIGH",
            "VERY_HIGH"
        ]
    )
    .astype(str)
)


# ============================================================================
# 11. WORKFLOW / CASE CONTEXT
# ============================================================================

context["workflow_context"] = (
    context[
        [
            "lifecycle_stage",
            "status_name",
            "action",
            "set_roles"
        ]
    ]
    .astype(str)
    .agg(
        " | ".join,
        axis=1
    )
)


context["case_context_available"] = (
    context[
        [
            "has_status",
            "has_lifecycle",
            "has_disposition"
        ]
    ]
    .any(axis=1)
)


# ============================================================================
# 12. ESCALATION CONTEXT
# ============================================================================

roles = (
    context["set_roles"]
    .map(parse_collection)
)


context["role_count"] = (
    roles.map(len)
)


context["escalation_context_available"] = (
    context["has_investigation_role"]
)


# We do not invent an escalation record.
# This is an evidence/context indicator only.

context["escalation_evidence"] = np.where(
    context["has_investigation_role"],
    "ROLE_INFORMATION_PRESENT",
    "NO_ROLE_INFORMATION_AVAILABLE"
)


# ============================================================================
# 13. DISPOSITION / CLOSURE CONTEXT
# ============================================================================

context["disposition_context"] = (
    context[
        [
            "disposition",
            "disposition_category",
            "status_name",
            "lifecycle_stage"
        ]
    ]
    .astype(str)
    .agg(
        " | ".join,
        axis=1
    )
)


context["closure_information_available"] = (
    context[
        [
            "has_disposition",
            "has_status"
        ]
    ]
    .any(axis=1)
)


# ============================================================================
# 14. RAPID-CLOSURE SIGNAL
# ============================================================================

print("Calculating closure timing signals...")


# There is no guaranteed case-open timestamp in the supplied schema.
# Therefore we do NOT fabricate a closure duration.
#
# Instead, we flag the existence of closure/disposition information.
#
# A future dashboard can show this as:
# "closure timing unavailable from current dataset".

context["rapid_closure_signal"] = False

context["rapid_closure_status"] = (
    np.where(
        context["closure_information_available"],
        "TIMING_NOT_AVAILABLE",
        "NO_CLOSURE_DATA"
    )
)


# ============================================================================
# 15. REPEATED ALERT / FREQUENCY SIGNALS
# ============================================================================

print("Calculating repetition signals...")


context["source_host_key"] = (
    context["src_host"]
    .map(safe_text)
)


context["destination_host_key"] = (
    context["dst_host"]
    .map(safe_text)
)


context["source_ip_key"] = (
    context["src_ip"]
    .map(safe_text)
)


context["destination_ip_key"] = (
    context["dst_ip"]
    .map(safe_text)
)


context["user_key"] = (
    context["username"]
    .map(safe_text)
)


# Repetition by source host.

context["source_host_frequency"] = (
    context["source_host_key"]
    .replace("", np.nan)
    .groupby(
        context["source_host_key"]
    )
    .transform("size")
)


# Repetition by destination host.

context["destination_host_frequency"] = (
    context["destination_host_key"]
    .replace("", np.nan)
    .groupby(
        context["destination_host_key"]
    )
    .transform("size")
)


# Repetition by source IP.

context["source_ip_frequency"] = (
    context["source_ip_key"]
    .replace("", np.nan)
    .groupby(
        context["source_ip_key"]
    )
    .transform("size")
)


# Repetition by destination IP.

context["destination_ip_frequency"] = (
    context["destination_ip_key"]
    .replace("", np.nan)
    .groupby(
        context["destination_ip_key"]
    )
    .transform("size")
)


frequency_columns = [
    "source_host_frequency",
    "destination_host_frequency",
    "source_ip_frequency",
    "destination_ip_frequency"
]


context[frequency_columns] = (
    context[frequency_columns]
    .fillna(0)
    .astype(int)
)


context["repeated_entity_signal"] = (
    context[frequency_columns]
    .max(axis=1)
    >= 2
)


context["high_frequency_entity_signal"] = (
    context[frequency_columns]
    .max(axis=1)
    >= 10
)


# ============================================================================
# 16. REPETITIVE INVESTIGATION SIGNAL
# ============================================================================

print("Calculating repetitive investigation signals...")


investigation_group_columns = [
    "src_host",
    "dst_host",
    "action",
    "matched_rules"
]


context["_investigation_signature"] = (
    context[
        investigation_group_columns
    ]
    .astype(str)
    .agg(
        "|".join,
        axis=1
    )
)


context["investigation_pattern_frequency"] = (
    context["_investigation_signature"]
    .groupby(
        context["_investigation_signature"]
    )
    .transform("size")
)


context["repetitive_investigation_signal"] = (
    context["investigation_pattern_frequency"]
    >= 5
)


# ============================================================================
# 17. TELEMETRY / MONITORING BLIND-SPOT SIGNAL
# ============================================================================

print("Calculating telemetry-gap signals...")


context["telemetry_evidence_count"] = (
    context[
        [
            "has_source_ip",
            "has_destination_ip",
            "has_source_host",
            "has_destination_host",
            "has_protocol",
            "has_action",
        ]
    ]
    .sum(axis=1)
)


context["low_telemetry_signal"] = (
    context["telemetry_evidence_count"]
    <= 1
)


context["monitoring_evidence_status"] = np.select(
    [
        context["telemetry_evidence_count"] <= 1,
        context["telemetry_evidence_count"] <= 3,
        context["telemetry_evidence_count"] >= 4
    ],
    [
        "LOW_TELEMETRY",
        "PARTIAL_TELEMETRY",
        "RICH_TELEMETRY"
    ],
    default="UNKNOWN"
)


# ============================================================================
# 18. INVESTIGATION-WITHOUT-EVIDENCE SIGNAL
# ============================================================================

context["investigation_without_evidence_signal"] = (
    context["has_investigation_role"]
    &
    (
        context["investigation_evidence_count"]
        <= 2
    )
)


# ============================================================================
# 19. NO-ESCALATION CONTEXT SIGNAL
# ============================================================================

context["no_escalation_context_signal"] = (
    ~context["has_investigation_role"]
)


# IMPORTANT:
#
# This does NOT mean the alert was actually not escalated.
#
# It means no role/escalation-related information was present
# in the available dataset row.


context["no_escalation_status"] = np.where(
    context["has_investigation_role"],
    "ESCALATION_ROLE_DATA_PRESENT",
    "ESCALATION_DATA_NOT_PRESENT"
)


# ============================================================================
# 20. CRITICAL ALERT + MISSING CONTEXT
# ============================================================================

severity_text = (
    context["severity"]
    .map(
        lambda x:
        safe_text(x).lower()
    )
)


context["critical_severity_signal"] = (
    severity_text.isin(
        {
            "critical",
            "crit",
            "5",
            "p1"
        }
    )
)


context["critical_missing_context_signal"] = (
    context["critical_severity_signal"]
    &
    (
        context["investigation_evidence_count"]
        <= 2
    )
)


# ============================================================================
# 21. EXECUTION GAP SCORE
# ============================================================================

print("Building execution-gap indicators...")


context["execution_gap_count"] = (
    context[
        [
            "investigation_without_evidence_signal",
            "no_escalation_context_signal",
            "repeated_entity_signal",
            "repetitive_investigation_signal",
            "low_telemetry_signal",
            "critical_missing_context_signal"
        ]
    ]
    .astype(int)
    .sum(axis=1)
)


context["execution_gap_level"] = np.select(
    [
        context["execution_gap_count"] >= 3,
        context["execution_gap_count"] == 2,
        context["execution_gap_count"] == 1
    ],
    [
        "HIGH",
        "MEDIUM",
        "LOW"
    ],
    default="NONE"
)


# ============================================================================
# 22. NEGATIVE-SPACE SIGNAL
# ============================================================================

print("Building negative-space indicators...")


context["negative_space_count"] = (
    context[
        [
            "low_telemetry_signal",
            "no_escalation_context_signal",
            "investigation_without_evidence_signal"
        ]
    ]
    .astype(int)
    .sum(axis=1)
)


context["negative_space_signal"] = (
    context["negative_space_count"]
    >= 1
)


context["negative_space_level"] = np.select(
    [
        context["negative_space_count"] >= 2,
        context["negative_space_count"] == 1
    ],
    [
        "HIGH",
        "LOW"
    ],
    default="NONE"
)


# ============================================================================
# 23. ENTITY-LEVEL RISK CONTEXT
# ============================================================================

print("Building entity-level context...")


context["entity_key"] = np.where(
    context["destination_host_key"].ne(""),
    context["destination_host_key"],
    np.where(
        context["source_host_key"].ne(""),
        context["source_host_key"],
        np.where(
            context["destination_ip_key"].ne(""),
            context["destination_ip_key"],
            context["source_ip_key"]
        )
    )
)


context["entity_alert_frequency"] = (
    context["entity_key"]
    .replace("", np.nan)
    .groupby(
        context["entity_key"]
    )
    .transform("size")
    .fillna(0)
    .astype(int)
)


context["entity_repeated_alert_signal"] = (
    context["entity_alert_frequency"]
    >= 2
)


context["entity_high_frequency_signal"] = (
    context["entity_alert_frequency"]
    >= 10
)


# ============================================================================
# 24. EXPLAINABILITY / EVIDENCE SUMMARY
# ============================================================================

def make_reason(row):

    reasons = []

    if row["repeated_entity_signal"]:

        reasons.append(
            "REPEATED_ENTITY"
        )


    if row["high_frequency_entity_signal"]:

        reasons.append(
            "HIGH_ENTITY_FREQUENCY"
        )


    if row["repetitive_investigation_signal"]:

        reasons.append(
            "REPETITIVE_INVESTIGATION_PATTERN"
        )


    if row["low_telemetry_signal"]:

        reasons.append(
            "LOW_TELEMETRY"
        )


    if row["investigation_without_evidence_signal"]:

        reasons.append(
            "INVESTIGATION_WITH_LIMITED_EVIDENCE"
        )


    if row["no_escalation_context_signal"]:

        reasons.append(
            "NO_ESCALATION_CONTEXT_RECORDED"
        )


    if row["critical_missing_context_signal"]:

        reasons.append(
            "CRITICAL_ALERT_WITH_LIMITED_CONTEXT"
        )


    if not reasons:

        reasons.append(
            "NO_CONTEXT_GAP_FLAG"
        )


    return " | ".join(
        reasons
    )


context["context_reason"] = (
    context.apply(
        make_reason,
        axis=1
    )
)


# ============================================================================
# 25. V6 RANK + CONTEXT PRIORITIZATION
# ============================================================================

#
# IMPORTANT:
#
# This is NOT a replacement ranking.
#
# It is a supervisory/context flag attached to the already-established
# V6 ranking.
#

context["v6_priority_rank"] = (
    context["priority_rank"]
)


context["v6_anomaly_score"] = (
    context["anomaly_score"]
)


context["v6_priority_score"] = (
    context["priority_score"]
)


# ============================================================================
# 26. POST-HOC INCIDENT INFORMATION
# ============================================================================

print("\nPreparing post-hoc incident information...")


def extract_incident_ids(value):

    return parse_collection(
        value
    )


context["incident_ids_posthoc"] = (
    context["incident_ids"]
    .map(
        extract_incident_ids
    )
)


context["actual_incident_posthoc"] = (
    context["incident_ids_posthoc"]
    .map(
        lambda x:
        len(x) > 0
    )
)


print(
    "Incident information attached for post-hoc evaluation only."
)


# ============================================================================
# 27. LEAKAGE SAFETY CHECK
# ============================================================================

print("\n" + "=" * 90)
print("LEAKAGE SAFETY CHECK")
print("=" * 90)


# These fields MUST NOT be used to construct V6 scores.
#
# We only preserve them for evaluation/context.

for forbidden in [
    "label_binary",
    "label_confidence",
    "incident_ids",
]:

    if forbidden in context.columns:

        print(
            f"{forbidden}: PRESERVED FOR POST-HOC ONLY"
        )


print(
    "\nNo label or incident field was used "
    "to calculate anomaly_score."
)

print(
    "No label or incident field was used "
    "to calculate priority_score."
)

print(
    "No label or incident field was used "
    "to calculate priority_rank."
)


# ============================================================================
# 28. UNSUPPORTED SIH SIGNALS — EXPLICITLY DOCUMENT THEM
# ============================================================================

context["rapid_closure_supported"] = False

context["missing_monitoring_coverage_supported"] = (
    context["low_telemetry_signal"]
)


context["peer_deviation_supported"] = False


context["remediation_completion_supported"] = False


context["formal_case_id_supported"] = (
    "artifact_id" in context.columns
)


# ============================================================================
# 29. FINAL OUTPUT COLUMNS
# ============================================================================

output_columns = [

    # Identity
    "_alert_id",

    # V6 ranking
    "v6_anomaly_score",
    "v6_priority_score",
    "v6_priority_rank",

    # Core alert metadata
    "timestamp",
    "event_time",
    "timestamp_source",
    "alert_source",
    "alert_type",
    "alert_stream",
    "alert_pipeline",
    "severity_context",

    # Network/entity
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "source_host_context",
    "destination_host_context",
    "username",

    # Action / workflow
    "action",
    "lifecycle_stage",
    "status_name",
    "disposition",
    "disposition_category",

    # Asset/system
    "org_id",
    "artifact_id",
    "product_context",
    "vendor_context",

    # Evidence
    "has_source_ip",
    "has_destination_ip",
    "has_source_host",
    "has_destination_host",
    "has_username",
    "has_protocol",
    "has_action",
    "has_matched_rule",
    "has_investigation_role",
    "investigation_evidence_count",
    "investigation_evidence_level",

    # Case/investigation
    "case_context_available",
    "workflow_context",
    "role_count",

    # Escalation
    "escalation_context_available",
    "escalation_evidence",
    "no_escalation_context_signal",
    "no_escalation_status",

    # Closure
    "closure_information_available",
    "rapid_closure_signal",
    "rapid_closure_status",

    # Frequency
    "source_host_frequency",
    "destination_host_frequency",
    "source_ip_frequency",
    "destination_ip_frequency",
    "entity_alert_frequency",
    "repeated_entity_signal",
    "high_frequency_entity_signal",

    # Investigation patterns
    "investigation_pattern_frequency",
    "repetitive_investigation_signal",

    # Telemetry / negative space
    "telemetry_evidence_count",
    "monitoring_evidence_status",
    "low_telemetry_signal",

    # Execution gaps
    "investigation_without_evidence_signal",
    "critical_severity_signal",
    "critical_missing_context_signal",
    "execution_gap_count",
    "execution_gap_level",

    # Negative space
    "negative_space_count",
    "negative_space_signal",
    "negative_space_level",

    # Entity supervisory context
    "entity_key",
    "entity_repeated_alert_signal",
    "entity_high_frequency_signal",

    # Explainability
    "context_reason",

    # Capability flags
    "rapid_closure_supported",
    "missing_monitoring_coverage_supported",
    "peer_deviation_supported",
    "remediation_completion_supported",
    "formal_case_id_supported",

    # Post-hoc evaluation
    "actual_incident_posthoc",
    "incident_ids_posthoc",
]


# Only keep columns that actually exist.

output_columns = [
    c
    for c in output_columns
    if c in context.columns
]


final_context = context[
    output_columns
].copy()


# ============================================================================
# 30. FINAL VALIDATION
# ============================================================================

print("\n" + "=" * 90)
print("FINAL CONTEXT VALIDATION")
print("=" * 90)


if len(final_context) != len(v6):

    raise ValueError(
        "Final context row count does not match V6."
    )


print(
    "Row count match: PASS"
)


if not final_context["_alert_id"].is_unique:

    raise ValueError(
        "Final context _alert_id is not unique."
    )


print(
    "Alert identity uniqueness: PASS"
)


rank_original = (
    v6
    .sort_values(
        "priority_rank"
    )[
        "_alert_id"
    ]
    .tolist()
)


rank_context = (
    final_context
    .sort_values(
        "v6_priority_rank"
    )[
        "_alert_id"
    ]
    .tolist()
)


if rank_original != rank_context:

    raise ValueError(
        "V6 ranking identity changed."
    )


print(
    "V6 ranking identity: PASS"
)


score_original = (
    v6
    .sort_values(
        "_alert_id"
    )[
        "anomaly_score"
    ]
    .to_numpy()
)


score_context = (
    final_context
    .sort_values(
        "_alert_id"
    )[
        "v6_anomaly_score"
    ]
    .to_numpy()
)


if not np.allclose(
    score_original,
    score_context,
    equal_nan=True
):

    raise ValueError(
        "V6 anomaly scores changed."
    )


print(
    "V6 anomaly scores unchanged: PASS"
)


priority_original = (
    v6
    .sort_values(
        "_alert_id"
    )[
        "priority_score"
    ]
    .to_numpy()
)


priority_context = (
    final_context
    .sort_values(
        "_alert_id"
    )[
        "v6_priority_score"
    ]
    .to_numpy()
)


if not np.allclose(
    priority_original,
    priority_context,
    equal_nan=True
):

    raise ValueError(
        "V6 priority scores changed."
    )


print(
    "V6 priority scores unchanged: PASS"
)


rank_values = (
    final_context
    .sort_values(
        "v6_priority_rank"
    )[
        "v6_priority_rank"
    ]
    .to_numpy()
)


if not np.array_equal(
    rank_values,
    np.arange(
        1,
        len(final_context) + 1
    )
):

    raise ValueError(
        "V6 priority rank sequence changed."
    )


print(
    "V6 priority ranks unchanged: PASS"
)


# ============================================================================
# 31. SUMMARY COUNTS
# ============================================================================

total_rows = len(final_context)


incident_count = int(
    final_context[
        "actual_incident_posthoc"
    ].sum()
)


execution_gap_count = int(
    final_context[
        "execution_gap_count"
    ].gt(0)
    .sum()
)


negative_space_count = int(
    final_context[
        "negative_space_signal"
    ].sum()
)


repeated_entity_count = int(
    final_context[
        "repeated_entity_signal"
    ].sum()
)


low_telemetry_count = int(
    final_context[
        "low_telemetry_signal"
    ].sum()
)


investigation_gap_count = int(
    final_context[
        "investigation_without_evidence_signal"
    ].sum()
)


# ============================================================================
# 32. SAVE CSV
# ============================================================================

print("\nSaving final SIH context layer...")


final_context.to_csv(
    OUTPUT_FILE,
    index=False
)


print(
    f"Saved: {OUTPUT_FILE}"
)


# ============================================================================
# 33. HUMAN-READABLE REPORT
# ============================================================================

with open(
    REPORT_FILE,
    "w",
    encoding="utf-8"
) as f:

    f.write(
        "FINAL V6 SIH CONTEXT LAYER REPORT\n"
    )

    f.write(
        "=" * 90 + "\n\n"
    )


    f.write(
        "V6 INTEGRITY\n"
    )

    f.write(
        "Isolation Forest scores were not changed.\n"
    )

    f.write(
        "Priority scores were not changed.\n"
    )

    f.write(
        "Priority ranks were not changed.\n"
    )

    f.write(
        "No model retraining was performed.\n"
    )

    f.write(
        "No incident labels were used for scoring.\n\n"
    )


    f.write(
        "DATASET\n"
    )

    f.write(
        f"Rows: {total_rows:,}\n"
    )

    f.write(
        f"Post-hoc incident alerts: {incident_count:,}\n\n"
    )


    f.write(
        "SIH CONTEXT COVERAGE\n"
    )

    f.write(
        "Alert metadata: AVAILABLE\n"
    )

    f.write(
        "Network/entity context: AVAILABLE\n"
    )

    f.write(
        "Case/workflow context: AVAILABLE\n"
    )

    f.write(
        "Escalation-related context: PARTIALLY AVAILABLE\n"
    )

    f.write(
        "Disposition/closure context: AVAILABLE\n"
    )

    f.write(
        "Asset/system context: AVAILABLE\n\n"
    )


    f.write(
        "EXECUTION-GAP SIGNALS\n"
    )

    f.write(
        f"Rows with execution-gap flags: "
        f"{execution_gap_count:,}\n"
    )

    f.write(
        f"Investigation-with-limited-evidence: "
        f"{investigation_gap_count:,}\n"
    )

    f.write(
        f"Repeated entities: "
        f"{repeated_entity_count:,}\n"
    )

    f.write(
        f"Low telemetry: "
        f"{low_telemetry_count:,}\n\n"
    )


    f.write(
        "NEGATIVE-SPACE SIGNALS\n"
    )

    f.write(
        f"Rows with negative-space flags: "
        f"{negative_space_count:,}\n\n"
    )


    f.write(
        "UNSUPPORTED / NOT FABRICATED\n"
    )

    f.write(
        "Rapid closure duration: not available because "
        "the dataset does not provide a reliable case-open "
        "timestamp and closure timestamp pair.\n"
    )

    f.write(
        "Peer deviation: not calculated because a defined "
        "peer-group population is not supplied.\n"
    )

    f.write(
        "Remediation completion: not calculated because "
        "a reliable remediation-completion field is not supplied.\n"
    )

    f.write(
        "Missing monitoring coverage: represented only through "
        "observable low-telemetry evidence, not claimed as a "
        "definitive monitoring outage.\n\n"
    )


    f.write(
        "GROUND TRUTH POLICY\n"
    )

    f.write(
        "incident_ids are attached only for post-hoc evaluation.\n"
    )

    f.write(
        "label_binary is not used for V6 scoring.\n"
    )

    f.write(
        "label_confidence is not used for V6 scoring.\n\n"
    )


    f.write(
        "TRACEABILITY\n"
    )

    f.write(
        "_alert_id maps every context row to the original "
        "chronological test row.\n"
    )

    f.write(
        "V6 ranking remains the production ranking.\n"
    )


print(
    f"Report saved: {REPORT_FILE}"
)


# ============================================================================
# 34. FINAL OUTPUT
# ============================================================================

print("\n" + "=" * 90)
print("V6 SIH CONTEXT LAYER COMPLETE")
print("=" * 90)

print(
    "\nRows                    : "
    f"{total_rows:,}"
)

print(
    "Post-hoc incidents      : "
    f"{incident_count:,}"
)

print(
    "Execution-gap rows      : "
    f"{execution_gap_count:,}"
)

print(
    "Negative-space rows     : "
    f"{negative_space_count:,}"
)

print(
    "Repeated-entity rows    : "
    f"{repeated_entity_count:,}"
)

print(
    "Low-telemetry rows      : "
    f"{low_telemetry_count:,}"
)

print(
    "\nV6 anomaly scores       : UNCHANGED"
)

print(
    "V6 priority scores      : UNCHANGED"
)

print(
    "V6 priority ranking     : UNCHANGED"
)

print(
    "V6 model retrained      : NO"
)

print(
    "Ground truth usage      : POST-HOC ONLY"
)

print(
    "\nOutput:"
)

print(
    OUTPUT_FILE
)

print(
    REPORT_FILE
)

print("=" * 90)