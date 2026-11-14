import pandas as pd
import numpy as np
from pathlib import Path


# ============================================================
# FINAL V6 SIH EVALUATION SUMMARY
# ============================================================

print("=" * 80)
print("FINAL V6 SIH EVALUATION SUMMARY")
print("=" * 80)


# ============================================================
# 1. PATHS
# ============================================================

V6_FILE = (
    "data/scored/test_unsupervised_v6_validated.csv"
)

BASELINE_FILE = (
    "data/scored/chronological_baseline_v6_test.csv"
)

ORIGINAL_TEST_FILE = (
    "data/train_test/test_20.csv"
)

OUTPUT_FILE = (
    "data/scored/final_v6_sih_evaluation_summary.csv"
)

UNIQUE_FILE = (
    "data/scored/final_v6_unique_incident_summary.csv"
)

REVIEW_FILE = (
    "data/scored/final_v6_review_fraction_summary.csv"
)

REPORT_FILE = (
    "data/scored/final_v6_sih_evaluation_report.txt"
)


# ============================================================
# 2. CREATE OUTPUT DIRECTORY
# ============================================================

Path(
    "data/scored"
).mkdir(
    parents=True,
    exist_ok=True
)


# ============================================================
# 3. LOAD V6 VALIDATED RESULTS
# ============================================================

print("\nLoading V6 validated results...")

v6 = pd.read_csv(
    V6_FILE,
    low_memory=False
)

print(
    f"V6 records: {len(v6):,}"
)


# ============================================================
# 4. LOAD CHRONOLOGICAL BASELINE
# ============================================================

print("\nLoading chronological baseline...")

baseline = pd.read_csv(
    BASELINE_FILE,
    low_memory=False
)

print(
    f"Baseline records: {len(baseline):,}"
)


# ============================================================
# 5. LOAD ORIGINAL TEST DATA
#
# Used only to construct the chronological evaluation
# sequence and attach post-hoc incident information.
#
# incident_ids are NEVER used for model scoring.
# ============================================================

print("\nLoading original test data...")

original = pd.read_csv(
    ORIGINAL_TEST_FILE,
    low_memory=False
)

print(
    f"Original test records: {len(original):,}"
)


# ============================================================
# 6. BASIC SAFETY CHECKS
# ============================================================

print("\n" + "=" * 80)
print("BASIC SAFETY CHECKS")
print("=" * 80)


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


if "actual_incident" not in baseline.columns:

    raise ValueError(
        "Missing required baseline column: "
        "actual_incident"
    )

print(
    "Baseline 'actual_incident': PASS"
)


if "_alert_id" not in v6.columns:

    raise ValueError(
        "V6 _alert_id column missing."
    )


if "incident_ids" not in original.columns:

    raise ValueError(
        "Original test incident_ids column missing."
    )

print(
    "Original 'incident_ids': PASS"
)


if "timestamp" not in original.columns:

    raise ValueError(
        "Original test timestamp column missing."
    )

print(
    "Original 'timestamp': PASS"
)


if len(v6) != len(baseline):

    raise ValueError(
        "V6 and chronological baseline row "
        "counts do not match."
    )

print(
    "V6 / baseline row count match: PASS"
)


if len(v6) != len(original):

    raise ValueError(
        "V6 and original test row counts "
        "do not match."
    )

print(
    "V6 / original row count match: PASS"
)


if not v6["_alert_id"].is_unique:

    raise ValueError(
        "V6 _alert_id values are not unique."
    )

print(
    "V6 _alert_id uniqueness: PASS"
)


# ============================================================
# 7. ALERT-ID RANGE SAFETY
# ============================================================

print("\n" + "=" * 80)
print("ALERT ID SAFETY")
print("=" * 80)


alert_ids = v6["_alert_id"]


if not pd.api.types.is_numeric_dtype(
    alert_ids
):

    raise ValueError(
        "_alert_id must be numeric."
    )


alert_ids = (
    pd.to_numeric(
        alert_ids,
        errors="raise"
    )
    .astype(int)
)


expected_ids = np.arange(
    len(original)
)


actual_ids_sorted = np.sort(
    alert_ids.to_numpy()
)


if np.array_equal(
    actual_ids_sorted,
    expected_ids
):

    print(
        "V6 _alert_id values cover "
        "0 -> N-1: PASS"
    )

else:

    raise ValueError(
        "V6 _alert_id values do not "
        "cover exactly 0 -> N-1."
    )


print(
    f"Minimum _alert_id: {alert_ids.min():,}"
)

print(
    f"Maximum _alert_id: {alert_ids.max():,}"
)


# ============================================================
# 8. POST-HOC GROUND TRUTH
# ============================================================

print("\n" + "=" * 80)
print("POST-HOC GROUND TRUTH")
print("=" * 80)


print(
    "\nincident_ids are used ONLY for "
    "post-hoc evaluation."
)


incident_ids_original = (
    original["incident_ids"]
)


def has_incident(value):

    if value is None:
        return False

    if isinstance(
        value,
        (list, tuple, set, np.ndarray)
    ):

        return len(value) > 0

    try:

        missing = pd.isna(value)

        if isinstance(
            missing,
            (bool, np.bool_)
        ):

            if missing:
                return False

    except (
        TypeError,
        ValueError
    ):

        pass

    text = str(value).strip()

    if text == "":
        return False

    if text.lower() in {
        "nan",
        "none",
        "null",
        "[]",
        "{}"
    }:

        return False

    return True


actual_incident_original = (
    incident_ids_original
    .apply(has_incident)
)


# Attach post-hoc ground truth to V6
# using _alert_id as row-position identity.

v6["actual_incident"] = (
    actual_incident_original
    .iloc[alert_ids]
    .to_numpy()
)


print(
    "Ground truth created for "
    "post-hoc evaluation: PASS"
)


# ============================================================
# 9. INCIDENT ID PARSER
# ============================================================

def extract_ids(value):

    """
    Safely convert an incident_ids value into
    a list of incident ID strings.

    Handles:
    - NaN
    - None
    - strings
    - lists
    - tuples
    - sets
    - NumPy arrays
    - nested arrays/lists
    - ['id1', 'id2']
    - id1;id2
    - single IDs
    """

    if value is None:
        return []


    # --------------------------------------------------------
    # Actual list / tuple / set / NumPy array
    # --------------------------------------------------------

    if isinstance(
        value,
        (list, tuple, set, np.ndarray)
    ):

        ids = []

        for item in value:

            if item is None:
                continue

            if isinstance(
                item,
                (list, tuple, set, np.ndarray)
            ):

                for nested_item in item:

                    if nested_item is None:
                        continue

                    try:

                        missing = pd.isna(
                            nested_item
                        )

                        if isinstance(
                            missing,
                            (bool, np.bool_)
                        ) and missing:

                            continue

                    except (
                        TypeError,
                        ValueError
                    ):

                        pass

                    text = (
                        str(nested_item)
                        .strip()
                    )

                    if text:
                        ids.append(text)

            else:

                try:

                    missing = pd.isna(item)

                    if isinstance(
                        missing,
                        (bool, np.bool_)
                    ) and missing:

                        continue

                except (
                    TypeError,
                    ValueError
                ):

                    pass

                text = str(item).strip()

                if text:
                    ids.append(text)

        return ids


    # --------------------------------------------------------
    # Scalar missing value
    # --------------------------------------------------------

    try:

        missing = pd.isna(value)

        if isinstance(
            missing,
            (bool, np.bool_)
        ) and missing:

            return []

    except (
        TypeError,
        ValueError
    ):

        pass


    # --------------------------------------------------------
    # Convert to string
    # --------------------------------------------------------

    text = str(value).strip()


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
    # List-like string
    #
    # ['id1', 'id2']
    # --------------------------------------------------------

    if (
        text.startswith("[")
        and
        text.endswith("]")
    ):

        inner = (
            text[1:-1]
            .strip()
        )


        if inner == "":
            return []


        parts = inner.split(",")

        ids = []


        for part in parts:

            part = (
                part
                .strip()
                .strip("'")
                .strip('"')
            )

            if part:
                ids.append(part)


        return ids


    # --------------------------------------------------------
    # Semicolon-separated IDs
    # --------------------------------------------------------

    if ";" in text:

        return [
            item.strip()
            for item in text.split(";")
            if item.strip()
        ]


    # --------------------------------------------------------
    # Single ID
    # --------------------------------------------------------

    return [text]


# ============================================================
# 10. V6 INCIDENT LISTS
# ============================================================

print(
    "\nPreparing V6 incident information "
    "for post-hoc evaluation..."
)


if "incident_id_eval" not in v6.columns:

    raise ValueError(
        "V6 validated file does not contain "
        "'incident_id_eval'."
    )


v6_incident_lists = (
    v6["incident_id_eval"]
    .apply(extract_ids)
)


print(
    "V6 incident evaluation data: PASS"
)


# ============================================================
# 11. CREATE CHRONOLOGICAL ORIGINAL DATA
# ============================================================

print(
    "\nPreparing chronological "
    "post-hoc evaluation sequence..."
)


original_eval = original.copy()


original_eval["_original_row_id"] = (
    np.arange(
        len(original_eval)
    )
)


original_eval["_timestamp_eval"] = (
    pd.to_datetime(
        original_eval["timestamp"],
        errors="coerce"
    )
)


if original_eval[
    "_timestamp_eval"
].isna().any():

    raise ValueError(
        "Original test contains invalid "
        "timestamps."
    )


original_chronological = (
    original_eval
    .sort_values(
        "_timestamp_eval",
        kind="mergesort"
    )
    .reset_index(drop=True)
)


print(
    "Chronological sorting: PASS"
)


# ============================================================
# 12. BASELINE INCIDENT INFORMATION
# ============================================================

baseline_incident_lists = (
    original_chronological[
        "incident_ids"
    ]
    .apply(extract_ids)
)


print(
    "Chronological incident evaluation "
    "data: PASS"
)


# ============================================================
# 13. VERIFY BASELINE ORDER
# ============================================================

if "timestamp" in baseline.columns:

    baseline_timestamp = (
        pd.to_datetime(
            baseline["timestamp"],
            errors="coerce"
        )
    )

    if baseline_timestamp.isna().any():

        raise ValueError(
            "Baseline contains invalid "
            "timestamps."
        )

    baseline_sorted_check = (
        baseline_timestamp
        .is_monotonic_increasing
    )

    if baseline_sorted_check:

        print(
            "Chronological baseline order: PASS"
        )

    else:

        raise ValueError(
            "Chronological baseline is not "
            "sorted by timestamp."
        )


# ============================================================
# 14. VERIFY BASELINE IDENTITY
# ============================================================

print(
    "\nVerifying chronological baseline "
    "identity..."
)


# The baseline should contain the same number
# of rows as the chronologically sorted original.

if len(
    original_chronological
) != len(baseline):

    raise ValueError(
        "Chronological baseline does not "
        "match original row count."
    )


print(
    "Chronological baseline identity: PASS"
)


# ============================================================
# 15. GROUND TRUTH DISTRIBUTION
# ============================================================

print("\n" + "=" * 80)
print("DATASET SUMMARY")
print("=" * 80)


total_alerts = len(v6)


total_incident_alerts = int(
    v6["actual_incident"].sum()
)


incident_rate = (
    total_incident_alerts
    /
    total_alerts
)


print(
    f"Total alerts          : "
    f"{total_alerts:,}"
)


print(
    f"Incident alerts       : "
    f"{total_incident_alerts:,}"
)


print(
    f"Incident rate         : "
    f"{incident_rate:.4%}"
)


# ============================================================
# 16. ALL UNIQUE INCIDENTS
# ============================================================

print(
    "\nCalculating unique incidents..."
)


all_incidents = set()


for ids in v6_incident_lists:

    for incident_id in ids:

        all_incidents.add(
            incident_id
        )


total_unique_incidents = len(
    all_incidents
)


print(
    f"Unique incidents      : "
    f"{total_unique_incidents:,}"
)


# ============================================================
# 17. PREPARE V6 PRIORITY QUEUE
# ============================================================

print(
    "\nPreparing V6 priority queue..."
)


v6_ranked = (
    v6
    .sort_values(
        "priority_rank",
        ascending=True
    )
    .reset_index(drop=True)
)


# ============================================================
# 18. VERIFY V6 PRIORITY RANK
# ============================================================

expected_ranks = np.arange(
    1,
    len(v6_ranked) + 1
)


if np.array_equal(
    v6_ranked[
        "priority_rank"
    ].to_numpy(),
    expected_ranks
):

    print(
        "V6 priority ranks: PASS"
    )

else:

    raise ValueError(
        "V6 priority ranks are not "
        "sequential."
    )


# ============================================================
# 19. VERIFY V6 SCORE ORDER
# ============================================================

priority_values = (
    v6_ranked[
        "priority_score"
    ]
    .to_numpy()
)


if np.all(
    priority_values[:-1]
    >=
    priority_values[1:]
):

    print(
        "V6 priority-score order: PASS"
    )

else:

    raise ValueError(
        "V6 priority-score ordering "
        "is invalid."
    )


anomaly_values = (
    v6_ranked[
        "anomaly_score"
    ]
    .to_numpy()
)


if np.all(
    anomaly_values[:-1]
    >=
    anomaly_values[1:]
):

    print(
        "V6 anomaly-score order: PASS"
    )

else:

    raise ValueError(
        "V6 anomaly-score ordering "
        "is invalid."
    )


# ============================================================
# 20. EVALUATION FUNCTION
# ============================================================

def evaluate_queue(
    dataframe,
    k
):

    k = min(
        int(k),
        len(dataframe)
    )


    if k <= 0:

        return {
            "K": 0,
            "Incidents_Found": 0,
            "Precision": 0.0,
            "Recall": 0.0,
            "Alerts_Avoided": total_alerts,
            "Alerts_Avoided_Percentage": 1.0
        }


    top_k = (
        dataframe
        .head(k)
    )


    incidents_found = int(
        top_k[
            "actual_incident"
        ].sum()
    )


    precision = (
        incidents_found
        /
        k
    )


    recall = (
        incidents_found
        /
        total_incident_alerts
        if total_incident_alerts > 0
        else 0.0
    )


    alerts_avoided = (
        total_alerts - k
    )


    avoided_percentage = (
        alerts_avoided
        /
        total_alerts
    )


    return {

        "K": k,

        "Incidents_Found":
            incidents_found,

        "Precision":
            precision,

        "Recall":
            recall,

        "Alerts_Avoided":
            alerts_avoided,

        "Alerts_Avoided_Percentage":
            avoided_percentage
    }


# ============================================================
# 21. TOP-K EVALUATION
# ============================================================

print("\n" + "=" * 80)
print("TOP-K EVALUATION")
print("=" * 80)


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


rows = []


for requested_k in top_ks:

    v6_result = evaluate_queue(
        v6_ranked,
        requested_k
    )


    # Chronological baseline:
    #
    # Its actual_incident column is already
    # available from the generated baseline.
    #
    baseline_result = evaluate_queue(
        baseline,
        requested_k
    )


    rows.append({

        "K":
            requested_k,

        "V6_Incidents_Found":
            v6_result[
                "Incidents_Found"
            ],

        "Chronological_Incidents_Found":
            baseline_result[
                "Incidents_Found"
            ],

        "V6_Precision":
            v6_result[
                "Precision"
            ],

        "Chronological_Precision":
            baseline_result[
                "Precision"
            ],

        "V6_Recall":
            v6_result[
                "Recall"
            ],

        "Chronological_Recall":
            baseline_result[
                "Recall"
            ],

        "V6_Alerts_Avoided":
            v6_result[
                "Alerts_Avoided"
            ],

        "Chronological_Alerts_Avoided":
            baseline_result[
                "Alerts_Avoided"
            ],

        "V6_Alerts_Avoided_Percentage":
            v6_result[
                "Alerts_Avoided_Percentage"
            ],

        "Chronological_Alerts_Avoided_Percentage":
            baseline_result[
                "Alerts_Avoided_Percentage"
            ],

        "Incident_Found_Difference":
            (
                v6_result[
                    "Incidents_Found"
                ]
                -
                baseline_result[
                    "Incidents_Found"
                ]
            ),

        "Precision_Difference":
            (
                v6_result[
                    "Precision"
                ]
                -
                baseline_result[
                    "Precision"
                ]
            ),

        "Recall_Difference":
            (
                v6_result[
                    "Recall"
                ]
                -
                baseline_result[
                    "Recall"
                ]
            )
    })


summary = pd.DataFrame(
    rows
)


# ============================================================
# 22. SAVE TOP-K SUMMARY
# ============================================================

summary.to_csv(
    OUTPUT_FILE,
    index=False
)


print(
    "\nFinal summary saved:"
)


print(
    OUTPUT_FILE
)


# ============================================================
# 23. PRINT TOP-K COMPARISON
# ============================================================

print("\n" + "=" * 80)
print("V6 vs CHRONOLOGICAL BASELINE")
print("=" * 80)


print(
    "\n"
    "K       | "
    "V6 Inc | "
    "Chron Inc | "
    "V6 Prec | "
    "Chron Prec | "
    "V6 Recall | "
    "Chron Recall"
)


print(
    "-" * 80
)


for _, row in summary.iterrows():

    print(

        f"{int(row['K']):<7} | "

        f"{int(row['V6_Incidents_Found']):<6} | "

        f"{int(row['Chronological_Incidents_Found']):<9} | "

        f"{row['V6_Precision'] * 100:>6.2f}% | "

        f"{row['Chronological_Precision'] * 100:>9.2f}% | "

        f"{row['V6_Recall'] * 100:>8.2f}% | "

        f"{row['Chronological_Recall'] * 100:>11.2f}%"
    )


# ============================================================
# 24. UNIQUE INCIDENT DISCOVERY
# ============================================================

print("\n" + "=" * 80)
print("UNIQUE INCIDENT DISCOVERY")
print("=" * 80)


def discovered_incidents(
    incident_lists,
    k
):

    k = min(
        int(k),
        len(incident_lists)
    )


    discovered = set()


    for ids in incident_lists.iloc[:k]:

        for incident_id in ids:

            discovered.add(
                incident_id
            )


    return len(discovered)


print(
    f"Total unique incidents: "
    f"{total_unique_incidents:,}"
)


unique_rows = []


for requested_k in top_ks:

    k = min(
        requested_k,
        total_alerts
    )


    v6_unique = (
        discovered_incidents(
            v6_incident_lists,
            k
        )
    )


    baseline_unique = (
        discovered_incidents(
            baseline_incident_lists,
            k
        )
    )


    v6_recall = (

        v6_unique
        /
        total_unique_incidents

        if total_unique_incidents > 0

        else 0.0
    )


    baseline_recall = (

        baseline_unique
        /
        total_unique_incidents

        if total_unique_incidents > 0

        else 0.0
    )


    unique_rows.append({

        "K":
            requested_k,

        "V6_Unique_Incidents":
            v6_unique,

        "Chronological_Unique_Incidents":
            baseline_unique,

        "V6_Unique_Recall":
            v6_recall,

        "Chronological_Unique_Recall":
            baseline_recall,

        "Unique_Incident_Recall_Difference":
            (
                v6_recall
                -
                baseline_recall
            )
    })


unique_summary = pd.DataFrame(
    unique_rows
)


print(
    "\n"
    "K       | "
    "V6 Unique | "
    "Chron Unique | "
    "V6 Recall | "
    "Chron Recall"
)


print(
    "-" * 80
)


for _, row in unique_summary.iterrows():

    print(

        f"{int(row['K']):<7} | "

        f"{int(row['V6_Unique_Incidents']):<9} | "

        f"{int(row['Chronological_Unique_Incidents']):<12} | "

        f"{row['V6_Unique_Recall'] * 100:>8.2f}% | "

        f"{row['Chronological_Unique_Recall'] * 100:>10.2f}%"
    )


# ============================================================
# 25. SAVE UNIQUE INCIDENT TABLE
# ============================================================

unique_summary.to_csv(
    UNIQUE_FILE,
    index=False
)


print(
    "\nUnique incident summary saved:"
)


print(
    UNIQUE_FILE
)


# ============================================================
# 26. REVIEW FRACTION EVALUATION
#
# This directly supports the SIH goal of reducing
# analyst review workload.
# ============================================================

print("\n" + "=" * 80)
print("INCIDENT DISCOVERY BY REVIEW FRACTION")
print("=" * 80)


review_percentages = [
    0.1,
    0.5,
    1,
    2,
    5,
    10,
    25
]


review_rows = []


for percentage in review_percentages:

    k = max(
        1,
        int(
            total_alerts
            *
            percentage
            /
            100
        )
    )


    # V6
    v6_unique = discovered_incidents(
        v6_incident_lists,
        k
    )


    # Chronological
    baseline_unique = discovered_incidents(
        baseline_incident_lists,
        k
    )


    v6_unique_recall = (

        v6_unique
        /
        total_unique_incidents

        if total_unique_incidents > 0

        else 0.0
    )


    baseline_unique_recall = (

        baseline_unique
        /
        total_unique_incidents

        if total_unique_incidents > 0

        else 0.0
    )


    v6_alerts_avoided = (
        total_alerts - k
    )


    review_rows.append({

        "Review_Percentage":
            percentage,

        "Alerts_Reviewed":
            k,

        "V6_Unique_Incidents":
            v6_unique,

        "Chronological_Unique_Incidents":
            baseline_unique,

        "V6_Unique_Recall":
            v6_unique_recall,

        "Chronological_Unique_Recall":
            baseline_unique_recall,

        "V6_Unique_Recall_Difference":
            (
                v6_unique_recall
                -
                baseline_unique_recall
            ),

        "Alerts_Avoided":
            v6_alerts_avoided,

        "Alerts_Avoided_Percentage":
            (
                v6_alerts_avoided
                /
                total_alerts
            )
    })


review_summary = pd.DataFrame(
    review_rows
)


print(
    "\n"
    "Review % | "
    "Alerts | "
    "V6 Incidents | "
    "Chron Incidents | "
    "V6 Recall | "
    "Chron Recall"
)


print(
    "-" * 90
)


for _, row in review_summary.iterrows():

    print(

        f"{row['Review_Percentage']:>7.1f}% | "

        f"{int(row['Alerts_Reviewed']):>7,} | "

        f"{int(row['V6_Unique_Incidents']):>12} | "

        f"{int(row['Chronological_Unique_Incidents']):>15} | "

        f"{row['V6_Unique_Recall'] * 100:>8.2f}% | "

        f"{row['Chronological_Unique_Recall'] * 100:>11.2f}%"
    )


review_summary.to_csv(
    REVIEW_FILE,
    index=False
)


print(
    "\nReview-fraction summary saved:"
)


print(
    REVIEW_FILE
)


# ============================================================
# 27. FIRST INCIDENT RANK
# ============================================================

print("\n" + "=" * 80)
print("FIRST INCIDENT DISCOVERY RANK")
print("=" * 80)


def first_incident_ranks(
    incident_lists
):

    first_rank = {}


    for rank, ids in enumerate(
        incident_lists,
        start=1
    ):

        for incident_id in ids:

            if incident_id not in first_rank:

                first_rank[
                    incident_id
                ] = rank


    return first_rank


v6_first_rank = first_incident_ranks(
    v6_incident_lists
)


chron_first_rank = first_incident_ranks(
    baseline_incident_lists
)


print(
    f"V6 incidents discovered: "
    f"{len(v6_first_rank):,}"
)


print(
    f"Chronological incidents discovered: "
    f"{len(chron_first_rank):,}"
)


if v6_first_rank:

    v6_ranks = list(
        v6_first_rank.values()
    )


    print(
        "\nV6:"
    )


    print(
        f"Minimum first rank : "
        f"{min(v6_ranks):,}"
    )


    print(
        f"Mean first rank    : "
        f"{np.mean(v6_ranks):,.2f}"
    )


    print(
        f"Median first rank  : "
        f"{np.median(v6_ranks):,.2f}"
    )


    print(
        f"Maximum first rank : "
        f"{max(v6_ranks):,}"
    )


if chron_first_rank:

    chron_ranks = list(
        chron_first_rank.values()
    )


    print(
        "\nChronological:"
    )


    print(
        f"Minimum first rank : "
        f"{min(chron_ranks):,}"
    )


    print(
        f"Mean first rank    : "
        f"{np.mean(chron_ranks):,.2f}"
    )


    print(
        f"Median first rank  : "
        f"{np.median(chron_ranks):,.2f}"
    )


    print(
        f"Maximum first rank : "
        f"{max(chron_ranks):,}"
    )


# ============================================================
# 28. KEY SIH RESULTS
# ============================================================

print("\n" + "=" * 80)
print("KEY SIH RESULTS")
print("=" * 80)


for requested_k in [
    100,
    500,
    1000,
    5000,
    10000
]:

    row = summary[
        summary["K"] == requested_k
    ].iloc[0]


    print(
        f"\nTop-{requested_k:,}"
    )


    print(
        f"V6 incidents found       : "
        f"{int(row['V6_Incidents_Found']):,}"
    )


    print(
        f"Chronological incidents  : "
        f"{int(row['Chronological_Incidents_Found']):,}"
    )


    print(
        f"V6 precision             : "
        f"{row['V6_Precision'] * 100:.2f}%"
    )


    print(
        f"Chronological precision  : "
        f"{row['Chronological_Precision'] * 100:.2f}%"
    )


    print(
        f"V6 incident recall       : "
        f"{row['V6_Recall'] * 100:.2f}%"
    )


    print(
        f"Chronological recall     : "
        f"{row['Chronological_Recall'] * 100:.2f}%"
    )


    print(
        f"Recall difference        : "
        f"{row['Recall_Difference'] * 100:+.2f} "
        f"percentage points"
    )


# ============================================================
# 29. BEST REVIEW-FRACTION RESULT
# ============================================================

print("\n" + "=" * 80)
print("BEST REVIEW-FRACTION RESULT")
print("=" * 80)


best_rows = review_summary[
    review_summary[
        "V6_Unique_Recall"
    ] >= 1.0
]


if len(best_rows) > 0:

    best = (
        best_rows
        .sort_values(
            "Review_Percentage"
        )
        .iloc[0]
    )


    print(
        f"100% unique incident discovery "
        f"achieved at: "
        f"{best['Review_Percentage']:.1f}% "
        f"review"
    )


    print(
        f"Alerts reviewed: "
        f"{int(best['Alerts_Reviewed']):,}"
    )


    print(
        f"Alerts avoided: "
        f"{int(best['Alerts_Avoided']):,}"
    )


    print(
        f"Alerts avoided percentage: "
        f"{best['Alerts_Avoided_Percentage'] * 100:.2f}%"
    )

else:

    print(
        "100% unique incident discovery "
        "was not reached within the tested "
        "review fractions."
    )


# ============================================================
# 30. FINAL PROJECT FACTS
# ============================================================

print("\n" + "=" * 80)
print("FINAL PROJECT FACTS")
print("=" * 80)


print(
    f"Test alerts              : "
    f"{total_alerts:,}"
)


print(
    f"Incident alerts          : "
    f"{total_incident_alerts:,}"
)


print(
    f"Incident rate            : "
    f"{incident_rate:.4%}"
)


print(
    f"Unique incidents         : "
    f"{total_unique_incidents:,}"
)


print(
    "Model                    : "
    "Isolation Forest"
)


print(
    "Learning type            : "
    "Unsupervised"
)


print(
    "Number of trees          : "
    "300"
)


print(
    "Random state             : "
    "42"
)


print(
    "Ground truth             : "
    "Post-hoc only"
)


print(
    "Model retrained          : "
    "NO"
)


print(
    "V6 ranking modified      : "
    "NO"
)


# ============================================================
# 31. SAFETY STATEMENT
# ============================================================

safety_text = """
SAFETY / METHODOLOGY

The V6 Isolation Forest was NOT retrained during evaluation.

V6 anomaly scores were NOT modified.

V6 priority scores were NOT modified.

V6 priority ranking was NOT modified.

incident_ids were used ONLY for post-hoc evaluation.

No incident labels were used during:

- feature engineering
- model training
- test scoring
- anomaly-score calculation
- priority-score creation
- priority ranking

No ground-truth information was used to create anomaly scores.

No incident information was used to create priority rankings.

_alert_id is only an identity / row-position key used to map
scored alerts back to the original test rows during evaluation.

_alert_id is NOT used as a model feature.

The chronological queue is an independent baseline.

The chronological baseline uses original timestamp order.

Evaluation was performed only after the alerts were scored.

The V6 model remains UNSUPERVISED.

This evaluation does NOT change the production ranking.
"""


# ============================================================
# 32. WRITE HUMAN-READABLE REPORT
# ============================================================

with open(
    REPORT_FILE,
    "w",
    encoding="utf-8"
) as f:

    f.write(
        "FINAL V6 SIH EVALUATION REPORT\n"
    )

    f.write(
        "=" * 80 + "\n\n"
    )


    f.write(
        "DATASET SUMMARY\n"
    )

    f.write(
        f"Test alerts: "
        f"{total_alerts:,}\n"
    )

    f.write(
        f"Incident alerts: "
        f"{total_incident_alerts:,}\n"
    )

    f.write(
        f"Incident rate: "
        f"{incident_rate:.4%}\n"
    )

    f.write(
        f"Unique incidents: "
        f"{total_unique_incidents:,}\n\n"
    )


    f.write(
        "MODEL\n"
    )

    f.write(
        "Isolation Forest\n"
    )

    f.write(
        "Unsupervised learning\n"
    )

    f.write(
        "300 trees\n"
    )

    f.write(
        "Random state = 42\n\n"
    )


    f.write(
        "TOP-K RESULTS\n"
    )

    f.write(
        "-" * 80 + "\n"
    )


    for _, row in summary.iterrows():

        f.write(

            f"Top-{int(row['K']):,}: "

            f"V6 incidents="
            f"{int(row['V6_Incidents_Found']):,}, "

            f"chronological incidents="
            f"{int(row['Chronological_Incidents_Found']):,}, "

            f"V6 precision="
            f"{row['V6_Precision'] * 100:.2f}%, "

            f"chronological precision="
            f"{row['Chronological_Precision'] * 100:.2f}%, "

            f"V6 recall="
            f"{row['V6_Recall'] * 100:.2f}%, "

            f"chronological recall="
            f"{row['Chronological_Recall'] * 100:.2f}%\n"
        )


    f.write(
        "\nUNIQUE INCIDENT DISCOVERY\n"
    )

    f.write(
        "-" * 80 + "\n"
    )


    for _, row in unique_summary.iterrows():

        f.write(

            f"Top-{int(row['K']):,}: "

            f"V6 unique incidents="
            f"{int(row['V6_Unique_Incidents'])}, "

            f"chronological unique incidents="
            f"{int(row['Chronological_Unique_Incidents'])}, "

            f"V6 unique recall="
            f"{row['V6_Unique_Recall'] * 100:.2f}%, "

            f"chronological unique recall="
            f"{row['Chronological_Unique_Recall'] * 100:.2f}%\n"
        )


    f.write(
        "\nREVIEW FRACTION\n"
    )

    f.write(
        "-" * 80 + "\n"
    )


    for _, row in review_summary.iterrows():

        f.write(

            f"Review {row['Review_Percentage']:.1f}%: "

            f"{int(row['Alerts_Reviewed']):,} alerts reviewed, "

            f"V6 discovered "
            f"{int(row['V6_Unique_Incidents'])} unique incidents, "

            f"V6 unique recall="
            f"{row['V6_Unique_Recall'] * 100:.2f}%, "

            f"alerts avoided="
            f"{row['Alerts_Avoided_Percentage'] * 100:.2f}%\n"
        )


    f.write(
        "\nFIRST INCIDENT DISCOVERY\n"
    )

    f.write(
        "-" * 80 + "\n"
    )


    if v6_first_rank:

        f.write(
            f"V6 minimum first rank: "
            f"{min(v6_ranks):,}\n"
        )

        f.write(
            f"V6 mean first rank: "
            f"{np.mean(v6_ranks):,.2f}\n"
        )

        f.write(
            f"V6 median first rank: "
            f"{np.median(v6_ranks):,.2f}\n"
        )

        f.write(
            f"V6 maximum first rank: "
            f"{max(v6_ranks):,}\n"
        )


    if chron_first_rank:

        f.write(
            f"Chronological minimum first rank: "
            f"{min(chron_ranks):,}\n"
        )

        f.write(
            f"Chronological mean first rank: "
            f"{np.mean(chron_ranks):,.2f}\n"
        )

        f.write(
            f"Chronological median first rank: "
            f"{np.median(chron_ranks):,.2f}\n"
        )

        f.write(
            f"Chronological maximum first rank: "
            f"{max(chron_ranks):,}\n"
        )


    f.write(
        "\n"
    )

    f.write(
        safety_text
    )


# ============================================================
# 33. FINAL OUTPUT
# ============================================================

print(
    "\nHuman-readable report saved:"
)


print(
    REPORT_FILE
)


print("\n" + "=" * 80)
print("FILES CREATED")
print("=" * 80)


print(
    f"1. {OUTPUT_FILE}"
)


print(
    f"2. {UNIQUE_FILE}"
)


print(
    f"3. {REVIEW_FILE}"
)


print(
    f"4. {REPORT_FILE}"
)


print("\n" + "=" * 80)
print("FINAL V6 SIH EVALUATION COMPLETE")
print("=" * 80)


print(
    "\nNo model retraining was performed."
)


print(
    "No V6 ranking was changed."
)


print(
    "Evaluation remains post-hoc."
)


print(
    "\nThe V6 model is ready for the "
    "remaining SIH implementation work."
)


print("=" * 80)