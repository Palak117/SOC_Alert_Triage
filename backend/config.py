"""
SOC Alert Triage - Backend Configuration
Defines file paths, model configurations, theme design tokens, and column schemas.
"""

from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
SCORED_DIR = DATA_DIR / "scored"
MODEL_DIR = BASE_DIR / "model"
TEST_DATA_PATH = DATA_DIR / "train_test" / "test_20.csv"

# Pre-consolidated Storage Paths
CONSOLIDATED_PARQUET = SCORED_DIR / "dashboard_consolidated.parquet"
CONSOLIDATED_CSV = SCORED_DIR / "dashboard_consolidated.csv"
CONSOLIDATED_LR_PARQUET = SCORED_DIR / "dashboard_consolidated_leakage_reduced.parquet"
CONSOLIDATED_LR_CSV = SCORED_DIR / "dashboard_consolidated_leakage_reduced.csv"

# Raw Baseline Files
BASELINE_ALERTS_CSV = SCORED_DIR / "final_v6_sih_dashboard_alerts.csv"
BASELINE_INCIDENTS_CSV = SCORED_DIR / "final_v6_sih_dashboard_incidents.csv"
BASELINE_SUMMARY_CSV = SCORED_DIR / "final_v6_sih_dashboard_summary.csv"
BASELINE_REVIEW_CSV = SCORED_DIR / "final_v6_sih_dashboard_review_fractions.csv"

# Leakage-Reduced Files
LR_ALERTS_CSV = SCORED_DIR / "test_v6_leakage_reduced_scored.csv"
LR_INCIDENTS_CSV = SCORED_DIR / "leakage_reduced_dashboard_incidents.csv"
LR_SUMMARY_CSV = SCORED_DIR / "leakage_reduced_dashboard_summary.csv"
LR_REVIEW_CSV = SCORED_DIR / "leakage_reduced_review_fractions.csv"
LR_VS_BASELINE_COMPARISON_CSV = SCORED_DIR / "leakage_reduced_vs_v6_comparison.csv"

# Context & Supervisory Audit Layers
CONTEXT_LAYER_CSV = SCORED_DIR / "final_v6_sih_context_layer.csv"
SUPERVISORY_AUDIT_CSV = SCORED_DIR / "final_v6_sih_supervisory_audit.csv"
SUPERVISORY_COMPLETE_CSV = SCORED_DIR / "final_v6_sih_supervisory_complete.csv"

# Model Artifacts
BASELINE_MODEL_PATH = MODEL_DIR / "isolation_forest_unsupervised_v6.pkl"
LR_MODEL_PATH = MODEL_DIR / "isolation_forest_v6_leakage_reduced.pkl"

# Enterprise SOC Dark Design Palette
PALETTE = {
    "bg_dark": "#0B1220",
    "panel_bg": "#111C2E",
    "card_bg": "#152238",
    "border": "#1E293B",
    "border_light": "#334155",
    "text_primary": "#F8FAFC",
    "text_secondary": "#94A3B8",
    "text_muted": "#64748B",
    "accent_cyan": "#38BDF8",
    "accent_teal": "#2DD4BF",
    "accent_green": "#34D399",
    "accent_amber": "#FBBF24",
    "accent_red": "#F87171",
    "accent_purple": "#A855F7",
    "critical": "#EF4444",
    "high": "#F97316",
    "medium": "#FBBF24",
    "low": "#38BDF8",
}

# Core Essential Columns for Consolidated Dataset
CORE_COLUMNS = [
    # Identifier & Timing
    "_alert_id",
    "timestamp",
    "event_time",
    "timestamp_datetime",
    "Timestamp",
    "origin",
    "org_id",
    "artifact_id",
    "pipeline",
    "stream_name",
    # Network & Entity
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "src_host",
    "dst_host",
    "username",
    "entity_key",
    "entity_alert_frequency",
    # Alert Details
    "action",
    "severity",
    "vendor_code",
    "message_type",
    "message_sanitized",
    "product_name",
    "vendor_name",
    "matched_rules",
    "set_roles",
    "lifecycle_stage",
    "disposition",
    "status_name",
    # Model Scoring
    "anomaly_score",
    "priority_score",
    "priority_rank",
    "priority_label",
    # Ground Truth & Evaluation
    "incident_ids",
    "actual_incident",
    "label_binary",
    "label_confidence",
    "attack_tactics",
    "attack_techniques",
    "is_suspicious_mitre",
    "security_relevant",
    # Supervisory & Context Gaps
    "evidence_gap_count",
    "evidence_gap_signal",
    "evidence_gap_level",
    "investigation_without_evidence_signal",
    "low_telemetry_signal",
    "no_escalation_context_signal",
    "critical_missing_context_signal",
    "repetitive_investigation_signal",
    "negative_space_signal",
    "execution_gap_count",
    "execution_gap_level",
    "context_reason",
    "repeated_entity_signal",
    "high_frequency_entity_signal",
    # Supervisory Audit
    "peer_comparison_supported",
    "peer_comparison_status",
    "supervisory_peer_reason",
    "supervisory_review_reason",
    "supervisory_review_recommended",
    "supervisory_disclaimer",
    "rapid_closure_duration_supported",
    "remediation_completion_supported",
    "incident_labels_used_for_peer_comparison",
    "v6_scores_or_ranks_modified",
    # Complete Supervisory Analytics
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
    # Peer Robust Z & Outlier Signals
    "peer_robust_z_investigation_evidence_count",
    "peer_outlier_investigation_evidence_count",
    "peer_robust_z_telemetry_evidence_count",
    "peer_outlier_telemetry_evidence_count",
    "peer_robust_z_evidence_gap_count",
    "peer_outlier_evidence_gap_count",
    "peer_robust_z_execution_gap_count",
    "peer_outlier_execution_gap_count",
    "peer_robust_z_negative_space_count",
    "peer_outlier_negative_space_count",
    "peer_robust_z_entity_alert_frequency",
    "peer_outlier_entity_alert_frequency",
    "peer_robust_z_source_ip_frequency",
    "peer_outlier_source_ip_frequency",
    "peer_robust_z_destination_ip_frequency",
    "peer_outlier_destination_ip_frequency",
]


class Config:
    """Configuration access helper."""
    BASE_DIR = BASE_DIR
    DATA_DIR = DATA_DIR
    SCORED_DIR = SCORED_DIR
    MODEL_DIR = MODEL_DIR
    PALETTE = PALETTE
    CORE_COLUMNS = CORE_COLUMNS
