"""
SAT-SA View: On-Demand Batch Alert Prediction Lab
Problem Statement: SIH26157 | SAT-SA V6
"""

import streamlit as st
import pandas as pd
from backend.batch_prediction import process_new_submission, get_submission_manifest
from dashboard.ui_theme import (
    render_command_header,
    render_kpi_card,
    render_section_header,
    render_severity_badge,
    CYBER_PALETTE
)

def render_batch_prediction_view(selected_org_id: str = "ORG-0004"):
    """Render the high-throughput offline batch alert prediction workbench."""
    render_command_header(
        page_title="On-Demand Batch Alert Prediction Lab",
        page_subtitle="High-Throughput Offline CSV/JSON Alert Scoring with Zero Target Leakage & SHA-256 Manifest Tracking",
        active_cse=selected_org_id,
        total_alerts=402335
    )

    # 1. Interactive Dropzone Card
    render_section_header(
        title="Submit Alert Batch for Autonomous Triage",
        subtitle="Upload raw or formatted SOC alert logs in CSV or JSON format.",
        badge="BATCH INGESTION"
    )

    with st.container():
        st.markdown(
            """
            <div class="cyber-card">
            """,
            unsafe_allow_html=True
        )

        uploaded_file = st.file_uploader(
            "Select Alert Batch File (.csv, .json)",
            type=["csv", "json"],
            key="batch_file_uploader",
            help="Supports standard SOC alert schemas. All ground truth labels and proxy rates are stripped automatically before inference."
        )

        col_b1, col_b2 = st.columns([3, 1])
        with col_b1:
            batch_model = st.selectbox(
                "Inference Engine",
                [
                    "V6 Baseline Model (Historical 54 Features, 300 Trees)",
                    "Leakage-Reduced Candidate (Clean 50 Features, 300 Trees)"
                ],
                key="batch_model_selector"
            )
        with col_b2:
            st.markdown("<div style='height: 28px;'></div>", unsafe_allow_html=True)
            submit_btn = st.button("🚀 Score Alert Batch", type="primary", width="stretch", key="batch_submit_btn")

        st.markdown("</div>", unsafe_allow_html=True)

        if submit_btn and uploaded_file is not None:
            m_key = "leakage_reduced" if "Leakage-Reduced" in batch_model else "baseline"
            with st.spinner("Executing arrival-time feature extraction and Isolation Forest inference..."):
                content_bytes = uploaded_file.getvalue()
                success, msg, res_df, manifest_entry = process_new_submission(
                    content_bytes=content_bytes,
                    filename=uploaded_file.name,
                    model_type=m_key,
                )

            if success:
                st.success(f"✅ {msg}")
                # Metric HUD
                k1, k2, k3, k4 = st.columns(4)
                with k1:
                    render_kpi_card("Alerts Scored", f"{manifest_entry['alert_count']:,}", "Complete batch volume", delta="100% Scored", delta_type="positive")
                with k2:
                    render_kpi_card("Mean Anomaly Score", f"{manifest_entry['mean_anomaly_score']:.4f}", "Isolation Forest anomaly", delta="Normalized", delta_type="neutral")
                with k3:
                    render_kpi_card("Critical Priority", f"{manifest_entry['critical_count']:,}", "Top 1% priority tier", delta="Immediate Review", delta_type="critical" if manifest_entry['critical_count'] > 0 else "neutral")
                with k4:
                    render_kpi_card("High Priority", f"{manifest_entry['high_count']:,}", "Secondary priority tier", delta="Elevated Risk", delta_type="warning" if manifest_entry['high_count'] > 0 else "neutral")

                if manifest_entry.get("stripped_ground_truth_fields"):
                    st.info(f"🔒 Ground-Truth Stripped: {', '.join(manifest_entry['stripped_ground_truth_fields'])} (Zero target leakage guaranteed)")

                # Prioritized results table
                st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)
                render_section_header("Prioritized Batch Triage Results", subtitle="Ranked by anomaly score in descending order.", badge="OUTPUT QUEUE")
                
                disp_cols = [c for c in ["priority_rank", "_alert_id", "priority_score", "priority_label", "Timestamp", "src_ip", "dst_ip", "severity", "action", "message_sanitized"] if c in res_df.columns]
                st.dataframe(res_df[disp_cols].head(250), width="stretch", hide_index=True)

                csv_download = res_df.to_csv(index=False).encode('utf-8')
                st.download_button(
                    "💾 Download Scored Priority Queue (CSV)",
                    data=csv_download,
                    file_name=f"scored_{uploaded_file.name}.csv",
                    mime="text/csv",
                )
            else:
                st.error(f"❌ Batch Scoring Failed: {msg}")

    # 2. Historical Submission Manifest Table
    st.markdown("<div style='height: 16px;'></div>", unsafe_allow_html=True)
    render_section_header(
        title="Persistent Submission History & Audit Trail",
        subtitle="Cryptographically verified SHA-256 records of previous batch evaluations.",
        badge="AUDIT LOG"
    )

    history = get_submission_manifest()
    if history:
        hist_df = pd.DataFrame(history)[["submission_id", "filename", "timestamp", "model_used", "alert_count", "mean_anomaly_score", "critical_count", "high_count"]]
        rename_h = {
            "submission_id": "Submission ID",
            "filename": "File Name",
            "timestamp": "Processed At",
            "model_used": "Model",
            "alert_count": "Alert Count",
            "mean_anomaly_score": "Mean Score",
            "critical_count": "Critical",
            "high_count": "High"
        }
        st.dataframe(hist_df.rename(columns=rename_h), width="stretch", hide_index=True)
    else:
        st.info("No batch submissions recorded in local manifest yet.")
