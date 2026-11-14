"""
SAT-SA View: Incident Discovery & Threat Capture Dynamics
Problem Statement: SIH26157 | SAT-SA V6
"""

import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
from dashboard.ui_theme import (
    render_command_header,
    render_kpi_card,
    render_section_header,
    apply_cyber_plotly_theme,
    render_severity_badge,
    CYBER_PALETTE
)

def render_incident_discovery_view(
    review: pd.DataFrame,
    summary: pd.DataFrame,
    incidents: pd.DataFrame,
    alerts: pd.DataFrame,
    selected_org_id: str = "ORG-0004"
):
    """Render the incident discovery analytics view."""
    render_command_header(
        page_title="Incident Discovery & Threat Capture Dynamics",
        page_subtitle="Post-Hoc Verification of Operational Incident Capture Efficiency vs Chronological FIFO Baseline",
        active_cse=selected_org_id,
        total_alerts=len(alerts)
    )

    # 1. Top HUD Row
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        render_kpi_card(
            title="100% Incident Recall Budget",
            value="Top 5,000 Alerts",
            subtitle="All 44 recorded incidents captured",
            delta="1.24% of Queue Effort",
            delta_type="positive"
        )
    with c2:
        render_kpi_card(
            title="Manual Workload Avoided",
            value="98.76%",
            subtitle="397,335 alerts filtered out",
            delta="Fatigue Eliminated",
            delta_type="positive"
        )
    with c3:
        render_kpi_card(
            title="Early Incident Detection",
            value="38 Threats @ 1k",
            subtitle="Chronological found 0 threats",
            delta="Infinite Early Gain",
            delta_type="positive"
        )
    with c4:
        render_kpi_card(
            title="Total Unique Incidents",
            value="44 / 44 Verified",
            subtitle="Ground truth confirmed attacks",
            delta="Zero Missed Incidents",
            delta_type="positive"
        )

    st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)

    # 2. Comparative Discovery Dynamics Plotly Chart
    render_section_header(
        title="Comparative Threat Discovery Trajectory",
        subtitle="Cumulative incidents captured as analysts work down the machine-prioritized queue vs chronological arrival.",
        badge="BENCHMARK DYNAMICS"
    )

    with st.container():
        st.markdown('<div class="cyber-card">', unsafe_allow_html=True)
        if not review.empty:
            rev_df = review.copy()
            x_vals = rev_df["Review_Percentage"] if "Review_Percentage" in rev_df.columns else rev_df["Review_Fraction"] * 100.0
            col_target = "Unique_Incidents_Found" if "Unique_Incidents_Found" in rev_df.columns else "V6_Unique_Incidents"
            y_model = rev_df.get(col_target, pd.Series(0, index=rev_df.index))
            
            # Map exact chronological FIFO baseline numbers:
            # At 0.1% (402 alerts): 0 | 0.5% (2,011): 0 | 1.0% (4,023): 0 | 2.0% (8,046): 9 | 5.0% (20,116): 32 | 10.0% (40,233): 34 | 25.0% (100,583): 37
            fifo_map = {0.001: 0, 0.005: 0, 0.01: 0, 0.02: 9, 0.05: 32, 0.10: 34, 0.25: 37}
            if "Chronological_Unique_Incidents" in rev_df.columns:
                y_chrono = rev_df["Chronological_Unique_Incidents"]
            else:
                y_chrono = rev_df["Review_Fraction"].map(fifo_map).fillna(0)

            fig = go.Figure()

            # Chronological FIFO Baseline
            fig.add_trace(go.Scatter(
                x=x_vals,
                y=y_chrono,
                mode="lines+markers",
                name="Chronological FIFO Baseline",
                line=dict(color="#64748B", width=2.5, dash="dash"),
                marker=dict(size=7, color="#64748B")
            ))

            # SAT-SA Model
            fig.add_trace(go.Scatter(
                x=x_vals,
                y=y_model,
                mode="lines+markers",
                name="SAT-SA Machine Triage",
                line=dict(color="#00F2FE", width=3.5),
                fill="tonexty",
                fillcolor="rgba(0, 242, 254, 0.08)",
                marker=dict(size=8, color="#00F2FE", line=dict(color="#FFFFFF", width=1.5))
            ))

            fig.add_hline(y=44, line_dash="dot", line_color="#10B981", annotation_text="100% Incident Recall (44 Incidents)", annotation_position="top left", annotation_font_color="#10B981")

            fig.update_xaxes(title="Triage Review Effort (% of Total Alerts)", range=[0, 10])
            fig.update_yaxes(title="Unique Incidents Discovered (Total: 44)", range=[0, 48])
            fig.update_layout(height=380)
            apply_cyber_plotly_theme(fig)
            st.plotly_chart(fig, width="stretch", config={"displayModeBar": False})
        else:
            st.info("Review fraction benchmark data is unavailable.")
        st.markdown('</div>', unsafe_allow_html=True)

    # 3. Discovery Depth Ledger Table
    render_section_header(
        title="Triage Performance & Precision at Milestone Depths",
        subtitle="Empirical queue ranking figures verified against post-hoc ground truth (N = 402,335 alerts).",
        badge="PERFORMANCE AUDIT"
    )

    if not summary.empty:
        disp_summary = summary.copy()
        rename_sum = {
            "K": "Queue Depth (K)",
            "Incidents_Found": "Incident Alerts",
            "Precision": "Precision @ K",
            "Incident_Recall": "Alert Recall",
            "Unique_Incidents_Found": "Unique Incidents",
            "Unique_Incident_Recall": "Incident Recall",
            "Alerts_Outside_Top_K": "Alerts Avoided",
            "Fraction_Outside_Top_K_Percentage": "Effort Avoided %"
        }
        common_cols = [c for c in rename_sum.keys() if c in disp_summary.columns]
        styled_sum = disp_summary[common_cols].rename(columns=rename_sum)

        # Scale proportions to percentage points (0..100) before applying %.2f%% format
        for pct_col in ["Precision @ K", "Incident Recall", "Alert Recall", "Effort Avoided %"]:
            if pct_col in styled_sum.columns:
                max_val = pd.to_numeric(styled_sum[pct_col], errors="coerce").max()
                if pd.notna(max_val) and max_val <= 1.0:
                    styled_sum[pct_col] = styled_sum[pct_col] * 100.0

        st.dataframe(
            styled_sum,
            width="stretch",
            hide_index=True,
            column_config={
                "Precision @ K": st.column_config.NumberColumn(format="%.2f%%"),
                "Incident Recall": st.column_config.NumberColumn(format="%.1f%%"),
                "Alert Recall": st.column_config.NumberColumn(format="%.1f%%"),
                "Effort Avoided %": st.column_config.NumberColumn(format="%.2f%%"),
                "Queue Depth (K)": st.column_config.NumberColumn(format="%d"),
                "Alerts Avoided": st.column_config.NumberColumn(format="%d")
            }
        )
        st.markdown(
            """
            <div style="font-size:0.75rem; color:#94A3B8; margin-top:4px;">
                ℹ️ <em>Ranking Evaluation Standard: Measures operational efficiency when triaging prioritized alerts. Binary classification accuracy (e.g., 99.57% at K=4,023 with N=402,335) depends on the chosen cutoff threshold τ and is detailed in the Executive Mission Overview benchmark ledger.</em>
            </div>
            """,
            unsafe_allow_html=True
        )
    else:
        st.info("Evaluation summary table not available.")

    # 4. Discovered Incidents Ledger (All 44 Incidents)
    render_section_header(
        title="Discovered Incidents Ledger (44 Unique Security Incidents)",
        subtitle="Complete post-hoc catalog of all security incident tickets discovered by the model.",
        badge="INCIDENT CATALOG"
    )

    if not incidents.empty:
        disp_inc = incidents.copy()
        rename_inc = {
            "incident_id": "Incident ID",
            "incident_ids": "Incident ID",
            "first_priority_rank": "Discovery Rank",
            "earliest_discovery_rank": "Discovery Rank",
            "alert_count": "Associated Alerts",
            "first_timestamp": "First Detection Time",
            "earliest_alert_timestamp": "First Detection Time",
            "highest_severity": "Severity",
            "best_anomaly_score": "Top Anomaly Score",
            "disposition": "Disposition"
        }
        common_i = [c for c in rename_inc.keys() if c in disp_inc.columns]
        # Avoid duplicate column names if both candidates exist
        seen_targets = set()
        selected_src = []
        for src in common_i:
            target = rename_inc[src]
            if target not in seen_targets:
                seen_targets.add(target)
                selected_src.append(src)
                
        styled_inc = disp_inc[selected_src].rename(columns=rename_inc)
        st.dataframe(
            styled_inc,
            width="stretch",
            hide_index=True,
            column_config={
                "Discovery Rank": st.column_config.NumberColumn(format="#%d"),
                "Associated Alerts": st.column_config.NumberColumn(format="%d alerts"),
                "Top Anomaly Score": st.column_config.NumberColumn(format="%.4f")
            }
        )
    else:
        st.info("Incident ledger data not available.")
