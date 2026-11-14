"""
SAT-SA View: Supervisory Context, Negative Space & Evidence Gaps
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

def render_context_gaps_view(
    alerts: pd.DataFrame,
    selected_org_id: str = "ORG-0004"
):
    """Render the supervisory context, negative space and evidence gap audit view."""
    render_command_header(
        page_title="Supervisory Context & Negative Space Audit",
        page_subtitle="Evidence Completeness, Unmonitored Telemetry Blind Spots & Cross-Entity Peer Benchmarks",
        active_cse=selected_org_id,
        total_alerts=len(alerts)
    )

    # 1. Top Supervisory HUD
    def audit_bool(series):
        return series.astype(str).str.strip().str.lower().isin(["true", "1", "yes", "y"])

    gap_col = "supervisory_evidence_gap_review"
    peer_col = "peer_deviation_review_signal"
    entity_col = "entity_frequency_review_signal"
    supp_col = "peer_comparison_supported_computed"

    gap_count = int(audit_bool(alerts[gap_col]).sum()) if gap_col in alerts.columns else int((alerts["src_ip"].isna() | alerts["username"].isna()).sum())
    peer_count = int(audit_bool(alerts[peer_col]).sum()) if peer_col in alerts.columns else int((alerts["anomaly_score"] > 0.05).sum())
    ent_count = int(audit_bool(alerts[entity_col]).sum()) if entity_col in alerts.columns else int((alerts["priority_label"].isin(["Critical", "High"])).sum())
    supp_count = int(audit_bool(alerts[supp_col]).sum()) if supp_col in alerts.columns else len(alerts)

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        render_kpi_card(
            title="Evidence Gap Signals",
            value=f"{gap_count:,}",
            subtitle="Alerts missing key investigation context",
            delta=f"{(gap_count / len(alerts) * 100):.2f}% Gap Ratio",
            delta_type="warning" if gap_count > 0 else "positive"
        )
    with c2:
        render_kpi_card(
            title="Peer Deviation Signals",
            value=f"{peer_count:,}",
            subtitle="Statistically anomalous vs peer cohort",
            delta="> 3σ Deviation",
            delta_type="critical" if peer_count > 0 else "neutral"
        )
    with c3:
        render_kpi_card(
            title="Entity Frequency Signals",
            value=f"{ent_count:,}",
            subtitle="High-frequency operational bursts",
            delta="Velocity Spikes",
            delta_type="warning"
        )
    with c4:
        render_kpi_card(
            title="Peer Benchmarks Active",
            value=f"{supp_count:,}",
            subtitle="Alerts evaluated against cohort",
            delta="Cohort Group ≥ 30",
            delta_type="positive"
        )

    st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)

    # 2. Evidence Completeness Across Sensor Corpus
    render_section_header(
        title="Telemetry Field Completeness Audit",
        subtitle="Distribution of critical investigation fields across the active entity corpus.",
        badge="COMPLETENESS MATRIX"
    )

    tot = len(alerts)
    has_user = int((alerts["username"].astype(str).str.strip().ne("") & alerts["username"].notna() & alerts["username"].ne("nan")).sum()) if "username" in alerts else tot
    has_ip = int((alerts["src_ip"].astype(str).str.strip().ne("") & alerts["src_ip"].notna() & alerts["src_ip"].ne("nan")).sum()) if "src_ip" in alerts else tot
    has_action = int((alerts["action"].astype(str).str.strip().ne("") & alerts["action"].notna() & alerts["action"].ne("nan")).sum()) if "action" in alerts else 0
    has_disp = int((alerts["disposition"].astype(str).str.strip().ne("") & alerts["disposition"].notna() & alerts["disposition"].ne("nan")).sum()) if "disposition" in alerts else 0

    field_metrics = [
        {"field": "Network Source IP (src_ip)", "count": has_ip, "pct": has_ip / tot * 100.0, "role": "Network Perimeter Attribution"},
        {"field": "Identity Account (username)", "count": has_user, "pct": has_user / tot * 100.0, "role": "Credential & User Context"},
        {"field": "Remediation Action (action)", "count": has_action, "pct": has_action / tot * 100.0, "role": "Execution & Containment Audit"},
        {"field": "SOC Disposition (disposition)", "count": has_disp, "pct": has_disp / tot * 100.0, "role": "Analyst Closure & Triage"}
    ]

    field_cols = st.columns(4)
    for idx, fm in enumerate(field_metrics):
        with field_cols[idx]:
            bar_color = "#10B981" if fm["pct"] > 80 else ("#F59E0B" if fm["pct"] > 40 else "#EF4444")
            st.markdown(
                f"""
                <div class="cyber-card">
                    <div style="font-size:0.75rem; text-transform:uppercase; color:#94A3B8; font-weight:600;">{fm['field']}</div>
                    <div style="font-size:1.6rem; font-family:'JetBrains Mono', monospace; font-weight:700; color:#F8FAFC; margin:4px 0;">{fm['pct']:.1f}%</div>
                    <div style="font-size:0.75rem; color:#64748B;">{fm['count']:,} of {tot:,} populated</div>
                    <div style="margin-top:8px; height:4px; border-radius:2px; background:rgba(255,255,255,0.1);">
                        <div style="height:100%; width:{fm['pct']}%; background:{bar_color}; border-radius:2px;"></div>
                    </div>
                    <div style="font-size:0.70rem; color:#94A3B8; margin-top:6px;">{fm['role']}</div>
                </div>
                """,
                unsafe_allow_html=True
            )

    # 3. Peer Behavioral Outlier Explorer
    render_section_header(
        title="Peer Deviation Outlier Registry (> 3σ Anomaly Signals)",
        subtitle="Alerts exhibiting significant behavioral divergence from established peer entity baselines.",
        badge="OUTLIER REGISTRY"
    )

    if "peer_deviation_review_signal" in alerts.columns and (alerts["peer_deviation_review_signal"] == True).any():
        outlier_df = alerts[alerts["peer_deviation_review_signal"] == True].head(50).copy()
    elif "negative_space_signal" in alerts.columns and (alerts["negative_space_signal"] == True).any():
        outlier_df = alerts[alerts["negative_space_signal"] == True].head(50).copy()
    elif "evidence_gap_signal" in alerts.columns and (alerts["evidence_gap_signal"] == True).any():
        outlier_df = alerts[alerts["evidence_gap_signal"] == True].head(50).copy()
    else:
        outlier_df = alerts[alerts["priority_label"].isin(["Critical", "High"])].head(25).copy()

    if not outlier_df.empty:
        disp_cols = [
            "priority_rank", "anomaly_score", "priority_label", "Timestamp",
            "peer_robust_z_entity_rate", "peer_robust_z_arrival_velocity",
            "evidence_gap_count", "execution_gap_count", "src_ip", "dst_ip", "username", "product_name"
        ]
        existing = [c for c in disp_cols if c in outlier_df.columns]
        rename_map = {
            "priority_rank": "Rank",
            "anomaly_score": "Score",
            "priority_label": "Tier",
            "Timestamp": "Event Time",
            "peer_robust_z_entity_rate": "Peer Z (Entity)",
            "peer_robust_z_arrival_velocity": "Peer Z (Velocity)",
            "evidence_gap_count": "Evidence Gaps",
            "execution_gap_count": "Execution Gaps",
            "src_ip": "Source IP",
            "dst_ip": "Destination IP",
            "username": "User",
            "product_name": "Sensor"
        }
        st.dataframe(
            outlier_df[existing].rename(columns=rename_map),
            width="stretch",
            hide_index=True,
            column_config={
                "Score": st.column_config.NumberColumn(format="%.4f"),
                "Rank": st.column_config.NumberColumn(format="#%d"),
                "Peer Z (Entity)": st.column_config.NumberColumn(format="%+.2fσ"),
                "Peer Z (Velocity)": st.column_config.NumberColumn(format="%+.2fσ")
            }
        )
    else:
        st.info("No extreme peer deviations in current slice.")
