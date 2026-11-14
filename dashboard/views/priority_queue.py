"""
SAT-SA View: Priority Alert Queue
Problem Statement: SIH26157 | SAT-SA V6
"""

import streamlit as st
import pandas as pd
import numpy as np
from dashboard.ui_theme import (
    render_command_header,
    render_kpi_card,
    render_section_header,
    apply_cyber_plotly_theme,
    render_severity_badge,
    CYBER_PALETTE
)

def render_priority_queue_view(
    filtered: pd.DataFrame,
    alerts: pd.DataFrame,
    selected_org_id: str = "ORG-0004"
):
    """Render the high-throughput operational priority queue."""
    render_command_header(
        page_title="Operational Triage Priority Queue",
        page_subtitle="Continuous Machine-Scored Alert Queue Ranked by Statistical Rarity & Threat Indicators",
        active_cse=selected_org_id,
        total_alerts=len(alerts)
    )

    # 1. Quick Triage HUD Metrics
    crit_count = int((filtered["priority_label"] == "Critical").sum()) if "priority_label" in filtered else 0
    high_count = int((filtered["priority_label"] == "High").sum()) if "priority_label" in filtered else 0
    inc_count = int((filtered["actual_incident"] == 1).sum()) if "actual_incident" in filtered else 0
    mean_score = float(filtered["anomaly_score"].mean()) if "anomaly_score" in filtered and not filtered.empty else 0.0

    m1, m2, m3, m4 = st.columns(4)
    with m1:
        render_kpi_card(
            title="Active Queue Depth",
            value=f"{len(filtered):,}",
            subtitle="Alerts in current filter scope",
            delta=f"{len(filtered)/len(alerts)*100:.1f}% of total corpus",
            delta_type="neutral"
        )
    with m2:
        render_kpi_card(
            title="Critical Priority Alerts",
            value=f"{crit_count:,}",
            subtitle="Immediate investigation tier",
            delta="Urgent Action",
            delta_type="critical" if crit_count > 0 else "neutral"
        )
    with m3:
        render_kpi_card(
            title="High Priority Alerts",
            value=f"{high_count:,}",
            subtitle="Elevated statistical anomaly",
            delta="Secondary Triage",
            delta_type="warning" if high_count > 0 else "neutral"
        )
    with m4:
        render_kpi_card(
            title="Mean Anomaly Score",
            value=f"{mean_score:.4f}",
            subtitle="Standardized Isolation Forest score",
            delta=f"{inc_count} Confirmed Incidents",
            delta_type="positive" if inc_count > 0 else "neutral"
        )

    st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)

    # 2. Interactive Controls & Fast Triage Slicing
    render_section_header(
        title="Queue Control & Ordering Console",
        subtitle="Sort, filter and inspect prioritized alerts.",
        badge="TRIAGE HUD"
    )

    with st.container():
        st.markdown('<div class="cyber-card">', unsafe_allow_html=True)
        c1, c2, c3, c4 = st.columns([1.2, 1.2, 1.2, 1])
        with c1:
            queue_size = st.selectbox(
                "Display Volume",
                [25, 50, 100, 250, 500, 1000, 2500, 5000],
                index=2,
                key="pq_display_volume",
                help="Number of alerts to render in the interactive triage table."
            )
        with c2:
            sort_mode = st.selectbox(
                "Queue Sort Key",
                ["Priority Rank (Ascending)", "Priority Score (Descending)", "Arrival Timestamp (Newest First)"],
                index=0,
                key="pq_sort_key"
            )
        with c3:
            tier_slice = st.selectbox(
                "Triage Tier Filter",
                ["All Tiers", "Critical Tier Only", "Critical + High Tiers", "Confirmed Incidents Only"],
                index=0,
                key="pq_tier_slice"
            )
        with c4:
            st.markdown("<div style='height: 28px;'></div>", unsafe_allow_html=True)
            export_csv = st.button("📥 Export Queue", width="stretch", key="pq_export_queue_btn")
        st.markdown('</div>', unsafe_allow_html=True)

    # Apply local tier slice
    queue = filtered.copy()
    if tier_slice == "Critical Tier Only":
        queue = queue[queue["priority_label"] == "Critical"]
    elif tier_slice == "Critical + High Tiers":
        queue = queue[queue["priority_label"].isin(["Critical", "High"])]
    elif tier_slice == "Confirmed Incidents Only":
        queue = queue[queue["actual_incident"] == 1]

    # Apply sort
    if sort_mode == "Priority Rank (Ascending)":
        queue = queue.sort_values("priority_rank", ascending=True)
    elif sort_mode == "Priority Score (Descending)":
        queue = queue.sort_values("priority_score", ascending=False)
    elif sort_mode == "Arrival Timestamp (Newest First)" and "Timestamp" in queue.columns:
        queue = queue.sort_values("Timestamp", ascending=False)

    sliced_queue = queue.head(queue_size).copy()

    # 3. Interactive Data Table
    render_section_header(
        title=f"Prioritized Alerts ({len(sliced_queue):,} of {len(queue):,} displayed)",
        subtitle="Ordered by ML threat likelihood with verified forensic columns.",
        badge="LIVE QUEUE"
    )

    disp_cols = ["priority_rank", "anomaly_score", "priority_label", "Timestamp", "src_ip", "dst_ip", "username", "message_sanitized", "actual_incident"]
    existing_cols = [c for c in disp_cols if c in sliced_queue.columns]

    rename_map = {
        "priority_rank": "Rank",
        "anomaly_score": "Score",
        "priority_label": "Priority",
        "Timestamp": "Timestamp",
        "src_ip": "Source IP",
        "dst_ip": "Destination IP",
        "username": "User",
        "message_sanitized": "Alert Summary",
        "actual_incident": "Incident Ground Truth"
    }

    styled_df = sliced_queue[existing_cols].rename(columns=rename_map)
    st.dataframe(
        styled_df,
        width="stretch",
        hide_index=True,
        column_config={
            "Score": st.column_config.NumberColumn(format="%.4f"),
            "Rank": st.column_config.NumberColumn(format="#%d"),
            "Incident Ground Truth": st.column_config.CheckboxColumn("Confirmed Incident")
        }
    )

    if export_csv:
        csv_bytes = sliced_queue.to_csv(index=False).encode('utf-8')
        st.download_button(
            "💾 Download Current Queue CSV",
            data=csv_bytes,
            file_name=f"priority_queue_{selected_org_id}_top{queue_size}.csv",
            mime="text/csv"
        )

    # 4. Quick Alert Inspector Drawer
    st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)
    with st.expander("🔍 Quick Alert Dossier Inspector", expanded=False):
        if not sliced_queue.empty:
            inspect_rank = st.number_input(
                "Enter Rank # to inspect",
                min_value=int(sliced_queue["priority_rank"].min()),
                max_value=int(sliced_queue["priority_rank"].max()),
                value=int(sliced_queue["priority_rank"].iloc[0]),
                step=1,
                key="pq_inspect_rank_input"
            )
            inspect_rows = sliced_queue[sliced_queue["priority_rank"] == inspect_rank]
            if not inspect_rows.empty:
                i_row = inspect_rows.iloc[0]
                ins_c1, ins_c2, ins_c3 = st.columns(3)
                with ins_c1:
                    st.markdown(f"**Source Asset:** `{i_row.get('src_ip', 'N/A')}:{i_row.get('src_port', 'N/A')}`")
                    st.markdown(f"**Destination Asset:** `{i_row.get('dst_ip', 'N/A')}:{i_row.get('dst_port', 'N/A')}`")
                    st.markdown(f"**Target Identity:** `{i_row.get('username', 'N/A')}`")
                with ins_c2:
                    st.markdown(f"**Anomaly Score:** `{i_row.get('anomaly_score', 0):.6f}`")
                    st.markdown(f"**Priority Tier:** {render_severity_badge(i_row.get('priority_label', 'Unknown'))}", unsafe_allow_html=True)
                    st.markdown(f"**Ground Truth Incident:** {'🚨 Confirmed' if i_row.get('actual_incident') == 1 else '🛡️ Benign'}")
                with ins_c3:
                    st.markdown(f"**Sensor:** `{i_row.get('product_name', i_row.get('origin', 'N/A'))}`")
                    st.markdown(f"**Event Time:** `{i_row.get('Timestamp', 'N/A')}`")
                st.info(f"**Alert Message:** {i_row.get('message_sanitized', 'No message body available')}")
            else:
                st.warning("Selected rank not found in current sliced view.")
        else:
            st.info("Queue is empty under current filters.")
