"""
SAT-SA View: CSE Regulatory Assessment & NCIIPC Audit Queue
Problem Statement: SIH26157 | SAT-SA V6
"""

import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
from backend.multientity_service import (
    load_multientity_summary,
    get_ranked_regulatory_queue,
    get_telemetry_coverage_matrix,
    generate_supervisory_dossier_text
)
from dashboard.ui_theme import (
    render_command_header,
    render_kpi_card,
    render_section_header,
    apply_cyber_plotly_theme,
    render_severity_badge,
    CYBER_PALETTE
)

def render_regulatory_assessment_view(selected_org_id: str = "ORG-0004"):
    """Render the NCIIPC statutory supervisory assessment view."""
    render_command_header(
        page_title="Critical Sector Entity (CSE) Regulatory Assessment",
        page_subtitle="National Sovereign Cyber Resilience, 8-Domain Statutory Audits & Prioritized Inspection Queue",
        active_cse=selected_org_id,
        total_alerts=402335
    )

    summary_meta = load_multientity_summary()
    ranked_queue = get_ranked_regulatory_queue()
    ent_map = {ent["org_id"]: ent for ent in ranked_queue}
    curr_ent = ent_map.get(selected_org_id, ranked_queue[0] if ranked_queue else {})
    ent_name = curr_ent.get("entity_name", "")
    full_cse_title = f"{selected_org_id} — {ent_name}" if ent_name else selected_org_id

    # 1. Top Executive HUD
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        render_kpi_card("Supervised Entities", f"{len(ranked_queue)} CSEs", "Active national critical sectors", delta="Tier-1 Infrastructure", delta_type="neutral")
    with c2:
        top_cse_id = ranked_queue[0]['org_id'] if ranked_queue else "N/A"
        top_cse_name = ranked_queue[0]['entity_name'] if ranked_queue else "N/A"
        top_risk = ranked_queue[0]["supervisory_risk_index"] if ranked_queue else 0.0
        render_kpi_card("Priority Inspection Target", f"{top_cse_id}", f"{top_cse_name} • Risk: {top_risk:.1f}/100", delta="Inspection Urgency", delta_type="critical")
    with c3:
        med_risk = summary_meta.get("cohort_medians", {}).get("supervisory_risk_index", 17.3)
        render_kpi_card("Cohort Median Risk Index", f"{med_risk:.1f} / 100", "Baseline supervisory risk", delta="Cohort Benchmark", delta_type="positive")
    with c4:
        render_kpi_card("Statutory Framework", "SIH26157 Compliant", "8 Domains • NCIIPC Mandate", delta="Air-Gapped Sovereign", delta_type="positive")

    st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)

    # 2. Prioritized Regulatory Audit Queue
    render_section_header(
        title="Prioritized CSE Regulatory Audit Queue",
        subtitle="Critical Sector Entities ranked by composite Supervisory Risk Index to direct national audit teams.",
        badge="REGULATORY QUEUE"
    )

    queue_rows = []
    for rk, ent in enumerate(ranked_queue, start=1):
        queue_rows.append({
            "Audit Priority": f"#{rk}",
            "Entity ID": ent["org_id"],
            "Critical Sector Entity": ent["entity_name"],
            "Sector": ent["sector"],
            "Supervisory Risk Index": ent["supervisory_risk_index"],
            "Resilience Score": ent.get("scores", {}).get("Cyber Resilience Index", "N/A"),
            "Critical/High Alerts": f"{ent['critical_high_alerts']:,} ({ent['critical_high_pct']}%)",
            "Evidence Gap Rate": f"{ent['evidence_gap_rate']}%",
            "Urgency Classification": ent["audit_urgency"]
        })

    st.dataframe(
        pd.DataFrame(queue_rows),
        width="stretch",
        hide_index=True,
        column_config={
            "Supervisory Risk Index": st.column_config.ProgressColumn(
                "Risk Index (0-100)",
                format="%.1f",
                min_value=0,
                max_value=100
            )
        }
    )

    # 3. Statutory 8-Domain Scorecards Grid for Selected Entity
    st.markdown("<div style='height: 16px;'></div>", unsafe_allow_html=True)
    render_section_header(
        title=f"Statutory 8-Domain Capability Scorecards: {full_cse_title}",
        subtitle="Cyber resilience domain ratings pursuant to official NCIIPC assessment guidelines.",
        badge="8 STATUTORY DOMAINS"
    )

    if curr_ent:
        scores = curr_ent.get("scores", {})
        domain_weights = {
            "Threat Detection": (0.15, "Automated alert filtering and high-priority threat identification."),
            "Investigation": (0.15, "Contextual depth, identity attribution, and forensic evidence completeness."),
            "Escalation": (0.15, "Timely escalation of severe security alerts to formal incident cases."),
            "Incident Response": (0.10, "Remediation action velocity, containment, and system disruption."),
            "Security Operations": (0.10, "Monitoring telemetry diversity, log sources, and pipeline coverage."),
            "Governance & Oversight": (0.15, "Institutional oversight, compliance adherence, and negative space control."),
            "Operational Discipline": (0.20, "Strict peer alignment, low evidence gap rates, and workflow adherence."),
            "Cyber Resilience Index": (1.00, "Weighted composite resilience rating across all operational dimensions.")
        }

        # 4 columns x 2 rows
        dom_cols = st.columns(4)
        for idx, (dom_name, (w, desc)) in enumerate(domain_weights.items()):
            col_target = dom_cols[idx % 4]
            score_val = scores.get(dom_name, 80.0)
            score_color = "#10B981" if score_val >= 80 else ("#F59E0B" if score_val >= 60 else "#EF4444")
            status_chip = "CLEARED" if score_val >= 80 else ("OBSERVATION" if score_val >= 60 else "ACTION REQUIRED")
            
            with col_target:
                st.markdown(
                    f"""
                    <div class="cyber-card" style="min-height: 170px; display:flex; flex-direction:column; justify-content:space-between;">
                        <div>
                            <div style="display:flex; justify-content:space-between; align-items:center;">
                                <span style="font-size:0.75rem; text-transform:uppercase; color:#94A3B8; font-weight:700;">{dom_name}</span>
                                <span style="font-size:0.68rem; color:#64748B; font-family:'JetBrains Mono';">w={w:.2f}</span>
                            </div>
                            <div style="font-size:1.85rem; font-family:'JetBrains Mono', monospace; font-weight:700; color:{score_color}; margin:6px 0;">{score_val:.1f}<span style="font-size:1rem; color:#64748B;">/100</span></div>
                            <div style="font-size:0.75rem; color:#64748B; line-height:1.3;">{desc}</div>
                        </div>
                        <div style="margin-top:10px; font-size:0.72rem; font-weight:700; color:{score_color}; font-family:'JetBrains Mono';">● {status_chip}</div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )

    # 4. Historical Operational Drift & Trend Trajectory (Quarterly Q1-Q4)
    trends = curr_ent.get("historical_trends", []) if curr_ent else []
    if trends:
        st.markdown("<div style='height: 16px;'></div>", unsafe_allow_html=True)
        render_section_header(
            title=f"Historical Operational Drift & Trend Trajectory: {full_cse_title}",
            subtitle="Quarterly telemetry progression tracking triage volumes, execution gaps and anomaly score evolution.",
            badge="HISTORICAL DRIFT"
        )
        tr_df = pd.DataFrame(trends)
        rename_tr = {
            "period": "Period",
            "start_time": "Window Start",
            "end_time": "Window End",
            "alerts": "Alert Volume",
            "execution_gap_pct": "Execution Gap %",
            "evidence_gap_pct": "Evidence Gap %",
            "mean_anomaly_score": "Mean Anomaly Score"
        }
        show_tr = [c for c in rename_tr.keys() if c in tr_df.columns]
        st.dataframe(
            tr_df[show_tr].rename(columns=rename_tr),
            width="stretch",
            hide_index=True,
            column_config={
                "Alert Volume": st.column_config.NumberColumn(format="%d alerts"),
                "Execution Gap %": st.column_config.NumberColumn(format="%.2f%%"),
                "Evidence Gap %": st.column_config.NumberColumn(format="%.2f%%"),
                "Mean Anomaly Score": st.column_config.NumberColumn(format="%.4f")
            }
        )

    # 5. Cross-Entity Telemetry Coverage Matrix (Negative Space)
    st.markdown("<div style='height: 16px;'></div>", unsafe_allow_html=True)
    render_section_header(
        title="Cross-Entity Telemetry Coverage Matrix (Negative Space Heatmap)",
        subtitle="Detecting unmonitored critical assets, missing log sensors and monitoring blind spots across CSEs.",
        badge="NEGATIVE SPACE"
    )

    df_matrix = get_telemetry_coverage_matrix()
    if not df_matrix.empty:
        st.dataframe(df_matrix, width="stretch", hide_index=True)
    else:
        st.info("Telemetry coverage matrix unavailable.")

    # 6. One-Click NCIIPC Supervisory Audit Dossier Generator
    st.markdown("<div style='height: 16px;'></div>", unsafe_allow_html=True)
    render_section_header(
        title=f"NCIIPC Supervisory Audit Dossier Export: {full_cse_title}",
        subtitle="Generate the official classified supervisory compliance dossier for NCIIPC inspectors.",
        badge="OFFICIAL DOSSIER"
    )

    with st.container():
        st.markdown('<div class="cyber-card">', unsafe_allow_html=True)
        dossier_text = generate_supervisory_dossier_text(selected_org_id if selected_org_id != "All CSEs" else "ORG-0004")
        st.text_area("Audit Dossier Preview", dossier_text, height=220, key="reg_dossier_preview")
        
        st.download_button(
            f"📥 Download Official NCIIPC Supervisory Dossier ({selected_org_id}.md)",
            data=dossier_text,
            file_name=f"NCIIPC_Supervisory_Dossier_{selected_org_id}.md",
            mime="text/markdown",
            type="primary",
            key="reg_dossier_download_btn"
        )
        st.markdown('</div>', unsafe_allow_html=True)
