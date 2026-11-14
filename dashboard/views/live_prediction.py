"""
SAT-SA View: Live Interactive Single-Alert Triage
Problem Statement: SIH26157 | SAT-SA V6
"""

import streamlit as st
import pandas as pd
from backend.live_prediction import score_single_alert, get_live_prediction_history
from dashboard.ui_theme import (
    render_command_header,
    render_kpi_card,
    render_section_header,
    render_severity_badge,
    CYBER_PALETTE
)

def render_live_prediction_view(selected_org_id: str = "ORG-0004"):
    """Render the live single-alert analyst inference terminal."""
    render_command_header(
        page_title="Live Interactive Single-Alert Triage Terminal",
        page_subtitle="On-Demand Statistical Anomaly Inference, Missing-Field Quality Audit & Explainable Reason Codes",
        active_cse=selected_org_id,
        total_alerts=402335
    )

    # 1. Terminal Form
    render_section_header(
        title="Live Analyst Telemetry Ingestion",
        subtitle="Submit candidate alert attributes for real-time statistical triage evaluation.",
        badge="INGESTION TERMINAL"
    )

    live_model = st.selectbox(
        "Inference Model Engine",
        ["V6 Unsupervised Baseline (300 Trees, 23 Features)", "V6 Leakage-Reduced (300 Trees, 21 Features)"],
        key="live_model_select"
    )
    m_type = "leakage_reduced" if "Leakage-Reduced" in live_model else "baseline"

    with st.form("live_single_alert_terminal_form"):
        st.markdown(
            """
            <div style="font-weight:700; color:#38BDF8; font-size:0.88rem; margin-bottom:8px;">
                1. NETWORK & CONNECTION ATTRIBUTES
            </div>
            """,
            unsafe_allow_html=True
        )
        c1, c2, c3, c4 = st.columns(4)
        src_ip = c1.text_input("Source IP", value="10.0.1.45")
        src_port = c2.number_input("Source Port", min_value=0, max_value=65535, value=22)
        dst_ip = c3.text_input("Destination IP", value="192.168.1.100")
        dst_port = c4.number_input("Destination Port", min_value=0, max_value=65535, value=443)

        st.markdown(
            """
            <div style="font-weight:700; color:#38BDF8; font-size:0.88rem; margin:12px 0 8px 0;">
                2. IDENTITY & SENSOR CONTEXT
            </div>
            """,
            unsafe_allow_html=True
        )
        c5, c6, c7, c8 = st.columns(4)
        username = c5.text_input("User Account", value="svc_backup_admin")
        proto = c6.selectbox("Protocol", ["6 (TCP)", "17 (UDP)", "1 (ICMP)", "0 (Other)"], index=0)
        proto_val = int(proto.split()[0])
        prod_name = c7.text_input("Sensor / Vendor Code", value="Cisco ASA Firewall / Syslog")
        sev = c8.selectbox("Reported Severity", ["Critical", "High", "Medium", "Low", "Informational"], index=1)

        st.markdown(
            """
            <div style="font-weight:700; color:#38BDF8; font-size:0.88rem; margin:12px 0 8px 0;">
                3. SIGNATURE & ALERT NARRATIVE
            </div>
            """,
            unsafe_allow_html=True
        )
        c9, c10 = st.columns([1.5, 2.5])
        sig_id = c9.text_input("Signature / Detection Rule", value="SIG_MALWARE_EXEC_01")
        msg_text = c10.text_input("Alert Payload / Sanitized Message", value="Outbound connection initiated on administrative port outside standard operating schedule.")

        score_btn = st.form_submit_button("⚡ Execute Anomaly Scoring", type="primary", width="stretch")

    # 2. Prediction Results Display
    if score_btn:
        alert_dict = {
            "signature_id": sig_id,
            "severity": sev,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": proto_val,
            "username": username,
            "product_name": prod_name,
            "message_sanitized": msg_text,
            "timestamp_datetime": pd.Timestamp.now().strftime("%Y-%m-%d %H:%M:%S")
        }

        with st.spinner("Scoring candidate alert with Isolation Forest..."):
            pred_res = score_single_alert(alert_dict, model_type=m_type)

        st.success(f"✅ Prediction Generated: **{pred_res['prediction_id']}** (Audit Hash: `{pred_res['input_hash'][:16]}`) ")

        # Result HUD Cards
        m1, m2, m3, m4 = st.columns(4)
        with m1:
            render_kpi_card(
                title="Assigned Priority Tier",
                value=pred_res["priority_label"],
                subtitle="Relative queue priority",
                delta=pred_res["relative_tier"],
                delta_type="critical" if pred_res["priority_label"] == "Critical" else ("warning" if pred_res["priority_label"] == "High" else "neutral")
            )
        with m2:
            render_kpi_card(
                title="Isolation Forest Anomaly Score",
                value=f"{pred_res['anomaly_score']:.6f}",
                subtitle="-decision_function(X)",
                delta="Continuous Raw Score",
                delta_type="neutral"
            )
        with m3:
            render_kpi_card(
                title="Cohort Score Deviation (Z)",
                value=f"{pred_res['score_z_score']:+.2f} σ",
                subtitle="vs baseline mean (-0.0798)",
                delta="Statistically Extreme" if pred_res['score_z_score'] > 2 else "Baseline Range",
                delta_type="critical" if pred_res['score_z_score'] > 2 else "neutral"
            )
        with m4:
            render_kpi_card(
                title="Target Leakage Status",
                value="Zero Leakage",
                subtitle="Strict feature insulation",
                delta=f"{len(pred_res.get('stripped_ground_truth_fields', []))} Fields Stripped",
                delta_type="positive"
            )

        # Contributing Evidence & Data Quality Check
        st.markdown("<div style='height: 8px;'></div>", unsafe_allow_html=True)
        col_res1, col_res2 = st.columns(2)
        with col_res1:
            st.markdown(
                """
                <div class="cyber-card">
                    <div style="font-weight:700; color:#38BDF8; font-size:0.92rem; margin-bottom:8px;">🔍 CONTRIBUTING RISK EVIDENCE</div>
                """,
                unsafe_allow_html=True
            )
            for r in pred_res["contributing_reasons"]:
                st.markdown(f"- ⚠️ **{r}**")
            st.markdown("</div>", unsafe_allow_html=True)

        with col_res2:
            st.markdown(
                """
                <div class="cyber-card">
                    <div style="font-weight:700; color:#34D399; font-size:0.92rem; margin-bottom:8px;">📋 DATA QUALITY & CONTEXT AUDIT</div>
                """,
                unsafe_allow_html=True
            )
            if pred_res["data_quality_warnings"]:
                for w in pred_res["data_quality_warnings"]:
                    st.markdown(f"- ℹ️ {w}")
            else:
                st.success("All critical telemetry fields populated cleanly with zero quality penalties.")
            st.markdown("</div>", unsafe_allow_html=True)

    # 3. Session Prediction History Table
    st.markdown("<div style='height: 16px;'></div>", unsafe_allow_html=True)
    render_section_header(
        title="Session Live Prediction History",
        subtitle="Persistent log of alerts scored during the current evaluation session.",
        badge="SESSION AUDIT"
    )

    live_hist = get_live_prediction_history()
    if live_hist:
        hist_df = pd.DataFrame(live_hist)
        disp_hcols = [c for c in ["prediction_id", "timestamp", "priority_label", "anomaly_score", "relative_tier", "model_used"] if c in hist_df.columns]
        rename_lh = {
            "prediction_id": "Prediction ID",
            "timestamp": "Timestamp",
            "priority_label": "Priority Tier",
            "anomaly_score": "Score",
            "relative_tier": "Operational Category",
            "model_used": "Model"
        }
        st.dataframe(hist_df[disp_hcols].rename(columns=rename_lh), width="stretch", hide_index=True)

        csv_data = hist_df.to_csv(index=False).encode("utf-8")
        st.download_button(
            "💾 Download Live Predictions Log (CSV)",
            data=csv_data,
            file_name="live_predictions_log.csv",
            mime="text/csv"
        )
    else:
        st.info("No live alert predictions submitted yet in this session.")
