"""
SAT-SA View: Forensic Alert Investigation Workbench
Problem Statement: SIH26157 | SAT-SA V6
"""

import streamlit as st
import pandas as pd
import numpy as np
import json
import html
import ipaddress
import re
from typing import Optional, Any, Dict, List
from pathlib import Path
from dashboard.ui_theme import (
    render_command_header,
    render_kpi_card,
    render_section_header,
    render_severity_badge,
    CYBER_PALETTE
)

def esc(val, default="N/A"):
    """Sanitize any user or telemetry input for safe HTML interpolation (XSS defense)."""
    if val is None or pd.isna(val):
        return default
    s = str(val).strip()
    return html.escape(s) if s else default

MISSING_EVIDENCE_SENTINELS = frozenset({
    "none", "nan", "null", "n/a", "na", "[]", "{}", "-", "--",
    "unknown", "<none>", "<na>", "<null>"
})

def validate_evidence_field(field_name: str, value: Any) -> bool:
    """
    Validate evidence field completeness and format for Evidence Quality Audit.
    Returns True if the field is populated and passes format checks (Verified),
    or False if it represents a missing, unusable, or malformed value (Missing Evidence Gap).
    """
    if value is None or pd.isna(value):
        return False
    s_val = str(value).strip()
    if not s_val:
        return False
    if s_val.lower() in MISSING_EVIDENCE_SENTINELS:
        return False
    # Validate IP address format strictly for IP fields
    if field_name in ("Source IP", "Destination IP", "src_ip", "dst_ip"):
        try:
            ipaddress.ip_address(s_val)
            return True
        except (ValueError, TypeError):
            return False
    return True

def extract_endpoint_telemetry(row: pd.Series) -> Dict[str, Any]:
    """
    Extracts deep endpoint telemetry from raw message payloads (e.g., CrowdStrike Falcon JSON).
    Distinguishes endpoint workstation identities, sensor event times, and micro-behavior
    ATT&CK techniques from SIEM-level correlation and relay envelopes.
    """
    msg = str(row.get("message_sanitized", row.get("message", ""))).strip()
    res: Dict[str, Any] = {
        "endpoint_host": None,
        "endpoint_timestamp": None,
        "endpoint_tactics": [],
        "endpoint_techniques": [],
        "raw_json_parsed": False,
    }
    if not msg:
        return res

    # 1. Regex search for clientHostname=
    m_host = re.search(r"clientHostname=([^\s:]+)", msg)
    if m_host:
        h_val = m_host.group(1).strip()
        if h_val and h_val.lower() not in MISSING_EVIDENCE_SENTINELS:
            res["endpoint_host"] = h_val

    # 2. Extract embedded JSON payload if present
    m_json = re.search(r"message=(\{.*\})(?:\s*:::\s*|\s*$)", msg)
    json_str = m_json.group(1) if m_json else (msg if msg.startswith("{") and msg.endswith("}") else None)

    if json_str:
        try:
            d = json.loads(json_str)
            res["raw_json_parsed"] = True
            dev = d.get("device", {})
            if isinstance(dev, dict) and dev.get("hostname"):
                h_dev = str(dev.get("hostname")).strip()
                if h_dev and h_dev.lower() not in MISSING_EVIDENCE_SENTINELS and not res["endpoint_host"]:
                    res["endpoint_host"] = h_dev

            if d.get("first_behavior"):
                res["endpoint_timestamp"] = str(d.get("first_behavior")).strip()
            elif d.get("created_timestamp"):
                res["endpoint_timestamp"] = str(d.get("created_timestamp")).strip()

            behaviors = d.get("behaviors", [])
            if isinstance(behaviors, list):
                for b in behaviors:
                    if isinstance(b, dict):
                        tac_id = b.get("tactic_id")
                        tac_name = b.get("tactic")
                        tec_id = b.get("technique_id")
                        tec_name = b.get("technique")
                        b_ts = b.get("timestamp")
                        if b_ts and not res["endpoint_timestamp"]:
                            res["endpoint_timestamp"] = str(b_ts).strip()
                        if tac_id:
                            item = f"{tac_id} — {tac_name}" if tac_name else str(tac_id)
                            if item not in res["endpoint_tactics"]:
                                res["endpoint_tactics"].append(item)
                        elif tac_name and tac_name not in res["endpoint_tactics"]:
                            res["endpoint_tactics"].append(str(tac_name))

                        if tec_id:
                            item = f"{tec_id} — {tec_name}" if tec_name else str(tec_id)
                            if item not in res["endpoint_techniques"]:
                                res["endpoint_techniques"].append(item)
                        elif tec_name and tec_name not in res["endpoint_techniques"]:
                            res["endpoint_techniques"].append(str(tec_name))
        except Exception:
            pass

    # 3. Fallback regex for timestamp if json.loads failed or was truncated
    if not res["endpoint_timestamp"]:
        m_ts = re.search(r'"timestamp":\s*"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d[^"]*)"', msg)
        if m_ts:
            res["endpoint_timestamp"] = m_ts.group(1).strip()

    # 4. Fallback regex for tactics/techniques
    if not res["endpoint_tactics"]:
        t_matches = re.findall(r'"tactic":\s*"([^"]+)",\s*"tactic_id":\s*"(TA\d{4})"', msg)
        for tname, tid in t_matches:
            item = f"{tid} — {tname}"
            if item not in res["endpoint_tactics"]:
                res["endpoint_tactics"].append(item)

    if not res["endpoint_techniques"]:
        te_matches = re.findall(r'"technique":\s*"([^"]+)",\s*"technique_id":\s*"(T\d{4}(?:\.\d{3})?)"', msg)
        for tename, teid in te_matches:
            item = f"{teid} — {tename}"
            if item not in res["endpoint_techniques"]:
                res["endpoint_techniques"].append(item)

    return res

def render_alert_investigation_view(
    alerts: pd.DataFrame,
    selected_org_id: str = "ORG-0004",
    parquet_path: Optional[Any] = None,
    total_corpus_alerts: Optional[int] = None
):
    """Render the forensic deep-dive alert investigation workbench with on-demand full-corpus search."""
    display_total = total_corpus_alerts if (total_corpus_alerts and total_corpus_alerts > 0) else len(alerts)
    render_command_header(
        page_title="Forensic Alert Investigation Workbench",
        page_subtitle="In-Depth Telemetry Inspection, Isolation Forest Attribution & Evidence Quality Audit",
        active_cse=selected_org_id,
        total_alerts=display_total
    )

    # 1. Quick Presets & Search
    render_section_header(
        title="Select Alert for Forensic Deep Dive",
        subtitle="Search by unique alert identifier across the complete corpus or select an operational preset.",
        badge="ALERT SELECTOR"
    )

    num_s = pd.to_numeric(alerts["_alert_id"], errors="coerce") if "_alert_id" in alerts.columns else pd.Series(dtype=float)
    is_all_numeric = num_s.notna().all() and not num_s.empty

    if total_corpus_alerts and total_corpus_alerts > 0:
        max_id = max(int(num_s.max() or 0), total_corpus_alerts - 1)
        min_id = min(int(num_s.min() or 0), 0) if not num_s.empty else 0
    elif is_all_numeric:
        max_id = int(num_s.max() or 0)
        min_id = int(num_s.min() or 0)
    else:
        max_id, min_id = max(len(alerts) - 1, 0), 0

    # Determine default alert ID (top-ranked threat in queue, or min_id)
    default_alert_id = (
        int(alerts.iloc[0]["_alert_id"]) if is_all_numeric
        else str(alerts.iloc[0]["_alert_id"])
    ) if not alerts.empty else min_id

    # Apply pending preset alert selection before input widget instantiation
    if "ai_pending_search_id" in st.session_state:
        st.session_state["ai_search_id_input"] = st.session_state.pop("ai_pending_search_id")

    col_s1, col_s2, col_s3, col_s4, col_s5 = st.columns([1.5, 1, 1, 1, 1])
    with col_s1:
        if is_all_numeric or (total_corpus_alerts and total_corpus_alerts > 0):
            current_raw = st.session_state.get("ai_search_id_input", default_alert_id)
            try:
                current_val = int(current_raw)
            except (ValueError, TypeError):
                current_val = int(default_alert_id) if is_all_numeric else min_id
            current_val = max(min_id, min(max_id, current_val))
            search_id = st.number_input(
                "Alert Identifier (_alert_id)",
                min_value=min_id,
                max_value=max_id,
                value=current_val,
                step=1,
                key="ai_search_id_input",
                help=f"Enter any alert identifier from 0 to {max_id:,} to inspect full forensic telemetry."
            )
        else:
            id_options = alerts["_alert_id"].astype(str).tolist()[:5000]
            default_val = st.session_state.get("ai_search_id_input", str(default_alert_id) if id_options else "")
            default_idx = id_options.index(str(default_val)) if str(default_val) in id_options else 0
            search_id = st.selectbox(
                "Alert Identifier (_alert_id)",
                id_options,
                index=default_idx,
                key="ai_search_id_input"
            )

    with col_s2:
        st.markdown("<div style='height: 28px;'></div>", unsafe_allow_html=True)
        if st.button("⚡ Top #1 Threat", width="stretch", key="ai_btn_top1"):
            top1 = alerts.iloc[0] if not alerts.empty else None
            if top1 is not None:
                st.session_state["ai_pending_search_id"] = int(top1["_alert_id"]) if is_all_numeric else str(top1["_alert_id"])
                st.rerun()
            else:
                st.warning("No alerts loaded in queue.")
    with col_s3:
        st.markdown("<div style='height: 28px;'></div>", unsafe_allow_html=True)
        if st.button("🔥 Top #25 Threat", width="stretch", key="ai_btn_top25"):
            idx = min(24, len(alerts) - 1)
            top25 = alerts.iloc[idx] if not alerts.empty else None
            if top25 is not None:
                st.session_state["ai_pending_search_id"] = int(top25["_alert_id"]) if is_all_numeric else str(top25["_alert_id"])
                st.rerun()
            else:
                st.warning("No alerts loaded in queue.")
    with col_s4:
        st.markdown("<div style='height: 28px;'></div>", unsafe_allow_html=True)
        if st.button("🚨 Top #100 Threat", width="stretch", key="ai_btn_top100"):
            idx = min(99, len(alerts) - 1)
            top100 = alerts.iloc[idx] if not alerts.empty else None
            if top100 is not None:
                st.session_state["ai_pending_search_id"] = int(top100["_alert_id"]) if is_all_numeric else str(top100["_alert_id"])
                st.rerun()
            else:
                st.warning("No alerts loaded in queue.")
    with col_s5:
        st.markdown("<div style='height: 28px;'></div>", unsafe_allow_html=True)
        if st.button("🎯 Random Incident", width="stretch", key="ai_btn_random"):
            inc_sample = alerts[alerts["actual_incident"] == 1]
            if not inc_sample.empty:
                pick = inc_sample.sample(1).iloc[0]
                st.session_state["ai_pending_search_id"] = int(pick["_alert_id"]) if is_all_numeric else str(pick["_alert_id"])
                st.rerun()
            else:
                st.warning("No confirmed incidents available in current queue.")

    # Locate alert in active memory queue
    if is_all_numeric:
        selected = alerts[pd.to_numeric(alerts["_alert_id"], errors="coerce") == search_id]
    else:
        selected = alerts[alerts["_alert_id"].astype(str) == str(search_id)]

    is_ondemand_query = False
    # If not in active queue, perform selective on-demand Parquet disk lookup
    if selected.empty and parquet_path is not None:
        p_path = Path(parquet_path)
        if p_path.exists():
            try:
                import pyarrow.parquet as pq
                avail_cols = [c for c in alerts.columns] if not alerts.empty else None
                try:
                    num_id = int(search_id)
                    table = pq.read_table(str(p_path), columns=avail_cols, filters=[('_alert_id', '=', num_id)])
                except (ValueError, TypeError):
                    table = pq.read_table(str(p_path), columns=avail_cols, filters=[('_alert_id', '=', str(search_id))])
                if table.num_rows > 0:
                    selected = table.to_pandas()
                    is_ondemand_query = True
            except Exception:
                pass

    if selected.empty:
        st.warning(f"🔍 No alert record found for Alert ID: #{search_id}. Please select an operational preset (Top #1, #25, #100) or enter a valid alert identifier.")
        return

    row = selected.iloc[0]
    ep_telemetry = extract_endpoint_telemetry(row)
    ingest_time = str(row.get("Timestamp", row.get("timestamp_datetime", "N/A")))

    # Display on-demand query banner if fetched directly from disk
    if is_ondemand_query:
        st.markdown(
            f"""
            <div style="background:rgba(14,165,233,0.12); border:1px solid rgba(56,189,248,0.3); border-radius:8px; padding:8px 14px; margin:4px 0 12px 0; font-size:0.78rem; color:#38BDF8; display:flex; align-items:center; gap:8px;">
                <span style="font-size:1.15rem;">⚡</span>
                <div><strong>On-Demand Telemetry Record:</strong> Alert ID <code>#{search_id}</code> was fetched dynamically from disk storage (outside active in-memory queue). Full forensic attribution, Mitre tactics, and telemetry fields are active.</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    # 2. Executive Alert Header Cards
    st.markdown("<div style='height: 8px;'></div>", unsafe_allow_html=True)
    h1, h2, h3, h4 = st.columns(4)
    with h1:
        rank_val = f"#{int(row['priority_rank']):,}" if pd.notna(row.get("priority_rank")) else "N/A"
        total_for_rank = display_total if display_total > 0 else max(len(alerts), 1)
        rank_num = float(row.get('priority_rank', 0))
        pct_tier = (rank_num / total_for_rank * 100) if rank_num > 0 else 0.0
        render_kpi_card(
            title="Operational Priority Rank",
            value=rank_val,
            subtitle=f"Queue position across {total_for_rank:,} alerts",
            delta=f"Top {pct_tier:.2f}% Tier",
            delta_type="critical" if rank_num <= (total_for_rank * 0.01) else ("warning" if rank_num <= (total_for_rank * 0.05) else "neutral")
        )
    with h2:
        score_val = f"{float(row.get('anomaly_score', 0)):.6f}"
        render_kpi_card(
            title="Isolation Forest Anomaly Score",
            value=score_val,
            subtitle="-decision_function(X)",
            delta=f"Severity: {row.get('priority_label', 'Unknown')}",
            delta_type="warning"
        )
    with h3:
        is_inc = row.get("actual_incident") == 1
        is_susp_mitre = (
            row.get("is_suspicious_mitre") == 1
            or row.get("security_relevant") == 1
            or str(row.get("label_binary", "")).lower() == "suspicious"
        )
        if is_inc:
            gt_val = "🚨 Confirmed Incident"
            gt_delta_type = "positive"
            gt_sub = "Verified post-hoc ticketing record"
        elif is_susp_mitre:
            gt_val = "⚠️ Unticketed / Security Relevant"
            gt_delta_type = "warning"
            gt_sub = "Suspicious activity without formal incident ticket"
        else:
            gt_val = "🛡️ No Confirmed Incident Ticket"
            gt_delta_type = "neutral"
            gt_sub = "No post-hoc incident ticket linked"

        render_kpi_card(
            title="Ground Truth Incident",
            value=gt_val,
            subtitle=gt_sub,
            delta=f"Ticket: {esc(row.get('incident_ids', 'None'))}",
            delta_type=gt_delta_type
        )
    with h4:
        endpoint_ts = ep_telemetry.get("endpoint_timestamp")
        delta_str = f"Sensor Event: {endpoint_ts}" if endpoint_ts else "UTC Synchronized"
        render_kpi_card(
            title="SIEM Ingestion Time",
            value=ingest_time,
            subtitle="Pipeline ingestion timestamp",
            delta=delta_str,
            delta_type="neutral"
        )

    st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)

    # 3. Tri-Column Forensic Dossier
    render_section_header(
        title="Forensic Evidence Dossier",
        subtitle="Multi-dimensional telemetry breakdown and asset identity context.",
        badge="FORENSIC DOSSIER"
    )

    fc1, fc2, fc3 = st.columns(3)

    # Col 1: Asset & Identity
    with fc1:
        ep_host_html = ""
        if ep_telemetry.get("endpoint_host"):
            ep_host_html = f"<div style='margin-bottom:8px;'><strong>Endpoint Workstation Host:</strong> <code>{esc(ep_telemetry.get('endpoint_host'))}</code></div>"

        ep_ts_html = ""
        if ep_telemetry.get("endpoint_timestamp"):
            ep_ts_html = f"<div style='margin-bottom:8px;'><strong>Endpoint Sensor Event Time:</strong> <code>{esc(ep_telemetry.get('endpoint_timestamp'))}</code></div>"

        st.markdown(
            f"""
            <div class="cyber-card" style="height: 100%;">
                <div style="font-weight:700; color:#38BDF8; font-size:0.95rem; margin-bottom:12px;">🌐 NETWORK & ASSET IDENTITY</div>
                <div style="margin-bottom:8px;"><strong>Source Asset:</strong> <code>{esc(row.get('src_ip'))}:{esc(row.get('src_port', '0'))}</code></div>
                <div style="margin-bottom:8px;"><strong>Destination Asset:</strong> <code>{esc(row.get('dst_ip'))}:{esc(row.get('dst_port', '0'))}</code></div>
                <div style="margin-bottom:8px;"><strong>Transport Protocol:</strong> <code>{esc(row.get('protocol'))}</code></div>
                <div style="margin-bottom:8px;"><strong>Target User / Account:</strong> <code>{esc(row.get('username'))}</code></div>
                <div style="margin-bottom:8px;"><strong>Collector / Relay Host:</strong> <code>{esc(row.get('src_host'))}</code></div>
                {ep_host_html}
                <div style="margin-bottom:8px;"><strong>Destination Host:</strong> <code>{esc(row.get('dst_host'))}</code></div>
                <div style="margin-bottom:8px;"><strong>Origin Node:</strong> <code>{esc(row.get('origin'))}</code></div>
                <div style="margin-bottom:8px;"><strong>SIEM Ingestion Time:</strong> <code>{esc(ingest_time)}</code></div>
                {ep_ts_html}
            </div>
            """,
            unsafe_allow_html=True
        )

    # Col 2: Machine Attribution & Supervisory Reasons
    with fc2:
        reasons = []
        if float(row.get("anomaly_score", 0)) > 0:
            reasons.append("Elevated isolation path rarity (sparse anomaly partition)")
        val_sp = pd.to_numeric(row.get("src_port", 0), errors="coerce")
        src_port_num = int(val_sp) if pd.notna(val_sp) else 0
        if src_port_num in [22, 3389, 445, 135]:
            reasons.append("High-risk administrative service port utilized")
        if pd.isna(row.get("username")) or str(row.get("username")).strip() == "":
            reasons.append("Unauthenticated identity signature (missing username)")
        if row.get("actual_incident") == 1:
            reasons.append(f"Linked to confirmed security incident ticket {esc(row.get('incident_ids'))}")

        reasons_html = "".join([f"<li style='margin-bottom:6px; color:#F8FAFC;'>⚠️ {r}</li>" for r in reasons]) if reasons else "<li style='color:#94A3B8;'>Normal baseline operational telemetry.</li>"

        st.markdown(
            f"""
            <div class="cyber-card" style="height: 100%;">
                <div style="font-weight:700; color:#A78BFA; font-size:0.95rem; margin-bottom:12px;">🧠 MACHINE ATTRIBUTION & REASONS</div>
                <div style="margin-bottom:8px;"><strong>Priority Tier:</strong> {render_severity_badge(row.get('priority_label', 'Unknown'))}</div>
                <div style="margin-bottom:8px;"><strong>Raw Priority Score:</strong> <code>{esc(row.get('priority_score', row.get('anomaly_score', 'N/A')))}</code></div>
                <div style="margin-bottom:10px;"><strong>Key Anomaly Factors:</strong></div>
                <ul style="padding-left:18px; margin-top:0; font-size:0.82rem;">
                    {reasons_html}
                </ul>
            </div>
            """,
            unsafe_allow_html=True
        )

    # Col 3: Evidence Completeness & Quality Checklist
    with fc3:
        fields = [
            ("Source IP", row.get("src_ip")),
            ("Destination IP", row.get("dst_ip")),
            ("User Identity", row.get("username")),
            ("Action Taken", row.get("action")),
            ("Disposition", row.get("disposition")),
            ("Message Payload", row.get("message_sanitized"))
        ]
        checks_html = ""
        for name, val in fields:
            is_present = validate_evidence_field(name, val)
            icon = "✅" if is_present else "❌"
            color = "#34D399" if is_present else "#F87171"
            status_text = "Verified" if is_present else "Missing Evidence Gap"
            checks_html += f"<div style='display:flex; justify-content:space-between; margin-bottom:6px; font-size:0.82rem;'><span>{html.escape(name)}</span><span style='color:{color}; font-weight:600;'>{icon} {status_text}</span></div>"

        st.markdown(
            f"""
            <div class="cyber-card" style="height: 100%;">
                <div style="font-weight:700; color:#34D399; font-size:0.95rem; margin-bottom:12px;">📋 EVIDENCE QUALITY AUDIT</div>
                {checks_html}
            </div>
            """,
            unsafe_allow_html=True
        )

    # 4. MITRE ATT&CK Matrix & Raw Telemetry
    render_section_header(
        title="SIEM Correlation & Endpoint ATT&CK Mapping",
        subtitle="Multi-layer adversarial tactics and techniques attributed across SIEM rules and EDR sensors.",
        badge="MITRE FRAMEWORK"
    )

    m_tactics = str(row.get("attack_tactics", row.get("mitre_tactic", "N/A")))
    m_techniques = str(row.get("attack_techniques", row.get("mitre_technique", "N/A")))
    m_rules = str(row.get("matched_rules", "N/A"))

    ep_tactics_list = ep_telemetry.get("endpoint_tactics", [])
    ep_techniques_list = ep_telemetry.get("endpoint_techniques", [])
    ep_tactics_str = ", ".join(ep_tactics_list) if ep_tactics_list else ""
    ep_techniques_str = ", ".join(ep_techniques_list) if ep_techniques_list else ""
    has_ep_attck = bool(ep_tactics_str or ep_techniques_str)

    endpoint_attck_html = ""
    if has_ep_attck:
        endpoint_attck_html = f"""
            <div style="margin-top:14px; padding-top:12px; border-top:1px solid rgba(244,114,182,0.2); display:flex; gap:20px; flex-wrap:wrap;">
                <div style="flex:1; min-width:240px;">
                    <span style="font-size:0.75rem; text-transform:uppercase; color:#F472B6; font-weight:600;">Endpoint Sensor ATT&CK Tactics</span>
                    <div style="font-size:1.02rem; font-weight:700; color:#FDF2F8; margin-top:3px;">🎯 {esc(ep_tactics_str if ep_tactics_str else 'N/A')}</div>
                </div>
                <div style="flex:1; min-width:240px;">
                    <span style="font-size:0.75rem; text-transform:uppercase; color:#F472B6; font-weight:600;">Endpoint Sensor ATT&CK Techniques</span>
                    <div style="font-size:1.02rem; font-weight:700; color:#F472B6; margin-top:3px;">⚡ {esc(ep_techniques_str if ep_techniques_str else 'N/A')}</div>
                </div>
                <div style="flex:2; min-width:300px;">
                    <span style="font-size:0.75rem; text-transform:uppercase; color:#94A3B8; font-weight:600;">Telemetry Source Attribution</span>
                    <div style="font-size:0.85rem; color:#E2E8F0; margin-top:3px;">Parsed directly from local EDR endpoint micro-behavior sensor stream.</div>
                </div>
            </div>
        """

    st.markdown(
        f"""
        <div class="cyber-card">
            <div style="display:flex; gap:20px; flex-wrap:wrap;">
                <div style="flex:1; min-width:240px;">
                    <span style="font-size:0.75rem; text-transform:uppercase; color:#94A3B8; font-weight:600;">SIEM Correlation ATT&CK Tactics</span>
                    <div style="font-size:1.05rem; font-weight:700; color:#F8FAFC; margin-top:3px;">🛡️ {esc(m_tactics)}</div>
                </div>
                <div style="flex:1; min-width:240px;">
                    <span style="font-size:0.75rem; text-transform:uppercase; color:#94A3B8; font-weight:600;">SIEM Correlation ATT&CK Techniques</span>
                    <div style="font-size:1.05rem; font-weight:700; color:#38BDF8; margin-top:3px;">⚡ {esc(m_techniques)}</div>
                </div>
                <div style="flex:2; min-width:300px;">
                    <span style="font-size:0.75rem; text-transform:uppercase; color:#94A3B8; font-weight:600;">Matched Detection Rules</span>
                    <div style="font-size:0.88rem; font-family:'JetBrains Mono', monospace; color:#C4B5FD; margin-top:3px;">{esc(m_rules)}</div>
                </div>
            </div>
            {endpoint_attck_html}
            <div style="margin-top:12px; padding-top:10px; border-top:1px solid rgba(56,189,248,0.12); font-size:0.85rem; color:#E2E8F0;">
                <strong>Alert Message Payload:</strong> {esc(row.get('message_sanitized', 'No raw message payload available'))}
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    # 5. Raw Telemetry Record Inspector
    with st.expander("📄 Full Telemetry Record Inspector (Raw Schema)", expanded=False):
        st.json(row.dropna().to_dict())
