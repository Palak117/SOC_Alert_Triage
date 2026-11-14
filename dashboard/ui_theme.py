"""
SAT-SA Cyber Supervisory Design System & Theme Engine
Enterprise UI/UX for NTRO / NCIIPC Cybersecurity Platform
Problem Statement: SIH26157 | SAT-SA V6
"""

import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
from typing import Optional, Dict, Any, List

# Core Design Palette Tokens
CYBER_PALETTE = {
    "canvas_bg": "#06090F",
    "surface_dark": "#0B111E",
    "surface_card": "rgba(13, 22, 38, 0.75)",
    "surface_card_hover": "rgba(18, 30, 52, 0.85)",
    "border_subtle": "rgba(56, 189, 248, 0.12)",
    "border_highlight": "rgba(56, 189, 248, 0.35)",
    "border_critical": "rgba(239, 68, 68, 0.35)",
    "border_emerald": "rgba(16, 185, 129, 0.35)",
    "border_amber": "rgba(245, 158, 11, 0.35)",
    
    # Semantic Colors
    "cyan": "#00F2FE",
    "cyan_glow": "#38BDF8",
    "emerald": "#10B981",
    "emerald_glow": "#34D399",
    "amber": "#F59E0B",
    "amber_glow": "#FBBF24",
    "crimson": "#EF4444",
    "crimson_glow": "#F87171",
    "purple": "#8B5CF6",
    "purple_glow": "#A78BFA",
    "blue": "#3B82F6",
    
    # Text Hierarchy
    "text_hero": "#F8FAFC",
    "text_primary": "#E2E8F0",
    "text_secondary": "#94A3B8",
    "text_muted": "#64748B",
    "text_faint": "#475569",
}

def inject_cyber_theme():
    """Inject high-grade enterprise cybersecurity CSS styling into Streamlit."""
    css = f"""
    <style>
    /* -------------------------------------------------------------
       GLOBAL STREAMLIT OVERRIDES & DARK CANVAS (SOVEREIGN OFFLINE FONT STACK)
    ------------------------------------------------------------- */
    html, body, [class*="css"], .stApp {{
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif !important;
        background-color: {CYBER_PALETTE["canvas_bg"]} !important;
        background-image: 
            radial-gradient(circle at 10% 5%, rgba(14, 165, 233, 0.12) 0%, transparent 35%),
            radial-gradient(circle at 90% 12%, rgba(99, 102, 241, 0.10) 0%, transparent 40%),
            radial-gradient(circle at 50% 95%, rgba(16, 185, 129, 0.06) 0%, transparent 50%),
            linear-gradient(180deg, rgba(6, 9, 15, 0.8) 0%, #06090F 100%) !important;
        background-attachment: fixed !important;
        color: {CYBER_PALETTE["text_primary"]} !important;
    }}

    code, pre, .mono-font, [data-testid="stMetricValue"] {{
        font-family: ui-monospace, "SFMono-Regular", Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace !important;
    }}

    .block-container {{
        padding-top: 1.25rem !important;
        padding-bottom: 3.5rem !important;
        max-width: 1720px !important;
    }}

    [data-testid="stHeader"] {{
        background: transparent !important;
        border-bottom: none !important;
    }}

    /* -------------------------------------------------------------
       ENTERPRISE SIDEBAR STYLING & COMPACT CONTROLS
    ------------------------------------------------------------- */
    [data-testid="stSidebar"] {{
        background: rgba(9, 14, 25, 0.95) !important;
        backdrop-filter: blur(20px) !important;
        -webkit-backdrop-filter: blur(20px) !important;
        border-right: 1px solid rgba(56, 189, 248, 0.15) !important;
        box-shadow: 4px 0 24px rgba(0, 0, 0, 0.4) !important;
        min-width: 300px !important;
        max-width: 350px !important;
        width: 320px !important;
    }}

    /* Compact, consistent single-line height for sidebar selectboxes */
    [data-testid="stSidebar"] div[data-baseweb="select"] {{
        min-height: 38px !important;
        max-height: 42px !important;
    }}
    [data-testid="stSidebar"] div[data-baseweb="select"] > div {{
        min-height: 38px !important;
        max-height: 42px !important;
        height: 40px !important;
        padding-top: 0 !important;
        padding-bottom: 0 !important;
        display: flex !important;
        align-items: center !important;
    }}
    [data-testid="stSidebar"] div[data-baseweb="select"] span {{
        white-space: nowrap !important;
        overflow: hidden !important;
        text-overflow: ellipsis !important;
    }}

    /* Popover dropdown menu items wrap cleanly with full descriptions */
    div[data-baseweb="popover"] ul[role="listbox"] {{
        background-color: #0B1325 !important;
        border: 1px solid rgba(56, 189, 248, 0.3) !important;
        border-radius: 8px !important;
        padding: 4px !important;
        max-width: 440px !important;
    }}
    div[data-baseweb="popover"] ul[role="listbox"] li {{
        white-space: normal !important;
        text-overflow: unset !important;
        word-break: break-word !important;
        line-height: 1.35 !important;
        padding: 8px 12px !important;
        font-size: 0.85rem !important;
    }}

    /* Telemetry chip for full CSE display */
    .telemetry-chip-cse {{
        display: inline-flex !important;
        align-items: center !important;
        gap: 8px !important;
        background: rgba(15, 23, 42, 0.9) !important;
        border: 1px solid rgba(56, 189, 248, 0.35) !important;
        border-radius: 8px !important;
        padding: 6px 14px !important;
        white-space: normal !important;
        word-break: break-word !important;
        max-width: 540px !important;
        line-height: 1.35 !important;
    }}

    [data-testid="stSidebar"] hr {{
        border-color: rgba(56, 189, 248, 0.12) !important;
        margin: 1.25rem 0 !important;
    }}

    /* Sidebar Radio / Navigation styling */
    [data-testid="stSidebar"] div[data-testid="stRadio"] > div {{
        gap: 6px !important;
    }}

    [data-testid="stSidebar"] div[data-testid="stRadio"] label {{
        background: rgba(15, 23, 42, 0.6) !important;
        border: 1px solid rgba(56, 189, 248, 0.08) !important;
        border-radius: 8px !important;
        padding: 9px 14px !important;
        transition: all 0.2s ease !important;
        cursor: pointer !important;
        color: {CYBER_PALETTE["text_secondary"]} !important;
        font-weight: 500 !important;
        font-size: 0.88rem !important;
    }}

    [data-testid="stSidebar"] div[data-testid="stRadio"] label:hover {{
        background: rgba(56, 189, 248, 0.10) !important;
        border-color: rgba(56, 189, 248, 0.3) !important;
        color: #F8FAFC !important;
        transform: translateX(3px) !important;
    }}

    [data-testid="stSidebar"] div[data-testid="stRadio"] label[data-checked="true"] {{
        background: linear-gradient(90deg, rgba(14, 165, 233, 0.20) 0%, rgba(56, 189, 248, 0.06) 100%) !important;
        border-left: 3px solid {CYBER_PALETTE["cyan_glow"]} !important;
        border-color: rgba(56, 189, 248, 0.4) !important;
        color: #FFFFFF !important;
        font-weight: 600 !important;
        box-shadow: 0 4px 16px rgba(14, 165, 233, 0.15) !important;
    }}

    /* -------------------------------------------------------------
       CARD SURFACES & GLASSMORPHISM
    ------------------------------------------------------------- */
    .cyber-card {{
        background: {CYBER_PALETTE["surface_card"]};
        backdrop-filter: blur(16px);
        -webkit-backdrop-filter: blur(16px);
        border: 1px solid {CYBER_PALETTE["border_subtle"]};
        border-radius: 12px;
        padding: 1.25rem 1.5rem;
        margin-bottom: 1.25rem;
        box-shadow: 0 8px 32px rgba(0, 0, 0, 0.35);
        transition: border-color 0.25s ease, box-shadow 0.25s ease;
    }}

    .cyber-card:hover {{
        border-color: {CYBER_PALETTE["border_highlight"]};
        box-shadow: 0 12px 36px rgba(14, 165, 233, 0.12);
    }}

    .cyber-card-elevated {{
        background: linear-gradient(135deg, rgba(15, 26, 46, 0.85) 0%, rgba(10, 18, 33, 0.90) 100%);
        backdrop-filter: blur(20px);
        -webkit-backdrop-filter: blur(20px);
        border: 1px solid {CYBER_PALETTE["border_highlight"]};
        border-radius: 14px;
        padding: 1.5rem 1.75rem;
        margin-bottom: 1.5rem;
        box-shadow: 0 10px 40px rgba(0, 0, 0, 0.45);
    }}

    /* Metric KPI HUD Cards */
    .kpi-hud-card {{
        background: linear-gradient(145deg, rgba(13, 23, 42, 0.85) 0%, rgba(9, 16, 29, 0.95) 100%);
        border: 1px solid {CYBER_PALETTE["border_subtle"]};
        border-radius: 12px;
        padding: 1.15rem 1.25rem;
        position: relative;
        overflow: hidden;
        min-height: 148px;
        display: flex;
        flex-direction: column;
        justify-content: space-between;
        box-shadow: 0 6px 20px rgba(0, 0, 0, 0.35);
        transition: transform 0.2s ease, border-color 0.2s ease, box-shadow 0.2s ease;
    }}

    .kpi-hud-card:hover {{
        transform: translateY(-2px);
        border-color: {CYBER_PALETTE["border_highlight"]};
        box-shadow: 0 8px 28px rgba(14, 165, 233, 0.18);
    }}

    .kpi-hud-card::before {{
        content: "";
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        height: 2px;
        background: linear-gradient(90deg, transparent, {CYBER_PALETTE["cyan_glow"]}, transparent);
    }}

    .kpi-hud-title {{
        font-size: 0.75rem;
        font-weight: 700;
        letter-spacing: 0.05em;
        text-transform: uppercase;
        color: {CYBER_PALETTE["text_secondary"]};
        margin-bottom: 0.35rem;
    }}

    .kpi-hud-value {{
        font-family: 'JetBrains Mono', monospace;
        font-size: clamp(1.4rem, 2vw, 1.85rem);
        font-weight: 800;
        color: #F8FAFC;
        letter-spacing: -0.02em;
        line-height: 1.15;
    }}

    .kpi-hud-subtitle {{
        font-size: 0.76rem;
        color: {CYBER_PALETTE["text_muted"]};
        margin-top: 0.35rem;
        line-height: 1.35;
        white-space: normal;
        word-break: break-word;
    }}

    .kpi-hud-delta {{
        display: inline-flex;
        align-items: center;
        gap: 4px;
        font-size: 0.74rem;
        font-weight: 600;
        padding: 3px 8px;
        border-radius: 4px;
        margin-top: 0.4rem;
        white-space: normal;
        word-break: break-word;
    }}

    .kpi-delta-positive {{
        background: rgba(16, 185, 129, 0.12);
        color: #6EE7B7;
        border: 1px solid rgba(16, 185, 129, 0.25);
    }}

    .kpi-delta-neutral {{
        background: rgba(56, 189, 248, 0.12);
        color: #7DD3FC;
        border: 1px solid rgba(56, 189, 248, 0.25);
    }}

    .kpi-delta-warning {{
        background: rgba(245, 158, 11, 0.12);
        color: #FCD34D;
        border: 1px solid rgba(245, 158, 11, 0.25);
    }}

    .kpi-delta-critical {{
        background: rgba(239, 68, 68, 0.12);
        color: #FCA5A5;
        border: 1px solid rgba(239, 68, 68, 0.25);
    }}

    /* -------------------------------------------------------------
       COMMAND BAR HEADER & SOVEREIGN BADGES
    ------------------------------------------------------------- */
    .command-header {{
        background: linear-gradient(90deg, rgba(14, 25, 46, 0.95) 0%, rgba(9, 16, 30, 0.85) 100%);
        border: 1px solid rgba(56, 189, 248, 0.20);
        border-radius: 14px;
        padding: 1.25rem 1.75rem;
        margin-bottom: 1.75rem;
        box-shadow: 0 10px 32px rgba(0, 0, 0, 0.4);
        display: flex;
        justify-content: space-between;
        align-items: center;
        flex-wrap: wrap;
        gap: 15px;
    }}

    .command-brand {{
        display: flex;
        align-items: center;
        gap: 14px;
    }}

    .command-logo-box {{
        width: 48px;
        height: 48px;
        background: linear-gradient(135deg, rgba(14, 165, 233, 0.2) 0%, rgba(99, 102, 241, 0.3) 100%);
        border: 1px solid {CYBER_PALETTE["cyan_glow"]};
        border-radius: 10px;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 24px;
        box-shadow: 0 0 16px rgba(14, 165, 233, 0.3);
    }}

    .command-titles h1 {{
        font-size: 1.45rem;
        font-weight: 800;
        letter-spacing: -0.02em;
        color: #F8FAFC;
        margin: 0;
        line-height: 1.2;
    }}

    .command-titles p {{
        font-size: 0.82rem;
        color: {CYBER_PALETTE["text_secondary"]};
        margin: 3px 0 0 0;
        font-weight: 500;
    }}

    .command-telemetry {{
        display: flex;
        align-items: center;
        gap: 10px;
        flex-wrap: wrap;
    }}

    .telemetry-chip {{
        display: inline-flex;
        align-items: center;
        gap: 7px;
        background: rgba(15, 23, 42, 0.8);
        border: 1px solid rgba(148, 163, 184, 0.18);
        border-radius: 8px;
        padding: 6px 12px;
        font-size: 0.78rem;
        font-weight: 600;
        color: {CYBER_PALETTE["text_primary"]};
    }}

    .telemetry-chip-pulse {{
        border-color: rgba(16, 185, 129, 0.35);
        color: #A7F3D0;
        background: rgba(16, 185, 129, 0.08);
    }}

    .pulse-dot {{
        width: 8px;
        height: 8px;
        border-radius: 50%;
        background: #10B981;
        box-shadow: 0 0 10px #10B981;
        animation: cyberPulse 2s infinite;
    }}

    @keyframes cyberPulse {{
        0% {{
            box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7);
        }}
        70% {{
            box-shadow: 0 0 0 6px rgba(16, 185, 129, 0);
        }}
        100% {{
            box-shadow: 0 0 0 0 rgba(16, 185, 129, 0);
        }}
    }}

    /* Section Subheaders */
    .cyber-section-header {{
        display: flex;
        align-items: center;
        gap: 12px;
        margin-top: 1.5rem;
        margin-bottom: 0.85rem;
        border-bottom: 1px solid rgba(56, 189, 248, 0.12);
        padding-bottom: 0.5rem;
    }}

    .cyber-section-title {{
        font-size: 1.15rem;
        font-weight: 750;
        letter-spacing: -0.01em;
        color: #F8FAFC;
        margin: 0;
    }}

    .cyber-section-badge {{
        font-size: 0.72rem;
        font-weight: 700;
        padding: 2px 8px;
        border-radius: 6px;
        background: rgba(56, 189, 248, 0.12);
        color: #38BDF8;
        border: 1px solid rgba(56, 189, 248, 0.25);
        font-family: 'JetBrains Mono', monospace;
    }}

    /* -------------------------------------------------------------
       SEVERITY & STATUS BADGES
    ------------------------------------------------------------- */
    .sev-badge {{
        display: inline-block;
        padding: 3px 9px;
        border-radius: 6px;
        font-size: 0.74rem;
        font-weight: 700;
        letter-spacing: 0.03em;
        text-transform: uppercase;
        font-family: 'JetBrains Mono', monospace;
    }}

    .sev-critical {{
        background: rgba(239, 68, 68, 0.16);
        color: #F87171;
        border: 1px solid rgba(239, 68, 68, 0.35);
        box-shadow: 0 0 10px rgba(239, 68, 68, 0.15);
    }}

    .sev-high {{
        background: rgba(245, 158, 11, 0.16);
        color: #FBBF24;
        border: 1px solid rgba(245, 158, 11, 0.35);
    }}

    .sev-medium {{
        background: rgba(56, 189, 248, 0.14);
        color: #7DD3FC;
        border: 1px solid rgba(56, 189, 248, 0.30);
    }}

    .sev-low {{
        background: rgba(148, 163, 184, 0.12);
        color: #CBD5E1;
        border: 1px solid rgba(148, 163, 184, 0.25);
    }}

    /* -------------------------------------------------------------
       CUSTOM BUTTONS & FORM INPUTS
    ------------------------------------------------------------- */
    div.stButton > button {{
        background: linear-gradient(135deg, rgba(14, 165, 233, 0.2) 0%, rgba(2, 132, 199, 0.3) 100%) !important;
        border: 1px solid rgba(56, 189, 248, 0.4) !important;
        color: #F8FAFC !important;
        font-weight: 600 !important;
        border-radius: 8px !important;
        padding: 0.55rem 1.25rem !important;
        transition: all 0.2s ease !important;
        box-shadow: 0 2px 10px rgba(14, 165, 233, 0.15) !important;
    }}

    div.stButton > button:hover {{
        background: linear-gradient(135deg, rgba(14, 165, 233, 0.35) 0%, rgba(2, 132, 199, 0.5) 100%) !important;
        border-color: {CYBER_PALETTE["cyan_glow"]} !important;
        box-shadow: 0 4px 18px rgba(14, 165, 233, 0.3) !important;
        transform: translateY(-1px) !important;
    }}

    div[data-baseweb="input"] > div {{
        background-color: rgba(15, 23, 42, 0.8) !important;
        border: 1px solid rgba(56, 189, 248, 0.20) !important;
        border-radius: 8px !important;
        color: #F8FAFC !important;
    }}

    div[data-baseweb="input"] > div:focus-within {{
        border-color: {CYBER_PALETTE["cyan_glow"]} !important;
        box-shadow: 0 0 12px rgba(14, 165, 233, 0.25) !important;
    }}

    div[data-baseweb="select"] > div {{
        background-color: rgba(15, 23, 42, 0.8) !important;
        border: 1px solid rgba(56, 189, 248, 0.20) !important;
        border-radius: 8px !important;
        color: #F8FAFC !important;
    }}

    [data-testid="stDataFrame"] {{
        border: 1px solid rgba(56, 189, 248, 0.15) !important;
        border-radius: 10px !important;
        overflow: hidden !important;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.25) !important;
    }}

    ::-webkit-scrollbar {{
        width: 7px;
        height: 7px;
    }}
    ::-webkit-scrollbar-track {{
        background: #070B14;
    }}
    ::-webkit-scrollbar-thumb {{
        background: rgba(56, 189, 248, 0.25);
        border-radius: 4px;
    }}
    ::-webkit-scrollbar-thumb:hover {{
        background: rgba(56, 189, 248, 0.5);
    }}
    </style>
    """
    st.markdown(css, unsafe_allow_html=True)


CSE_PROFILES = {
    "ORG-0001": "National Power Grid Infrastructure",
    "ORG-0003": "Central Banking & Financial Services",
    "ORG-0004": "Defense & National Telecommunications",
    "ORG-0005": "Petroleum & Pipeline Control Systems",
    "All CSEs": "Multi-Entity Regulatory Cohort",
}

def render_command_header(page_title: str, page_subtitle: str, active_cse: str = "ORG-0004", total_alerts: int = 402335):
    """Render the sovereign NCIIPC command bar header with complete CSE identity."""
    org_id = active_cse.split(" — ")[0].strip()
    clean_name = CSE_PROFILES.get(org_id, "")
    if not clean_name and " — " in active_cse:
        clean_name = active_cse.split(" — ")[1].replace("(Baseline V6)", "").replace("(Multi-Entity Regulatory View)", "").replace("(Consolidated View)", "").strip()

    cse_name_display = f"— {clean_name}" if clean_name else ""

    header_html = f"""
    <div class="command-header">
        <div class="command-brand">
            <div class="command-logo-box">🛡️</div>
            <div class="command-titles">
                <h1>{page_title}</h1>
                <p>{page_subtitle}</p>
            </div>
        </div>
        <div class="command-telemetry">
            <div class="telemetry-chip telemetry-chip-pulse">
                <span class="pulse-dot"></span>
                <span>NCIIPC SECURE CLUSTER</span>
            </div>
            <div class="telemetry-chip telemetry-chip-cse">
                <span style="color:#38BDF8; font-weight:700;">CSE:</span>
                <span style="font-family:'JetBrains Mono', monospace; font-weight:800; color:#F8FAFC;">{org_id}</span>
                <span style="color:#CBD5E1; font-weight:600;">{cse_name_display}</span>
            </div>
            <div class="telemetry-chip">
                <span style="color:#94A3B8;">CORPUS:</span>
                <span style="font-family:'JetBrains Mono', monospace;">{total_alerts:,} Alerts</span>
            </div>
            <div class="telemetry-chip" style="border-color:rgba(139, 92, 246, 0.3); color:#C4B5FD;">
                <span>AIR-GAPPED v6.0</span>
            </div>
        </div>
    </div>
    """
    st.markdown(header_html, unsafe_allow_html=True)


def render_kpi_card(
    title: str,
    value: str,
    subtitle: str,
    delta: Optional[str] = None,
    delta_type: str = "positive"
):
    """Render a tactical HUD metric card."""
    delta_class = {
        "positive": "kpi-delta-positive",
        "neutral": "kpi-delta-neutral",
        "warning": "kpi-delta-warning",
        "critical": "kpi-delta-critical"
    }.get(delta_type, "kpi-delta-neutral")

    delta_html = f'<div class="kpi-hud-delta {delta_class}">{delta}</div>' if delta else ""

    card_html = f"""
    <div class="kpi-hud-card">
        <div class="kpi-hud-title">{title}</div>
        <div class="kpi-hud-value">{value}</div>
        <div class="kpi-hud-subtitle">{subtitle}</div>
        {delta_html}
    </div>
    """
    st.markdown(card_html, unsafe_allow_html=True)


def render_incident_capture_card(
    heading: str,
    large_value: str,
    caption: str = "Unique incidents captured",
    badge_text: str = "",
    badge_type: str = "positive"
):
    """Render an Incident Capture KPI card adhering strictly to SIH supervisory specifications."""
    badge_colors = {
        "positive": "background:rgba(16,185,129,0.12); color:#6EE7B7; border:1px solid rgba(16,185,129,0.3);",
        "neutral": "background:rgba(56,189,248,0.12); color:#7DD3FC; border:1px solid rgba(56,189,248,0.3);",
        "warning": "background:rgba(245,158,11,0.12); color:#FCD34D; border:1px solid rgba(245,158,11,0.3);",
    }
    b_style = badge_colors.get(badge_type, badge_colors["neutral"])

    card_html = f"""
    <div class="kpi-hud-card incident-capture-card" style="min-height:152px; display:flex; flex-direction:column; justify-content:space-between; padding:1.15rem 1.25rem;">
        <div>
            <div class="kpi-hud-title" style="font-size:0.75rem; letter-spacing:0.06em; text-transform:uppercase; color:#94A3B8; margin-bottom:0.35rem; font-weight:700;">{heading}</div>
            <div class="kpi-hud-value" style="font-size:clamp(1.6rem, 2.2vw, 2.05rem); font-weight:800; color:#F8FAFC; line-height:1.15; font-family:'JetBrains Mono', ui-monospace, monospace;">{large_value}</div>
            <div class="kpi-hud-subtitle" style="font-size:0.76rem; color:#94A3B8; margin-top:0.35rem; line-height:1.35; white-space:normal; word-break:break-word;">{caption}</div>
        </div>
        <div style="margin-top:0.65rem;">
            <div style="display:inline-flex; align-items:center; gap:5px; font-size:0.74rem; font-weight:700; padding:3px 9px; border-radius:6px; font-family:'JetBrains Mono', ui-monospace, monospace; white-space:normal; word-break:break-word; line-height:1.25; {b_style}">
                {badge_text}
            </div>
        </div>
    </div>
    """
    st.markdown(card_html, unsafe_allow_html=True)


def render_section_header(title: str, subtitle: Optional[str] = None, badge: Optional[str] = None):
    """Render a clean cyber section header."""
    badge_html = f'<span class="cyber-section-badge">{badge}</span>' if badge else ""
    sub_html = f'<p style="color:#64748B; font-size:0.80rem; margin:2px 0 0 0;">{subtitle}</p>' if subtitle else ""
    
    html = f"""
    <div class="cyber-section-header">
        <h3 class="cyber-section-title">{title}</h3>
        {badge_html}
    </div>
    {sub_html}
    """
    st.markdown(html, unsafe_allow_html=True)


def apply_cyber_plotly_theme(fig: go.Figure) -> go.Figure:
    """Apply the high-end dark obsidian cyber styling to any Plotly figure."""
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(11, 18, 32, 0.45)",
        font=dict(
            family="Inter, -apple-system, sans-serif",
            color=CYBER_PALETTE["text_secondary"],
            size=12
        ),
        margin=dict(l=25, r=25, t=35, b=25),
        legend=dict(
            bgcolor="rgba(15, 23, 42, 0.7)",
            bordercolor="rgba(56, 189, 248, 0.15)",
            borderwidth=1,
            font=dict(size=11, color=CYBER_PALETTE["text_primary"]),
            orientation="h",
            yanchor="bottom",
            y=1.02,
            xanchor="right",
            x=1
        ),
        hoverlabel=dict(
            bgcolor="#0B132B",
            bordercolor="#38BDF8",
            font=dict(family="JetBrains Mono, monospace", size=12, color="#FFFFFF")
        ),
        xaxis=dict(
            gridcolor="rgba(148, 163, 184, 0.08)",
            zerolinecolor="rgba(56, 189, 248, 0.2)",
            tickfont=dict(color=CYBER_PALETTE["text_muted"], size=11)
        ),
        yaxis=dict(
            gridcolor="rgba(148, 163, 184, 0.08)",
            zerolinecolor="rgba(56, 189, 248, 0.2)",
            tickfont=dict(color=CYBER_PALETTE["text_muted"], size=11)
        )
    )
    return fig


def render_severity_badge(priority_label: str) -> str:
    """Return HTML for a glowing severity badge."""
    label_lower = str(priority_label).lower()
    if "crit" in label_lower:
        cls = "sev-critical"
    elif "high" in label_lower:
        cls = "sev-high"
    elif "med" in label_lower:
        cls = "sev-medium"
    else:
        cls = "sev-low"
    return f'<span class="sev-badge {cls}">{priority_label}</span>'
