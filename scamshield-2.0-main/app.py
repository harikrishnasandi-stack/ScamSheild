"""
ScamShield 2.0 - Enterprise Cybersecurity SaaS Platform.
Next-generation AI-powered scam, phishing, and threat intelligence system.
Features:
- Multi-vector detection (Financial scams, urgency manipulation, personal threats, extortion).
- Dual-engine architecture: Primary Azure AI Foundry with automatic zero-latency Local Fallback.
- Multilingual NLP support (English, Telugu, Tamil, Hindi, etc.).
- ScamShield AI Assistant: Conversational, context-aware cybersecurity investigation assistant.
- PropChk Write Collaboration portal & threat intelligence reporting.
"""

import datetime
import html
import json
import os
import textwrap
import streamlit as st

from fast_analyzer import quick_analyze
from file_reader import extract_text_from_file
from translator import LANGUAGES, t, translate_analysis
from ai_assistant import get_chat_response
from email_service import (
    get_contact_recipient,
    send_contact_inquiry,
    send_threat_report_email,
    validate_email_address,
)


def safe_html(content: str):
    """Render HTML safely without triggering Markdown's 4-space code block parser."""
    st.markdown(textwrap.dedent(content).strip(), unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Page Configuration
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="ScamShield | Cybersecurity Threat Defense",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# Session State Initialization
# ---------------------------------------------------------------------------
if "current_page" not in st.session_state:
    st.session_state.current_page = "Dashboard"

if "message_text" not in st.session_state:
    st.session_state.message_text = ""

if "current_analysis" not in st.session_state:
    st.session_state.current_analysis = None

if "history" not in st.session_state:
    st.session_state.history = []

if "chat_messages" not in st.session_state:
    st.session_state.chat_messages = []

if "feedback_submissions" not in st.session_state:
    st.session_state.feedback_submissions = []

if "language" not in st.session_state:
    st.session_state.language = "English"

# ---------------------------------------------------------------------------
# Professional SaaS Styling (Light Cybersecurity Theme)
# ---------------------------------------------------------------------------
st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=Space+Grotesk:wght@500;600;700&family=Inter:wght@400;500;600;700&family=Noto+Sans+Devanagari&family=Noto+Sans+Tamil&family=Noto+Sans+Telugu&display=swap');

    :root {
        --bg-main: #F8FAFC;
        --bg-card: #FFFFFF;
        --bg-subtle: #F1F5F9;
        --border-color: #E2E8F0;
        --border-focus: #0284C7;
        --text-primary: #0F172A;
        --text-secondary: #475569;
        --text-muted: #64748B;
        --brand-primary: #0284C7;
        --brand-hover: #0369A1;
        --brand-accent: #0D9488;
        --brand-light: #E0F2FE;
        --success-bg: #F0FDF4;
        --success-text: #16A34A;
        --success-border: #BBF7D0;
        --warning-bg: #FFFBEB;
        --warning-text: #D97706;
        --warning-border: #FDE68A;
        --danger-bg: #FEF2F2;
        --danger-text: #DC2626;
        --danger-border: #FECACA;
        --critical-bg: #7F1D1D;
        --critical-text: #FFFFFF;
    }

    html, body, [class*="css"] {
        font-family: 'Plus Jakarta Sans', 'Inter', 'Noto Sans Devanagari', 'Noto Sans Tamil', 'Noto Sans Telugu', sans-serif;
        color: var(--text-primary);
        background-color: var(--bg-main);
    }

    .stApp {
        background-color: var(--bg-main);
    }

    /* Professional Topbar Banner */
    .saas-topbar {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 12px 20px;
        background: #FFFFFF;
        border: 1px solid var(--border-color);
        border-radius: 12px;
        margin-bottom: 24px;
        box-shadow: 0 1px 3px rgba(0,0,0,0.03);
    }
    .saas-brand-wrap {
        display: flex;
        align-items: center;
        gap: 12px;
    }
    .saas-logo-icon {
        width: 38px;
        height: 38px;
        background: linear-gradient(135deg, #0284C7, #0D9488);
        border-radius: 9px;
        display: flex;
        align-items: center;
        justify-content: center;
        color: white;
        font-size: 19px;
        font-weight: 700;
        box-shadow: 0 2px 4px rgba(2, 132, 199, 0.25);
    }
    .saas-brand-title {
        font-family: 'Space Grotesk', sans-serif;
        font-weight: 700;
        font-size: 19px;
        color: var(--text-primary);
        letter-spacing: -0.2px;
        display: flex;
        align-items: center;
        gap: 8px;
    }
    .saas-brand-tag {
        font-size: 10px;
        font-weight: 700;
        background: #E0F2FE;
        color: #0369A1;
        padding: 2px 8px;
        border-radius: 999px;
        letter-spacing: 0.5px;
    }
    .saas-status-pill {
        display: flex;
        align-items: center;
        gap: 7px;
        font-size: 12px;
        font-weight: 600;
        color: #059669;
        background: #ECFDF5;
        border: 1px solid #A7F3D0;
        padding: 4px 12px;
        border-radius: 999px;
    }
    .saas-dot-green {
        width: 7px;
        height: 7px;
        background: #10B981;
        border-radius: 50%;
        box-shadow: 0 0 6px rgba(16, 185, 129, 0.6);
    }

    /* Cards */
    .saas-card {
        background: var(--bg-card);
        border: 1px solid var(--border-color);
        border-radius: 12px;
        padding: 22px;
        margin-bottom: 20px;
        box-shadow: 0 1px 3px rgba(0,0,0,0.03);
    }
    .saas-card-header {
        font-family: 'Space Grotesk', sans-serif;
        font-weight: 700;
        font-size: 16px;
        color: var(--text-primary);
        margin-bottom: 6px;
        display: flex;
        align-items: center;
        justify-content: space-between;
    }
    .saas-card-subtitle {
        font-size: 13px;
        color: var(--text-muted);
        margin-bottom: 16px;
    }

    /* Metric Tiles */
    .metric-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
        gap: 16px;
        margin-bottom: 24px;
    }
    .metric-card {
        background: #FFFFFF;
        border: 1px solid var(--border-color);
        border-radius: 10px;
        padding: 18px 20px;
        box-shadow: 0 1px 2px rgba(0,0,0,0.02);
    }
    .metric-title {
        font-size: 12.5px;
        font-weight: 600;
        color: var(--text-muted);
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    .metric-value {
        font-family: 'Space Grotesk', sans-serif;
        font-size: 26px;
        font-weight: 700;
        color: var(--text-primary);
        margin-top: 4px;
    }
    .metric-desc {
        font-size: 12px;
        color: var(--text-secondary);
        margin-top: 4px;
    }

    /* Risk Ring / Meter */
    .risk-score-box {
        text-align: center;
        padding: 24px 20px;
        background: #FFFFFF;
        border: 1px solid var(--border-color);
        border-radius: 12px;
        box-shadow: 0 1px 3px rgba(0,0,0,0.03);
    }
    .risk-score-num {
        font-family: 'Space Grotesk', sans-serif;
        font-size: 44px;
        font-weight: 800;
        line-height: 1;
    }
    .risk-score-label {
        font-size: 11px;
        font-weight: 700;
        letter-spacing: 1px;
        color: var(--text-muted);
        margin-top: 4px;
    }

    /* Risk Badges */
    .badge-critical {
        background: #FEF2F2;
        color: #B91C1C;
        border: 1px solid #FCA5A5;
        font-size: 12px;
        font-weight: 700;
        padding: 4px 12px;
        border-radius: 999px;
        display: inline-block;
    }
    .badge-high {
        background: #FFF7ED;
        color: #C2410C;
        border: 1px solid #FDBA74;
        font-size: 12px;
        font-weight: 700;
        padding: 4px 12px;
        border-radius: 999px;
        display: inline-block;
    }
    .badge-medium {
        background: #FFFBEB;
        color: #B45309;
        border: 1px solid #FCD34D;
        font-size: 12px;
        font-weight: 700;
        padding: 4px 12px;
        border-radius: 999px;
        display: inline-block;
    }
    .badge-low {
        background: #F0FDF4;
        color: #15803D;
        border: 1px solid #86EFAC;
        font-size: 12px;
        font-weight: 700;
        padding: 4px 12px;
        border-radius: 999px;
        display: inline-block;
    }

    /* Indicators Chips */
    .saas-chip {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        font-size: 12.5px;
        font-weight: 500;
        color: #334155;
        background: #F1F5F9;
        border: 1px solid #CBD5E1;
        padding: 5px 12px;
        border-radius: 8px;
        margin: 3px;
    }
    .saas-chip.red {
        background: #FEF2F2;
        color: #991B1B;
        border-color: #FECACA;
    }

    /* Chat UI */
    .chat-bubble-user {
        background: #0284C7;
        color: #FFFFFF;
        padding: 12px 16px;
        border-radius: 12px 12px 2px 12px;
        max-width: 80%;
        margin-left: auto;
        margin-bottom: 12px;
        font-size: 14px;
        line-height: 1.5;
        box-shadow: 0 1px 2px rgba(2, 132, 199, 0.2);
    }
    .chat-bubble-assistant {
        background: #FFFFFF;
        color: #0F172A;
        border: 1px solid var(--border-color);
        padding: 14px 18px;
        border-radius: 12px 12px 12px 2px;
        max-width: 85%;
        margin-right: auto;
        margin-bottom: 14px;
        font-size: 14px;
        line-height: 1.6;
        box-shadow: 0 1px 3px rgba(0,0,0,0.03);
    }
    .chat-meta {
        font-size: 11px;
        color: var(--text-muted);
        margin-top: 4px;
        display: flex;
        align-items: center;
        gap: 8px;
    }

    /* Buttons */
    div.stButton > button {
        border-radius: 8px;
        font-weight: 600;
        font-size: 13.5px;
        border: 1px solid var(--border-color);
        background: #FFFFFF;
        color: var(--text-primary);
        transition: all 0.15s ease;
    }
    div.stButton > button:hover {
        border-color: #0284C7;
        color: #0284C7;
        background: #F0F9FF;
    }
    div.stButton > button[kind="primary"] {
        background: #0284C7;
        color: #FFFFFF;
        border: none;
        box-shadow: 0 1px 3px rgba(2, 132, 199, 0.3);
    }
    div.stButton > button[kind="primary"]:hover {
        background: #0369A1;
        box-shadow: 0 2px 5px rgba(2, 132, 199, 0.4);
    }

    /* Textarea & Inputs */
    [data-testid="stTextArea"] textarea {
        background: #FFFFFF !important;
        border: 1px solid var(--border-color) !important;
        border-radius: 8px !important;
        color: #0F172A !important;
        font-size: 14px !important;
    }
    [data-testid="stTextArea"] textarea:focus {
        border-color: #0284C7 !important;
        box-shadow: 0 0 0 2px rgba(2, 132, 199, 0.15) !important;
    }

    /* File uploader */
    [data-testid="stFileUploaderDropzone"] {
        background: #F8FAFC !important;
        border: 1.5px dashed #CBD5E1 !important;
        border-radius: 10px !important;
    }

    /* Sidebar Navigation Styling */
    [data-testid="stSidebar"] {
        background-color: #FFFFFF !important;
        border-right: 1px solid var(--border-color) !important;
    }
    .sidebar-brand {
        display: flex;
        align-items: center;
        gap: 10px;
        padding: 10px 0 18px 0;
        border-bottom: 1px solid var(--border-color);
        margin-bottom: 20px;
    }
    .sidebar-section-title {
        font-size: 11px;
        font-weight: 700;
        text-transform: uppercase;
        color: var(--text-muted);
        letter-spacing: 0.6px;
        margin: 16px 0 8px 0;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# Sidebar Navigation & Workspace Controls
# ---------------------------------------------------------------------------
with st.sidebar:
    st.markdown(
        """
        <div class="sidebar-brand">
            <div class="saas-logo-icon">🛡️</div>
            <div>
                <div style="font-family:'Space Grotesk',sans-serif; font-weight:700; font-size:17px; color:#0F172A;">SCAMSHIELD</div>
                <div style="font-size:11px; color:#64748B;">Cyber Threat Intelligence</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown('<div class="sidebar-section-title">Navigation</div>', unsafe_allow_html=True)
    pages = [
        "Dashboard",
        "Analyse Message",
        "AI Assistant",
        "Analysis History",
        "Contact & Collaboration",
        "About ScamShield",
    ]

    selected_page = st.radio(
        "Navigation",
        pages,
        index=pages.index(st.session_state.current_page) if st.session_state.current_page in pages else 0,
        label_visibility="collapsed",
    )
    if selected_page != st.session_state.current_page:
        st.session_state.current_page = selected_page
        st.rerun()

    st.markdown('<div class="sidebar-section-title">Language & Regional</div>', unsafe_allow_html=True)
    lang_choice = st.selectbox(
        "Language",
        list(LANGUAGES.keys()),
        index=list(LANGUAGES.keys()).index(st.session_state.language) if st.session_state.language in LANGUAGES else 0,
        format_func=lambda k: LANGUAGES[k],
        label_visibility="collapsed",
    )
    if lang_choice != st.session_state.language:
        st.session_state.language = lang_choice
        st.rerun()

    st.markdown("---")
    st.markdown(
        f"""
        <div style="padding: 12px; background: #F8FAFC; border: 1px solid #E2E8F0; border-radius: 8px;">
            <div style="font-size: 11.5px; font-weight: 700; color: #475569; margin-bottom: 4px;">SYSTEM ARCHITECTURE</div>
            <div style="font-size: 11px; color: #64748B;">• Primary: <b>Azure AI Foundry</b></div>
            <div style="font-size: 11px; color: #64748B;">• Fallback: <b>ScamShield Engine v2</b></div>
            <div style="font-size: 11px; color: #64748B;">• Credential: <b>Azure CLI / Managed</b></div>
            <div style="font-size: 11px; color: #64748B; margin-top: 4px;">• Session Analyses: <b>{len(st.session_state.history)}</b></div>
        </div>
        """,
        unsafe_allow_html=True,
    )

language = st.session_state.language

# ---------------------------------------------------------------------------
# Global Header
# ---------------------------------------------------------------------------
st.markdown(
    """
    <div class="saas-topbar">
        <div class="saas-brand-wrap">
            <div class="saas-logo-icon">🛡️</div>
            <div>
                <div class="saas-brand-title">
                    SCAMSHIELD 2.0
                    <span class="saas-brand-tag">ENTERPRISE SAAS</span>
                </div>
                <div style="font-size: 12px; color: #64748B;">Next-Gen Phishing, Threat & Fraud Intelligence Platform</div>
            </div>
        </div>
        <div style="display: flex; align-items: center; gap: 14px;">
            <div class="saas-status-pill">
                <div class="saas-dot-green"></div>
                SYSTEM ONLINE
            </div>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

# ===========================================================================
# PAGE 1: DASHBOARD
# ===========================================================================
if st.session_state.current_page == "Dashboard":
    st.markdown(
        """
        <div style="margin-bottom: 24px;">
            <h2 style="font-family:'Space Grotesk',sans-serif; font-size:24px; font-weight:700; margin:0 0 6px 0; color:#0F172A;">
                Threat Intelligence Dashboard
            </h2>
            <p style="font-size:14px; color:#64748B; margin:0;">
                Comprehensive overview of message scans, threat telemetry, automated safeguards, and active security status.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Real data metrics
    total_scanned = len(st.session_state.history)
    high_threats = sum(1 for h in st.session_state.history if h.get("result", {}).get("risk_level") in ["High", "Critical"])
    avg_score = int(sum(h.get("result", {}).get("risk_score", 0) for h in st.session_state.history) / total_scanned) if total_scanned > 0 else 0

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-title">Messages Analyzed</div>
                <div class="metric-value">{total_scanned}</div>
                <div class="metric-desc">In current session</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with col2:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-title">High Threats Flagged</div>
                <div class="metric-value" style="color: {'#DC2626' if high_threats > 0 else '#0F172A'};">{high_threats}</div>
                <div class="metric-desc">Critical & high severity</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with col3:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-title">Avg. Session Risk</div>
                <div class="metric-value">{avg_score}%</div>
                <div class="metric-desc">Mean severity score</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with col4:
        st.markdown(
            """
            <div class="metric-card">
                <div class="metric-title">Detection Engines</div>
                <div class="metric-value" style="color: #0D9488;">2 Active</div>
                <div class="metric-desc">Azure AI + Local Heuristic</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)

    # 2-column layout: Quick Scanner + Assistant Access
    left_col, right_col = st.columns([1.4, 1.0])

    with left_col:
        st.markdown('<div class="saas-card">', unsafe_allow_html=True)
        st.markdown(
            """
            <div class="saas-card-header">
                <span>⚡ Quick Message Threat Scan</span>
            </div>
            <div class="saas-card-subtitle">
                Paste any suspicious SMS, WhatsApp, or email message for immediate multi-stage risk assessment.
            </div>
            """,
            unsafe_allow_html=True,
        )

        dash_msg = st.text_area(
            "Quick message input",
            placeholder="e.g. 'Your SBI account is blocked. Share your OTP to reactivate.'",
            height=110,
            label_visibility="collapsed",
            key="dash_quick_input",
        )

        c_btn1, c_btn2 = st.columns([1, 1.5])
        with c_btn1:
            if st.button("Run Quick Analysis", type="primary", use_container_width=True):
                if dash_msg.strip():
                    st.session_state.message_text = dash_msg.strip()
                    st.session_state.current_page = "Analyse Message"
                    st.rerun()
                else:
                    st.warning("Please enter a message to analyze.")
        with c_btn2:
            if st.button("Open Full Forensic Scanner", use_container_width=True):
                st.session_state.current_page = "Analyse Message"
                st.rerun()

        st.markdown("</div>", unsafe_allow_html=True)

        # Recent Analysis History preview
        st.markdown('<div class="saas-card">', unsafe_allow_html=True)
        st.markdown('<div class="saas-card-header">Recent Security Analyses</div>', unsafe_allow_html=True)
        if not st.session_state.history:
            st.markdown(
                """
                <div style="text-align: center; padding: 24px 10px; color: #64748B; font-size: 13.5px;">
                    No messages scanned yet in this session.<br>
                    Use the quick scanner above or open the <b>Analyse Message</b> tab to begin.
                </div>
                """,
                unsafe_allow_html=True,
            )
        else:
            for item in reversed(st.session_state.history[-3:]):
                r = item.get("result", {})
                lvl = r.get("risk_level", "Medium")
                badge_class = f"badge-{lvl.lower()}" if lvl.lower() in ["critical", "high", "medium", "low"] else "badge-medium"
                msg_preview = html.escape(item.get("message", "")[:80])
                st.markdown(
                    f"""
                    <div style="display:flex; justify-content:space-between; align-items:center; padding:10px 0; border-bottom:1px solid #F1F5F9;">
                        <div>
                            <span class="{badge_class}">{lvl} ({r.get('risk_score', 'N/A')}%)</span>
                            <span style="font-size:13px; color:#1E293B; margin-left:8px; font-weight:500;">"{msg_preview}..."</span>
                        </div>
                        <div style="font-size:11.5px; color:#64748B;">{item.get('timestamp', '')}</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
            if st.button("View Full History", use_container_width=True):
                st.session_state.current_page = "Analysis History"
                st.rerun()
        st.markdown("</div>", unsafe_allow_html=True)

    with right_col:
        # ScamShield AI Assistant Callout
        st.markdown(
            """
            <div class="saas-card" style="border-left: 4px solid #0284C7;">
                <div class="saas-card-header">
                    <span>💬 ScamShield AI Assistant</span>
                    <span class="saas-brand-tag" style="background:#E0F2FE; color:#0369A1;">GPT-4o Powered</span>
                </div>
                <div class="saas-card-subtitle">
                    Interact directly with an intelligent cybersecurity investigator. Ask why a message was flagged, what to do if you shared an OTP, or how to verify senders.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        if st.button("Launch Investigation Assistant", type="primary", use_container_width=True):
            st.session_state.current_page = "AI Assistant"
            st.rerun()

        # Threat Defense Information
        st.markdown(
            """
            <div class="saas-card">
                <div class="saas-card-header">Active Threat Vectors Monitored</div>
                <div style="font-size: 13px; color: #475569; display: flex; flex-direction: column; gap: 10px;">
                    <div style="display: flex; gap: 10px; align-items: flex-start;">
                        <span style="color: #DC2626; font-size: 16px;">•</span>
                        <div><b>Banking & OTP Phishing:</b> Fraudulent account suspension claims requiring immediate verification.</div>
                    </div>
                    <div style="display: flex; gap: 10px; align-items: flex-start;">
                        <span style="color: #DC2626; font-size: 16px;">•</span>
                        <div><b>Physical Violence & Extortion:</b> Explicit death threats, stalking intimidation, and coercion.</div>
                    </div>
                    <div style="display: flex; gap: 10px; align-items: flex-start;">
                        <span style="color: #D97706; font-size: 16px;">•</span>
                        <div><b>Digital Arrest & Law Impersonation:</b> Fake police, CBI, customs, or RBI notices.</div>
                    </div>
                    <div style="display: flex; gap: 10px; align-items: flex-start;">
                        <span style="color: #0284C7; font-size: 16px;">•</span>
                        <div><b>Malicious URL Lookalikes:</b> Shortened links and credential-harvesting phishing portals.</div>
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # Digital Safety Best Practices
        st.markdown(
            """
            <div class="saas-card" style="background: #F8FAFC;">
                <div class="saas-card-header" style="font-size: 14.5px;">🛡️ Safety Protocol Checklist</div>
                <div style="font-size: 12.5px; color: #64748B; line-height: 1.5;">
                    1. Never disclose OTPs or UPI PINs to anyone, even bank staff.<br>
                    2. Check registered enterprise SMS sender IDs (e.g. AD-HDFCBK).<br>
                    3. If an urgent deadline is demanded, stop and verify via official apps.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

# ===========================================================================
# PAGE 2: ANALYSE MESSAGE
# ===========================================================================
elif st.session_state.current_page == "Analyse Message":
    st.markdown(
        f"""
        <div style="margin-bottom: 20px;">
            <h2 style="font-family:'Space Grotesk',sans-serif; font-size:24px; font-weight:700; margin:0 0 6px 0; color:#0F172A;">
                Message Forensics & Risk Classification
            </h2>
            <p style="font-size:14px; color:#64748B; margin:0;">
                {t(language, 'tagline')}
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown('<div class="saas-card">', unsafe_allow_html=True)
    st.markdown(f'<div style="font-size:13px; font-weight:600; color:#475569; margin-bottom:8px;">{t(language, "try_example")}</div>', unsafe_allow_html=True)

    EXAMPLE_KEYS = ["example_bank", "example_delivery", "example_lottery"]
    EXAMPLE_TEXT = {
        "example_bank": "Dear customer, your account will be suspended. Click http://kotak-verify.net/confirm or call 8899001122 immediately to avoid penalty.",
        "example_delivery": "Your order #4521 has been shipped and will arrive tomorrow by 6pm.",
        "example_lottery": "Congratulations! You have won Rs 25,00,000 in the KBC lucky draw. Share your bank details and OTP to claim your prize now.",
    }

    cols = st.columns(len(EXAMPLE_KEYS))
    for col, key in zip(cols, EXAMPLE_KEYS):
        if col.button(t(language, key), use_container_width=True):
            st.session_state.message_text = EXAMPLE_TEXT[key]
            st.rerun()

    message = st.text_area(
        "Message to analyze",
        value=st.session_state.message_text,
        height=130,
        placeholder=t(language, "message_placeholder"),
        label_visibility="collapsed",
        max_chars=5000,
        key="main_analysis_textarea",
    )
    st.markdown(f'<div style="text-align:right; font-size:11.5px; color:#64748B; margin-top:-6px; margin-bottom:12px;">{len(message)} / 5000 characters</div>', unsafe_allow_html=True)

    uploaded_file = st.file_uploader(
        t(language, "upload_label"),
        type=["png", "jpg", "jpeg", "webp", "pdf", "txt"],
    )

    analyze_clicked = st.button("⚡ " + t(language, "analyze_button"), type="primary", use_container_width=True)
    st.markdown("</div>", unsafe_allow_html=True)

    # Trigger Analysis
    if analyze_clicked:
        text_to_analyze = message.strip()[:4000]
        if uploaded_file is not None:
            extracted = ""
            with st.spinner(t(language, "reading_file")):
                try:
                    extracted = extract_text_from_file(
                        uploaded_file.name, uploaded_file.getvalue(), uploaded_file.type or ""
                    )
                except Exception as e:
                    st.error(f"{t(language, 'error_prefix')}{e}")
            if extracted == "NO_MESSAGE_FOUND":
                st.warning(t(language, "no_file_found"))
            elif extracted:
                extracted = extracted[:4000]
                text_to_analyze = (text_to_analyze + "\n\n" + extracted).strip()[:4000]
                with st.expander(t(language, "read_expander")):
                    st.text(extracted)

        if not text_to_analyze:
            st.warning(t(language, "enter_message_warning"))
        else:
            with st.spinner(t(language, "analyzing")):
                try:
                    result = quick_analyze(text_to_analyze)
                except Exception as e:
                    st.error(f"{t(language, 'error_prefix')}{e}")
                    result = None

            if result and language != "English":
                with st.spinner(t(language, "translating")):
                    result = translate_analysis(result, language)

            if result:
                result["original_text"] = text_to_analyze
                st.session_state.current_analysis = result
                st.session_state.history.append({
                    "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
                    "message": text_to_analyze,
                    "result": result,
                })

    # Render Current Analysis Result (if available)
    if st.session_state.current_analysis:
        res = st.session_state.current_analysis
        risk = res.get("risk_level", "Medium")
        score = res.get("risk_score", 50)
        display_score = score if isinstance(score, (int, float)) else 50
        scam_type = res.get("scam_type", "Suspicious Message")
        threat_type = res.get("threat_category", "None detected" if risk == "Low" else "Potential intimidation / coercion")
        indicators = res.get("indicators", [])
        recommendation = res.get("recommendation", "")
        analysis_mode = res.get("analysis_mode", "Azure AI Analysis")
        is_fallback = "local" in analysis_mode.lower() or "fallback" in analysis_mode.lower()

        risk_colors = {
            "Critical": {"text": "#B91C1C", "bg": "#FEF2F2", "border": "#FCA5A5"},
            "High": {"text": "#C2410C", "bg": "#FFF7ED", "border": "#FDBA74"},
            "Medium": {"text": "#B45309", "bg": "#FFFBEB", "border": "#FCD34D"},
            "Low": {"text": "#15803D", "bg": "#F0FDF4", "border": "#86EFAC"},
        }
        color_info = risk_colors.get(risk, risk_colors["Medium"])

        # Fallback Alert if applicable
        if is_fallback:
            st.info(f"ℹ️ {t(language, 'fallback_notice')}")

        st.markdown('<div class="saas-card">', unsafe_allow_html=True)
        # Header / Status Row
        st.markdown(
            f"""
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:18px;">
                <div style="font-family:'Space Grotesk',sans-serif; font-size:18px; font-weight:700; color:#0F172A;">
                    Threat Assessment Report
                </div>
                <div>
                    <span style="font-size:11.5px; font-weight:600; padding:4px 12px; border-radius:999px;
                        background: {'#FFFBEB' if is_fallback else '#E0F2FE'};
                        color: {'#B45309' if is_fallback else '#0369A1'};
                        border: 1px solid {'#FDE68A' if is_fallback else '#BAE6FD'};">
                        {analysis_mode}
                    </span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # 3-Column Assessment Grid: Score Box + Scam Risk + Threat Risk
        g1, g2, g3 = st.columns([1, 1.2, 1.2])

        with g1:
            st.markdown(
                f"""
                <div class="risk-score-box" style="border-top: 4px solid {color_info['text']};">
                    <div class="risk-score-num" style="color: {color_info['text']};">{display_score}%</div>
                    <div class="risk-score-label">OVERALL THREAT SCORE</div>
                    <div style="margin-top: 10px;">
                        <span style="background:{color_info['bg']}; color:{color_info['text']}; border:1px solid {color_info['border']}; font-size:13px; font-weight:700; padding:4px 14px; border-radius:999px;">
                            {t(language, f'risk_{risk.lower()}')}
                        </span>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        with g2:
            st.markdown(
                f"""
                <div style="background:#FFFFFF; border:1px solid #E2E8F0; border-radius:10px; padding:18px; height:100%;">
                    <div style="font-size:12px; font-weight:700; color:#64748B; text-transform:uppercase; letter-spacing:0.5px;">
                        FINANCIAL SCAM VECTOR
                    </div>
                    <div style="font-family:'Space Grotesk',sans-serif; font-size:16px; font-weight:700; color:#0F172A; margin:6px 0;">
                        {scam_type}
                    </div>
                    <div style="font-size:12.5px; color:#475569;">
                        {"High probability of fraud attempt or unauthorized financial credential harvesting." if risk in ["High", "Critical"] else "Evaluated against known banking and payment fraud patterns."}
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        with g3:
            st.markdown(
                f"""
                <div style="background:#FFFFFF; border:1px solid #E2E8F0; border-radius:10px; padding:18px; height:100%;">
                    <div style="font-size:12px; font-weight:700; color:#64748B; text-transform:uppercase; letter-spacing:0.5px;">
                        PHYSICAL & COERCION THREAT
                    </div>
                    <div style="font-family:'Space Grotesk',sans-serif; font-size:16px; font-weight:700; color:#0F172A; margin:6px 0;">
                        {threat_type}
                    </div>
                    <div style="font-size:12.5px; color:#475569;">
                        {"Physical intimidation, blackmail, or stalking signals detected." if "threat" in scam_type.lower() or "threat" in threat_type.lower() else "No physical violence or direct personal extortion detected."}
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        # Indicators Section
        st.markdown(f'<div style="font-weight:700; font-size:14.5px; color:#0F172A; margin:22px 0 10px 0;">🚨 {t(language, "why_flagged")}</div>', unsafe_allow_html=True)
        if indicators:
            chips_html = "".join([f'<span class="saas-chip red">• {html.escape(p)}</span>' for p in indicators])
            st.markdown(f'<div>{chips_html}</div>', unsafe_allow_html=True)
        else:
            st.markdown(f'<span class="saas-chip" style="background:#F0FDF4; color:#15803D; border-color:#86EFAC;">✓ {t(language, "no_patterns")}</span>', unsafe_allow_html=True)

        # Safety Recommendations
        st.markdown(f'<div style="font-weight:700; font-size:14.5px; color:#0F172A; margin:22px 0 10px 0;">🛡️ {t(language, "what_to_do")}</div>', unsafe_allow_html=True)
        st.markdown(
            f"""
            <div style="background:#F0F9FF; border:1px solid #BAE6FD; border-radius:10px; padding:16px; color:#0369A1; font-size:14px; line-height:1.5;">
                <b>Actionable Recommendation:</b><br>{recommendation}
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown("<div style='height: 16px;'></div>", unsafe_allow_html=True)

        # Interactive Chatbot Callout Button
        btn_c1, btn_c2 = st.columns([1.5, 1])
        with btn_c1:
            if st.button("💬 Ask ScamShield AI Assistant About This Result", type="primary", use_container_width=True):
                # Preload context and switch to AI Assistant
                st.session_state.current_page = "AI Assistant"
                # If chat doesn't have an opening greeting with this context, add one
                if not st.session_state.chat_messages:
                    st.session_state.chat_messages.append({
                        "role": "assistant",
                        "content": f"I have loaded your scanned message (*\"{res.get('original_text', '')[:60]}...\"*) which was classified as **{risk} Risk ({display_score}%)**. How can I help investigate this further?",
                        "source": "ScamShield Engine",
                        "timestamp": datetime.datetime.now().strftime("%H:%M"),
                    })
                st.rerun()

        with btn_c2:
            with st.expander(t(language, "json_expander")):
                st.json(res)

        st.markdown("</div>", unsafe_allow_html=True)

# ===========================================================================
# PAGE 3: AI ASSISTANT (CHATBOT)
# ===========================================================================
elif st.session_state.current_page == "AI Assistant":
    st.markdown(
        """
        <div style="margin-bottom: 20px;">
            <div style="display: flex; align-items: center; justify-content: space-between;">
                <div>
                    <h2 style="font-family:'Space Grotesk',sans-serif; font-size:24px; font-weight:700; margin:0 0 6px 0; color:#0F172A;">
                        ScamShield AI Assistant
                    </h2>
                    <p style="font-size:14px; color:#64748B; margin:0;">
                        Your personal scam investigation and digital safety assistant.
                    </p>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Active Context Banner
    active_ctx = st.session_state.current_analysis
    if active_ctx:
        msg_snip = html.escape(active_ctx.get("original_text", "")[:120])
        ctx_risk = active_ctx.get("risk_level", "Medium")
        ctx_score = active_ctx.get("risk_score", 50)
        c_badge_class = f"badge-{ctx_risk.lower()}" if ctx_risk.lower() in ["critical", "high", "medium", "low"] else "badge-medium"

        st.markdown(
            f"""
            <div style="background:#F8FAFC; border:1px solid #E2E8F0; border-radius:10px; padding:12px 18px; margin-bottom:18px; display:flex; justify-content:space-between; align-items:center;">
                <div>
                    <div style="font-size:11px; font-weight:700; color:#0284C7; text-transform:uppercase; letter-spacing:0.5px;">ACTIVE INVESTIGATION CONTEXT</div>
                    <div style="font-size:13.5px; color:#1E293B; margin-top:2px;">
                        <span class="{c_badge_class}">{ctx_risk} ({ctx_score}%)</span>
                        <span style="margin-left:8px; font-style:italic;">"{msg_snip}..."</span>
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # Suggested Prompts
    st.markdown('<div style="font-size:12.5px; font-weight:600; color:#64748B; margin-bottom:8px;">Suggested Investigation Questions:</div>', unsafe_allow_html=True)
    s_cols = st.columns(3)
    suggested_queries = [
        "Why was this message classified as suspicious?",
        "What should I do if I shared my OTP?",
        "Is this message a financial scam or a personal threat?",
    ]
    for col, q_text in zip(s_cols, suggested_queries):
        if col.button(q_text, use_container_width=True):
            # Append to chat and generate response
            now_str = datetime.datetime.now().strftime("%H:%M")
            st.session_state.chat_messages.append({
                "role": "user",
                "content": q_text,
                "timestamp": now_str,
            })
            with st.spinner("ScamShield Assistant is analyzing..."):
                reply = get_chat_response(
                    st.session_state.chat_messages,
                    analysis_context=st.session_state.current_analysis,
                    language=st.session_state.language,
                )
            st.session_state.chat_messages.append(reply)
            st.rerun()

    st.markdown("---")

    # Chat Messages History
    if not st.session_state.chat_messages:
        # Default welcome message
        st.markdown(
            """
            <div style="text-align: center; padding: 40px 20px; background: #FFFFFF; border: 1px solid #E2E8F0; border-radius: 12px; margin-bottom: 20px;">
                <div style="font-size: 36px; margin-bottom: 12px;">🛡️</div>
                <div style="font-family:'Space Grotesk',sans-serif; font-size: 18px; font-weight: 700; color: #0F172A;">How can I assist your investigation today?</div>
                <div style="font-size: 13.5px; color: #64748B; max-width: 520px; margin: 8px auto 0 auto; line-height: 1.5;">
                    I can explain why a message was flagged, identify specific warning phrases, advise you on immediate emergency steps if credentials were leaked, or help verify legitimate sender identities.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    else:
        for msg in st.session_state.chat_messages:
            role = msg.get("role", "assistant")
            content = msg.get("content", "")
            ts = msg.get("timestamp", "")
            source = msg.get("source", "Azure AI")

            if role == "user":
                st.markdown(
                    f"""
                    <div class="chat-bubble-user">
                        <div>{html.escape(content)}</div>
                        <div style="font-size:10.5px; color:#E0F2FE; text-align:right; margin-top:4px;">{ts}</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
            else:
                source_badge = f'<span style="background:#F1F5F9; color:#475569; padding:2px 8px; border-radius:999px; font-size:10.5px; border:1px solid #CBD5E1;">{source}</span>'
                st.markdown(
                    f"""
                    <div class="chat-bubble-assistant">
                        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
                            <span style="font-weight:700; font-size:12.5px; color:#0284C7;">🛡️ ScamShield AI Assistant</span>
                            {source_badge}
                        </div>
                        <div style="margin-top:4px; font-size:14px;">{content}</div>
                        <div class="chat-meta">{ts}</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

    # Chat Input
    user_prompt = st.chat_input("Ask a question about this message or cybersecurity threat...")
    if user_prompt:
        now_str = datetime.datetime.now().strftime("%H:%M")
        st.session_state.chat_messages.append({
            "role": "user",
            "content": user_prompt,
            "timestamp": now_str,
        })
        with st.spinner("ScamShield Assistant is evaluating..."):
            reply = get_chat_response(
                st.session_state.chat_messages,
                analysis_context=st.session_state.current_analysis,
                language=st.session_state.language,
            )
        st.session_state.chat_messages.append(reply)
        st.rerun()

    # Clear Chat option
    if st.session_state.chat_messages:
        if st.button("Clear Conversation"):
            st.session_state.chat_messages = []
            st.rerun()

# ===========================================================================
# PAGE 4: ANALYSIS HISTORY
# ===========================================================================
elif st.session_state.current_page == "Analysis History":
    st.markdown(
        """
        <div style="margin-bottom: 20px;">
            <h2 style="font-family:'Space Grotesk',sans-serif; font-size:24px; font-weight:700; margin:0 0 6px 0; color:#0F172A;">
                Analysis History & Threat Log
            </h2>
            <p style="font-size:14px; color:#64748B; margin:0;">
                Review past message analyses, classification verdicts, and forensic evidence from this session.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if not st.session_state.history:
        st.markdown(
            """
            <div style="text-align: center; padding: 48px 20px; background: #FFFFFF; border: 1px solid #E2E8F0; border-radius: 12px;">
                <div style="font-size: 38px; margin-bottom: 12px;">📂</div>
                <div style="font-family:'Space Grotesk',sans-serif; font-size: 17px; font-weight: 700; color: #0F172A;">No Messages Analyzed Yet</div>
                <div style="font-size: 13.5px; color: #64748B; max-width: 440px; margin: 6px auto 18px auto;">
                    Messages you submit for scanning will be automatically logged here with full forensic details.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        if st.button("Start First Analysis", type="primary"):
            st.session_state.current_page = "Analyse Message"
            st.rerun()
    else:
        for idx, entry in enumerate(reversed(st.session_state.history)):
            r = entry.get("result", {})
            risk_lvl = r.get("risk_level", "Medium")
            score = r.get("risk_score", 50)
            scam_type = r.get("scam_type", "Suspicious Message")
            msg_body = entry.get("message", "")
            ts = entry.get("timestamp", "")
            mode = r.get("analysis_mode", "Azure AI Analysis")
            badge_class = f"badge-{risk_lvl.lower()}" if risk_lvl.lower() in ["critical", "high", "medium", "low"] else "badge-medium"

            with st.container():
                st.markdown(
                    f"""
                    <div class="saas-card" style="margin-bottom: 14px;">
                        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px;">
                            <div>
                                <span class="{badge_class}">{risk_lvl} ({score}%)</span>
                                <span style="font-size:14px; font-weight:700; color:#0F172A; margin-left:10px;">{scam_type}</span>
                            </div>
                            <div style="font-size:12px; color:#64748B;">{ts} &middot; <span style="color:#0284C7;">{mode}</span></div>
                        </div>
                        <div style="background:#F8FAFC; border:1px solid #E2E8F0; border-radius:8px; padding:12px; font-size:13px; color:#334155; margin-bottom:12px;">
                            "{html.escape(msg_body)}"
                        </div>
                        <div style="font-size:12.5px; color:#475569;">
                            <b>Recommendation:</b> {r.get('recommendation', 'Exercise caution.')}
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

        if st.button("Clear History Log"):
            st.session_state.history = []
            st.rerun()

# ===========================================================================
# PAGE 5: CONTACT & COLLABORATION
# ===========================================================================
elif st.session_state.current_page == "Contact & Collaboration":
    st.markdown(
        """
        <div style="margin-bottom: 20px;">
            <h2 style="font-family:'Space Grotesk',sans-serif; font-size:24px; font-weight:700; margin:0 0 6px 0; color:#0F172A;">
                Contact & Strategic Collaboration
            </h2>
            <p style="font-size:14px; color:#64748B; margin:0;">
                Reach Team ScamShield, review proposed strategic partnerships, or submit suspicious samples for forensic analysis.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    tab_contact, tab_partner, tab_report = st.tabs([
        "Contact Team ScamShield",
        "PropChk Write Collaboration",
        "Report a Suspicious Message",
    ])

    # -----------------------------------------------------------------------
    # Section A: Contact Team ScamShield
    # -----------------------------------------------------------------------
    with tab_contact:
        st.subheader("Contact Team ScamShield")
        st.write("Send an inquiry directly to Team ScamShield.")

        recipient_addr = get_contact_recipient()
        st.info(f"Inquiries are delivered to: **{recipient_addr}**")

        with st.form("scamshield_contact_form"):
            c_name = st.text_input("Name / Organization *", placeholder="e.g. Dr. Alex Morgan / Security Labs")
            c_email = st.text_input("Contact Email Address *", placeholder="alex.morgan@company.com")
            c_subject = st.text_input("Subject *", placeholder="Inquiry regarding ScamShield 2.0 evaluation or integration")
            c_msg = st.text_area("Your Message *", placeholder="Please write your detailed inquiry here...", height=140)

            c_submitted = st.form_submit_button("Send Inquiry", type="primary", use_container_width=True)
            if c_submitted:
                success, feedback_text = send_contact_inquiry(c_name, c_email, c_subject, c_msg)
                if success:
                    st.success(feedback_text)
                    st.session_state.feedback_submissions.append({
                        "type": "Contact Inquiry",
                        "name": c_name,
                        "email": c_email,
                        "subject": c_subject,
                        "message": c_msg,
                        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
                        "delivered_email": True,
                    })
                else:
                    st.error(feedback_text)
                    st.session_state.feedback_submissions.append({
                        "type": "Contact Inquiry (Failed Delivery)",
                        "name": c_name,
                        "email": c_email,
                        "subject": c_subject,
                        "message": c_msg,
                        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
                        "delivered_email": False,
                    })

    # -----------------------------------------------------------------------
    # Section B: PropChk Write Collaboration
    # -----------------------------------------------------------------------
    with tab_partner:
        st.subheader("PropChk Write Strategic Collaboration")
        st.markdown("**Partnership Status:** `Proposed Collaboration (Formal Confirmation Pending)`")

        st.write(
            "**PropChk Write** is presented as a proposed strategic collaboration partner for the ScamShield platform. "
            "This initiative explores integrating ScamShield's real-time threat intelligence and NLP pipeline with PropChk Write "
            "to enhance communication integrity, mitigate escrow fraud, and detect deceptive transactional notices."
        )

        col_left, col_right = st.columns(2)
        with col_left:
            with st.container(border=True):
                st.markdown("#### Collaboration Purpose & Objectives")
                st.markdown(
                    "- **Transaction Integrity:** Screen contractual correspondence and real-estate transaction communications against lookalike domain spoofing.\n"
                    "- **Escrow & Wire Defense:** Detect high-pressure payment modification notices and artificial urgency patterns before fund disbursement.\n"
                    "- **Verification Reporting:** Provide automated safety audits for property buyers, sellers, and legal stakeholders."
                )

        with col_right:
            with st.container(border=True):
                st.markdown("#### What ScamShield Offers")
                st.markdown(
                    "- **Multi-Stage AI Threat Parsing:** Deconstructed entity and pattern verification powered by Azure AI Foundry.\n"
                    "- **Indic Multilingual NLP:** Real-time threat and scam detection across English, Telugu, Tamil, and Hindi.\n"
                    "- **Autonomous Local Fallback:** Zero-latency offline heuristic engine ensuring continuous, presentation-grade reliability."
                )

        with st.container(border=True):
            st.markdown("#### Partner Information (Editable Placeholders)")
            st.caption("The details below represent placeholders awaiting formal partnership confirmation. No unverified contact details are displayed.")

            p1, p2 = st.columns(2)
            with p1:
                st.text_input("Partner Organization", value="PropChk Write", disabled=True)
                st.text_input("Official Website", value="[Partner Website: To be provided upon confirmation]", disabled=True)
            with p2:
                st.text_input("Partner Contact Email", value="[Partner Email: To be provided upon confirmation]", disabled=True)
                st.text_input("Designated Liaison", value="[Partner Liaison: To be provided upon confirmation]", disabled=True)

        st.info("ℹ️ Formal partnership confirmation, operational scope, and official contact channels will be updated upon final project confirmation.")

    # -----------------------------------------------------------------------
    # Section C: Report a Suspicious Message
    # -----------------------------------------------------------------------
    with tab_report:
        st.subheader("Report a Suspicious Message")
        st.write("Share suspicious messages, scam alerts, or phishing samples to support forensic model analysis.")

        st.warning(
            "⚠️ **Security Notice:** Do **NOT** submit personal passwords, active OTP codes, credit/debit card numbers, PINs, or unnecessary sensitive personal information. Only submit the text or pattern of the suspicious message."
        )

        with st.form("report_suspicious_form"):
            r_sender = st.text_input("Sender Phone Number / SMS Header / Email Address", placeholder="e.g. +91 9876543210 or AD-HDFCBK")
            r_category = st.selectbox(
                "Suspected Threat Category",
                [
                    "Banking / OTP Phishing",
                    "Physical Violence or Threat",
                    "Fake Lottery / Prize Claim",
                    "Urgent Account Suspension Notice",
                    "Digital Arrest / Police Impersonation",
                    "Job Offer / Advance Payment Fraud",
                    "Other Suspicious Communication",
                ],
            )
            r_message = st.text_area("Suspicious Message Content *", placeholder="Paste the exact suspicious message content here...", height=120)
            r_notes = st.text_input("Additional Context / Notes (Optional)", placeholder="e.g. Received via SMS claiming electricity disconnection")

            r_submitted = st.form_submit_button("Submit Sample for Review", type="primary", use_container_width=True)
            if r_submitted:
                if not r_message.strip():
                    st.warning("Please provide the suspicious message content before submitting.")
                else:
                    success, rep_feedback = send_threat_report_email(r_sender, r_message, r_category, r_notes)
                    if success:
                        st.success(rep_feedback)
                        st.session_state.feedback_submissions.append({
                            "type": "Suspicious Message Report",
                            "sender": r_sender,
                            "category": r_category,
                            "message": r_message,
                            "notes": r_notes,
                            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
                        })
                    else:
                        st.error(rep_feedback)


# ===========================================================================
# PAGE 6: ABOUT SCAMSHIELD
# ===========================================================================
elif st.session_state.current_page == "About ScamShield":
    st.markdown(
        """
        <div style="margin-bottom: 24px;">
            <h2 style="font-family:'Space Grotesk',sans-serif; font-size:24px; font-weight:700; margin:0 0 6px 0; color:#0F172A;">
                About ScamShield Platform Architecture
            </h2>
            <p style="font-size:14px; color:#64748B; margin:0;">
                Engineered for robust digital defense, responsible AI transparency, and zero-compromise availability.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown('<div class="saas-card">', unsafe_allow_html=True)
    st.markdown('<div class="saas-card-header">5-Stage Analysis Pipeline</div>', unsafe_allow_html=True)
    st.markdown(
        """
        <div style="font-size: 13.5px; color: #475569; line-height: 1.6;">
            ScamShield utilizes a modular, multi-stage prompt engineering architecture that decouples entity extraction from risk evaluation:
            <ol style="margin-top: 8px; padding-left: 20px;">
                <li><b>Entity Extraction:</b> Parses sender identifiers, telephone numbers, URLs, requested amounts, and referenced institutions.</li>
                <li><b>Pattern Recognition:</b> Scans for artificial urgency, financial demands, credential requests (OTP/PIN), and impersonation cues.</li>
                <li><b>Risk Classification:</b> Synthesizes evidence to assign an objective risk tier (Low, Medium, High, Critical) with a 0-100 severity index.</li>
                <li><b>Plain-Language Evidence:</b> Translates technical indicators into digestible, human-understandable safety explanations.</li>
                <li><b>Recommended Action:</b> Delivers immediate defensive containment steps and specific warnings on what to avoid.</li>
            </ol>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.markdown("</div>", unsafe_allow_html=True)

    st.markdown('<div class="saas-card">', unsafe_allow_html=True)
    st.markdown('<div class="saas-card-header">Intelligent Local Fallback Engine (Mode B)</div>', unsafe_allow_html=True)
    st.markdown(
        """
        <div style="font-size: 13.5px; color: #475569; line-height: 1.6;">
            To ensure presentation-grade reliability and uninterrupted protection during network drops, cloud rate limits, or content-filter triggers,
            ScamShield incorporates a standalone local detection engine (<code>local_detector.py</code>):
            <ul>
                <li><b>Multilingual Threat Detection:</b> Advanced pattern matching covering direct violence, extortion, and intimidation in English, Telugu, Tamil, and Hindi.</li>
                <li><b>Context Awareness:</b> Negation handling (<i>"I will not hurt you"</i>) and fictional context recognition (<i>"The movie says..."</i>) prevent false positives.</li>
                <li><b>Transparent Provenance:</b> Clear UI badges indicate whether an evaluation originated from <b>Azure AI Analysis</b> or <b>Local Fallback Analysis</b>.</li>
            </ul>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.markdown("</div>", unsafe_allow_html=True)

    st.markdown('<div class="saas-card">', unsafe_allow_html=True)
    st.markdown('<div class="saas-card-header">Responsible AI & Ethical Compliance</div>', unsafe_allow_html=True)
    st.markdown(
        """
        <div style="font-size: 13.5px; color: #475569; line-height: 1.6;">
            • <b>No Malicious Click Policy:</b> ScamShield never instructs users to visit suspect links or dial unknown phone numbers.<br>
            • <b>No Secret Exposure:</b> Cloud credentials and access tokens are strictly managed via Azure CLI / Managed Identities with zero frontend exposure.<br>
            • <b>Transparent AI Limitations:</b> System recommendations serve as security aids; users are always encouraged to verify high-stakes financial requests through official mobile applications.
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.markdown("</div>", unsafe_allow_html=True)

    st.markdown('<div class="saas-card">', unsafe_allow_html=True)
    st.markdown('<div class="saas-card-header">Project Engineering Team</div>', unsafe_allow_html=True)
    st.markdown(
        """
        <div style="font-size: 13.5px; color: #475569; line-height: 1.6;">
            <b>Engineering & Research Lead:</b> Team ScamShield<br>
            <b>Mission:</b> Advanced AI-driven scam prevention, real-time multilingual cyber threat mitigation, and accessible digital defense.<br>
            <b>Inquiry Desk:</b> sandiharikrishna4@gmail.com
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.markdown("</div>", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Global Footer
# ---------------------------------------------------------------------------
st.markdown(
    f"""
    <div style="text-align: center; color: #64748B; font-size: 12px; margin-top: 40px; padding: 20px 0; border-top: 1px solid #E2E8F0;">
        {t(language, 'footer')}<br>
        ScamShield 2.0 &middot; Developed by Team ScamShield &middot; Enterprise Cybersecurity Platform &middot; AI analysis is an advisory aid; independently verify critical requests.
    </div>
    """,
    unsafe_allow_html=True,
)
