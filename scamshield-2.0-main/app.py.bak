"""ScamShield 2.0 - Streamlit web UI (premium dark cybersecurity theme)
Run with:  streamlit run app.py
Requires scamshield_chain.py, fast_analyzer.py, file_reader.py, translator.py
in the same folder, and az login already done.
Backend (quick_analyze, extract_text_from_file, translate_analysis) is unchanged.
"""

import streamlit as st
from fast_analyzer import quick_analyze
from file_reader import extract_text_from_file
from translator import LANGUAGES, t, translate_analysis

st.set_page_config(page_title="ScamShield 2.0", page_icon="\U0001F6E1", layout="centered")

# ---------------------------------------------------------------------------
# Styling - dark navy / glass / cyan cybersecurity theme
# ---------------------------------------------------------------------------
st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;700&family=Inter:wght@400;500;600&family=Noto+Sans+Devanagari&family=Noto+Sans+Tamil&family=Noto+Sans+Telugu&family=Noto+Sans+Kannada&family=Noto+Sans+Malayalam&family=Noto+Sans+Bengali&display=swap');

    :root {
        --bg: #07101F;
        --bg2: #0A1222;
        --glass: rgba(255,255,255,0.04);
        --glass-border: rgba(255,255,255,0.09);
        --cyan: #38BDF8;
        --cyan2: #22D3EE;
        --text: #F8FAFC;
        --muted: #94A3B8;
        --safe: #22C55E;
        --warn: #F59E0B;
        --danger: #EF4444;
    }

    html, body, [class*="css"] { font-family: 'Inter', 'Noto Sans Devanagari', 'Noto Sans Tamil', 'Noto Sans Telugu', 'Noto Sans Kannada', 'Noto Sans Malayalam', 'Noto Sans Bengali', sans-serif; }
    .stApp {
        background: radial-gradient(ellipse 900px 500px at 50% -10%, rgba(56,189,248,0.12), transparent),
                    linear-gradient(180deg, var(--bg) 0%, var(--bg2) 100%);
        color: var(--text);
    }
    [data-testid="stHeader"] { background: transparent; }

    .ss-navbar {
        display: flex; align-items: center; justify-content: space-between;
        padding: 10px 18px; border: 1px solid var(--glass-border); border-radius: 14px;
        background: var(--glass); backdrop-filter: blur(10px); margin-bottom: 26px;
    }
    .ss-brand { display: flex; align-items: center; gap: 10px; }
    .ss-brand .ss-icon { font-size: 24px; }
    .ss-brand .ss-name { font-family: 'Space Grotesk', sans-serif; font-weight: 700; font-size: 18px; color: var(--text); letter-spacing: 0.3px; }
    .ss-badge {
        font-size: 10.5px; font-weight: 600; letter-spacing: 0.6px; color: var(--cyan2);
        background: rgba(34,211,238,0.12); border: 1px solid rgba(34,211,238,0.3);
        padding: 3px 9px; border-radius: 999px; margin-left: 4px;
    }
    .ss-status { font-size: 12px; color: var(--muted); display: flex; align-items: center; gap: 6px; }
    .ss-dot { width: 7px; height: 7px; border-radius: 50%; background: var(--safe); box-shadow: 0 0 8px var(--safe); }

    .ss-hero { text-align: center; margin: 6px 0 28px 0; }
    .ss-hero h1 {
        font-family: 'Space Grotesk', sans-serif; font-weight: 700; font-size: 30px;
        color: var(--text); margin: 0 0 8px 0; letter-spacing: -0.3px;
    }
    .ss-hero p { color: var(--muted); font-size: 14.5px; max-width: 520px; margin: 0 auto; }

    .ss-card {
        border: 1px solid var(--glass-border); border-radius: 16px; padding: 22px 22px;
        background: var(--glass); backdrop-filter: blur(10px); margin-bottom: 18px;
    }
    .ss-card-title { font-weight: 600; font-size: 14px; color: var(--text); margin-bottom: 4px; }
    .ss-card-sub { font-size: 12.5px; color: var(--muted); margin-bottom: 14px; }

    .ss-chip-label { font-size: 12.5px; color: var(--muted); margin: 2px 0 8px 2px; }

    div.stButton > button {
        border-radius: 10px; font-weight: 500; border: 1px solid var(--glass-border);
        background: rgba(255,255,255,0.03); color: var(--text);
    }
    div.stButton > button:hover { border-color: rgba(56,189,248,0.5); color: var(--cyan2); }
    div.stButton > button[kind="primary"] {
        background: linear-gradient(90deg, #2563EB, #22D3EE); border: none; color: #04101E;
        font-weight: 700; box-shadow: 0 0 22px rgba(34,211,238,0.25);
    }
    div.stButton > button[kind="primary"]:hover { box-shadow: 0 0 32px rgba(34,211,238,0.4); }

    [data-testid="stTextArea"] textarea {
        background: rgba(255,255,255,0.03) !important; border: 1px solid var(--glass-border) !important;
        border-radius: 12px !important; color: var(--text) !important;
    }
    [data-testid="stTextArea"] textarea:focus {
        border-color: var(--cyan) !important; box-shadow: 0 0 0 3px rgba(56,189,248,0.15) !important;
    }
    .ss-charcount { text-align: right; font-size: 11.5px; color: var(--muted); margin-top: -4px; }

    [data-testid="stFileUploaderDropzone"] {
        background: rgba(255,255,255,0.02) !important; border: 1.5px dashed var(--glass-border) !important;
        border-radius: 14px !important;
    }

    .ss-result-panel {
        border: 1px solid var(--glass-border); border-radius: 18px; padding: 26px 24px;
        background: var(--glass); backdrop-filter: blur(10px); margin-top: 20px; text-align: center;
    }
    .ss-ring {
        width: 128px; height: 128px; border-radius: 50%; margin: 0 auto 14px auto;
        display: flex; align-items: center; justify-content: center;
        background: conic-gradient(var(--ring-color) calc(var(--score) * 1%), rgba(255,255,255,0.07) 0);
    }
    .ss-ring-inner {
        width: 100px; height: 100px; border-radius: 50%; background: var(--bg2);
        display: flex; flex-direction: column; align-items: center; justify-content: center;
    }
    .ss-ring-score { font-family: 'Space Grotesk', sans-serif; font-weight: 700; font-size: 24px; color: var(--text); }
    .ss-ring-label { font-size: 10px; color: var(--muted); letter-spacing: 0.5px; }
    .ss-verdict { font-family: 'Space Grotesk', sans-serif; font-weight: 700; font-size: 20px; margin: 4px 0 2px 0; }
    .ss-type-badge {
        display: inline-block; font-size: 12px; color: var(--muted); margin-top: 4px;
        border: 1px solid var(--glass-border); border-radius: 999px; padding: 3px 12px;
    }

    .ss-section-title {
        font-weight: 600; color: var(--text); margin: 24px 0 10px 0; font-size: 14.5px;
        display: flex; align-items: center; gap: 8px; text-align: left;
    }
    .ss-chip-grid { display: flex; flex-wrap: wrap; gap: 8px; justify-content: flex-start; text-align: left; }
    .ss-indicator-chip {
        font-size: 13px; color: var(--text); background: rgba(239,68,68,0.08);
        border: 1px solid rgba(239,68,68,0.25); border-radius: 10px; padding: 7px 12px;
    }
    .ss-indicator-chip.safe { background: rgba(34,197,94,0.08); border-color: rgba(34,197,94,0.25); }

    .ss-action-card {
        text-align: left; border: 1px solid rgba(56,189,248,0.25); background: rgba(56,189,248,0.06);
        border-radius: 12px; padding: 14px 16px; color: var(--text); font-size: 14px; margin-top: 4px;
    }

    .ss-steps { display: flex; flex-direction: column; gap: 10px; margin-top: 10px; text-align: left; }
    .ss-step { display: flex; gap: 12px; align-items: flex-start; }
    .ss-step-num {
        min-width: 26px; height: 26px; border-radius: 50%; background: rgba(56,189,248,0.12);
        border: 1px solid rgba(56,189,248,0.3); color: var(--cyan2); font-size: 12px; font-weight: 700;
        display: flex; align-items: center; justify-content: center;
    }
    .ss-step-text b { color: var(--text); font-size: 13.5px; }
    .ss-step-text span { color: var(--muted); font-size: 12.5px; display: block; }

    .ss-footer { text-align: center; color: var(--muted); font-size: 12px; margin-top: 36px; padding-top: 16px; border-top: 1px solid var(--glass-border); }

    /* Fix low-contrast native Streamlit widgets on the dark theme */
    [data-testid="stWidgetLabel"] p, [data-testid="stWidgetLabel"] label { color: var(--text) !important; }

    div[data-baseweb="select"] > div, .stSelectbox div[data-baseweb="select"] > div {
        background: rgba(255,255,255,0.05) !important; border: 1px solid var(--glass-border) !important;
        color: var(--text) !important; border-radius: 10px !important;
    }
    div[data-baseweb="select"] svg { fill: var(--muted) !important; }
    ul[role="listbox"] { background: var(--bg2) !important; }
    ul[role="listbox"] li { color: var(--text) !important; background: var(--bg2) !important; }
    ul[role="listbox"] li:hover { background: rgba(56,189,248,0.18) !important; }

    div[data-testid="stTextArea"] textarea, .stTextArea textarea, textarea {
        background: rgba(255,255,255,0.05) !important; color: var(--text) !important;
        border: 1px solid var(--glass-border) !important; border-radius: 12px !important;
    }
    textarea::placeholder { color: var(--muted) !important; opacity: 1 !important; }

    [data-testid="stFileUploader"] section, [data-testid="stFileUploaderDropzone"] {
        background: rgba(255,255,255,0.03) !important; border: 1.5px dashed var(--glass-border) !important;
    }
    [data-testid="stFileUploader"] span, [data-testid="stFileUploader"] small,
    [data-testid="stFileUploader"] p, [data-testid="stFileUploader"] div { color: var(--muted) !important; }
    [data-testid="stFileUploaderDropzone"] button {
        background: rgba(255,255,255,0.06) !important; color: var(--text) !important;
        border: 1px solid var(--glass-border) !important; border-radius: 8px !important;
    }

    footer, #MainMenu { visibility: hidden; }
    </style>
    """,
    unsafe_allow_html=True,
)

RISK_META = {
    "High":   {"ring": "#EF4444", "score_fallback": 85},
    "Medium": {"ring": "#F59E0B", "score_fallback": 50},
    "Low":    {"ring": "#22C55E", "score_fallback": 10},
}

EXAMPLE_KEYS = ["example_bank", "example_delivery", "example_lottery"]
EXAMPLE_TEXT = {
    "example_bank": "Dear customer, your account will be suspended. Click http://kotak-verify.net/confirm or call 8899001122 immediately to avoid penalty.",
    "example_delivery": "Your order #4521 has been shipped and will arrive tomorrow by 6pm.",
    "example_lottery": "Congratulations! You have won Rs 25,00,000 in the KBC lucky draw. Share your bank details and OTP to claim your prize now.",
}

if "message_text" not in st.session_state:
    st.session_state.message_text = ""

# ---------------------------------------------------------------------------
# Navbar
# ---------------------------------------------------------------------------
language = st.selectbox("Language", list(LANGUAGES.keys()), format_func=lambda k: LANGUAGES[k], label_visibility="collapsed")

st.markdown(
    """
    <div class="ss-navbar">
        <div class="ss-brand">
            <div class="ss-icon">&#128737;&#65039;</div>
            <div class="ss-name">SCAMSHIELD</div>
            <div class="ss-badge">AI SECURITY</div>
        </div>
        <div class="ss-status"><div class="ss-dot"></div>ONLINE</div>
    </div>
    """,
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# Hero
# ---------------------------------------------------------------------------
st.markdown(
    f"""
    <div class="ss-hero">
        <h1>AI-Powered Threat Detection</h1>
        <p>{t(language, 'tagline')}</p>
    </div>
    """,
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# Scanner card
# ---------------------------------------------------------------------------
st.markdown('<div class="ss-card">', unsafe_allow_html=True)
st.markdown(f'<div class="ss-chip-label">{t(language, "try_example")}</div>', unsafe_allow_html=True)
cols = st.columns(len(EXAMPLE_KEYS))
for col, key in zip(cols, EXAMPLE_KEYS):
    if col.button(t(language, key), use_container_width=True):
        st.session_state.message_text = EXAMPLE_TEXT[key]
        st.rerun()

message = st.text_area(
    "Message to analyze",
    key="message_text",
    height=120,
    placeholder=t(language, "message_placeholder"),
    label_visibility="collapsed",
    max_chars=5000,
)
st.markdown(f'<div class="ss-charcount">{len(message)} / 5000</div>', unsafe_allow_html=True)

uploaded_file = st.file_uploader(
    t(language, "upload_label"),
    type=["png", "jpg", "jpeg", "webp", "pdf", "txt"],
)

analyze_clicked = st.button("\u26a1 " + t(language, "analyze_button"), type="primary", use_container_width=True)
st.markdown("</div>", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Result
# ---------------------------------------------------------------------------
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
            risk = result.get("risk_level", "Medium")
            meta = RISK_META.get(risk, RISK_META["Medium"])
            risk_label = t(language, f"risk_{risk.lower()}")
            score = result.get("risk_score")
            display_score = score if isinstance(score, (int, float)) else meta["score_fallback"]
            scam_type = result.get("scam_type")

            st.markdown(
                f"""
                <div class="ss-result-panel">
                    <div class="ss-ring" style="--score:{display_score}; --ring-color:{meta['ring']};">
                        <div class="ss-ring-inner">
                            <div class="ss-ring-score">{display_score}%</div>
                            <div class="ss-ring-label">RISK</div>
                        </div>
                    </div>
                    <div class="ss-verdict" style="color:{meta['ring']};">{risk_label}</div>
                    {f'<div class="ss-type-badge">{scam_type}</div>' if scam_type else ''}
                </div>
                """,
                unsafe_allow_html=True,
            )

            indicators = result.get("indicators", [])
            st.markdown(f'<div class="ss-section-title">\U0001F6A8 {t(language, "why_flagged")}</div>', unsafe_allow_html=True)
            if indicators:
                chips = "".join(f'<div class="ss-indicator-chip">{p}</div>' for p in indicators)
                st.markdown(f'<div class="ss-chip-grid">{chips}</div>', unsafe_allow_html=True)
            else:
                st.markdown(f'<div class="ss-indicator-chip safe">{t(language, "no_patterns")}</div>', unsafe_allow_html=True)

            st.markdown(f'<div class="ss-section-title">\U0001F6E1\uFE0F {t(language, "what_to_do")}</div>', unsafe_allow_html=True)
            st.markdown(f'<div class="ss-action-card">{result.get("recommendation", "")}</div>', unsafe_allow_html=True)

            with st.expander(t(language, "json_expander")):
                st.json(result)

# ---------------------------------------------------------------------------
# How it works
# ---------------------------------------------------------------------------
st.markdown('<div class="ss-card">', unsafe_allow_html=True)
st.markdown('<div class="ss-card-title">How ScamShield works</div>', unsafe_allow_html=True)
steps = [
    ("1", "Input", "Paste a suspicious message or upload a screenshot/file."),
    ("2", "Local pre-check", "Suspicious patterns (links, urgency, OTP requests) are scanned on-device first."),
    ("3", "AI analysis", "The message is analyzed by an AI model for scam signals."),
    ("4", "Risk classification", "A risk level and score are generated from the analysis."),
    ("5", "Protection", "You get a plain-language explanation and a recommended action."),
]
steps_html = "".join(
    f'<div class="ss-step"><div class="ss-step-num">{n}</div>'
    f'<div class="ss-step-text"><b>{title}</b><span>{desc}</span></div></div>'
    for n, title, desc in steps
)
st.markdown(f'<div class="ss-steps">{steps_html}</div>', unsafe_allow_html=True)
st.markdown("</div>", unsafe_allow_html=True)

st.markdown(
    f'<div class="ss-footer">{t(language, "footer")}<br>AI analysis is an aid, not a guarantee &middot; always verify important requests independently.</div>',
    unsafe_allow_html=True,
)
st.markdown("""<style>[data-testid="stTextArea"] textarea{color:var(--text) !important;-webkit-text-fill-color:var(--text) !important;background-color:rgba(255,255,255,0.05) !important;opacity:1 !important;caret-color:var(--text) !important;font-size:16px !important;}[data-testid="stTextArea"] textarea::placeholder{color:#64748b !important;-webkit-text-fill-color:#64748b !important;opacity:1 !important;}</style>""", unsafe_allow_html=True)
