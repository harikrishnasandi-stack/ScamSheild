"""
ScamShield 2.0 - AI Scam Investigation Chatbot Engine.
Provides natural, context-aware cybersecurity and fraud investigation support
reusing the existing Azure AI Foundry deployment and authentication.
Includes intelligent offline fallback so the assistant never crashes.
"""

import datetime
import os
import re
from typing import Optional, Dict, Any, List

from scamshield_chain import (
    openai_client,
    MODEL,
    execute_with_retry,
    DEFAULT_REQUEST_TIMEOUT,
    is_content_filter_error,
)

SYSTEM_BASE_PROMPT = """You are ScamShield AI Assistant — a specialized cybersecurity and scam investigation assistant developed for the ScamShield platform.
Your mission is to help users investigate suspicious messages, understand cyber threats, verify communications, and take immediate defensive actions.

Core Personality & Style:
- Professional, reassuring, clear, objective, and cybersecurity-focused.
- Direct and conversational like an experienced digital forensics analyst.
- Avoid unnecessary jargon; explain technical risks in plain terms.
- Never encourage clicking unknown links or contacting phone numbers in suspicious messages.
- Always distinguish between financial fraud (phishing, OTP theft, lottery, KYC) and personal threats (extortion, physical harm, stalking, harassment).
- If the user indicates they already shared an OTP, card details, or password, give immediate emergency containment steps (freeze account, call bank helpline 1930 in India / national cyber fraud helpline, change credentials).
- If physical danger is threatened, advise contacting emergency law enforcement immediately.

Context Awareness:
You may be provided with an "Active Investigation Context" containing a message the user scanned with ScamShield and its detection results.
When the user asks questions referring to "this message", "the result", "why was it flagged", or "is it real", refer specifically to the active message and its indicators.
Do NOT invent facts not present in the message, but provide intelligent threat analysis of the patterns shown.
"""


def _build_context_prompt(analysis_context: Optional[Dict[str, Any]]) -> str:
    """Format the active analysis into a readable context block for the model."""
    if not analysis_context:
        return "No specific message has been analyzed yet in this session. Assist the user with general cybersecurity, scam identification, and prevention advice."

    original_text = analysis_context.get("original_text", "") or analysis_context.get("message", "")
    risk_level = analysis_context.get("risk_level", "Unknown")
    risk_score = analysis_context.get("risk_score", "N/A")
    scam_type = analysis_context.get("scam_type", "General")
    threat_category = analysis_context.get("threat_category", "None detected")
    indicators = analysis_context.get("indicators", [])
    recommendation = analysis_context.get("recommendation", "")
    analysis_mode = analysis_context.get("analysis_mode", "Azure AI Analysis")

    indicators_str = ", ".join(indicators) if isinstance(indicators, list) and indicators else "None specifically extracted"

    return f"""=== ACTIVE INVESTIGATION CONTEXT ===
Original Message: "{original_text}"
Risk Classification: {risk_level} (Score: {risk_score}/100)
Scam Category: {scam_type}
Threat Category: {threat_category}
Detected Red Flags: {indicators_str}
Initial Recommendation: {recommendation}
Detection Engine: {analysis_mode}
====================================
Use this context to answer the user's specific questions about this message. Explain exactly why these indicators matter and what specific actions the user should take."""


def get_chat_response(
    messages: List[Dict[str, str]],
    analysis_context: Optional[Dict[str, Any]] = None,
    language: str = "English",
) -> Dict[str, Any]:
    """
    Generate an assistant response using Azure AI Foundry.
    If Azure AI is slow, offline, rate-limited, or blocked by content filters,
    seamlessly falls back to the intelligent local investigation responder.
    """
    system_instruction = SYSTEM_BASE_PROMPT + "\n\n" + _build_context_prompt(analysis_context)
    if language and language != "English":
        system_instruction += f"\n\nIMPORTANT: The user has selected the language: {language}. Please reply in {language} (or natural bilingual format if explaining technical terms)."

    api_messages = [{"role": "system", "content": system_instruction}]
    for m in messages[-10:]:  # Keep up to last 10 messages for conversational context
        role = m.get("role", "user")
        content = m.get("content", "")
        if role in ("user", "assistant") and content:
            api_messages.append({"role": role, "content": content})

    # Try Azure AI Foundry
    try:
        def _call_azure():
            input_items = [
                {"type": "message", "role": "system", "content": system_instruction}
            ]
            for m in messages[-8:]:  # Keep up to last 8 messages for conversational context
                role = m.get("role", "user")
                content = m.get("content", "")
                if role in ("user", "assistant") and content:
                    input_items.append({"type": "message", "role": role, "content": content})

            return openai_client.responses.create(
                model=MODEL,
                input=input_items,
                timeout=DEFAULT_REQUEST_TIMEOUT,
            )

        resp = execute_with_retry(_call_azure)
        content = (resp.output_text or "").strip()
        return {
            "role": "assistant",
            "content": content,
            "source": "Azure AI",
            "timestamp": datetime.datetime.now().strftime("%H:%M"),
        }
    except Exception as e:
        err_type = type(e).__name__
        print(f"⚠️ ScamShield Chatbot: Azure AI unavailable ({err_type}: {e}). Using Local Investigation Engine.", flush=True)
        user_query = messages[-1].get("content", "") if messages else ""
        fallback_content = local_chat_fallback(user_query, analysis_context, language)
        return {
            "role": "assistant",
            "content": fallback_content,
            "source": "Local Fallback",
            "timestamp": datetime.datetime.now().strftime("%H:%M"),
            "fallback_reason": err_type,
        }


def local_chat_fallback(
    query: str,
    analysis_context: Optional[Dict[str, Any]] = None,
    language: str = "English",
) -> str:
    """
    Intelligent rule-based and context-driven investigation responder.
    Ensures complete, helpful answers to user inquiries even when completely offline.
    """
    q = (query or "").lower()
    msg = ""
    risk_level = "Unknown"
    scam_type = "Suspicious Message"
    indicators = []
    recommendation = ""

    if analysis_context:
        msg = analysis_context.get("original_text", "") or analysis_context.get("message", "")
        risk_level = analysis_context.get("risk_level", "Medium")
        scam_type = analysis_context.get("scam_type", "General Scam / Threat")
        indicators = analysis_context.get("indicators", [])
        recommendation = analysis_context.get("recommendation", "Exercise caution and do not send funds or OTPs.")

    # 1. User shared OTP or PIN
    has_otp_query = ("otp" in q or "pin" in q or "password" in q or "cvv" in q or "card" in q) and any(
        w in q for w in ["share", "shared", "give", "gave", "enter", "entered", "sent", "send", "leak", "leaked", "lost", "told", "provide", "provided", "click", "clicked"]
    )
    if has_otp_query or any(k in q for k in ["shared otp", "gave otp", "clicked link", "money sent", "compromised", "account hacked"]):
        if language == "Telugu":
            return (
                "🚨 **వెంటనే తీసుకోవాల్సిన అత్యవసర చర్యలు:**\n\n"
                "1. **బ్యాంకును సంప్రదించండి:** మీ బ్యాంక్ కస్టమర్ కేర్‌కు వెంటనే కాల్ చేసి మీ ఖాతా లేదా డెబిట్/క్రెడిట్ కార్డును బ్లాక్ చేయించండి.\n"
                "2. **పాస్‌వర్డ్‌లు మార్చండి:** మీ నెట్ బ్యాంకింగ్ మరియు UPI పాస్‌వర్డ్‌లను వెంటనే మార్చండి.\n"
                "3. **ఫిర్యాదు నమోదు చేయండి:** జాతీయ సైబర్ క్రైమ్ హెల్ప్‌లైన్ **1930** కు కాల్ చేయండి లేదా [cybercrime.gov.in](https://cybercrime.gov.in) లో ఫిర్యాదు చేయండి."
            )
        elif language == "Tamil":
            return (
                "🚨 **உடனடி அவசர நடவடிக்கைகள்:**\n\n"
                "1. **வங்கி தொடர்பு:** உடனடியாக உங்கள் வங்கியைத் தொடர்புகொண்டு கணக்கு அல்லது அட்டையை முடக்கவும்.\n"
                "2. **கடவுச்சொல்லை மாற்றவும்:** இணைய வங்கி மற்றும் UPI கடவுச்சொற்களை மாற்றவும்.\n"
                "3. **புகார் அளிக்கவும்:** தேசிய சைபர் கிரைம் உதவி எண் **1930** ஐ அழைக்கவும் அல்லது [cybercrime.gov.in](https://cybercrime.gov.in) இல் புகார் செய்யவும்."
            )
        elif language == "Hindi":
            return (
                "🚨 **तत्काल सुरक्षा कदम (Immediate Action Required):**\n\n"
                "1. **बैंक से तुरंत संपर्क करें:** अपने बैंक के हेल्पलाइन नंबर पर कॉल करके तुरंत अपने खाते और कार्ड को ब्लॉक करवाएं।\n"
                "2. **पासवर्ड बदलें:** अपने नेट बैंकिंग और UPI पिन/पासवर्ड तुरंत बदलें।\n"
                "3. **साइबर क्राइम में शिकायत करें:** राष्ट्रीय हेल्पलाइन **1930** पर कॉल करें या [cybercrime.gov.in](https://cybercrime.gov.in) पर रिपोर्ट दर्ज करें।"
            )
        return (
            "🚨 **Immediate Emergency Actions to Take:**\n\n"
            "1. **Call Your Bank Immediately:** Contact your bank's official 24x7 customer helpline and request an immediate temporary freeze on your account, debit/credit cards, and UPI access.\n"
            "2. **Change Credentials:** If you shared a password or PIN, change your internet banking and email passwords immediately from a secure device.\n"
            "3. **File a Cyber Fraud Report:** In India, dial **1930** immediately to report financial cyber fraud, or report online at [cybercrime.gov.in](https://cybercrime.gov.in). In other regions, report directly to your national financial fraud center.\n"
            "4. **Preserve Evidence:** Take full screenshots of the message, transaction SMS, sender ID, and any web pages visited."
        )

    # 2. Threat vs Financial Scam
    if any(k in q for k in ["threat", "kill", "harm", "police", "extortion", "physical"]):
        return (
            f"⚠️ **Threat & Safety Assessment:**\n\n"
            f"Based on our investigation, this message exhibits characteristics of **{scam_type}**.\n\n"
            "• **Personal Threat / Extortion:** If the sender threatens physical harm, violence, or stalking, this constitutes criminal intimidation rather than typical financial fraud.\n"
            "• **Immediate Action:** Do not engage or antagonize the sender. Take complete screenshots including phone numbers or email headers.\n"
            "• **Law Enforcement:** If you believe you or your family are in immediate physical danger, report this to local police emergency services immediately."
        )

    # 3. Why classified / Which words
    if any(k in q for k in ["why", "classified", "words", "indicate", "flagged", "reason"]):
        ind_list = "\n".join([f"• **{ind}**" for ind in indicators]) if indicators else "• Suspicious phrasing or urgency patterns."
        return (
            f"🔍 **Why This Message Was Flagged:**\n\n"
            f"This message was classified as **{risk_level} Risk** under **{scam_type}**.\n\n"
            f"**Key Warning Signs Detected:**\n"
            f"{ind_list}\n\n"
            f"**Safety Context:**\n"
            f"Legitimate organizations, banks, and official agencies do not use artificial panic deadlines, threaten immediate punitive actions via SMS/WhatsApp, or demand credentials through direct links."
        )

    # 4. Sender verification
    if any(k in q for k in ["verify", "genuine", "real", "legitimate", "check sender"]):
        return (
            "🛡️ **How to Safely Verify the Sender:**\n\n"
            "1. **Never use contact details from the message:** Do not call phone numbers or tap links sent in the suspicious text.\n"
            "2. **Use Official Channels Only:** Look up the organization's official website independently via search or check the back of your bank card.\n"
            "3. **Check SMS Headers:** Official bank SMS in India typically comes from registered enterprise alphanumeric sender IDs (e.g., `AD-HDFCBK`, `VK-SBIINB`), never personal 10-digit mobile numbers.\n"
            "4. **When in Doubt, Do Nothing:** Legitimate transactions or package deliveries can always be verified inside your official mobile app."
        )

    # Default / General assistance
    if analysis_context and msg:
        return (
            f"💡 **ScamShield Analysis Summary:**\n\n"
            f"• **Active Message:** *\"{msg[:160]}{'...' if len(msg) > 160 else ''}\"*\n"
            f"• **Assessed Risk:** **{risk_level}** ({analysis_context.get('risk_score', 'N/A')}%)\n"
            f"• **Category:** {scam_type}\n\n"
            f"**Key Recommendations:**\n{recommendation}\n\n"
            "Feel free to ask me:\n"
            "- *'Why was this classified as suspicious?'*\n"
            "- *'What should I do if I already clicked the link or shared OTP?'*\n"
            "- *'How can I verify if this sender is real?'*"
        )

    return (
        "Hello! I am your **ScamShield AI Assistant**. You can paste any message in the 'Analyse Message' section, "
        "and I will help you investigate suspicious indicators, understand scam methods, and guide you on digital safety."
    )
