"""
ScamShield 2.0 - fast live analyzer (single LLM call).
Used by the app's "Analyze" button. The 5-stage chain and the 5-technique
comparison (compare_prompts.py) remain separate, for the Prompt Lab / evaluation only.

Flow: message -> local preprocessor (regex indicators + sanitized text) -> one compact LLM call -> JSON result.
"""

import json
import re

from scamshield_chain import (
    openai_client,
    MODEL,
    execute_with_retry,
    DEFAULT_REQUEST_TIMEOUT,
    is_content_filter_error,
)


MAX_INPUT_CHARS = 4000  # keep prompts small even for big uploaded files

THREAT_RE = re.compile(
    r"\b(kill|hurt|harm|beat|attack|die|dead|hospital)\b.{0,40}\b(you|unless|if you)\b"
    r"|\b(you|unless|if you).{0,40}\b(kill|hurt|harm|beat|attack)\b",
    re.IGNORECASE,
)
MONEY_RE = re.compile(r"\b(send|pay|transfer|deposit)\b.{0,20}(money|rs\.?|inr|\u20b9|\$|amount)", re.IGNORECASE)
URGENCY_RE = re.compile(r"\b(immediately|urgent|right now|within \d+ (hour|min)|today only|act now)\b", re.IGNORECASE)
OTP_RE = re.compile(r"\b(otp|pin|password|cvv|one[- ]time code)\b", re.IGNORECASE)
LINK_RE = re.compile(r"https?://\S+")
IMPERSONATION_RE = re.compile(r"\b(bank|police|court|income tax|government|customs|rbi|sbi|hdfc|icici)\b", re.IGNORECASE)
REWARD_RE = re.compile(r"\b(won|winner|prize|lucky draw|free gift|cashback|lottery)\b", re.IGNORECASE)


def preprocess(text: str) -> tuple[str, dict]:
    """Extract indicators locally and return a sanitized version of the text.
    Threatening phrases are tagged rather than deleted, so the security-relevant
    meaning (a threat was made) reaches the model without the explicit wording."""
    text = text[:MAX_INPUT_CHARS]

    indicators = {
        "threat": bool(THREAT_RE.search(text)),
        "money_demand": bool(MONEY_RE.search(text)),
        "urgency": bool(URGENCY_RE.search(text)),
        "otp_request": bool(OTP_RE.search(text)),
        "link_present": bool(LINK_RE.search(text)),
        "impersonation": bool(IMPERSONATION_RE.search(text)),
        "fake_reward": bool(REWARD_RE.search(text)),
    }

    sanitized = THREAT_RE.sub("[THREAT_LANGUAGE]", text)
    return sanitized, indicators


COMPACT_PROMPT = """Analyze this suspicious message for scam risk.

Return ONLY JSON:
{"risk_level": "Low|Medium|High", "risk_score": 0-100, "scam_type": "...", "indicators": ["..."], "recommendation": "..."}

Focus on: urgency/threats, money requests, OTP/PIN/password requests, suspicious links, impersonation, fake rewards, remote-access requests.
Note: bracketed tags like [THREAT_LANGUAGE] mean threatening language was detected and redacted; treat that as a real threat signal.
Never tell the user to click any link in the message. Never invent a specific official phone number or website."""


def quick_analyze(text: str) -> dict:
    """Analyze a message. Tries Azure AI first (Mode A).
    Automatically and seamlessly falls back to the intelligent local detection engine (Mode B)
    if Azure AI is unreachable, times out, returns an error, or content filter triggers."""
    try:
        result = _quick_analyze_core(text)
        result["analysis_mode"] = "Azure AI Analysis"
        return result
    except Exception as e:
        err_type = type(e).__name__
        print(f"⚠️ ScamShield: Azure AI unavailable ({err_type}: {e}). Activating Local Fallback Engine.", flush=True)
        try:
            from local_detector import local_analyze
            return local_analyze(text, fallback_reason=f"Azure AI ({err_type})")
        except Exception as local_err:
            print(f"❌ Local fallback failed: {local_err}", flush=True)
            _, local_flags = preprocess(text)
            local_hits = [k.replace("_", " ") for k, v in local_flags.items() if v]
            return {
                "risk_level": "High" if local_flags.get("threat") else "Medium",
                "risk_score": 90 if local_flags.get("threat") else 50,
                "scam_type": "Threat / Harassment" if local_flags.get("threat") else "Suspicious Message",
                "indicators": local_hits or ["Suspicious indicators detected locally"],
                "recommendation": "Exercise caution. Do not comply with demands or send money.",
                "local_flags": local_flags,
                "analysis_mode": "Local Fallback Analysis",
                "fallback_reason": f"System fallback ({err_type})",
            }


def _quick_analyze_core(text: str) -> dict:
    """One compact LLM call for live use. Local indicators are merged in
    even if the model's own indicators list misses one."""
    sanitized, local_flags = preprocess(text)
    local_hits = [k.replace("_", " ") for k, v in local_flags.items() if v]

    user_content = f"Message:\n{sanitized}\n\nLocally detected signals: {', '.join(local_hits) or 'none'}"
    print("🚀 ScamShield: Sending request to Azure AI...", flush=True)

    def _send():
        return openai_client.responses.create(
            model=MODEL,
            input=[
                {"type": "message", "role": "system", "content": COMPACT_PROMPT},
                {"type": "message", "role": "user", "content": user_content},
            ],
            timeout=DEFAULT_REQUEST_TIMEOUT,
        )

    response = execute_with_retry(_send)
    print("✅ ScamShield: Azure AI response received!", flush=True)
    raw = (response.output_text or "").strip()
    if raw.startswith("```"):
        raw = raw.strip("`")
        if raw.lower().startswith("json"):
            raw = raw[4:].strip()

    try:
        result = json.loads(raw)
    except json.JSONDecodeError:
        json_match = re.search(r"\{.*\}", raw, re.DOTALL)
        if json_match:
            result = json.loads(json_match.group(0))
        else:
            raise ValueError(f"AI response did not contain valid JSON: {raw[:120]}")

    if not isinstance(result, dict):
        raise ValueError("AI response format was invalid (expected JSON dictionary).")

    # Validate and preserve risk level
    risk_level = result.get("risk_level", "Medium")
    if risk_level not in ["Low", "Medium", "High"]:
        risk_level = "Medium"
    result["risk_level"] = risk_level

    merged_indicators = list(dict.fromkeys(result.get("indicators", []) + local_hits))
    result["indicators"] = merged_indicators
    result["local_flags"] = local_flags
    return result
