"""
ScamShield 2.0 - 5-stage prompt chain
Runs entity extraction -> pattern check -> risk classification -> evidence -> action
against the Azure AI Foundry model, feeding each stage's output into the next.

Before running:
    pip install azure-ai-projects>=2.1.0 azure-identity
    az login
"""

import json
import os
import time
from azure.identity import AzureCliCredential, DefaultAzureCredential, ChainedTokenCredential
from azure.ai.projects import AIProjectClient

ENDPOINT = os.getenv("AZURE_AI_ENDPOINT", "https://khayumsheikh91-0599-resource.services.ai.azure.com/api/projects/khayumsheikh91-0599")
MODEL = os.getenv("AZURE_AI_MODEL", "gpt-6-astra")

DEFAULT_REQUEST_TIMEOUT = float(os.getenv("AZURE_REQUEST_TIMEOUT", "20.0"))
MAX_RETRIES = int(os.getenv("AZURE_MAX_RETRIES", "1"))


def _get_credential():
    """Returns a credential prioritizing AzureCliCredential for fast, reliable local
    Windows execution, falling back to DefaultAzureCredential for hosted/cloud environments."""
    try:
        return ChainedTokenCredential(AzureCliCredential(), DefaultAzureCredential())
    except Exception:
        return DefaultAzureCredential()


project_client = AIProjectClient(endpoint=ENDPOINT, credential=_get_credential())
openai_client = project_client.get_openai_client()


def is_content_filter_error(err: Exception) -> bool:
    """Detect whether an exception was caused by Azure OpenAI content safety filters."""
    msg = str(err).lower()
    return any(
        term in msg
        for term in [
            "content_filter",
            "content management policy",
            "content filtering",
            "response was filtered",
            "jailbreak",
            "responsible ai",
        ]
    )


def execute_with_retry(func, *args, **kwargs):
    """Execute func with limited retries and exponential backoff for transient errors."""
    delay = 1.5
    last_err = None
    for attempt in range(MAX_RETRIES + 1):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            last_err = e
            err_str = str(e).lower()
            if is_content_filter_error(e) or "unauthorized" in err_str or "forbidden" in err_str:
                raise
            if attempt < MAX_RETRIES and ("timeout" in err_str or "rate" in err_str or "429" in err_str or "500" in err_str or "502" in err_str or "503" in err_str or "connection" in err_str):
                time.sleep(delay)
                delay *= 2
                continue
            raise
    raise last_err


# ---------------------------------------------------------------------------
# Stage prompts (system instructions). Edit these as you tune your versions.
# ---------------------------------------------------------------------------

PROMPT_1_EXTRACT = """You are Stage 1 of a scam-detection pipeline. Extract structured entities from the message given. Reply with ONLY a JSON object, no explanation, no markdown formatting.

Schema:
{"message_type": "sms|whatsapp|email|ad|payment_request|other", "sender": "string or null", "phone_numbers": [], "links": [], "amounts": [], "organizations_mentioned": []}

Example:
Input: "Dear customer, your SBI account will be blocked. Verify now at http://sbi-verify.co/123 or call 9876543210"
Output: {"message_type":"sms","sender":null,"phone_numbers":["9876543210"],"links":["http://sbi-verify.co/123"],"amounts":[],"organizations_mentioned":["SBI"]}"""

PROMPT_2_PATTERNS = """You are Stage 2 of a scam-detection pipeline. You are given the original message and the entities already extracted from it (as JSON). Identify suspicious patterns. Reply with ONLY a JSON object, no explanation, no markdown formatting.

Schema:
{"patterns": [{"type": "urgency|threat|otp_request|shortened_link|lookalike_sender|too_good_offer|payment_request|grammar_anomaly", "quote": "exact text from message supporting this", "severity": "low|medium|high"}]}

If no suspicious patterns exist, return {"patterns": []}. Avoid overlapping quotes; merge similar patterns rather than repeating them."""

PROMPT_3_CLASSIFY = """You are Stage 3 of a scam-detection pipeline. Based on the message, extracted entities, and detected patterns (all given as JSON), classify the overall risk. Reply with ONLY a JSON object, no explanation, no markdown formatting.

Schema:
{"risk_level": "Low|Medium|High", "confidence": 0.0, "reason": "one sentence"}

Guidance:
- High: multiple high-severity patterns, especially threats/urgency combined with a link or payment request.
- Medium: one or two medium/low-severity patterns, or a single high-severity pattern with no other red flags.
- Low: no patterns, or only very weak/ambiguous signals."""

PROMPT_4_EVIDENCE = """You are Stage 4 of a scam-detection pipeline. Convert the technical patterns into simple, plain-language evidence points a non-technical person can understand. Reply with ONLY a JSON object, no explanation, no markdown formatting.

Schema:
{"evidence": ["max 4 short plain-language points, each tied to a quote from the message"]}"""

PROMPT_5_ACTION = """You are Stage 5 of a scam-detection pipeline, the final safety-facing stage. Based on the risk level and evidence (given as JSON), give the user clear next steps. Reply with ONLY a JSON object, no explanation, no markdown formatting.

Rules:
- Never tell the user to click any link in the message, even to "check" it.
- Never invent or state a specific official phone number, website, or bank name unless it was already given by the user as a known safe contact.
- Keep recommended_action to 1-2 short lines.

Schema:
{"recommended_action": "1-2 lines", "do_not": ["short list of things to avoid"]}"""


def call_stage(system_prompt: str, user_content: str) -> dict:
    """Send one stage's system prompt + user content to the model and parse JSON back."""
    def _send():
        return openai_client.responses.create(
            model=MODEL,
            input=[
                {"type": "message", "role": "system", "content": system_prompt},
                {"type": "message", "role": "user", "content": user_content},
            ],
            timeout=DEFAULT_REQUEST_TIMEOUT,
        )

    response = execute_with_retry(_send)
    raw = response.output_text.strip()
    # Strip markdown code fences if the model adds them despite instructions
    if raw.startswith("```"):
        raw = raw.strip("`")
        if raw.lower().startswith("json"):
            raw = raw[4:].strip()
    try:
        return json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError(f"Stage did not return valid JSON: {raw!r}") from e


def analyze_message(message: str) -> dict:
    try:
        res = _analyze_message_core(message)
        res["analysis_mode"] = "Azure AI Analysis"
        return res
    except Exception as e:
        print(f"⚠️ ScamShield Chain: Azure AI unavailable ({type(e).__name__}). Invoking local fallback.", flush=True)
        try:
            from local_detector import local_analyze
            local_res = local_analyze(message, fallback_reason=f"Azure AI ({type(e).__name__})")
            return {
                "message": message,
                "entities": {},
                "patterns": {
                    "patterns": [
                        {"type": p, "quote": p, "severity": "high"}
                        for p in local_res.get("suspicious_phrases", [])
                    ]
                },
                "risk_level": local_res["risk_level"],
                "confidence": 0.95 if local_res["risk_score"] > 50 else 0.85,
                "reason": local_res["scam_type"],
                "evidence": local_res["evidence"],
                "recommended_action": local_res["recommendation"],
                "do_not": local_res.get("do_not", []),
                "analysis_mode": "Local Fallback Analysis",
                "fallback_reason": local_res.get("fallback_reason"),
            }
        except Exception as local_err:
            print(f"❌ Local fallback error: {local_err}", flush=True)
            if is_content_filter_error(e):
                return {
                    "message": message,
                    "entities": {},
                    "patterns": {"patterns": []},
                    "risk_level": "High",
                    "confidence": 1.0,
                    "reason": "This message triggered a content safety filter; treated conservatively as High risk.",
                    "evidence": ["Triggered Azure content safety filter."],
                    "recommended_action": "Treat this as high risk. Do not comply with demands.",
                    "do_not": ["Send money", "Click links"],
                    "analysis_mode": "Local Fallback Analysis",
                }
            raise


def _analyze_message_core(message: str) -> dict:
    """Run the full 5-stage chain on a single message and return the combined result."""

    entities = call_stage(PROMPT_1_EXTRACT, message)

    patterns = call_stage(
        PROMPT_2_PATTERNS,
        f"Original message:\n{message}\n\nExtracted entities:\n{json.dumps(entities)}",
    )

    classification = call_stage(
        PROMPT_3_CLASSIFY,
        f"Original message:\n{message}\n\nExtracted entities:\n{json.dumps(entities)}"
        f"\n\nPatterns:\n{json.dumps(patterns)}",
    )

    evidence = call_stage(
        PROMPT_4_EVIDENCE,
        f"Original message:\n{message}\n\nPatterns:\n{json.dumps(patterns)}",
    )

    action = call_stage(
        PROMPT_5_ACTION,
        f"Risk level: {classification.get('risk_level')}\n"
        f"Evidence:\n{json.dumps(evidence.get('evidence', []))}",
    )

    return {
        "message": message,
        "entities": entities,
        "patterns": patterns,
        "risk_level": classification.get("risk_level"),
        "confidence": classification.get("confidence"),
        "reason": classification.get("reason"),
        "evidence": evidence.get("evidence", []),
        "recommended_action": action.get("recommended_action"),
        "do_not": action.get("do_not", []),
    }


if __name__ == "__main__":
    test_message = (
        "Dear customer, your account will be suspended. Click "
        "http://kotak-verify.net/confirm or call 8899001122 immediately to avoid penalty."
    )
    result = analyze_message(test_message)
    print(json.dumps(result, indent=2))

