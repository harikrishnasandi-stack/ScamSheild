"""
ScamShield 2.0 - 5-stage prompt chain
Runs entity extraction -> pattern check -> risk classification -> evidence -> action
against the Azure AI Foundry model, feeding each stage's output into the next.

Before running:
    pip install azure-ai-projects>=2.1.0 azure-identity
    az login
"""

import json
from azure.identity import DefaultAzureCredential
from azure.ai.projects import AIProjectClient

ENDPOINT = "https://khayumsheikh91-0599-resource.services.ai.azure.com/api/projects/khayumsheikh91-0599"
MODEL = "gpt-6-astra"

project_client = AIProjectClient(endpoint=ENDPOINT, credential=DefaultAzureCredential())
openai_client = project_client.get_openai_client()


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
    response = openai_client.responses.create(
        model=MODEL,
        input=[
            {"type": "message", "role": "system", "content": system_prompt},
            {"type": "message", "role": "user", "content": user_content},
        ],
    )
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
        return _analyze_message_core(message)
    except Exception as e:
        msg = str(e)
        if "content_filter" in msg or "jailbreak" in msg.lower():
            return {
                "message": message,
                "entities": {},
                "patterns": {"patterns": []},
                "risk_level": "High",
                "confidence": 1.0,
                "reason": "This message triggered a content safety filter, which itself is a strong signal of extreme or manipulative language; treated conservatively as High risk.",
                "evidence": ["Could not be fully analyzed because it triggered a safety filter, which often indicates explicit threats or an attempt to manipulate the AI."],
                "recommended_action": "Treat this as high risk. Do not comply with any demands. If you feel unsafe, contact local police.",
                "do_not": ["Send money or personal details", "Click any link in the message", "Engage further with the sender"],
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

