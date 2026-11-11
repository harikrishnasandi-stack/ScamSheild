"""
ScamShield 2.0 - Local Threat and Scam Detection Engine.

Provides an offline, rule-based detection pipeline used as an automatic fallback
whenever Azure AI is unavailable, slow, or returning errors.

Identifies:
1. Threatening & violent language (English, Hindi, Telugu, Tamil, transliterations).
2. Context-aware negation ("will not hurt you") and quoted/fictional contexts ("the movie says...").
3. Financial scams (OTP/PIN/CVV requests, fake lotteries, fraudulent payment requests, KYC fraud, job scams).
4. Urgency, manipulation, blackmail, and impersonation.
5. Suspicious links, shortened URLs, and suspicious contact details.

Returns a structured analysis matching the frontend schema with risk levels:
LOW, MEDIUM, HIGH, CRITICAL.
"""

import re
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# 1. Threatening & Violent Language Patterns
# ---------------------------------------------------------------------------

# High-severity direct death / violent harm threats (English)
DIRECT_VIOLENT_THREATS_RE = re.compile(
    r"\b("
    r"(?:i\s*(?:will|am\s*going\s*to|gonna|shall|\'ll)\s*(?:kill|murder|slaughter|shoot|stab|choke|strangle|cut|hang|end|destroy)\s*(?:you|u|your\s*life|your\s*family))|"
    r"(?:(?:you|u)\s*(?:will|are\s*going\s*to|gonna)\s*(?:die|be\s*killed|be\s*dead|bleed|suffer))|"
    r"(?:i\s*(?:will|am\s*going\s*to|gonna|\'ll)\s*(?:hurt|harm|beat|attack|break|smash|hit)\s*(?:you|u|your\s*family))|"
    r"(?:i\s*know\s*where\s*(?:you|u)\s*(?:live|stay|sleep|work))|"
    r"(?:i\s*(?:will|am\s*going\s*to|gonna|\'ll)\s*(?:find|hunt|track|come\s*after)\s*(?:you|u))|"
    r"(?:i\s*(?:will|am\s*going\s*to|gonna|\'ll)\s*(?:destroy\s*your\s*life|make\s*you\s*suffer|harm\s*your\s*family))|"
    r"(?:(?:you|u)\s*will\s*regret\s*this)|"
    r"(?:watch\s*your\s*back)|"
    r"(?:pay\s*or\s*(?:you|u|your\s*family)\s*(?:die|get\s*hurt|will\s*regret))"
    r")\b",
    re.IGNORECASE,
)

# Indirect or conditional threats / intimidation
INDIRECT_THREATS_RE = re.compile(
    r"\b("
    r"(?:unless\s*(?:you|u)\s*(?:pay|send|do|comply|respond)\b.{0,30}\b(?:consequences|regret|suffer|police|expose|leak|destroy))|"
    r"(?:you\s*have\s*been\s*warned)|"
    r"(?:this\s*is\s*your\s*(?:last|final)\s*warning)|"
    r"(?:or\s*else\s*(?:you\s*will\s*face|there\s*will\s*be\s*consequences))|"
    r"(?:i\s*(?:will|gonna)\s*(?:expose|leak|ruin|humiliate)\s*(?:you|your\s*photos|your\s*video))"
    r")\b",
    re.IGNORECASE,
)

# Multilingual threat keywords and phrases (Native scripts + transliterations)
# Hindi threats
HINDI_THREATS_RE = re.compile(
    r"("
    r"मार\s*डालूंगा|जान\s*से\s*मार\s*दूंगा|तुझे\s*छोड़ूंगा\s*नहीं|तुझे\s*बर्बाद\s*कर\s*दूंगा|"
    r"नुकसान\s*पहुंचाऊंगा|घर\s*आकर\s*मारूंगा|धमकी|तुझे\s*सबक\s*सिखाऊंगा|"
    r"\b(?:jaan\s*se\s*maar\s*dunga|maar\s*dalunga|tujhe\s*chhodunga\s*nahi|tujhe\s*barbaad\s*kar\s*dunga)\b"
    r")",
    re.IGNORECASE,
)

# Telugu threats
TELUGU_THREATS_RE = re.compile(
    r"("
    r"నిన్ను\s*చంపుతాను|చంపేస్తా|నిన్ను\s*నాశనం\s*చేస్తాను|నిన్ను\s*వదలను|నీ\s*అంతు\s*చూస్తా|హాని\s*చేస్తా|"
    r"\b(?:ninnu\s*champuthanu|champestha|ninnu\s*nasanam\s*chestha|nee\s*anthu\s*choostha)\b"
    r")",
    re.IGNORECASE,
)

# Tamil threats
TAMIL_THREATS_RE = re.compile(
    r"("
    r"உன்னைக்\s*கொன்றுவிடுவேன்|உன்னை\s*கொல்லுவேன்|உன்னை\s*அடிப்பேன்|உன்னை\s*விடமாட்டேன்|உன்னை\s*அழிப்பேன்|உன்னை\s*நாசமாக்குவேன்|"
    r"\b(?:unnaik\s*konruviduven|kolluven|unnai\s*vidamaten|unnai\s*azhippan)\b"
    r")",
    re.IGNORECASE,
)

# Contextual Negation (e.g. "I will not hurt you", "nobody will kill you")
NEGATION_THREAT_RE = re.compile(
    r"\b(?:not|never|no\s*intention|won\'?t|do\s*not|don\'?t|cannot|can\'?t|would\s*never)\s*(?:to\s*)?"
    r"(?:kill|murder|hurt|harm|attack|beat|destroy|strike|damage)\b",
    re.IGNORECASE,
)

# Quoted or fictional contexts (e.g. 'movie says "I will kill you"', 'dialogue in the play', 'quote from book')
FICTIONAL_OR_QUOTED_RE = re.compile(
    r"\b("
    r"(?:movie|film|book|novel|dialogue|lyrics|song|character|actor|scene|quote|said\s*in\s*the\s*film|drama|script|story|game|fiction)\b|"
    r"(?:\"[^\"]{1,100}\"|\'[^\']{1,100}\')"
    r")",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# 2. Financial & Credential Scams
# ---------------------------------------------------------------------------

OTP_CREDENTIAL_RE = re.compile(
    r"\b("
    r"(?:share|send|provide|tell|enter|verify|update|confirm)\b.{0,25}\b(?:otp|one[- ]time\s*(?:password|pin|code)|pin|password|cvv|mpin|secret\s*code|net\s*banking\s*credentials)\b|"
    r"\b(?:never\s*share\s*otp)\b|"  # Sometimes genuine messages say 'never share otp', handled in scoring
    r"\b(?:otp|pin|password|cvv)\s*(?:is|code|required|verification)\b"
    r")",
    re.IGNORECASE,
)

FAKE_REWARD_LOTTERY_RE = re.compile(
    r"\b("
    r"(?:won|winner|winning|congratulations|prize|lucky\s*draw|lottery|cashback|cash\s*reward|jackpot)\b.{0,35}"
    r"(?:rs\.?|inr|\u20b9|\$|lakh|crore|\d+[\d,]*\s*(?:dollars|rupees|pounds))|"
    r"(?:kbc\s*(?:lucky\s*draw|winner|lottery))|"
    r"(?:claim\s*(?:your\s*)?(?:prize|reward|lottery|gift|cash))"
    r")",
    re.IGNORECASE,
)

KYC_REFUND_BILL_RE = re.compile(
    r"\b("
    r"(?:(?:kyc|pan|aadhaar)\s*(?:expired|blocked|suspended|update|verification|pending|failed))|"
    r"(?:electricity\s*(?:power\s*)?(?:bill|power)\s*(?:unpaid|disconnect|cut\s*at|power\s*will\s*be\s*disconnected))|"
    r"(?:income\s*tax\s*refund|customs\s*clearance\s*fee|parcel\s*(?:stuck|held\s*at\s*customs|unclaimed))|"
    r"(?:part[- ]time\s*job|work\s*from\s*home\s*earn\s*\d+|daily\s*income\s*guaranteed|telegram\s*(?:task|job))"
    r")",
    re.IGNORECASE,
)

SUSPICIOUS_MONEY_DEMAND_RE = re.compile(
    r"\b("
    r"(?:send|pay|transfer|deposit|remit)\b.{0,25}(?:money|fee|charges|rs\.?|inr|\u20b9|\$|penalty|fine|crypto|usdt|bitcoin)\b|"
    r"(?:to\s*avoid\s*(?:penalty|legal\s*action|arrest|blocking|suspension))"
    r")",
    re.IGNORECASE,
)

IMPERSONATION_RE = re.compile(
    r"\b("
    r"state\s*bank\s*of\s*india|sbi|hdfc|icici|kotak|axis\s*bank|punjab\s*national\s*bank|pnb|"
    r"reserve\s*bank\s*of\s*india|rbi|income\s*tax\s*department|cbi|police\s*department|cyber\s*crime|"
    r"fedex|dhl|india\s*post|bluedart|amazon\s*support|netflix\s*billing|microsoft\s*support"
    r")\b",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# 3. Urgency, Manipulation & Deadlines
# ---------------------------------------------------------------------------

URGENCY_DEADLINE_RE = re.compile(
    r"\b("
    r"immediately|urgent|right\s*now|within\s*\d+\s*(?:hours?|mins?|minutes?)|"
    r"today\s*only|act\s*now|instant|immediate\s*effect|action\s*required\s*within|"
    r"account\s*(?:will\s*be\s*)?(?:suspended|blocked|terminated|frozen|closed|deactivated)\b|"
    r"legal\s*(?:action|notice|proceedings)|arrest\s*warrant|court\s*summons"
    r")\b",
    re.IGNORECASE,
)

EXTORTION_BLACKMAIL_RE = re.compile(
    r"\b("
    r"recorded\s*(?:you|video|webcam)|private\s*photos|leaked|expose\s*you|"
    r"send\s*to\s*all\s*(?:your\s*)?contacts|blackmail|extortion"
    r")\b",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# 4. Links and Contact Details
# ---------------------------------------------------------------------------

URL_RE = re.compile(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+", re.IGNORECASE)
SHORTENED_URL_RE = re.compile(
    r"https?://(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|cutt\.ly|rb\.gy|v\.gd)/[^\s<>\"']+",
    re.IGNORECASE,
)
SUSPICIOUS_DOMAIN_RE = re.compile(
    r"https?://[^\s/]*?(?:verify|login|secure|banking|update|confirm|support|service|portal|refund|kyc|bonus|gift|free)[^\s/]*?\.(?:net|org|xyz|top|info|live|club|cc|tk|ml|ga|cf|gq|co|work)[^\s<>\"']*",
    re.IGNORECASE,
)
PHONE_RE = re.compile(r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}|\b[6-9]\d{9}\b")

# Benign delivery notifications
GENUINE_DELIVERY_RE = re.compile(
    r"\b("
    r"(?:order\s*#?\s*\w+\s*(?:has\s*been|is)\s*(?:shipped|delivered|out\s*for\s*delivery))|"
    r"(?:delivered\s*by\s*\d+\s*(?:am|pm)?)|"
    r"(?:arriving\s*(?:today|tomorrow|on|by))|"
    r"(?:package\s*(?:is\s*on\s*its\s*way|has\s*been\s*delivered))"
    r")\b",
    re.IGNORECASE,
)

# Common friendly greetings / normal conversation
GREETING_RE = re.compile(
    r"^(?:hi|hello|hey|good\s*morning|good\s*evening|good\s*afternoon|how\s*are\s*you|what\'?s\s*up|dear\s*friend|see\s*you\s*soon|talk\s*later)[.!?\s]*$",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Local Detection & Rule Evaluation Engine
# ---------------------------------------------------------------------------

def detect_signals(text: str) -> Dict[str, Any]:
    """Scan input text against all local pattern rules and return detailed match data."""
    text_clean = text.strip()

    # Negation and Fictional Context checks
    has_negated_threat = bool(NEGATION_THREAT_RE.search(text_clean))
    has_fictional_context = bool(FICTIONAL_OR_QUOTED_RE.search(text_clean))

    # Threat signals
    direct_threat_match = DIRECT_VIOLENT_THREATS_RE.search(text_clean)
    indirect_threat_match = INDIRECT_THREATS_RE.search(text_clean)
    hindi_threat_match = HINDI_THREATS_RE.search(text_clean)
    telugu_threat_match = TELUGU_THREATS_RE.search(text_clean)
    tamil_threat_match = TAMIL_THREATS_RE.search(text_clean)

    is_violent_threat = bool(
        direct_threat_match or hindi_threat_match or telugu_threat_match or tamil_threat_match
    )
    is_indirect_threat = bool(indirect_threat_match)

    # Scams & Fraud signals
    otp_match = OTP_CREDENTIAL_RE.search(text_clean)
    reward_match = FAKE_REWARD_LOTTERY_RE.search(text_clean)
    kyc_match = KYC_REFUND_BILL_RE.search(text_clean)
    money_match = SUSPICIOUS_MONEY_DEMAND_RE.search(text_clean)
    impersonation_match = IMPERSONATION_RE.search(text_clean)
    urgency_match = URGENCY_DEADLINE_RE.search(text_clean)
    blackmail_match = EXTORTION_BLACKMAIL_RE.search(text_clean)

    # Links
    links = URL_RE.findall(text_clean)
    shortened_links = SHORTENED_URL_RE.findall(text_clean)
    suspicious_links = SUSPICIOUS_DOMAIN_RE.findall(text_clean)
    phone_numbers = PHONE_RE.findall(text_clean)

    # Benign signals
    is_genuine_delivery = bool(GENUINE_DELIVERY_RE.search(text_clean)) and not bool(otp_match or reward_match or suspicious_links)
    is_simple_greeting = bool(GREETING_RE.match(text_clean))

    # Extract matched phrases
    suspicious_phrases = []
    for match in [
        direct_threat_match,
        indirect_threat_match,
        hindi_threat_match,
        telugu_threat_match,
        tamil_threat_match,
        otp_match,
        reward_match,
        kyc_match,
        money_match,
        urgency_match,
        blackmail_match,
    ]:
        if match:
            phrase = match.group(0).strip()
            if phrase and phrase not in suspicious_phrases:
                suspicious_phrases.append(phrase)

    return {
        "text": text_clean,
        "is_violent_threat": is_violent_threat,
        "is_indirect_threat": is_indirect_threat,
        "has_negated_threat": has_negated_threat,
        "has_fictional_context": has_fictional_context,
        "is_otp_credential_theft": bool(otp_match),
        "is_fake_reward": bool(reward_match),
        "is_kyc_or_bill_fraud": bool(kyc_match),
        "is_money_demand": bool(money_match),
        "is_impersonation": bool(impersonation_match),
        "is_urgency_pressure": bool(urgency_match),
        "is_blackmail_extortion": bool(blackmail_match),
        "has_links": bool(links),
        "has_shortened_links": bool(shortened_links),
        "has_suspicious_links": bool(suspicious_links),
        "links": links,
        "phone_numbers": phone_numbers,
        "is_genuine_delivery": is_genuine_delivery,
        "is_simple_greeting": is_simple_greeting,
        "suspicious_phrases": suspicious_phrases,
    }


def compute_risk(signals: Dict[str, Any]) -> Tuple[int, str, str, str, List[str], List[str], str, List[str]]:
    """
    Evaluate threat severity and scam risk with context-aware logic.
    Returns:
    (score, risk_level, scam_type, threat_category, indicators, evidence, recommendation, do_not)
    """
    indicators = []
    evidence = []
    do_not = []

    # 1. Simple greeting or conversational message
    if signals["is_simple_greeting"]:
        return (
            0,
            "Low",
            "Benign Greeting",
            "None",
            ["Ordinary conversational greeting"],
            ["No scam, fraud, or threat patterns detected."],
            "This appears to be a normal friendly message. No safety action required.",
            [],
        )

    # 2. Quoted or Fictional Context Handling
    if signals["has_fictional_context"] and signals["is_violent_threat"]:
        indicators.append("Fictional or quoted phrasing detected")
        evidence.append("Threatening wording appears within a fictional, media, or quoted context.")
        recommendation = "The message references dialogue or media quotes. If this was received out of context from an unknown person, exercise caution."
        return (
            15,
            "Low",
            "Fictional / Quoted Dialogue",
            "Low Contextual Uncertainty",
            indicators,
            evidence,
            recommendation,
            ["Do not escalate without verifying context"],
        )

    # 3. Negated Threat Handling ("I will not hurt you")
    if signals["has_negated_threat"] and not (signals["is_otp_credential_theft"] or signals["has_suspicious_links"]):
        indicators.append("Negated statement regarding harm")
        evidence.append("The statement explicitly negates violent intent (e.g., 'will not hurt you').")
        return (
            10,
            "Low",
            "Reassuring / Non-Threatening Statement",
            "None",
            indicators,
            evidence,
            "No harmful intent is asserted in this message.",
            [],
        )

    # 4. Genuine Delivery Notification
    if signals["is_genuine_delivery"]:
        indicators.append("Standard delivery confirmation format")
        evidence.append("Matches legitimate order tracking or arrival notifications with no credential requests.")
        return (
            5,
            "Low",
            "Genuine Delivery Notification",
            "None",
            indicators,
            evidence,
            "This appears to be a routine delivery update. Verify delivery through your official retailer app or account.",
            ["Do not share delivery OTP before physically inspecting the package"],
        )

    # 5. Direct Violence & Death Threats (CRITICAL)
    if signals["is_violent_threat"]:
        indicators.append("Direct violent or death threat")
        if signals["is_blackmail_extortion"] or signals["is_money_demand"]:
            indicators.append("Extortion and ransom demand")
            evidence.append("Message combines explicit threats to life or safety with a demand for money or compliance.")
            evidence.append("This is an aggravated extortion attempt involving threats of violence.")
            return (
                100,
                "Critical",
                "Violent Extortion & Threat to Life",
                "Personal Safety Threat (Critical)",
                indicators,
                evidence,
                "Treat this immediately as a matter of personal safety. Do not comply with demands or send money. Contact local police or emergency law enforcement immediately.",
                ["Do not send money or cryptocurrency", "Do not engage or argue with the sender", "Preserve all screenshots and message records for police"],
            )

        evidence.append("Explicit violent language directed at personal safety detected.")
        evidence.append("Direct death threats and intimidation are classified with highest severity regardless of financial scam indicators.")
        return (
            95,
            "Critical",
            "Direct Violent Threat",
            "Personal Safety Threat (Critical)",
            indicators,
            evidence,
            "Treat this as a serious personal safety threat. Do not respond or engage. Contact law enforcement or emergency services if you feel in immediate danger.",
            ["Do not antagonize or meet with the sender", "Do not delete the message; take screenshots for police reporting"],
        )

    # 6. Indirect Threats & Intimidation
    if signals["is_indirect_threat"] or signals["is_blackmail_extortion"]:
        indicators.append("Intimidation / Blackmail threat")
        if signals["is_urgency_pressure"]:
            indicators.append("Aggressive coercive deadline")
        evidence.append("Sender uses fear, coercion, or blackmail to force compliance.")
        return (
            88,
            "High",
            "Blackmail & Coercive Intimidation",
            "Interpersonal Harassment",
            indicators,
            evidence,
            "Do not give in to intimidation or threats of exposure. Blackmailers rarely stop after the first payment. Report the incident to cybercrime authorities.",
            ["Do not pay ransom or blackmail demands", "Do not send sensitive media or personal information", "Block the sender and report to platform"],
        )

    # 7. High-Severity Financial Scams (OTP theft, Account Block + Phishing Link)
    is_phishing_combo = (
        signals["is_otp_credential_theft"]
        or (signals["is_urgency_pressure"] and (signals["has_suspicious_links"] or signals["is_impersonation"]))
        or (signals["is_kyc_or_bill_fraud"] and signals["has_links"])
    )

    if is_phishing_combo:
        score = 92
        if signals["is_otp_credential_theft"]:
            indicators.append("Request for secret OTP / PIN / Credentials")
            evidence.append("Legitimate institutions never ask for your one-time password or security PIN.")
        if signals["is_urgency_pressure"]:
            indicators.append("Artificial urgency / Threat of account block")
            evidence.append("Creates panic by threatening immediate account suspension or service disconnection.")
        if signals["is_impersonation"]:
            indicators.append("Impersonation of official entity")
            evidence.append("Claims to represent a bank, utility provider, or government body.")
        if signals["has_suspicious_links"] or signals["has_shortened_links"]:
            indicators.append("Deceptive or shortened web link")
            evidence.append("Directs users to an unofficial or masked phishing website.")

        scam_type = "Banking Phishing & Credential Theft" if signals["is_impersonation"] else "Urgent Credential Phishing Scam"
        threat_cat = "Financial Fraud & Identity Theft"

        return (
            score,
            "Critical" if score >= 90 else "High",
            scam_type,
            threat_cat,
            indicators,
            evidence,
            "Do not click any link and never share your OTP, PIN, or password with anyone. Open your bank's official app or website directly to verify your status.",
            ["Never share OTP, PIN, or CVV under any circumstance", "Never click links received in unverified SMS or messages", "Do not call phone numbers provided in the message"],
        )

    # 8. Fake Lottery, Prizes, Job Scams
    if signals["is_fake_reward"] or (signals["is_kyc_or_bill_fraud"] and signals["is_money_demand"]):
        indicators.append("Unsolicited prize / Fake lottery claim")
        evidence.append("Promises large cash rewards, lotteries, or easy earnings requiring upfront fees or details.")
        if signals["is_money_demand"]:
            indicators.append("Advance fee / deposit request")
            evidence.append("Demands an advance payment or processing fee before releasing supposed funds.")

        return (
            85,
            "High",
            "Advance-Fee Lottery / Prize Scam",
            "Financial Fraud",
            indicators,
            evidence,
            "Delete this message. You cannot win a lottery you never entered. Genuine prizes never require advance payment or taxes sent via UPI/transfer.",
            ["Never transfer processing fees or taxes to claim a reward", "Do not share bank account or personal details", "Do not engage with the sender on WhatsApp or Telegram"],
        )

    # 9. Moderate Risk: Unsolicited links or suspicious demands
    if signals["has_links"] or signals["is_money_demand"] or signals["is_urgency_pressure"]:
        if signals["has_suspicious_links"] or signals["has_shortened_links"]:
            indicators.append("Suspicious or masked link present")
        if signals["is_money_demand"]:
            indicators.append("Unverified payment request")
        if signals["is_urgency_pressure"]:
            indicators.append("Urgent action deadline")

        evidence.append("The message displays suspicious urgency, unverified links, or requests for funds.")
        return (
            65,
            "Medium",
            "Suspicious Link / Unverified Request",
            "Potential Phishing",
            indicators or ["Unverified link or sender"],
            evidence,
            "Verify the sender's identity through independent official channels before clicking links or sending any money.",
            ["Do not click links from unfamiliar senders", "Do not make payments based on unverified text messages"],
        )

    # 10. Default Low / Ambiguous
    return (
        15,
        "Low",
        "Low Risk / Unflagged Message",
        "None",
        ["No high-confidence threat or scam patterns detected"],
        ["No suspicious links, credential requests, threats, or urgency keywords were detected."],
        "No immediate threat detected. As always, remain vigilant and avoid sharing personal data with unknown senders.",
        [],
    )


def local_analyze(text: str, fallback_reason: Optional[str] = None) -> Dict[str, Any]:
    """
    Primary entry point for local rule-based analysis.
    Returns a dictionary formatted exactly for the ScamShield frontend.
    """
    signals = detect_signals(text)
    (
        score,
        risk_level,
        scam_type,
        threat_category,
        indicators,
        evidence,
        recommendation,
        do_not,
    ) = compute_risk(signals)

    return {
        "risk_level": risk_level,
        "risk_score": score,
        "scam_type": scam_type,
        "threat_category": threat_category,
        "indicators": indicators,
        "suspicious_phrases": signals["suspicious_phrases"],
        "evidence": evidence,
        "recommendation": recommendation,
        "do_not": do_not,
        "local_flags": {
            "threat": signals["is_violent_threat"],
            "indirect_threat": signals["is_indirect_threat"],
            "otp_request": signals["is_otp_credential_theft"],
            "fake_reward": signals["is_fake_reward"],
            "money_demand": signals["is_money_demand"],
            "impersonation": signals["is_impersonation"],
            "urgency": signals["is_urgency_pressure"],
            "link_present": signals["has_links"],
            "suspicious_link": signals["has_suspicious_links"],
        },
        "analysis_mode": "Local Fallback Analysis",
        "fallback_reason": fallback_reason or "Local detection engine executed",
    }

