"""
ScamShield 2.0 - Verification Suite for AI Assistant Chatbot and Features.
Tests context-awareness, Azure AI integration, local fallback under error conditions,
and safety emergency containment recommendations.
"""

import unittest
from unittest.mock import patch
import ai_assistant


class TestAIAssistantChatbot(unittest.TestCase):

    def test_01_general_assistant_query_azure(self):
        """Chatbot should respond to general inquiries via Azure AI Foundry."""
        messages = [{"role": "user", "content": "What is ScamShield in 2 sentences?"}]
        res = ai_assistant.get_chat_response(messages)
        self.assertIn("source", res)
        self.assertIn("content", res)
        self.assertTrue(len(res["content"]) > 20)
        print("\nTest 1 (General Query):", res["source"], "->", res["content"][:80], "...")

    def test_02_context_aware_investigation(self):
        """Chatbot should receive and utilize the active analysis context."""
        context = {
            "original_text": "Your Kotak account is suspended. Verify OTP immediately at http://kotak-fix.net",
            "risk_level": "High",
            "risk_score": 90,
            "scam_type": "Banking Phishing",
            "threat_category": "Credential Theft / Urgency",
            "indicators": ["Account suspension threat", "Suspicious link", "OTP request"],
            "recommendation": "Do not share OTP or click the link.",
            "analysis_mode": "Azure AI Analysis",
        }
        messages = [
            {"role": "user", "content": "Why was this message classified as suspicious?"}
        ]
        res = ai_assistant.get_chat_response(messages, analysis_context=context)
        self.assertTrue("OTP" in res["content"] or "suspend" in res["content"].lower() or "bank" in res["content"].lower() or "link" in res["content"].lower())
        print("Test 2 (Context Aware):", res["source"], "-> Content mentions key indicators.")

    def test_03_offline_fallback_on_azure_error(self):
        """Chatbot should gracefully fall back to local investigation engine if Azure fails."""
        with patch("ai_assistant.openai_client.responses.create", side_effect=TimeoutError("Request timed out")):
            context = {
                "original_text": "I will kill you if you do not pay $500",
                "risk_level": "Critical",
                "risk_score": 95,
                "scam_type": "Extortion / Threat",
                "threat_category": "Direct Violence",
                "indicators": ["Death threat", "Money demand"],
                "recommendation": "Contact law enforcement immediately.",
                "analysis_mode": "Local Fallback Analysis",
            }
            messages = [{"role": "user", "content": "Is this a real threat?"}]
            res = ai_assistant.get_chat_response(messages, analysis_context=context)
            self.assertEqual(res["source"], "Local Fallback")
            self.assertTrue(len(res["content"]) > 30)
            self.assertTrue("threat" in res["content"].lower() or "police" in res["content"].lower())
            print("Test 3 (Offline Fallback on Timeout):", res["source"], "-> Successfully activated.")

    def test_04_emergency_otp_containment(self):
        """Chatbot must provide immediate bank freeze and 1930 helpline guidance if OTP was shared."""
        messages = [{"role": "user", "content": "What should I do if I shared my OTP?"}]
        res = ai_assistant.get_chat_response(messages)
        content_lower = res["content"].lower()
        self.assertTrue("bank" in content_lower)
        self.assertTrue("1930" in res["content"] or "freeze" in content_lower or "cybercrime" in content_lower)
        print("Test 4 (OTP Emergency Protocol): Guidance delivered properly.")

    def test_05_multilingual_fallback_telugu(self):
        """Local fallback provides localized emergency advice in Telugu."""
        content = ai_assistant.local_chat_fallback("I shared my OTP with the scammer", None, language="Telugu")
        self.assertTrue("బ్యాంకు" in content or "1930" in content)
        print("Test 5 (Telugu Localization): Verified successfully.")


if __name__ == "__main__":
    unittest.main()

