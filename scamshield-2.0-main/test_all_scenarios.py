"""
Comprehensive test script for the 14 mandatory ScamShield scenarios:
1. Azure works normally
2. Azure request times out
3. Internet is disconnected / endpoint unreachable
4. Azure authentication fails
5. Azure returns an invalid response
6. Normal greeting
7. Direct death threat
8. Indirect threatening language
9. Genuine delivery notification
10. OTP phishing message
11. Fake lottery message
12. Mixed threat and financial scam message
13. Negated threat
14. Quoted fictional threat
"""

import unittest
from unittest.mock import patch, MagicMock
from fast_analyzer import quick_analyze
from local_detector import local_analyze
import scamshield_chain


class TestScamShield14Scenarios(unittest.TestCase):

    # -----------------------------------------------------------------------
    # 1. Azure works normally
    # -----------------------------------------------------------------------
    def test_01_azure_works_normally(self):
        msg = "Dear customer, your account will be suspended. Click http://kotak-verify.net/confirm immediately."
        res = quick_analyze(msg)
        self.assertIn("analysis_mode", res)
        # Should succeed with valid risk level and score
        self.assertIn(res["risk_level"], ["High", "Critical"])
        self.assertGreaterEqual(res["risk_score"], 80)
        self.assertIsInstance(res["indicators"], list)
        print(f"Scenario 1 (Azure normal): mode={res['analysis_mode']}, risk={res['risk_level']} ({res['risk_score']}%)")

    # -----------------------------------------------------------------------
    # 2. Azure request times out -> Local Fallback activates
    # -----------------------------------------------------------------------
    @patch("scamshield_chain.openai_client.responses.create")
    def test_02_azure_times_out(self, mock_create):
        mock_create.side_effect = TimeoutError("Azure AI request timed out after 20.0s")
        msg = "URGENT: Click http://secure-sbi.net to prevent account suspension."
        res = quick_analyze(msg)
        self.assertEqual(res["analysis_mode"], "Local Fallback Analysis")
        self.assertIn(res["risk_level"], ["High", "Critical"])
        self.assertIn("Azure AI", res.get("fallback_reason", ""))
        print(f"Scenario 2 (Azure timeout fallback): mode={res['analysis_mode']}, risk={res['risk_level']}")

    # -----------------------------------------------------------------------
    # 3. Internet is disconnected / Endpoint unreachable -> Local Fallback
    # -----------------------------------------------------------------------
    @patch("scamshield_chain.openai_client.responses.create")
    def test_03_azure_network_disconnected(self, mock_create):
        mock_create.side_effect = ConnectionError("Could not resolve host: services.ai.azure.com")
        msg = "Congratulations! You won Rs 20,00,000 in lucky draw. Call 9876543210."
        res = quick_analyze(msg)
        self.assertEqual(res["analysis_mode"], "Local Fallback Analysis")
        self.assertIn(res["risk_level"], ["High", "Critical"])
        self.assertTrue(res["local_flags"]["fake_reward"])
        print(f"Scenario 3 (Network disconnect fallback): mode={res['analysis_mode']}, risk={res['risk_level']}")

    # -----------------------------------------------------------------------
    # 4. Azure authentication fails -> Local Fallback (no infinite retry)
    # -----------------------------------------------------------------------
    @patch("scamshield_chain.openai_client.responses.create")
    def test_04_azure_auth_fails(self, mock_create):
        mock_create.side_effect = PermissionError("ClientAuthenticationError: 401 Unauthorized / Token expired")
        msg = "Share your OTP 4821 immediately to unlock your debit card."
        res = quick_analyze(msg)
        self.assertEqual(res["analysis_mode"], "Local Fallback Analysis")
        self.assertIn(res["risk_level"], ["High", "Critical"])
        self.assertTrue(res["local_flags"]["otp_request"])
        print(f"Scenario 4 (Auth failure fallback): mode={res['analysis_mode']}, risk={res['risk_level']}")

    # -----------------------------------------------------------------------
    # 5. Azure returns an invalid / malformed response -> Local Fallback
    # -----------------------------------------------------------------------
    @patch("scamshield_chain.openai_client.responses.create")
    def test_05_azure_invalid_response(self, mock_create):
        mock_resp = MagicMock()
        mock_resp.output_text = "I am an AI and cannot process this format... <<<NOT JSON>>>"
        mock_create.return_value = mock_resp
        msg = "I will hunt you down and destroy your life."
        res = quick_analyze(msg)
        self.assertEqual(res["analysis_mode"], "Local Fallback Analysis")
        self.assertEqual(res["risk_level"], "Critical")
        print(f"Scenario 5 (Malformed response fallback): mode={res['analysis_mode']}, risk={res['risk_level']}")

    # -----------------------------------------------------------------------
    # 6. Normal greeting
    # -----------------------------------------------------------------------
    def test_06_normal_greeting(self):
        msg = "Hi, how are you doing today?"
        res = local_analyze(msg)
        self.assertEqual(res["risk_level"], "Low")
        self.assertLessEqual(res["risk_score"], 15)
        print(f"Scenario 6 (Greeting): risk={res['risk_level']} ({res['risk_score']}%)")

    # -----------------------------------------------------------------------
    # 7. Direct death threat -> CRITICAL
    # -----------------------------------------------------------------------
    def test_07_direct_death_threat(self):
        msg = "I will kill you. I know where you live."
        res = local_analyze(msg)
        self.assertEqual(res["risk_level"], "Critical")
        self.assertGreaterEqual(res["risk_score"], 90)
        self.assertTrue(res["local_flags"]["threat"])
        print(f"Scenario 7 (Direct death threat): risk={res['risk_level']} ({res['risk_score']}%)")

    # -----------------------------------------------------------------------
    # 8. Indirect threatening language -> HIGH
    # -----------------------------------------------------------------------
    def test_08_indirect_threatening_language(self):
        msg = "Unless you comply with my demands, you will regret this. This is your final warning."
        res = local_analyze(msg)
        self.assertIn(res["risk_level"], ["High", "Critical"])
        self.assertTrue(res["local_flags"]["indirect_threat"])
        print(f"Scenario 8 (Indirect threat): risk={res['risk_level']} ({res['risk_score']}%)")

    # -----------------------------------------------------------------------
    # 9. Genuine delivery notification -> LOW
    # -----------------------------------------------------------------------
    def test_09_genuine_delivery_notification(self):
        msg = "Your order #4521 has been shipped and will arrive tomorrow by 6pm."
        res = local_analyze(msg)
        self.assertEqual(res["risk_level"], "Low")
        self.assertLessEqual(res["risk_score"], 15)
        print(f"Scenario 9 (Genuine delivery): risk={res['risk_level']} ({res['risk_score']}%)")

    # -----------------------------------------------------------------------
    # 10. OTP phishing message -> HIGH or CRITICAL
    # -----------------------------------------------------------------------
    def test_10_otp_phishing_message(self):
        msg = "Your HDFC account is suspended. Verify and share your OTP immediately at http://hdfc-security.net"
        res = local_analyze(msg)
        self.assertIn(res["risk_level"], ["High", "Critical"])
        self.assertTrue(res["local_flags"]["otp_request"])
        print(f"Scenario 10 (OTP Phishing): risk={res['risk_level']} ({res['risk_score']}%)")

    # -----------------------------------------------------------------------
    # 11. Fake lottery message -> HIGH
    # -----------------------------------------------------------------------
    def test_11_fake_lottery_message(self):
        msg = "Congratulations! You have won Rs 25,00,000 in the KBC lucky draw. Claim your prize now."
        res = local_analyze(msg)
        self.assertIn(res["risk_level"], ["High", "Critical"])
        self.assertTrue(res["local_flags"]["fake_reward"])
        print(f"Scenario 11 (Fake lottery): risk={res['risk_level']} ({res['risk_score']}%)")

    # -----------------------------------------------------------------------
    # 12. Mixed threat and financial scam message -> CRITICAL
    # -----------------------------------------------------------------------
    def test_12_mixed_threat_and_financial_scam(self):
        msg = "Pay Rs 50,000 immediately or I will kill your family and destroy your life."
        res = local_analyze(msg)
        self.assertEqual(res["risk_level"], "Critical")
        self.assertEqual(res["risk_score"], 100)
        self.assertIn("Extortion", res["scam_type"])
        print(f"Scenario 12 (Mixed Extortion): risk={res['risk_level']} ({res['risk_score']}%)")

    # -----------------------------------------------------------------------
    # 13. Negated threat -> LOW
    # -----------------------------------------------------------------------
    def test_13_negated_threat(self):
        msg = "Please stay calm, I will not hurt you and I have no intention to harm you."
        res = local_analyze(msg)
        self.assertEqual(res["risk_level"], "Low")
        self.assertLessEqual(res["risk_score"], 15)
        print(f"Scenario 13 (Negated threat): risk={res['risk_level']} ({res['risk_score']}%)")

    # -----------------------------------------------------------------------
    # 14. Quoted fictional threat -> LOW
    # -----------------------------------------------------------------------
    def test_14_quoted_fictional_threat(self):
        msg = 'In the movie, the villain shouts "I will kill you all" during the fight scene.'
        res = local_analyze(msg)
        self.assertEqual(res["risk_level"], "Low")
        self.assertLessEqual(res["risk_score"], 25)
        print(f"Scenario 14 (Quoted fictional): risk={res['risk_level']} ({res['risk_score']}%)")


if __name__ == "__main__":
    unittest.main()

