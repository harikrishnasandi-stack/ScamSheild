"""
Unit tests for ScamShield Local Threat & Scam Detection Engine.
Validates the 14 mandatory scenarios including edge cases, multilingual threats,
negation, and quoted context handling.
"""

import unittest
from local_detector import local_analyze, detect_signals


class TestLocalDetector(unittest.TestCase):
    def test_normal_greeting(self):
        """Scenario 6: Normal greeting -> LOW"""
        res = local_analyze("Hi, how are you?")
        self.assertEqual(res["risk_level"], "Low")
        self.assertLessEqual(res["risk_score"], 15)
        self.assertEqual(res["analysis_mode"], "Local Fallback Analysis")

    def test_direct_death_threat_english(self):
        """Scenario 7: Direct death threat -> CRITICAL"""
        threats = [
            "I will kill you.",
            "I am going to kill you",
            "I will hurt you",
            "I will beat you",
            "I will attack you",
            "I know where you live",
            "I will destroy your life",
            "I will make you suffer",
            "I will find you",
            "I will come after you",
            "I will harm your family",
        ]
        for t in threats:
            res = local_analyze(t)
            self.assertEqual(res["risk_level"], "Critical", f"Failed for: {t}")
            self.assertGreaterEqual(res["risk_score"], 90, f"Failed score for: {t}")
            self.assertTrue(res["local_flags"]["threat"])

    def test_indirect_threat_intimidation(self):
        """Scenario 8: Indirect threatening language -> HIGH"""
        res = local_analyze("Unless you do as I say, you will face severe consequences. You have been warned.")
        self.assertIn(res["risk_level"], ["High", "Critical"])
        self.assertTrue(res["local_flags"]["indirect_threat"])

    def test_genuine_delivery_notification(self):
        """Scenario 9: Genuine delivery notification -> LOW"""
        res = local_analyze("Your order #4521 has been shipped and will arrive tomorrow by 6pm.")
        self.assertEqual(res["risk_level"], "Low")
        self.assertLessEqual(res["risk_score"], 15)

    def test_otp_phishing_message(self):
        """Scenario 10: OTP phishing message -> HIGH or CRITICAL"""
        res = local_analyze("Dear customer, your SBI account will be blocked. Share your OTP immediately to verify.")
        self.assertIn(res["risk_level"], ["High", "Critical"])
        self.assertGreaterEqual(res["risk_score"], 85)
        self.assertTrue(res["local_flags"]["otp_request"])
        self.assertTrue(res["local_flags"]["impersonation"])

    def test_fake_lottery_message(self):
        """Scenario 11: Fake lottery message -> HIGH"""
        res = local_analyze("Congratulations! You have won Rs 25,00,000 in the KBC lucky draw. Claim your prize now.")
        self.assertIn(res["risk_level"], ["High", "Critical"])
        self.assertGreaterEqual(res["risk_score"], 80)
        self.assertTrue(res["local_flags"]["fake_reward"])

    def test_mixed_threat_and_financial_scam(self):
        """Scenario 12: Mixed threat and financial scam message -> CRITICAL"""
        res = local_analyze("Pay Rs 50,000 immediately or I will kill your family.")
        self.assertEqual(res["risk_level"], "Critical")
        self.assertEqual(res["risk_score"], 100)
        self.assertIn("Extortion", res["scam_type"])

    def test_negated_threat(self):
        """Scenario 13: Negated threat -> LOW"""
        res = local_analyze("Do not worry, I will not hurt you at all.")
        self.assertEqual(res["risk_level"], "Low")
        self.assertLessEqual(res["risk_score"], 15)

    def test_quoted_fictional_threat(self):
        """Scenario 14: Quoted fictional threat -> LOW with contextual uncertainty note"""
        res = local_analyze('The movie character says "I will kill you".')
        self.assertEqual(res["risk_level"], "Low")
        self.assertLessEqual(res["risk_score"], 25)
        self.assertIn("Fictional", res["scam_type"])

    def test_multilingual_threats(self):
        """Multilingual threat detection for Hindi, Telugu, Tamil"""
        # Hindi
        res_hi = local_analyze("मैं तुम्हें जान से मार दूंगा")
        self.assertEqual(res_hi["risk_level"], "Critical")
        self.assertTrue(res_hi["local_flags"]["threat"])

        # Telugu
        res_te = local_analyze("నేను నిన్ను చంపుతాను")
        self.assertEqual(res_te["risk_level"], "Critical")
        self.assertTrue(res_te["local_flags"]["threat"])

        # Tamil
        res_ta = local_analyze("நான் உன்னைக் கொன்றுவிடுவேன்")
        self.assertEqual(res_ta["risk_level"], "Critical")
        self.assertTrue(res_ta["local_flags"]["threat"])


if __name__ == "__main__":
    unittest.main()

