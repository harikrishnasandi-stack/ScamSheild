"""
ScamShield 2.0 - Contact Form & Email Integration Verification Suite.
Tests input validation, recipient configuration (sandiharikrishna4@gmail.com),
honest error reporting when unconfigured, and SMTP dispatch parameters.
"""

import os
import unittest
from unittest.mock import patch, MagicMock
import email_service


class TestContactEmailIntegration(unittest.TestCase):

    def test_01_recipient_configuration(self):
        """Recipient must default to sandiharikrishna4@gmail.com or respect SCAMSHIELD_CONTACT_EMAIL."""
        self.assertEqual(email_service.get_contact_recipient(), "sandiharikrishna4@gmail.com")
        with patch.dict(os.environ, {"SCAMSHIELD_CONTACT_EMAIL": "custom_team@domain.com"}):
            self.assertEqual(email_service.get_contact_recipient(), "custom_team@domain.com")

    def test_02_email_validation(self):
        """Contact form validator must enforce standard email format."""
        self.assertTrue(email_service.validate_email_address("sandiharikrishna4@gmail.com"))
        self.assertTrue(email_service.validate_email_address("user.name+tag@company.co.in"))
        self.assertFalse(email_service.validate_email_address("invalid-email"))
        self.assertFalse(email_service.validate_email_address("user@"))
        self.assertFalse(email_service.validate_email_address("@domain.com"))
        self.assertFalse(email_service.validate_email_address(""))
        self.assertFalse(email_service.validate_email_address(None))

    def test_03_field_validation_errors(self):
        """Missing or blank fields must return descriptive user errors."""
        ok, msg = email_service.send_contact_inquiry("", "test@domain.com", "Subject", "Message")
        self.assertFalse(ok)
        self.assertIn("name", msg.lower())

        ok, msg = email_service.send_contact_inquiry("User", "", "Subject", "Message")
        self.assertFalse(ok)
        self.assertIn("contact email", msg.lower())

        ok, msg = email_service.send_contact_inquiry("User", "notanemail", "Subject", "Message")
        self.assertFalse(ok)
        self.assertIn("not a valid email", msg.lower())

        ok, msg = email_service.send_contact_inquiry("User", "test@domain.com", "", "Message")
        self.assertFalse(ok)
        self.assertIn("subject", msg.lower())

        ok, msg = email_service.send_contact_inquiry("User", "test@domain.com", "Subject", "")
        self.assertFalse(ok)
        self.assertIn("message", msg.lower())

    def test_04_unconfigured_smtp_honest_error(self):
        """When SMTP credentials are missing, system must display an honest error, NOT success."""
        with patch.dict(os.environ, {"SMTP_USERNAME": "", "SMTP_PASSWORD": ""}, clear=False):
            ok, msg = email_service.send_contact_inquiry(
                "Jane Doe",
                "jane@cyberlab.org",
                "Collaboration inquiry",
                "Testing contact form submission."
            )
            self.assertFalse(ok)
            self.assertIn("SMTP_USERNAME", msg)
            self.assertIn("sandiharikrishna4@gmail.com", msg)

    def test_05_successful_smtp_dispatch(self):
        """When SMTP credentials are configured, email is formatted and dispatched to sandiharikrishna4@gmail.com."""
        mock_server = MagicMock()
        with patch("smtplib.SMTP", return_value=mock_server):
            with patch.dict(os.environ, {
                "SMTP_USERNAME": "sender@gmail.com",
                "SMTP_PASSWORD": "app-password-123",
                "SMTP_SERVER": "smtp.gmail.com",
                "SMTP_PORT": "587",
                "SCAMSHIELD_CONTACT_EMAIL": "sandiharikrishna4@gmail.com",
            }):
                ok, msg = email_service.send_contact_inquiry(
                    "Prof. Alan Turing",
                    "alan@cambridge.edu",
                    "AI Security Evaluation",
                    "We would like to test ScamShield on our institutional SMS dataset."
                )
                self.assertTrue(ok)
                self.assertIn("Your inquiry has been sent successfully to Team ScamShield.", msg)

                # Verify SMTP methods were called
                mock_server.starttls.assert_called_once()
                mock_server.login.assert_called_once_with("sender@gmail.com", "app-password-123")
                mock_server.send_message.assert_called_once()
                sent_msg = mock_server.send_message.call_args[0][0]
                self.assertEqual(sent_msg["To"], "sandiharikrishna4@gmail.com")
                self.assertEqual(sent_msg["Reply-To"], "alan@cambridge.edu")
                self.assertIn("[ScamShield Inquiry] AI Security Evaluation", sent_msg["Subject"])
                payload = sent_msg.get_payload()[0].get_payload()
                self.assertIn("Prof. Alan Turing", payload)
                self.assertIn("alan@cambridge.edu", payload)
                self.assertIn("Team ScamShield", sent_msg["From"])

    def test_06_threat_report_submission(self):
        """Threat report form validates empty message and logs report."""
        ok, msg = email_service.send_threat_report_email("+91 9988776655", "", "Phishing")
        self.assertFalse(ok)
        self.assertIn("provide the suspicious message", msg.lower())

        ok, msg = email_service.send_threat_report_email(
            "+91 9988776655",
            "Your account will be suspended. Send OTP now.",
            "Banking / OTP Phishing",
            "Received via SMS"
        )
        self.assertTrue(ok)


if __name__ == "__main__":
    unittest.main()

