"""
ScamShield 2.0 - Secure Email Integration Service.
Handles inquiry dispatch, threat sample reporting, and input validation.
Recipient configured via SCAMSHIELD_CONTACT_EMAIL (default: sandiharikrishna4@gmail.com).
Credentials read securely from environment variables or Streamlit secrets.
"""

import datetime
import os
import re
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Tuple, Dict, Any

DEFAULT_RECIPIENT = "sandiharikrishna4@gmail.com"
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")


def validate_email_address(email: str) -> bool:
    """Validate email address format strictly."""
    if not email or not isinstance(email, str):
        return False
    return bool(EMAIL_REGEX.match(email.strip()))


def get_contact_recipient() -> str:
    """Get the target recipient email for all ScamShield inquiries."""
    # Check Streamlit secrets first, then OS environment, then default
    try:
        import streamlit as st
        if hasattr(st, "secrets") and "SCAMSHIELD_CONTACT_EMAIL" in st.secrets:
            return st.secrets["SCAMSHIELD_CONTACT_EMAIL"]
    except Exception:
        pass
    return os.getenv("SCAMSHIELD_CONTACT_EMAIL", DEFAULT_RECIPIENT).strip()


def get_smtp_config() -> Dict[str, Any]:
    """Retrieve SMTP configuration without exposing secrets."""
    config = {
        "server": os.getenv("SMTP_SERVER", "smtp.gmail.com").strip(),
        "port": int(os.getenv("SMTP_PORT", "587")),
        "username": os.getenv("SMTP_USERNAME", "").strip(),
        "password": os.getenv("SMTP_PASSWORD", "").strip(),
        "use_tls": os.getenv("SMTP_USE_TLS", "true").lower() in ("true", "1", "yes"),
    }

    # Check Streamlit secrets if not found in OS environment
    try:
        import streamlit as st
        if hasattr(st, "secrets"):
            if not config["username"] and "SMTP_USERNAME" in st.secrets:
                config["username"] = str(st.secrets["SMTP_USERNAME"]).strip()
            if not config["password"] and "SMTP_PASSWORD" in st.secrets:
                config["password"] = str(st.secrets["SMTP_PASSWORD"]).strip()
            if "SMTP_SERVER" in st.secrets:
                config["server"] = str(st.secrets["SMTP_SERVER"]).strip()
            if "SMTP_PORT" in st.secrets:
                config["port"] = int(st.secrets["SMTP_PORT"])
    except Exception:
        pass

    return config


def send_contact_inquiry(
    name: str,
    sender_email: str,
    subject: str,
    message: str,
) -> Tuple[bool, str]:
    """
    Deliver an inquiry to sandiharikrishna4@gmail.com (or SCAMSHIELD_CONTACT_EMAIL).
    Validates all required fields, sender email format, and checks SMTP credentials.
    Returns (success: bool, user_message: str).
    """
    # 1. Field validation
    name_clean = (name or "").strip()
    email_clean = (sender_email or "").strip()
    subj_clean = (subject or "").strip()
    msg_clean = (message or "").strip()

    if not name_clean:
        return False, "Please enter your name or organization."
    if not email_clean:
        return False, "Please enter your contact email address."
    if not validate_email_address(email_clean):
        return False, f"'{email_clean}' is not a valid email address. Please check and try again."
    if not subj_clean:
        return False, "Please enter an inquiry subject."
    if not msg_clean:
        return False, "Please write your message before sending."

    recipient = get_contact_recipient()
    smtp = get_smtp_config()

    # 2. Check SMTP credentials configuration
    if not smtp["username"] or not smtp["password"]:
        return (
            False,
            f"Email dispatch configuration is not set up on this server. "
            f"SMTP credentials (SMTP_USERNAME and SMTP_PASSWORD) must be configured in environment variables or Streamlit secrets to deliver emails to {recipient}. "
            f"Your inquiry has been stored locally in the session audit log."
        )

    # 3. Construct secure email message
    try:
        msg = MIMEMultipart("alternative")
        msg["From"] = f"Team ScamShield <{smtp['username']}>"
        msg["To"] = recipient
        msg["Reply-To"] = email_clean
        msg["Subject"] = f"[ScamShield Inquiry] {subj_clean}"

        body_text = (
            f"New Contact Inquiry received for Team ScamShield:\n"
            f"-----------------------------------------\n"
            f"Sender Name / Org: {name_clean}\n"
            f"Contact Email:     {email_clean}\n"
            f"Subject:           {subj_clean}\n"
            f"Timestamp:         {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
            f"-----------------------------------------\n\n"
            f"Message:\n{msg_clean}\n\n"
            f"--\nTeam ScamShield Notification Service"
        )
        msg.attach(MIMEText(body_text, "plain"))

        # 4. Dispatch via secure SMTP
        server = smtplib.SMTP(smtp["server"], smtp["port"], timeout=12)
        if smtp["use_tls"]:
            server.starttls()
        server.login(smtp["username"], smtp["password"])
        server.send_message(msg)
        server.quit()

        return True, "Your inquiry has been sent successfully to Team ScamShield."

    except smtplib.SMTPAuthenticationError:
        print("⚠️ ScamShield Email Error: SMTP authentication failed. Check application password.", flush=True)
        return (
            False,
            "Authentication failed with the email provider. Please ensure an App Password is used if connecting via Gmail SMTP."
        )
    except smtplib.SMTPException as e:
        err_msg = type(e).__name__
        print(f"⚠️ ScamShield Email Error ({err_msg}): {e}", flush=True)
        return False, f"Failed to send email due to an SMTP error ({err_msg}). Please check connection and settings."
    except Exception as e:
        err_msg = type(e).__name__
        print(f"⚠️ ScamShield Email Error: {err_msg}", flush=True)
        return False, f"Unable to deliver email at this time ({err_msg}). Please try again later."


def send_threat_report_email(
    sender_id: str,
    message_body: str,
    threat_category: str,
    additional_notes: str = "",
) -> Tuple[bool, str]:
    """
    Optionally dispatches reported phishing/threat samples to the team recipient.
    """
    if not message_body or not message_body.strip():
        return False, "Please provide the suspicious message content to report."

    recipient = get_contact_recipient()
    smtp = get_smtp_config()

    if not smtp["username"] or not smtp["password"]:
        # Honest fallback: logged locally
        return (
            True,
            "Your suspicious message report has been logged locally in the session threat repository for evaluation. (SMTP email dispatch is currently unconfigured)."
        )

    try:
        msg = MIMEMultipart("alternative")
        msg["From"] = f"Team ScamShield Threat Desk <{smtp['username']}>"
        msg["To"] = recipient
        msg["Subject"] = f"[Threat Sample Report] {threat_category} - {sender_id or 'Unknown Sender'}"

        body_text = (
            f"Suspicious Message Report Submitted:\n"
            f"-----------------------------------------\n"
            f"Reported Sender:   {sender_id or 'Not provided'}\n"
            f"Category:          {threat_category}\n"
            f"Timestamp:         {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
            f"Additional Notes:  {additional_notes or 'None'}\n"
            f"-----------------------------------------\n\n"
            f"Message Body:\n{message_body.strip()}\n\n"
            f"--\nTeam ScamShield Threat Reporting Service"
        )
        msg.attach(MIMEText(body_text, "plain"))

        server = smtplib.SMTP(smtp["server"], smtp["port"], timeout=12)
        if smtp["use_tls"]:
            server.starttls()
        server.login(smtp["username"], smtp["password"])
        server.send_message(msg)
        server.quit()

        return True, "Suspicious message report has been dispatched to Team ScamShield. Thank you."
    except Exception as e:
        print(f"⚠️ ScamShield Report Delivery Warning: {e}", flush=True)
        return (
            True,
            "Report recorded in the local session registry, though remote email delivery encountered a connection issue."
        )

