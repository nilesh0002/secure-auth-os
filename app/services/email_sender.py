from __future__ import annotations

import smtplib
from email.message import EmailMessage

from app.core.config import Settings


class EmailDeliveryError(RuntimeError):
    pass


class EmailSender:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def is_configured(self) -> bool:
        return bool(self.settings.smtp_host and self.settings.smtp_from_email)

    def send_otp(self, to_email: str, otp_code: str) -> None:
        if not self.is_configured():
            raise EmailDeliveryError("SMTP is not configured")

        subject = self.settings.email_otp_subject
        body = (
            f"Your {self.settings.app_name} verification code is: {otp_code}\n\n"
            f"This code expires in {self.settings.email_otp_ttl_minutes} minutes.\n"
            "If you did not request this, you can ignore this email."
        )

        message = EmailMessage()
        message["Subject"] = subject
        message["From"] = self.settings.smtp_from_email
        message["To"] = to_email
        message.set_content(body)

        try:
            with smtplib.SMTP(self.settings.smtp_host, self.settings.smtp_port, timeout=15) as smtp:
                if self.settings.smtp_use_starttls:
                    smtp.starttls()
                if self.settings.smtp_username and self.settings.smtp_password:
                    smtp.login(self.settings.smtp_username, self.settings.smtp_password)
                smtp.send_message(message)
        except Exception as exc:
            raise EmailDeliveryError("Failed to send OTP email") from exc
