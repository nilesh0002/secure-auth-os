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

    def _smtp_use_starttls(self) -> bool:
        value = self.settings.smtp_use_starttls
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in {"1", "true", "yes", "on"}

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
                if self._smtp_use_starttls():
                    smtp.starttls()
                if self.settings.smtp_username and self.settings.smtp_password:
                    smtp.login(self.settings.smtp_username, self.settings.smtp_password)
                smtp.send_message(message)
        except Exception as exc:
            raise EmailDeliveryError("Failed to send OTP email") from exc

    def send_password_reset(self, to_email: str, reset_token: str) -> None:
        if not self.is_configured():
            raise EmailDeliveryError("SMTP is not configured")

        reset_link = ""
        if self.settings.password_reset_url_base:
            base = self.settings.password_reset_url_base.rstrip("/")
            reset_link = f"{base}?token={reset_token}"

        body = (
            "We received a request to reset your password.\n\n"
            f"Reset token: {reset_token}\n"
            f"Expires in {self.settings.password_reset_ttl_minutes} minutes.\n"
        )
        if reset_link:
            body += f"Reset link: {reset_link}\n"
        body += "\nIf you did not request this, you can ignore this email."

        message = EmailMessage()
        message["Subject"] = self.settings.password_reset_subject
        message["From"] = self.settings.smtp_from_email
        message["To"] = to_email
        message.set_content(body)

        try:
            with smtplib.SMTP(self.settings.smtp_host, self.settings.smtp_port, timeout=15) as smtp:
                if self._smtp_use_starttls():
                    smtp.starttls()
                if self.settings.smtp_username and self.settings.smtp_password:
                    smtp.login(self.settings.smtp_username, self.settings.smtp_password)
                smtp.send_message(message)
        except Exception as exc:
            raise EmailDeliveryError("Failed to send password reset email") from exc
