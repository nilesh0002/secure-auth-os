from __future__ import annotations

import json
import smtplib
from email.message import EmailMessage
from urllib import error, request

from app.core.config import Settings


class EmailDeliveryError(RuntimeError):
    pass


class EmailSender:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def is_configured(self) -> bool:
        provider = self.settings.email_delivery_provider.strip().lower()
        if provider == "resend":
            return bool(self.settings.resend_api_key and self.settings.resend_from_email)
        return bool(self.settings.smtp_host and self.settings.smtp_from_email)

    def _smtp_use_starttls(self) -> bool:
        value = self.settings.smtp_use_starttls
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in {"1", "true", "yes", "on"}

    def _provider(self) -> str:
        provider = self.settings.email_delivery_provider.strip().lower()
        return provider or "smtp"

    def _send_via_resend(self, to_email: str, subject: str, body: str) -> None:
        if not self.settings.resend_api_key or not self.settings.resend_from_email:
            raise EmailDeliveryError("Resend is not configured")

        endpoint = self.settings.resend_api_base.rstrip("/") + "/emails"
        payload = json.dumps(
            {
                "from": self.settings.resend_from_email,
                "to": [to_email],
                "subject": subject,
                "text": body,
            }
        ).encode("utf-8")
        req = request.Request(
            endpoint,
            data=payload,
            headers={
                "Authorization": f"Bearer {self.settings.resend_api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with request.urlopen(req, timeout=15) as response:  # nosec B310
                if response.status >= 400:
                    raise EmailDeliveryError("Resend API rejected request")
        except error.HTTPError as exc:
            raise EmailDeliveryError("Failed to send email via Resend") from exc
        except error.URLError as exc:
            raise EmailDeliveryError("Resend API is unreachable") from exc

    def send_otp(self, to_email: str, otp_code: str) -> None:
        if not self.is_configured():
            raise EmailDeliveryError("Email delivery provider is not configured")

        subject = self.settings.email_otp_subject
        body = (
            f"Your {self.settings.app_name} verification code is: {otp_code}\n\n"
            f"This code expires in {self.settings.email_otp_ttl_minutes} minutes.\n"
            "If you did not request this, you can ignore this email."
        )

        if self._provider() == "resend":
            self._send_via_resend(to_email, subject, body)
            return

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
            raise EmailDeliveryError("Email delivery provider is not configured")

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

        if self._provider() == "resend":
            self._send_via_resend(to_email, self.settings.password_reset_subject, body)
            return

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
