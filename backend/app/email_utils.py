"""Email notifications — gracefully disabled when SMTP is not configured."""
import smtplib, logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from . import config

log = logging.getLogger(__name__)


def _enabled():
    return bool(config.SMTP_HOST and config.SMTP_FROM)


def send(to: str, subject: str, body: str, html: str = None) -> bool:
    if not _enabled() or not to:
        return False
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[{config.ORG_NAME}] {subject}"
        msg["From"] = config.SMTP_FROM
        msg["To"] = to
        msg.attach(MIMEText(body, "plain"))
        if html:
            msg.attach(MIMEText(html, "html"))
        with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT, timeout=10) as s:
            if config.SMTP_TLS:
                s.starttls()
            if config.SMTP_USER:
                s.login(config.SMTP_USER, config.SMTP_PASS)
            s.sendmail(msg["From"], [to], msg.as_string())
        return True
    except Exception as e:
        log.warning("Email send failed to %s: %s", to, e)
        return False


def notify_password_reset(user_email: str, username: str, temp_pw: str):
    send(user_email, "Your password has been reset",
         f"Hello {username},\n\nYour password has been reset by an administrator.\n"
         f"Temporary password: {temp_pw}\n\nYou must change it at next login.\n\n{config.ORG_NAME}")


def notify_account_approved(user_email: str, username: str):
    send(user_email, "Your account has been approved",
         f"Hello {username},\n\nYour account has been approved and is now active.\n"
         f"You may now log in to {config.ORG_NAME}.")


def notify_custody_transfer(to_email: str, to_name: str, evidence_ref: str, from_name: str, reason: str):
    send(to_email, f"Custody transfer — {evidence_ref}",
         f"Hello {to_name},\n\nEvidence {evidence_ref} has been transferred to your custody by {from_name}.\n"
         f"Reason: {reason}\n\nPlease acknowledge receipt in the system.\n\n{config.ORG_NAME}")


def notify_case_assigned(to_email: str, to_name: str, case_ref: str, case_title: str):
    send(to_email, f"Case assigned — {case_ref}",
         f"Hello {to_name},\n\nYou have been assigned to case {case_ref}: {case_title}.\n\n{config.ORG_NAME}")
