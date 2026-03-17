from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
from pydantic import EmailStr

conf = ConnectionConfig(
    MAIL_USERNAME = "form@vidad.webd.pl",
    MAIL_PASSWORD = "Form2026@!",  # jeśli Gmail, użyj App Password
    MAIL_FROM = "form@vidad.webd.pl",
    MAIL_PORT=587,
    MAIL_SERVER="vidad.webd.pl",
    MAIL_STARTTLS=True,      # zamiast MAIL_TLS
    MAIL_SSL_TLS=False,      # zamiast MAIL_SSL
    USE_CREDENTIALS=True,
    # TEMPLATE_FOLDER="email_templates"  # musi istnieć folder w projekcie
)