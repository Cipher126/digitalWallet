import os
import smtplib
from email.mime.text import MIMEText
from dotenv import load_dotenv

from error_handling.error_handler import logger

load_dotenv()

EMAIL_HOST = os.getenv("EMAIL_HOST")
EMAIL_PORT = int(os.getenv("EMAIL_PORT"))
EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")

def send_otp(email, otp):
    body = f"Your OTP code is: {otp}\n\nDo not share with anybody\n\nThis code expires in 5 minutes."
    msg = MIMEText(body)
    msg["Subject"] = "Your OTP code"
    msg["From"] = EMAIL_ADDRESS
    msg["To"] = email

    try:
        with smtplib.SMTP_SSL(EMAIL_HOST, 465) as server:
            # server.starttls()
            server.login(user=EMAIL_ADDRESS, password=EMAIL_PASSWORD)
            server.sendmail(msg['From'], msg['To'], msg.as_string())

    except Exception as e:
        logger.error(f"exception occurred in email otp service: {e}", exc_info=True)
