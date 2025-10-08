import os
import smtplib
from email.mime.text import MIMEText
from dotenv import load_dotenv
from firebase_admin import messaging

from error_handling.error_handler import logger
from models.users_model import search_user_with_params

load_dotenv()

EMAIL_HOST = os.getenv("EMAIL_HOST")
EMAIL_PORT = int(os.getenv("EMAIL_PORT"))
EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")

def send_email(email, body, subject):
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = EMAIL_ADDRESS
    msg["To"] = email

    try:
        with smtplib.SMTP_SSL(EMAIL_HOST, 465) as server:
            server.login(user=EMAIL_ADDRESS, password=EMAIL_PASSWORD)
            server.sendmail(msg['From'], msg['To'], msg.as_string())

        return True

    except Exception as e:
        logger.error(f"exception occurred in email otp service: {e}", exc_info=True)
        raise


def send_push_notification(user_id, title, body):
    try:
        user = search_user_with_params(user_id=user_id)
        token = user["fcm_token"]

        if not token:
            logger.warn("No token found for user")

        message = messaging.Message(
            notification=messaging.Notification(
                title=title,
                body=body
            ),
            token=token
        )

        res = messaging.send(message)

        logger.warn(res)

    except Exception as e:
        logger.error(f"exception occurred in send push notification: {e}", exc_info=True)


def send_txn_push(user_id, txn_type: str, amount, balance):
    try:
        title = f"{txn_type.title()} alert"
        body = (f"Your account has been {txn_type} with the sum of {amount} \n."
                f"Your balance is {balance}")

        send_push_notification(user_id, title, body)

        return True

    except Exception as e:
        logger.error(f"exception occurred in send txn push")
        raise
