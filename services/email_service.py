import datetime

from error_handling.error_handler import logger
from services.notification_services import send_email

def send_otp(email, otp):
    try:
        body = f"Your OTP code is: {otp}\n\nDo not share with anybody\n\nThis code expires in 5 minutes."

        send_email(email, body, subject="Your OTP code")

        return True

    except Exception as e:
        logger.error(f"exception occurred in send otp: {e}", exc_info=True)
        raise


def send_transaction_notification(email, name: str, txn_type: str, amount, balance):
    try:
        timestamp = datetime.datetime.now(datetime.UTC).strftime("%d/%m/%Y, %H:%M:%S")

        body = (f"Dear {name.title()} \n your account has been {txn_type} with an of {amount}. \n Your available balance is {balance}. \n"
                f"Transaction date: {timestamp}")

        send_email(email, body, subject=f"{txn_type.title()} alert")

        return True

    except Exception as e:
        logger.error(f"exception occurred in send transaction notification: {e}", exc_info=True)
        raise

def send_login_alert(email, location):
    try:
        timestamp = datetime.datetime.now(datetime.UTC).strftime("%d/%m/%Y, %H:%M:%S")

        body = f"New login detected on your account near location: {location} at {timestamp}"
        subject = "Login Alert"

        send_email(email, body, subject)

        return True

    except Exception as e:
        logger.error(f"exception occurred in send otp: {e}", exc_info=True)
        raise