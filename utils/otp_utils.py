import hmac
import hashlib
import base64
import os
import random
import time

from dotenv import load_dotenv

from error_handling.error_handler import logger
load_dotenv()

SECRET_KEY = os.getenv("OTP_SECRET")

def generate_otp(email, ttl = 300):
    exp = int(time.time()) + ttl
    otp = str(random.randint(100000, 999999))
    payload = f"{email}:{exp}:{otp}"
    digest = hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).digest()
    signature = f"{payload}:{base64.urlsafe_b64encode(digest).decode()}"

    return otp, signature

def verify_otp(email, user_otp, signature):
    try:
        payload, sign = signature.rsplit(":", 1)
        digest = hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).digest()
        digest_b64 = base64.urlsafe_b64encode(digest).decode()

        if not hmac.compare_digest(sign, digest_b64):
            return False
        uid, exp, otp = payload.split(":")

        if uid != email:
            return False
        if int(exp) < int(time.time()):
            return False
        if user_otp != otp:
            return False

        return True
    except Exception as e:
        logger.error(f"exception occurred: {e}", exc_info=True)
        return False

# otp = generate_otp("email")
# print(otp)
verified = verify_otp("email", "776296", 'email:1758040036:776296:5J7VECDlmkm1XOgQQG_dryU1vZWQwFnww4ffa8xuXwA=')
print(verified)
