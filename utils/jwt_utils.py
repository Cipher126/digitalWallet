import jwt
import datetime
from utils.hashing import generate_id
import os
from dotenv import load_dotenv

load_dotenv()
SECRET_KEY = os.getenv("SECRET_KEY")

def create_access_token(user_id, role):
    payload = {
        "jti": generate_id(15),
        "user_id": user_id,
        "role": role,
        "type": "access",
        "exp": datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=60)
    }

    access_token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")

    return access_token

def create_refresh_token(user_id):
    payload = {
        "jti": generate_id(15),
        "user_id": user_id,
        "type": "refresh",
        "exp": datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=7)
    }

    refresh_token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")

    return refresh_token

def verify_token(token, refresh = False):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])

        token_type = payload.get("type")
        if refresh and token_type != "refresh":
            raise Exception("Invalid token type, refresh token expected")
        if not refresh and token_type != "access":
            raise Exception("Invalid token type, access token expected")

        return payload
    except jwt.ExpiredSignatureError:
        raise Exception("Token has expired")
    except jwt.InvalidTokenError:
        raise Exception("Invalid Token")