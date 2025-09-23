import logging
import jwt
import redis
import datetime
from database.connection import conn
from utils.jwt_utils import create_access_token
import os
from dotenv import load_dotenv

load_dotenv()
SECRET_KEY = os.getenv("SECRET_KEY")
REDIS_HOST = os.getenv("REDIS_HOST")
REDIS_PORT = int(os.getenv("REDIS_PORT"))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD")
REDIS_USER = os.getenv("REDIS_USER")

logger = logging.getLogger(__name__)

r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, username=REDIS_USER, password=REDIS_PASSWORD, decode_responses=True)

def blacklist_access_token(token: str):
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        jti = decoded["jti"]
        exp = decoded["exp"]
        ttl = exp - int(datetime.datetime.now(datetime.UTC).timestamp())

        if ttl > 0:
            r.setex(f"blacklist:{jti}", ttl, "true")

    except jwt.ExpiredSignatureError:
        pass

def refresh_access_token(refresh_token: str):
    try:
        decoded = jwt.decode(refresh_token, SECRET_KEY, algorithms=["HS256"])

        if decoded.get("type") != "refresh":
            return None

        user_id = decoded["user_id"]

        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT 1 FROM tokens WHERE user_id = %s AND token = %s
            """, (user_id, refresh_token))

            details = cursor.fetchone()
            if not details:
                return None

            cursor.execute("""
                SELECT role FROM users WHERE user_id = %s
            """, (user_id, ))

            result = cursor.fetchone()

            if not result:
                return None, "user not found"

        role = result[0]

        access_token = create_access_token(user_id, role)

        return access_token, None

    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
    except Exception as e:
        logger.error(f"exception occurred: {e}", exc_info=True)
        return None

def logout(user_id, refresh_token, access_token):
    blacklist_access_token(access_token)



    return {
        "message": "user logout successful"
    }, 200

def is_token_blacklisted(token):
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        jti = decoded["jti"]
        return r.exists(f"blacklist:{jti}") == 1

    except Exception:
        return False