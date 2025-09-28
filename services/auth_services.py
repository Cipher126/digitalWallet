import logging
import jwt
import redis
import datetime
from database.connection import conn
from error_handling.errors import NotFoundError, ValidationError, InternalServerError
from models.tokens_model import delete_token, get_refresh_token
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
            raise ValidationError("invalid token type")

        user_id = decoded["user_id"]

        token_record = get_refresh_token(user_id, refresh_token)
        if not token_record:
            raise NotFoundError("refresh token not found")

        with conn.cursor() as cursor:
            cursor.execute("""SELECT role FROM users WHERE user_id = %s""", (user_id,))
            result = cursor.fetchone()

            if not result:
                raise NotFoundError("user not found")

        role = result[0]

        access_token = create_access_token(user_id, role)

        return {
            "success": True,
            "message": "token refresh successful",
            "access_token": access_token
        }, 200

    except jwt.ExpiredSignatureError as e:
        raise e
    except jwt.InvalidTokenError as e:
        raise e
    except (ValidationError, NotFoundError) as e:
        raise e
    except Exception as e:
        logger.error(f"Exception occurred in refresh_access_token: {e}", exc_info=True)
        raise InternalServerError

def logout(user_id, refresh_token, access_token):
    blacklist_access_token(access_token)

    delete_token(user_id=user_id, token=refresh_token)

    return {
        "message": "user logout successful"
    }, 200

def is_token_blacklisted(token):
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        jti = decoded["jti"]
        return r.exists(f"blacklist:{jti}") == 1

    except Exception as e:
        raise e