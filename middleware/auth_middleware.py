from functools import wraps
from typing import List
import jwt
from flask import request
from error_handling.errors import ForbiddenError, UnauthorizedError, ValidationError
from services.auth_services import is_token_blacklisted
from error_handling.error_handler import logger
from utils.jwt_utils import verify_token

def token_required(role: str | List = None):
    def _decorator(f):
        @wraps(f)
        def _wrapper(*args, **kwargs):
            try:
                header = request.headers.get("Authorization")

                if not header or not header.startswith("Bearer "):
                    raise UnauthorizedError("Bearer token required")

                token = header.split(" ")[1]

                if is_token_blacklisted(token):
                    raise UnauthorizedError("token has been revoked")

                payload = verify_token(token, refresh=False)
                user_id = payload.get("user_id")
                user_role = payload.get("role")

                if not user_id:
                    raise UnauthorizedError("invalid token")

                if isinstance(role, list) and user_role not in role:
                    raise ForbiddenError(f"roles in {role} don't match {user_role}")

                elif isinstance(role, str) and user_role != role:
                    raise ForbiddenError(f"{role} doesn't match {user_role}")

                return f(user_id, *args, **kwargs)

            except jwt.ExpiredSignatureError:
                raise ForbiddenError("Expired token")

            except jwt.InvalidSignatureError:
                raise ForbiddenError("Invalid token")

            except (ForbiddenError, UnauthorizedError, ValidationError) as e:
                raise e

            except Exception as ex:
                logger.error(f"exception occurred in token verification: {ex}", exc_info=True)
                raise UnauthorizedError("invalid or malformed token")

        return _wrapper
    return _decorator
