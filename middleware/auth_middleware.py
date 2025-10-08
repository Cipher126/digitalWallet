from functools import wraps
from typing import List

import jwt
from flask import request, jsonify

from error_handling.errors import ForbiddenError, UnauthorizedError
from services.auth_services import is_token_blacklisted
from error_handling.error_handler import logger
from utils.jwt_utils import verify_token

def token_required(role: str | List =None):
    def _decorator(f):
        @wraps(f)
        def _wrapper(*args, **kwargs):
            # token = None

            # if "Authorization" in request.headers:
            header = request.headers["Authorization"]
            if not header:
                raise UnauthorizedError

            if not header.startswith("Bearer "):
                raise UnauthorizedError("Bearer token required")
            token = header.split(" ")[1]

            if not token:
                raise UnauthorizedError("access token required")

            if is_token_blacklisted(token):
                raise UnauthorizedError("token has been revoked")

            try:
                payload = verify_token(token, refresh=False)
                user_id = payload.get("user_id")
                user_role = payload.get("role")

                if not user_id:
                    raise UnauthorizedError("invalid token")

                if role is not None and isinstance(role, list) and user_role not in role:
                    raise ForbiddenError(f"roles in {role} doesn't match {user_role}")

                if role is not None and isinstance(role, str) and user_role != role:
                    raise ForbiddenError(f"{role} doesn't match {user_role}")

                # request.user = {"user_id": user_id, "role": user_role}

            except (ForbiddenError, UnauthorizedError) as e:
                raise e

            except (jwt.ExpiredSignatureError, jwt.InvalidSignatureError) as e:
                raise e

            except Exception as e:
                logger.error(f"exception occurred: {e}", exc_info=True)
                return jsonify({
                    "error": "something went wrong"
                }), 500

            return f(user_id, *args, **kwargs)

        return _wrapper
    return _decorator
