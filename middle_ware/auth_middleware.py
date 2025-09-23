from functools import wraps
from flask import request, jsonify
from services.auth_services import is_token_blacklisted, logger
from utils.jwt_utils import verify_token

def token_required(role=None):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            token = None

            if "Authorization" in request.headers:
                header = request.headers["Authorization"]

                if header.startswith("Bearer "):
                    token = header.split(" ")[1]

            if not token:
                return jsonify({
                    "error": "access token required"
                }), 401

            if is_token_blacklisted(token):
                return jsonify({
                    "error": "token has been revoked"
                }), 401

            try:
                payload = verify_token(token, refresh=False)
                user_id = payload.get("user_id")
                user_role = payload.get("role")

                if not user_id:
                    return jsonify({
                        "error": "Invalid token"
                    }), 401

                if role is not None and user_role != role:
                    return jsonify({
                        "error": "Access denied"
                    }), 403

                request.user = {"user_id": user_id, "role": user_role}

            except Exception as e:
                logger.error(f"exception occurred: {e}", exc_info=True)
                return jsonify({
                    "error": "something went wrong"
                }), 500

            return f(user_id=payload.get("user_id"), *args, **kwargs)

        return wrapper
    return decorator
