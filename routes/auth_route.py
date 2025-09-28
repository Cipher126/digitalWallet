from flask import Blueprint, request, redirect, url_for, jsonify
import requests, jwt, os
from dotenv import load_dotenv

from error_handling.error_handler import logger
from error_handling.errors import ValidationError, InternalServerError, InsufficientDataError, NotFoundError, \
    LockoutError, ConflictError
from middleware.auth_middleware import token_required
from services.auth_services import refresh_access_token
from services.totp_services import verify_totp_service
from services.user_services import oauth_user_login, signup_normal_user, user_login_email, user_login_username, \
    generate_otp_service, verify_user_account, use_2fa

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

load_dotenv()

auth_bp = Blueprint("auth", __name__)
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["5 per minute"]
)


GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI")

@auth_bp.route('/auth/google')
def google_login():
    google_auth_url = (
        "https://accounts.google.com/o/oauth2/v2/auth"
        f"?client_id={GOOGLE_CLIENT_ID}"
        f"&redirect_uri={REDIRECT_URI}"
        "&response_type=code"
        "&scope=openid email profile"
    )

    return redirect(google_auth_url)

@auth_bp.route("/auth/google/callback")
def google_callback():
    code = request.args.get("code")

    if not code:
        raise ValidationError("Missing code")

    token_url = "https://oauth2.googleapis.com/token"

    payload = {
        "code": code,
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri": REDIRECT_URI,
        "grant_type":"authorization_code"
    }

    res = requests.post(token_url, data=payload)
    tokens = res.json()

    id_token = tokens.get("id_token")

    if not id_token:
        raise ValidationError("Invalid token response")

    user_data = jwt.decode(id_token, options={"verify_signature": False})

    name = user_data.get("name")
    email = user_data.get("email")
    oauth_id = user_data.get("sub")

    try:
        response, status = oauth_user_login(provider="google", full_name=name, oauth_id=oauth_id, email=email)

        return jsonify(response), status

    except (ValidationError, NotFoundError, ConflictError, LockoutError) as e:
        raise e

    except Exception as e:
        logger.error(f"exception occurred in oauth google call back: {e}", exc_info=True)
        raise InternalServerError("something went wrong")


@auth_bp.route('/auth/signup', methods=['POST'])
def signup():
    data = request.get_json()
    try:
        response, status = signup_normal_user(data)

        return jsonify(response), status

    except (ValidationError, NotFoundError, ConflictError, LockoutError) as e:
        raise e

    except Exception as e:
        logger.error(f"exception occurred in normal user signup: {e}", exc_info=True)
        raise InternalServerError("something went wrong")


@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")

    try:
        if username:
            if not all([username, password]):
                raise InsufficientDataError
            response, status = user_login_username(username, password)

            return jsonify(response), status

        if email:
            if not all([email, password]):
                raise InsufficientDataError
            response, status = user_login_email(email, password)

            return jsonify(response), status

        raise ValidationError

    except (ValidationError, NotFoundError, LockoutError, InsufficientDataError) as e:
        raise e

    except Exception as e:
        logger.error(f"exception occurred in user login: {e}", exc_info=True)
        raise InternalServerError


@auth_bp.route('/verify-totp')
def verify():
    data = request.get_json()
    try:
        response, status = verify_totp_service(data)

        return jsonify(response), status

    except Exception as e:
        logger.error(f"exception occurred in verify totp: {e}", exc_info=True)
        raise InternalServerError


@auth_bp.route('/get-otp', methods=['GET'])
@limiter.limit("5 per minutes")
def get_otp():
    try:
        email = request.args.get("email")

        if not email:
            raise InsufficientDataError("email required")

        response, status = generate_otp_service(email)

        return jsonify(response), status

    except (ValidationError, NotFoundError, InsufficientDataError) as e:
        raise e

    except Exception as e:
        logger.error(f"exception occurred in get otp: {e}", exc_info=True)
        raise InternalServerError


@auth_bp.route('/verify-account', methods=['PUT'])
def verify_user():
    try:
        data = request.get_json()

        otp = data.get("otp")
        signature = data.get("signature")
        email = data.get("email")

        response, status = verify_user_account(email, otp, signature)

        return jsonify(response), status

    except ValidationError as e:
        raise e

    except Exception as e:
        logger.error(f"exception occurred in verify user route: {e}", exc_info=True)
        raise InternalServerError


@auth_bp.route('/enable-2fa', methods=['PUT'])
@token_required(role="user")
def activate_2fa(user_id):
    try:
        data = request.get_json()

        username = data.get("username")

        response, status = use_2fa(username, user_id)

        return jsonify(response), status

    except ValidationError as e:
        raise e

    except Exception as e:
        logger.error(f"exception occurred in activate 2fa route: {e}", exc_info=True)
        raise InternalServerError


@auth_bp.route('/refresh-token', methods=['GET'])
def refresh():
    try:
        token = request.args.get("refresh-token")
        response, status = refresh_access_token(token)

        return jsonify(response), status

    except (ValidationError, NotFoundError, jwt.InvalidTokenError,
            jwt.ExpiredSignatureError, jwt.exceptions.DecodeError) as e:
        raise e

    except Exception as e:
        logger.error(f"exception occurred in refresh token route: {e}", exc_info=True)
        raise InternalServerError
