from flask import Blueprint, request, redirect, jsonify
import requests, jwt, os
from dotenv import load_dotenv

from error_handling.error_handler import logger
from error_handling.errors import ValidationError, InternalServerError, InsufficientDataError, NotFoundError, \
    LockoutError, ConflictError, ForbiddenError, UnauthorizedError
from middleware.auth_middleware import token_required
from middleware.rate_middleware import rate_limiter
from models.users_model import search_user_with_params
from services.auth_services import refresh_access_token, logout
from services.email_service import send_login_alert
from services.totp_services import verify_totp_service
from services.user_services import oauth_user_login, signup_normal_user, user_login_email, user_login_username, \
    generate_otp_service, verify_user_account, use_2fa, reset_password, edit_user_info, delete_user_account, \
    user_dashboard, enable_notification

load_dotenv()

user_bp = Blueprint("user", __name__)


GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI")

@user_bp.route('/auth/google')
def google_login():
    google_auth_url = (
        "https://accounts.google.com/o/oauth2/v2/auth"
        f"?client_id={GOOGLE_CLIENT_ID}"
        f"&redirect_uri={REDIRECT_URI}"
        "&response_type=code"
        "&scope=openid email profile"
    )

    return redirect(google_auth_url)

@user_bp.route("/auth/google/callback", methods=['GET'])
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
        ip_address = request.remote_addr
        location = ""
        response, status = oauth_user_login(provider="google", full_name=name, oauth_id=oauth_id, email=email)

        try:
            res = requests.get(f"http://ip-api.com/json/{ip_address}", timeout=3)
            res.raise_for_status()
            location_info = res.json()

            if location_info.get("status") == "success":

                location = f"{location_info.get('city', 'Unknown')}, {location_info.get('country', 'Unknown')}"
        except Exception as e:
            logger.warning(f"Could not fetch location for {ip_address}: {e}")

        if response.get("message") == "OAuth login successful":
            sent = send_login_alert(email, location)

            if not sent:
                logger.warning(f"Unable to send login alert email to {email}")

        return jsonify(response), status

    except (ValidationError, NotFoundError, ConflictError, LockoutError) as e:
        raise e

    except Exception as e:
        logger.error(f"exception occurred in oauth google call back: {e}", exc_info=True)
        raise InternalServerError("something went wrong")


@user_bp.route('/auth/signup', methods=['POST'])
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


@user_bp.route('/login', methods=['POST'])
@rate_limiter(capacity=5, refill_rate=0.1)
def login():
    data = request.get_json()
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")
    ip_address = request.remote_addr
    location = "Unknown"

    try:
        res = requests.get(f"http://ip-api.com/json/{ip_address}", timeout=3)
        res.raise_for_status()
        location_info = res.json()

        if location_info.get("status") == "success":
            location = f"{location_info.get('city', 'Unknown')}, {location_info.get('country', 'Unknown')}"
    except Exception as e:
        logger.warning(f"Could not fetch location for {ip_address}: {e}")

    try:
        if username:
            user = search_user_with_params(username=username)
            if not user:
                raise NotFoundError("User not found")

            email = user.get("email")
            if not all([username, password]):
                raise InsufficientDataError

            response, status = user_login_username(username, password)

            if response.get("message") == "login successful":
                sent = send_login_alert(email, location)
                if not sent:
                    logger.warning(f"Unable to send login alert email to {email}")

            return jsonify(response), status

        if email:
            if not all([email, password]):
                raise InsufficientDataError

            response, status = user_login_email(email, password)

            if response.get("message") == "login successful":
                sent = send_login_alert(email, location)
                if not sent:
                    logger.warning(f"Unable to send login alert email to {email}")

            return jsonify(response), status

        raise ValidationError("Missing username or email")

    except (ValidationError, NotFoundError, LockoutError, InsufficientDataError) as e:
        raise e

    except Exception as e:
        logger.error(f"Exception occurred in user login: {e}", exc_info=True)
        raise InternalServerError


@user_bp.route('/dashboard', methods=['GET'])
@rate_limiter(capacity=30, refill_rate=1)
@token_required(role="user")
def dashboard(user_id):
    try:
        response, status = user_dashboard(user_id)

        return jsonify(response), status

    except (NotFoundError, ValidationError, ForbiddenError, UnauthorizedError) as e:
        raise e

    except Exception as e:
        logger.error(f"exception occurred in dashboard: {e}", exc_info=True)
        raise InternalServerError


@user_bp.route('/verify-totp', methods=['POST'])
@rate_limiter(capacity=5, refill_rate=0.1)
def verify():
    data = request.get_json()
    try:
        response, status = verify_totp_service(data)

        return jsonify(response), status

    except Exception as e:
        logger.error(f"exception occurred in verify totp: {e}", exc_info=True)
        raise InternalServerError


@user_bp.route('/get-otp', methods=['GET'])
@rate_limiter(capacity=10, refill_rate=0.5)
def get_otp():
    try:
        email = request.args.get("email")

        if not email:
            raise InsufficientDataError("email required")

        response, status = generate_otp_service(email)

        return jsonify(response), status

    except (ValidationError, NotFoundError, InsufficientDataError, ForbiddenError, UnauthorizedError) as e:
        raise e

    except Exception as e:
        logger.error(f"exception occurred in get otp: {e}", exc_info=True)
        raise InternalServerError


@user_bp.route('/verify-account', methods=['PUT'])
@rate_limiter(capacity=5, refill_rate=0.1)
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


@user_bp.route('/enable-2fa', methods=['PUT'])
@rate_limiter(capacity=10, refill_rate=0.5)
@token_required()
def activate_2fa(user_id):
    try:
        data = request.get_json()

        username = data.get("username")

        response, status = use_2fa(username, user_id)

        return jsonify(response), status

    except (ValidationError, ForbiddenError, UnauthorizedError) as e:
        raise e

    except Exception as e:
        logger.error(f"exception occurred in activate 2fa route: {e}", exc_info=True)
        raise InternalServerError


@user_bp.route('/refresh-token', methods=['POST'])
@rate_limiter(capacity=30, refill_rate=1)
def refresh():
    try:
        data = request.get_json()
        token = data.get("refresh-token")
        response, status = refresh_access_token(token)

        return jsonify(response), status

    except (ValidationError, NotFoundError, jwt.InvalidTokenError,
            jwt.ExpiredSignatureError, jwt.exceptions.DecodeError) as e:
        raise e

    except Exception as e:
        logger.error(f"exception occurred in refresh token route: {e}", exc_info=True)
        raise InternalServerError


@user_bp.route('/change-password', methods=['PUT'])
@rate_limiter(capacity=5, refill_rate=0.1)
@token_required()
def new_password(user_id):
    try:
        data = request.get_json()
        password = data.get("new_password")
        old_password = data.get("old_password")

        if not all([password, old_password]):
            raise InsufficientDataError("provide your old password")

        response, status = reset_password(new_password=password, old_password=old_password, user_id=user_id)

        return jsonify(response), status

    except (ValidationError, ForbiddenError, NotFoundError, InsufficientDataError, UnauthorizedError) as e:
        raise e

    except Exception as e:
        logger.error(f"exception occurred in change password: {e}")
        raise InternalServerError


@user_bp.route('/reset-password', methods=['PUT'])
@rate_limiter(capacity=5, refill_rate=0.1)
def reset():
    try:
        data = request.get_json()
        email = data.get("email")
        password = data.get("new_password")
        otp = data.get("otp")
        signature = data.get("signature")

        if not all([email, password, otp, signature]):
            raise InsufficientDataError

        response, status = reset_password(new_password=password, email=email, otp=otp, signature=signature)
        return jsonify(response), status

    except (ValidationError, ForbiddenError, NotFoundError, InsufficientDataError) as e:
        raise e

    except Exception as e:
        logger.error(f"exception occurred in reset password: {e}")
        raise InternalServerError


@user_bp.route('/edit-info/<username>', methods=['PUT'])
@rate_limiter(capacity=30, refill_rate=1)
@token_required(role="user")
def update(user_id, username):
    try:
        data = request.get_json()

        response, status = edit_user_info(username, data)

        return jsonify(response), status

    except (ValidationError, InsufficientDataError, ForbiddenError, UnauthorizedError) as e:
        raise e

    except Exception as e:
        logger.error(f"exception occurred in edit info: {e}", exc_info=True)
        raise InternalServerError


@user_bp.route('/enable-notification', methods=['PUT'])
@token_required(role="user")
@rate_limiter(capacity=30, refill_rate=1)
def notify(user_id):
    try:
        data = request.get_json()
        token = data.get("token")

        response, status = enable_notification(token, user_id)

        return jsonify(response), status

    except (ValidationError, UnauthorizedError, ForbiddenError) as e:
        raise e

    except Exception as e:
        logger.error(f"exception occurred in enable notification: {e}", exc_info=True)
        raise InternalServerError


@user_bp.route('/delete-account', methods=['DELETE'])
@token_required(role="user")
def delete_user(user_id):
    try:
        response, status = delete_user_account(user_id)

        return jsonify(response), status

    except (ValidationError, ForbiddenError, UnauthorizedError) as e:
        raise e

    except Exception as e:
        logger.error(f"exception occurred in delete user: {e}", exc_info=True)
        raise InternalServerError


@user_bp.route('/logout', methods=['POST'])
@token_required(role=['user', 'admin'])
def logout_user(user_id):
    try:
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            raise UnauthorizedError("access token missing")

        token = auth_header.split(" ")[1]
        refresh_token = request.json.get("refresh_token")
        if not refresh_token:
            raise InsufficientDataError("refresh token missing")

        response, status = logout(user_id, token, refresh_token)

        return jsonify(response), status

    except (UnauthorizedError, InsufficientDataError, ForbiddenError, jwt.ExpiredSignatureError,
            jwt.InvalidSignatureError) as e:
        raise e

    except Exception as e:
        logger.error(f"exception occurred in logout user: {e}")
        raise InternalServerError