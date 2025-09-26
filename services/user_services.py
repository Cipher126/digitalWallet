from error_handling.error_handler import logger
from error_handling.errors import ConflictError, InsufficientDataError, InternalServerError, \
    ValidationError, NotFoundError, LockoutError
from models.users_model import (create_user, get_user_by_oauth, oauth_login,
                                authenticate_user_with_email, authenticate_user_with_username,
                                search_user_with_params, verify_user, update_user_info, update_user_password,
                                update_user_active_status, enable_2fa, delete_account)

from services.audit_services import log_action
from utils.hashing import generate_username
from utils.rate_limiter import register_failed_login, is_user_locked_out, clear_failed_attempts
from utils.totp_utils import generate_totp_secret, generate_totp_uri, verify_totp


def signup_normal_user(data):
    email = data.get("email")
    username = data.get("username")
    full_name = data.get("full_name")
    phone = data.get("phone")
    password = data.get("password")

    try:

        if not all([email, username, full_name, phone, password]):
            raise InsufficientDataError("not enough data provided, missing some required fields")

        try:
            user = search_user_with_params(username=username)
            if user:
                raise ConflictError("User already exists")
        except NotFoundError:
            pass

        new_user = create_user(email, username, full_name, phone, password)
        log_action(username, "register_user", {"email":email})

        return {
            "message": "user created successfully",
            "user_details": new_user
        }, 201

    except (ValidationError, NotFoundError, ConflictError, LockoutError) as e:
        raise e

    except Exception as e:
        logger.error(f"exception occurred in signup normal user: {e}", exc_info=True)
        raise InternalServerError


def oauth_user_login(provider, oauth_id, email, full_name=None, phone=None, otp=None):
    try:
        user = oauth_login(provider=provider, oauth_id=oauth_id, full_name=full_name, email=email)

        if user:
            if user.get("two_fa_enabled"):
                if not otp:
                    raise ValidationError("2FA code required")
                if not verify_totp(user["totp_secret"], otp):
                    register_failed_login(identifier=user["user_id"], scope="user")
                    raise ValidationError("invalid 2FA code")

            clear_failed_attempts(identifier=user["user_id"], scope="user")
            log_action(user_id=user["user_id"], action="oauth login", metadata={"provider":provider})
            return {
                "success": True,
                "message": "user login by OAUTH",
                "user":user
            }, 200

        if email:
            existing_user = search_user_with_params(email=email)
            if existing_user:
                raise ConflictError("User already exists with this email, please login normally")

        username = generate_username()

        new = create_user(oauth_provider=provider, oauth_id=oauth_id, username=username, full_name=full_name, email=email, phone=phone)

        log_action(new["user_id"], "oauth signup", {"provider": provider})

        return {
            "success": True,
            "message": "oauth signup successful",
            "user": new,
        }, 201

    except (ValidationError, NotFoundError, ConflictError, LockoutError) as e:
        raise e

    except Exception as e:
        logger.error(f"Exception occurred in oauth user signup: {e}", exc_info=True)
        raise InternalServerError


def user_login_email(data):
    try:
        email = data.get("email")
        password = data.get("password")
        otp_code = data.get("otp")


        if not all([email, password]):
            raise InsufficientDataError("please provide your email and password")

        user = search_user_with_params(email=email)

        if not user:
            raise NotFoundError("user does not exist")

        if is_user_locked_out(identifier=user["user_id"], scope="user"):
            raise LockoutError("account locked due to too many failed attempts, try later")

        verified = authenticate_user_with_email(email, password)

        if not verified:
            register_failed_login(identifier=user["user_id"], scope="user")
            log_action(user_id=user["user_id"], action="failed login attempt", metadata={"email": email})
            raise ValidationError("incorrect password or email address")


        if user["two_fa_enabled"]:
            if not otp_code:
                raise InsufficientDataError

            if not verify_totp(user["otp_secret"], otp_code):
                register_failed_login(identifier=user["user_id"], scope="user")
                raise ValidationError("invalid otp")

        clear_failed_attempts(identifier=user["user_id"], scope="user")

        return {
            "success": True,
            "message": "login successful",
            "user": verified
        }, 200

    except (ValidationError, NotFoundError, InsufficientDataError, LockoutError) as e:
        raise e

    except Exception as e:
        logger.error(f"exception occurred in user login email: {e}", exc_info=True)
        raise InternalServerError

def user_login_username(data):
    try:
        username = data.get("username")
        password = data.get("password")
        otp_code = data.get("otp")

        if not all([username, password]):
            raise InsufficientDataError("please provide your username and password")

        user = search_user_with_params(username=username)

        if not user:
            raise NotFoundError("user does not exist")

        if is_user_locked_out(identifier=user["user_id"], scope="user"):
            raise LockoutError("account locked due to too many failed attempts, try later")

        verified = authenticate_user_with_username(username, password)

        if not verified:
            register_failed_login(identifier=user["user_id"], scope="user")
            log_action(user_id=user["user_id"], action="failed login attempt", metadata={"username":username})
            raise ValidationError("incorrect password or username")

        if user["two_fa_enabled"]:
            if not otp_code:
                raise InsufficientDataError

            if not verify_totp(user["otp_secret"], otp_code):
                register_failed_login(identifier=user["user_id"], scope="user")
                raise ValidationError("invalid otp")

        clear_failed_attempts(identifier=user["user_id"], scope="user")

        return {
            "success": True,
            "message": "login successful",
            "user": verified
        }, 200

    except (ValidationError, NotFoundError, LockoutError, InsufficientDataError) as e:
        raise e

    except Exception as e:
        logger.error(f"Exception occurred in user login username: {e}", exc_info=True)
        raise InternalServerError


def verify_user_account(user_id):
    try:
        verified = verify_user(user_id, True)

        if verified:
            return {
                "success": True,
                "message": "user verified successfully"
            }, 200

        raise ValidationError("unable to verify user")

    except ValidationError as e:
        raise e

    except Exception as e:
        logger.error(f"exception occurred in verify user account: {e}", exc_info=True)
        raise InternalServerError


def use_2fa(username, user_id):
    try:
        secret = generate_totp_secret()

        enabled = enable_2fa(user_id, secret, True)

        if enabled:
            uri = generate_totp_uri(secret, username)

            return {
                "success": True,
                "message": "2-FA enabled",
                "totp_uri": uri
            }, 200

        raise ValidationError("unable to enable 2fa try again")

    except ValidationError as e:
        raise e

    except Exception as e:
        logger.error(f"exception occurred in use 2fa: {e}", exc_info=True)
        raise InternalServerError


def reset_password(email, new_password):
    try:
        reset = update_user_password(email, new_password)

        if reset:
            return {
                "success": True,
                "message": "password has been changed successfully"
            }, 200

        raise NotFoundError

    except NotFoundError as e:
        raise e

    except Exception as e:
        logger.error(f"exception occurred in reset password: {e}", exc_info=True)
        raise InternalServerError


def disable_user(user_id):
    try:

        set_state = update_user_active_status(user_id, is_active=False)

        if set_state:
            return {
                "success": True,
                "message": "user account disabled"
            }, 200

        raise ConflictError

    except ConflictError as e:
        raise e

    except Exception as e:
        logger.error(f"exception occurred in disable user: {e}", exc_info=True)
        raise InternalServerError


def enable_user(user_id):
    try:

        set_state = update_user_active_status(user_id, is_active=True)

        if set_state:
            return {
                "success": True,
                "message": "user account enabled"
            }, 200

        raise ConflictError

    except ConflictError as e:
        raise e

    except Exception as e:
        logger.error(f"exception occurred in enable user: {e}", exc_info=True)
        raise InternalServerError


def edit_user_info(username, data):
    try:
        allowed = {'username', 'name', 'email', 'full_name', 'phone'}
        update = {k : v for k, v in data.items() if k in allowed and v is not None}

        if not update:
            raise InsufficientDataError

        updated = update_user_info(username, update)

        if updated:
            return {
                "success": True,
                "message": "user info has been updated successfully"
            }, 200

        raise ValidationError

    except (ValidationError, InsufficientDataError) as e:
        raise e

    except Exception as e:
        logger.error(f"exception occurred in edit user info: {e}", exc_info=True)
        raise InternalServerError


def delete_user_account(user_id):
    try:
        deleted = delete_account(user_id)

        if deleted:
            return {
                "success": True,
                "message": "account deleted"
            }, 200

        raise ValidationError

    except ValidationError as e:
        raise e

    except Exception as e:
        logger.error(f"exception occurred in delete user account: {e}", exc_info=True)
        raise InternalServerError