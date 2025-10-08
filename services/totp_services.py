from error_handling.error_handler import logger
from error_handling.errors import ValidationError, NotFoundError, LockoutError, InsufficientDataError, \
    InternalServerError
from models.users_model import generate_tokens, search_user_with_params
from services.audit_services import log_action
from utils.lockout import clear_failed_attempts, register_failed_login, is_user_locked_out
from utils.totp_utils import verify_totp


def verify_totp_service(data):
    try:
        identifier = data.get("identifier")
        otp = data.get("otp")

        if not all([identifier, otp]):
            raise InsufficientDataError("Please provide identifier and otp code")

        user = search_user_with_params(username=identifier)
        # print(user)

        if not user:
            raise NotFoundError("User not found")

        if is_user_locked_out(identifier=user["user_id"], scope="user"):
            raise LockoutError("Account locked due to too many failed attempts, try later")

        if not verify_totp(user["otp_secret"], otp):
            register_failed_login(identifier=user["user_id"], scope="user")
            log_action(user_id=user["user_id"], action="failed 2FA attempt", metadata={"identifier": identifier})
            raise ValidationError("Invalid 2FA code")

        clear_failed_attempts(identifier=user["user_id"], scope="user")

        access, refresh = generate_tokens(user["user_id"], user["role"])

        log_action(user_id=user["user_id"], action="successful 2FA login", metadata={"identifier": identifier})

        return {
            "success": True,
            "message": "2FA verification successful",
            "tokens": {
                "access_token": access,
                "refresh_token": refresh
            },
            "username": user["username"]
        }, 200

    except (ValidationError, NotFoundError, LockoutError, InsufficientDataError) as e:
        raise e
    except Exception as e:
        logger.error(f"Exception in verify_otp_service: {e}", exc_info=True)
        raise InternalServerError
