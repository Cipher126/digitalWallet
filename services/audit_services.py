from error_handling.error_handler import logger
from error_handling.errors import NotFoundError, ForbiddenError, UnauthorizedError, ValidationError, InternalServerError
from models.audit_logs_model import insert_audit_log, get_user_audit_logs, get_audit_log
from models.users_model import search_user_with_params


def log_action(user_id, action, metadata=None):
    insert_audit_log(
        user_id=user_id,
        action=action,
        metadata=metadata
    )


def view_user_log_history(username, limit=None):
    try:
        user = search_user_with_params(username=username)

        if not user:
            raise NotFoundError("user does not exist")

        user_id = user["user_id"]

        history = get_user_audit_logs(user_id, limit)

        if not history:
            raise NotFoundError("logs history not found")

        return {
            "success": True,
            "message": "successful, logs retrieved",
            "logs_history": history
        }, 200

    except (NotFoundError, ForbiddenError, UnauthorizedError, ValidationError) as e:
        raise e

    except Exception as e:
        logger.error(f"exception occurred in view user log history: {e}", exc_info=True)
        raise InternalServerError


def view_all_log_history(limit=None):
    try:
        history = get_audit_log(limit)

        if not history:
            raise NotFoundError("logs history not found")

        return {
            "success": True,
            "message": "successful, logs retrieved",
            "logs_history": history
        }, 200

    except (NotFoundError, ForbiddenError, UnauthorizedError, ValidationError) as e:
        raise e

    except Exception as e:
        logger.error(f"exception occurred in view user log history: {e}", exc_info=True)
        raise InternalServerError