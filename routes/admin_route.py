from flask import Blueprint, request, jsonify

from error_handling.error_handler import logger
from error_handling.errors import UnauthorizedError, ForbiddenError, ConflictError, InternalServerError, \
    ValidationError, NotFoundError
from middleware.auth_middleware import token_required
from middleware.rate_middleware import rate_limiter
from services.audit_services import view_user_log_history, view_all_log_history
from services.user_services import disable_user, enable_user
from services.wallet_services import deactivate_wallet, activate_wallet

admin_bp = Blueprint("admin", __name__)

@admin_bp.route('/deactivate-user/<identifier>', methods=['PUT'])
@rate_limiter(capacity=10, refill_rate=0.5)
@token_required(role="admin")
def deactivate(user_id, identifier):
    try:
        response, status = disable_user(identifier)

        return jsonify(response), status

    except (UnauthorizedError, ForbiddenError, ConflictError) as e:
        raise e

    except Exception as e:
        logger.error(f"exception occurred in deactivate: {e}", exc_info=True)
        raise InternalServerError


@admin_bp.route('/activate-user/<identifier>', methods=['PUT'])
@rate_limiter(capacity=10, refill_rate=0.5)
@token_required(role="admin")
def activate(user_id, identifier):
    try:
        response, status = enable_user(identifier)

        return jsonify(response), status

    except (UnauthorizedError, ForbiddenError, ConflictError) as e:
        raise e

    except Exception as e:
        logger.error(f"exception occurred in deactivate: {e}", exc_info=True)
        raise InternalServerError


@admin_bp.route('/freeze-wallet/<identifier>', methods=['PUT'])
@rate_limiter(capacity=10, refill_rate=0.5)
@token_required(role="user")
def freeze(user_id, identifier):
    try:
        response, status = deactivate_wallet(identifier)

        return jsonify(response), status

    except (UnauthorizedError, ForbiddenError, ConflictError) as e:
        raise e

    except Exception as e:
        logger.error(f"exception occurred in deactivate: {e}", exc_info=True)
        raise InternalServerError


@admin_bp.route('/unfreeze-wallet/<identifier>', methods=['PUT'])
@rate_limiter(capacity=10, refill_rate=0.5)
@token_required(role="user")
def freeze(user_id, identifier):
    try:
        response, status =  activate_wallet(identifier)

        return jsonify(response), status

    except (UnauthorizedError, ForbiddenError, ConflictError) as e:
        raise e

    except Exception as e:
        logger.error(f"exception occurred in deactivate: {e}", exc_info=True)
        raise InternalServerError


@admin_bp.route('/user_logs/<username>', methods=['GET'])
@rate_limiter(capacity=30, refill_rate=1)
@token_required(role="admin")
def view_user_activity(user_id, username):
    try:
        limit = request.args.get("limit", type=int)

        response, status = view_user_log_history(username, limit)

        return jsonify(response), status

    except (NotFoundError, ForbiddenError, UnauthorizedError, ValidationError) as e:
        raise e

    except Exception as e:
        logger.error(f"exception occurred in view user activity: {e}", exc_info=True)
        raise InternalServerError


@admin_bp.route('/view_logs', methods=['GET'])
@rate_limiter(capacity=30, refill_rate=1)
@token_required(role="admin")
def view_activity(user_id):
    try:
        limit = request.args.get("limit", type=int)

        response, status = view_all_log_history(limit)

        return jsonify(response), status

    except (NotFoundError, ForbiddenError, UnauthorizedError, ValidationError) as e:
        raise e

    except Exception as e:
        logger.error(f"exception occurred in view user activity: {e}", exc_info=True)
        raise InternalServerError