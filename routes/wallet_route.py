from flask import Blueprint, request, jsonify

from error_handling.error_handler import logger
from error_handling.errors import InsufficientDataError, ValidationError, NotFoundError, InternalServerError, \
    UnauthorizedError, ForbiddenError, LockoutError, InsufficientFundsError
from middleware.auth_middleware import token_required
from middleware.rate_middleware import rate_limiter
from services.wallet_services import set_wallet_pin, change_wallet_pin, transfer_between_wallet

wallet_bp = Blueprint("wallet", __name__)

@wallet_bp.route('/set-pin', methods=['POST'])
@rate_limiter(capacity=5, refill_rate=0.1)
@token_required(role="user")
def set_pin(user_id):
    try:
        data = request.get_json()
        pin = data.get("pin")

        if not pin:
            raise InsufficientDataError("provide new wallet pin")

        response, status = set_wallet_pin(pin, user_id)

        return jsonify(response), status

    except (ValidationError, NotFoundError, InsufficientDataError, UnauthorizedError, ForbiddenError) as e:
        raise e

    except Exception as e:
        logger.error(f"exception occurred in set wallet pin: {e}", exc_info=True)
        raise InternalServerError


@wallet_bp.route('/change-pin', methods=['PUT'])
@rate_limiter(capacity=5, refill_rate=0.1)
@token_required(role="user")
def change(user_id):
    try:
        data = request.get_json()
        pin = data.get("pin")
        old_pin = data.get("old_pin")

        if not pin and old_pin:
            raise InsufficientDataError("provide new wallet pin and old pin")

        response, status = change_wallet_pin(pin, old_pin, user_id)

        return jsonify(response), status

    except (ValidationError, NotFoundError, InsufficientDataError, UnauthorizedError, ForbiddenError) as e:
        raise e

    except Exception as e:
        logger.error(f"exception occurred in set wallet pin: {e}", exc_info=True)
        raise InternalServerError


@wallet_bp.route('/transfer', methods=['POST'])
@rate_limiter(capacity=5, refill_rate=0.1)
@token_required(role="user")
def transfer(user_id):
    try:
        data = request.get_json()
        amount = data.get("amount")
        to_account = data.get("to_account")
        from_account = data.get("from_account")
        pin = data.get("pin")

        response, status = transfer_between_wallet(amount, to_account, from_account, pin)

        return jsonify(response), status

    except (UnauthorizedError, ValidationError, NotFoundError,
            InsufficientFundsError, LockoutError, ForbiddenError) as e:
        raise e

    except Exception as e:
        logger.error(f"exception occurred in transfer: {e}", exc_info=True)
        raise InternalServerError