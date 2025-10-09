from flask import Blueprint, request, jsonify

from error_handling.error_handler import logger
from error_handling.errors import InsufficientDataError, ValidationError, NotFoundError, InternalServerError, \
    UnauthorizedError, ForbiddenError, LockoutError, InsufficientFundsError
from middleware.auth_middleware import token_required
from middleware.rate_middleware import rate_limiter
from models.wallets_model import get_wallet_by_params
from services.monnify_services import process_outgoing_transfer
from services.wallet_services import set_wallet_pin, change_wallet_pin, transfer_between_wallet, activate_wallet

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


@wallet_bp.route('/activate', methods=['POST'])
@rate_limiter(capacity=5, refill_rate=0.1)
@token_required(role="user")
def activate(user_id):
    try:
        data = request.get_json()
        bvn = data.get("bvn")

        response, status = activate_wallet(user_id, bvn)

        return jsonify(response), status

    except (ValidationError, UnauthorizedError, NotFoundError, ForbiddenError) as e:
        raise e

    except Exception as e:
        logger.error(f"exception occurred in activate wallet: {e}", exc_info=True)
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


@wallet_bp.route('/transfer/internal', methods=['POST'])
@rate_limiter(capacity=5, refill_rate=0.1)
@token_required(role=["user", "admin"])
def transfer(user_id):
    try:
        data = request.get_json()
        amount = float(data.get("amount"))
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


@wallet_bp.route('/transfer/external', methods=['POST'])
@rate_limiter(capacity=5, refill_rate=0.1)
@token_required(role=["user", "admin"])
def external(user_id):
    try:
        data = request.get_json()
        amount = data.get("amount")
        bank_code = data.get("bank_code")
        destination_account = data.get("destination_account")
        narration = data.get("narration")

        account_number = get_wallet_by_params(user_id=user_id)["account_number"]

        if not account_number:
            raise NotFoundError("wallet not found")

        response, status = process_outgoing_transfer(
            account_number,
            amount,
            bank_code,
            destination_account,
            narration
        )

        return jsonify(response), status

    except (InsufficientFundsError, NotFoundError) as e:
        raise e

    except Exception as e:
        logger.error(f"Error initiating interbank transfer: {e}", exc_info=True)
        raise