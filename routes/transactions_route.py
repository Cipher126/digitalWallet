from flask import Blueprint, request, jsonify

from error_handling.error_handler import logger
from error_handling.errors import InternalServerError, NotFoundError, ValidationError, UnauthorizedError, \
    ForbiddenError, InsufficientDataError
from middleware.auth_middleware import token_required
from middleware.rate_middleware import rate_limiter
from services.transaction_services import view_transaction_history, view_single_transaction

txn_bp = Blueprint("transaction", __name__)


@txn_bp.route('/transaction-history', methods=['GET'])
@rate_limiter(capacity=30, refill_rate=1)
@token_required(role=["user", "admin"])
def history(user_id):
    try:
        limit = request.args.get("limit", type=int)
        offset = request.args.get("offset", type=int)

        response, status = view_transaction_history(user_id, limit, offset)

        return jsonify(response), status

    except (NotFoundError, ValidationError, UnauthorizedError, ForbiddenError) as e:
        raise e

    except Exception as e:
        logger.error(f"exception occurred in view transaction history: {e}", exc_info=True)
        raise InternalServerError


@txn_bp.route('/view-single-transaction/<reference>', methods=['GET'])
@rate_limiter(capacity=30, refill_rate=1)
@token_required(role=["user", "admin"])
def single_txn(user_id, reference):
    try:
        response, status = view_single_transaction(ref=reference)

        return jsonify(response), status

    except (NotFoundError, InsufficientDataError, ForbiddenError, UnauthorizedError) as e:
        raise e

    except Exception as e:
        logger.error(f"exception occurred in view single transaction: {e}", exc_info=True)
        raise InternalServerError