from error_handling.error_handler import logger
from error_handling.errors import NotFoundError, InternalServerError, InsufficientDataError, ValidationError, \
    UnauthorizedError, ForbiddenError
from models.transactions_model import get_transaction_per_user, get_transaction_with_param
from models.users_model import search_user_with_params


def view_transaction_history(user_id, limit=None, offset=None):
    try:
        user = search_user_with_params(user_id=user_id)

        if not user:
            raise NotFoundError("user not found")

        if limit and offset:
            history = get_transaction_per_user(user_id=user_id, limit=limit, offset=offset)

            if not history:
                raise NotFoundError("unable to get transaction history for user try again")

            return {
                "success": True,
                "message": "this is your transaction history for the selected period",
                "history": history
            }, 200

        history = get_transaction_per_user(user_id=user_id)

        if not history:
                raise NotFoundError("unable to get transaction history for user try again")

        return {
            "success": True,
            "message": "this is your transaction history for the selected period",
            "history": history
        }, 200

    except (NotFoundError, ValidationError, UnauthorizedError, ForbiddenError) as e:
        raise e

    except Exception as e:
        logger.error(f"exception occurred in view transaction history: {e}", exc_info=True)
        raise InternalServerError


def view_single_transaction(txn_id=None, ref=None):
    try:
        if ref:
            details = get_transaction_with_param(ref=ref, txn_id=txn_id)

            if not details:
                raise NotFoundError("transaction not found")

            return {
                "success": True,
                "message": f"this is the transaction details for txn with ref: {ref}",
                "details": details
            }, 200

        if not ref or not txn_id:
            raise InsufficientDataError("Missing required fields")

        details = get_transaction_with_param(txn_id=txn_id)

        return {
            "success": True,
            "message": f"this is the transaction details for txn_id: {txn_id}",
            "details": details
        }, 200

    except (NotFoundError, InsufficientDataError) as e:
        raise e

    except Exception as e:
        logger.error(f"exception occurred in view single transaction: {e}", exc_info=True)
        raise InternalServerError


