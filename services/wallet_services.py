from error_handling.error_handler import logger
from error_handling.errors import NotFoundError, ValidationError, LockoutError, UnauthorizedError, \
    InsufficientFundsError, InternalServerError, ConflictError
from models.transactions_model import create_transaction, update_transaction_status
from models.wallets_model import (create_wallet_pin, update_wallet_status, get_wallet_by_params,
                            update_wallet_balance_debit, update_wallet_balance_deposit)
from utils.hashing import verify_password, generate_id
from utils.rate_limiter import register_failed_login, is_user_locked_out, clear_failed_attempts


def transfer_between_wallet(amount, to_account, from_account, pin):
    txn_base = generate_id(15)  # shared base ID for both transactions
    debit_txn_id = f"{txn_base}D"
    credit_txn_id = f"{txn_base}C"

    try:
        from_wallet = get_wallet_by_params(account_number=from_account)
        to_wallet = get_wallet_by_params(account_number=to_account)

        if not to_wallet:
            raise NotFoundError("receiver account number not found")

        if is_user_locked_out(scope="wallet", identifier=from_wallet["wallet_id"]):
            raise LockoutError

        if not from_wallet["is_active"]:
            raise UnauthorizedError("Your wallet has been suspended, contact admin")

        if not verify_password(pin, from_wallet["txn_pin"]):
            register_failed_login(scope="wallet", identifier=from_wallet["wallet_id"])
            raise ValidationError("Incorrect PIN try again, note you will be lockout after 3 attempts")

        if from_wallet["balance"] < amount:
            raise InsufficientFundsError(details={"available": from_wallet["balance"], "required": amount})

        credit = update_wallet_balance_deposit(amount, to_wallet["user_id"])
        debit = update_wallet_balance_debit(amount, from_wallet["user_id"])
        new_balance = from_wallet["balance"] - amount

        create_transaction(
            debit_txn_id,
            from_wallet["wallet_id"],
            from_wallet["user_id"],
            "debit",
            amount,
            from_account=from_wallet,
            to_account=to_wallet
        )

        create_transaction(
            credit_txn_id,
            to_wallet["wallet_id"],
            to_wallet["user_id"],
            "credit",
            amount,
            from_account=from_wallet,
            to_account=to_wallet
        )

        if credit and not debit:
            update_transaction_status("failed", debit_txn_id)
            update_wallet_balance_debit(amount, to_wallet["user_id"])  # rollback credit

        if debit and not credit:
            update_transaction_status("failed", credit_txn_id)
            update_wallet_balance_deposit(amount, from_wallet["user_id"])  # rollback debit

        if debit and credit:
            clear_failed_attempts(scope="wallet", identifier=from_wallet["wallet_id"])
            update_transaction_status("success", debit_txn_id)
            update_transaction_status("success", credit_txn_id)

            return {
                "success": True,
                "message": "transfer successful, recipient will be credited shortly",
                "balance": new_balance
            }, 200

        raise ValidationError("Unexpected error occurred in transfer")

    except (UnauthorizedError, ValidationError, NotFoundError, InsufficientFundsError, LockoutError) as e:
        raise e

    except Exception as e:
        update_transaction_status("failed", debit_txn_id)
        update_transaction_status("failed", credit_txn_id)
        logger.error(f"exception occurred in transfer between wallet: {e}", exc_info=True)
        raise InternalServerError



def set_wallet_pin(pin, user_id):
    try:
        user = get_wallet_by_params(user_id=user_id)

        if not user:
            raise NotFoundError

        updated = create_wallet_pin(pin, user_id)

        if not updated:
            raise ValidationError("Failed to set transaction PIN")


        return {
            "success": True,
            "message": "transaction pin updated"
        }, 200

    except (ValidationError, NotFoundError) as e:
        raise e

    except Exception as e:
        logger.error(f"exception occurred in set txn pin: {e}", exc_info=True)
        raise InternalServerError


def deactivate_wallet(user_id):
    try:

        set_state = update_wallet_status(user_id=user_id, status=False)

        if set_state:
            return {
                "success": True,
                "message": "user wallet disabled"
            }, 200

        raise ConflictError("Could not update wallet status")

    except ConflictError as e:
        raise e

    except Exception as e:
        logger.error(f"exception occurred in disable user: {e}", exc_info=True)
        raise InternalServerError


def activate_wallet(user_id):
    try:

        set_state = update_wallet_status(user_id=user_id, status=True)

        if set_state:
            return {
                "success": True,
                "message": "user wallet enabled"
            }, 200

        raise ConflictError("Could not update wallet status")

    except ConflictError as e:
        raise e

    except Exception as e:
        logger.error(f"exception occurred in disable user: {e}", exc_info=True)
        raise InternalServerError