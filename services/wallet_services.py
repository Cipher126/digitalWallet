from error_handling.error_handler import logger
from error_handling.errors import NotFoundError, ValidationError, LockoutError, UnauthorizedError, \
    InsufficientFundsError, InternalServerError, ConflictError, ForbiddenError
from models.transactions_model import create_transaction, update_transaction_status
from models.users_model import search_user_with_params
from models.wallets_model import (create_wallet_pin, update_wallet_status, get_wallet_by_params,
                                  update_wallet_balance_debit, update_wallet_balance_deposit, update_wallet_pin,
                                  update_wallet_bvn, set_account_number)
from services.email_service import send_transaction_notification
from services.monnify_services import create_reserved_account
from services.notification_services import send_txn_push
from utils.hashing import verify_password, generate_id
from utils.lockout import register_failed_login, is_user_locked_out, clear_failed_attempts


def activate_wallet(user_id, bvn):
    try:
        wallet = get_wallet_by_params(user_id=user_id)

        if not wallet:
            raise NotFoundError("wallet not found")

        user = search_user_with_params(user_id=user_id)
        email = user["email"]
        name = user["name"]

        reserved_account = create_reserved_account(user_id, name, email, bvn)

        if not reserved_account:
            raise ValidationError("unable to create account number for user")

        new_bvn = update_wallet_bvn(bvn, user_id)

        if not new_bvn:
            raise ValidationError("unable to update user bvn")


        account_number = reserved_account["accountNumber"]

        account = set_account_number(account_number, user_id)

        if not account:
            raise ValidationError("unable to save account number to db")

        return {
            "success": True,
            "message": "wallet activation successful",
            "account_number": account_number
        }, 201

    except (ValidationError, UnauthorizedError, NotFoundError, ForbiddenError) as e:
        raise e

    except Exception as e:
        logger.error(f"exception occurred in activate wallet: {e}", exc_info=True)
        raise InternalServerError


def transfer_between_wallet(amount, to_account, from_account, pin):
    txn_base = generate_id(15)
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
            txn_id = debit_txn_id,
            wallet_id=from_wallet["wallet_id"],
            user_id=from_wallet["user_id"],
            txn_type="debit",
            amount=amount,
            from_account=from_wallet,
            to_account=to_wallet
        )

        create_transaction(
            txn_id=credit_txn_id,
            wallet_id=to_wallet["wallet_id"],
            user_id=to_wallet["user_id"],
            txn_type="credit",
            amount=amount,
            from_account=from_wallet,
            to_account=to_wallet
        )

        if credit and not debit:
            update_transaction_status("failed", debit_txn_id)
            update_wallet_balance_debit(amount, to_wallet["user_id"])

        if debit and not credit:
            update_transaction_status("failed", credit_txn_id)
            update_wallet_balance_deposit(amount, from_wallet["user_id"])  # rollback debit

        if debit and credit:
            debit_user = search_user_with_params(user_id=from_wallet["user_id"])
            debit_email = debit_user["email"]
            debit_name = debit_user["name"]

            debit_sent = send_transaction_notification(debit_email, debit_name, "debit", amount, new_balance)
            debit_push = send_txn_push(from_wallet["user_id"], "debit", amount, new_balance)

            if not debit_sent or not debit_push:
                logger.warn(f"unable to send debit alert: {debit_sent or debit_push}", exc_info=True)

            credit_user = search_user_with_params(user_id=to_wallet["user_id"])
            credit_email = credit_user["email"]
            credit_name = credit_user["name"]
            credit_wallet = get_wallet_by_params(account_number=to_account)
            credit_balance = credit_wallet["balance"]

            credit_push = send_txn_push(to_wallet["user_id"], "credit", amount, credit_balance)

            credit_sent = send_transaction_notification(credit_email, credit_name, "credit", amount, credit_balance)

            if not credit_sent or not credit_push:
                logger.warn(f"unable to send credit alert: {credit_sent or credit_push}", exc_info=True)

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
            "message": "transaction pin created"
        }, 200

    except (ValidationError, NotFoundError) as e:
        raise e

    except Exception as e:
        logger.error(f"exception occurred in set txn pin: {e}", exc_info=True)
        raise InternalServerError


def change_wallet_pin(pin, old_pin,  user_id):
    try:
        user = get_wallet_by_params(user_id=user_id)

        if not user:
            raise NotFoundError

        updated = update_wallet_pin(pin, old_pin, user_id)

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