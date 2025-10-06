from database.connection import conn
from error_handling.error_handler import logger
from error_handling.errors import NotFoundError, InsufficientFundsError, InternalServerError, ValidationError
from utils.hashing import hash_password, verify_password


def get_wallet_by_params(account_number=None, user_id=None):
    try:
        with conn:
            with conn.cursor() as cursor:
                cursor.execute("""
                    SELECT * FROM wallets WHERE account_number = %s OR user_id = %s 
                """, (account_number, user_id))

                wallet = cursor.fetchone()

        if wallet:
            return {
                "wallet_id": wallet[0],
                "user_id": wallet[1],
                "account_number": wallet[2],
                "balance": wallet[3],
                "txn_pin": wallet[4],
                "bvn": wallet[6],
                "is_active": wallet[5]
            }

        raise NotFoundError("wallet not found")

    except Exception as e:
        logger.error(f"Exception occurred in get wallet by params: {e}", exc_info=True)
        raise InternalServerError


def create_wallet_pin(pin, user_id):
    try:
        hashed_pin = hash_password(pin)

        with conn:
            with conn.cursor() as cursor:
                cursor.execute("""
                    UPDATE wallets SET txn_pin = %s WHERE user_id = %s
                """, (hashed_pin, user_id))

        return True

    except Exception as e:
        logger.error(f"exception occurred in create wallet pin: {e}", exc_info=True)
        raise InternalServerError


def update_wallet_bvn(bvn, user_id):
    try:
        with conn:
            with conn.cursor() as cursor:
                cursor.execute("""
                    UPDATE wallets SET bvn = %s WHERE user_id = %s
                """, (bvn, user_id))

        return True

    except Exception as e:
        logger.error(f"exception occurred in update wallet bvn: {e}", exc_info=True)
        raise InternalServerError


def set_account_number(account, user_id):
    try:
        with conn:
            with conn.cursor() as cursor:
                cursor.execute("""
                    UPDATE wallets SET account_number = %s WHERE user_id = %s
                """, (account, user_id))

        return True

    except Exception as e:
        logger.error(f"exception occurred in set account number: {e}", exc_info=True)
        raise InternalServerError


def update_wallet_pin(pin, old_pin, user_id):
    try:
        wallet = get_wallet_by_params(user_id=user_id)

        if not wallet:
            raise NotFoundError("wallet not found")

        if not verify_password(old_pin, wallet["txn_pin"]):
            raise ValidationError("incorrect pin provided")

        hashed_pin = hash_password(pin)

        with conn:
            with conn.cursor() as cursor:
                cursor.execute("""
                    UPDATE wallets SET txn_pin = %s WHERE user_id = %s
                """, (hashed_pin, user_id))

        return True

    except Exception as e:
        logger.error(f"exception occurred in create wallet pin: {e}", exc_info=True)
        raise InternalServerError


def update_wallet_balance_deposit(amount, user_id):
    try:
        with conn:
            with conn.cursor() as cursor:
                cursor.execute("""
                    UPDATE wallets 
                    SET balance = balance + %s 
                    WHERE user_id = %s
                    RETURNING wallet_id, account_number;
                """, (amount, user_id))

                details = cursor.fetchone()

        if not details:
            raise NotFoundError("wallet not found")

        return details

    except Exception as e:
        logger.error(f"Exception in update_wallet_balance_deposit: {e}", exc_info=True)
        raise InternalServerError


def update_wallet_balance_debit(amount, user_id):
    try:
        with conn:
            with conn.cursor() as cursor:
                cursor.execute("""
                    UPDATE wallets 
                    SET balance = balance - %s 
                    WHERE user_id = %s AND balance >= %s
                    RETURNING wallet_id, account_number;
                """, (amount, user_id, amount))

                details = cursor.fetchone()

        if not details:
            raise InsufficientFundsError(f"Not enough funds for debit of: {amount}")

        return details

    except Exception as e:
        logger.error(f"Exception in update_wallet_balance_debit: {e}", exc_info=True)
        raise InternalServerError


def update_wallet_status(status: bool, user_id):
    try:
        with conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "UPDATE wallets SET is_active = %s WHERE user_id = %s",
                    (status, user_id)
                )

        return True
    except Exception as e:
        logger.error(f"Error updating wallet active status: {e}", exc_info=True)
        raise InternalServerError
