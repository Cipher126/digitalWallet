from database.connection import conn
from error_handling.error_handler import logger
from error_handling.errors import NotFoundError, InsufficientFundsError
from models.transactions_model import create_transaction
from utils.hashing import hash_password


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
                "is_active": wallet[5]
            }

        raise NotFoundError("wallet not found")

    except Exception as e:
        logger.error(f"Exception occurred in get wallet by params: {e}", exc_info= True)
        raise

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
        raise


def update_wallet_balance_deposit(amount, user_id):
    try:

        with conn:
            with conn.cursor() as cursor:
                cursor.execute("""
                    UPDATE wallets SET balance = balance + %s WHERE user_id = %s
                    RETURNING wallet_id, account_number;
                """, (amount, user_id))

                details = cursor.fetchone()

        if not details:
            raise NotFoundError("wallet not found")

        wallet_id, to_account = details

        if not details:
            raise NotFoundError("wallet does not exist")

        create_transaction(wallet_id, user_id, "credit", amount=amount, to_account=to_account)

        return True

    except Exception as e:
        logger.error(f"exception occurred in update wallet balance: {e}", exc_info=True)
        raise


def update_wallet_balance_debit(amount, user_id):
    try:

        with conn:
            with conn.cursor() as cursor:
                cursor.execute("""
                    UPDATE wallets SET balance = balance - %s WHERE user_id = %s AND balance >= %s
                    RETURNING wallet_id, account_number;
                """, (amount, user_id))

                details = cursor.fetchone()

        if not details:
            raise NotFoundError("wallet not found")

        wallet_id, from_account = details

        if not details:
            raise InsufficientFundsError(f"not enough funds for debit of: {amount}")

        create_transaction(wallet_id, user_id, "debit", amount=amount, from_account=from_account)

        return True

    except Exception as e:
        logger.error(f"exception occurred in create wallet pin: {e}", exc_info=True)
        raise

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
        raise
