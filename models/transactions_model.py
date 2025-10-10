import json
from decimal import Decimal

from database.connection import conn
from error_handling.error_handler import logger
from error_handling.errors import NotFoundError
from models.audit_logs_model import insert_audit_log
from models.webhook_logs_model import insert_webhook_log
from utils.hashing import generate_reference, generate_id


def create_transaction(wallet_id, user_id, txn_type, amount, txn_id=None,
                       to_account=None, from_account=None, reference=None, description=""):
    """Insert a transaction record"""
    try:
        if not txn_id:
            txn_id = generate_id(20)
        if not reference:
            reference = generate_reference()

        metadata = {
            "sender_account": from_account,
            "receiver_account": to_account
        }

        metadata = {k: str(v) if isinstance(v, Decimal) else v for k, v in metadata.items()}

        with conn:
            with conn.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO transactions (txn_id, wallet_id, user_id, txn_type, amount, reference, metadata)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                """, (txn_id, wallet_id, user_id, txn_type, amount, reference, json.dumps(metadata)))

        insert_audit_log(user_id, "TRANSACTION_CREATED", {
            "type": txn_type,
            "amount": amount,
            "description": description
        })

        insert_webhook_log("wallet.transaction", {
            "user_id": user_id,
            "type": txn_type,
            "amount": amount,
            "description": description
        })

        return txn_id

    except Exception as e:
        logger.error(f"Error creating transaction: {e}", exc_info=True)
        raise


def get_transaction_with_param(ref=None, txn_id=None):
    try:
        with conn:
            with conn.cursor() as cursor:
                cursor.execute("""
                    SELECT * FROM transactions WHERE reference = %s OR txn_id = %s
                """, (ref, txn_id))

                txn = cursor.fetchone()

        if not txn:
            raise NotFoundError("transaction not found")

        return {
            "txn_id": txn[0],
            "wallet_id": txn[1],
            "user_id": txn[2],
            "txn_type": txn[3],
            "amount": txn[4],
            "status": txn[5],
            "reference": txn[6],
            "metadata": txn[7] if txn[7] else None,
            "created_at": txn[8]
        }

    except Exception as e:
        logger.error(f"exception occurred in get transaction with params: {e}", exc_info=True)
        raise

def get_transaction_per_user(user_id, limit=None, offset=None):
    try:
        with conn:
            with conn.cursor() as cursor:
                if limit and offset:
                    cursor.execute("""
                        SELECT * FROM transactions WHERE user_id = %s ORDER BY created_at DESC LIMIT %s OFFSET %s
                    """, (user_id, limit, offset))

                else:
                    cursor.execute("""
                        SELECT * FROM transactions WHERE user_id = %s ORDER BY created_at DESC
                    """, (user_id, ))

                txn = cursor.fetchall()

        if not txn:
            raise NotFoundError("transaction not found")

        txn_list = []

        for t in txn:
            txn_list.append({
                "txn_id": t[0],
                "wallet_id": t[1],
                "user_id": t[2],
                "txn_type": t[3],
                "amount": t[4],
                "status": t[5],
                "reference": t[6],
                "metadata": t[7] if t[7] else None,
                "created_at": t[8]
            })

        return txn_list

    except Exception as e:
        logger.error(f"exception occurred in get transaction per user: {e}", exc_info=True)
        raise


def update_transaction_status(status: str, txn_id):
    try:
        with conn:
            with conn.cursor() as cursor:
                cursor.execute("""
                    UPDATE transactions SET status = %s WHERE txn_id = %s
                """, (status, txn_id))

        return True

    except Exception as e:
        logger.error(f"exception occurred in update transaction status: {e}", exc_info=True)
        raise