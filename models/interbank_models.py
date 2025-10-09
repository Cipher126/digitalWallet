from database.connection import conn
from error_handling.error_handler import logger
from error_handling.errors import NotFoundError
from models.audit_logs_model import insert_audit_log
from models.webhook_logs_model import insert_webhook_log
from utils.hashing import generate_id


def insert_interbank_transfer(user_id, wallet_id, amount, destination_bank_code,
                              destination_account_number, beneficiary_name, narration):
    transfer_id = generate_id(20)

    try:
        with conn:
            with conn.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO interbank_transfers (transfer_id, user_id, wallet_id, amount, destination_bank_code,
                                  destination_account_number, beneficiary_name, narration)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """, (transfer_id, user_id, wallet_id, amount, destination_bank_code,
                      destination_account_number, beneficiary_name, narration)
                )

        insert_audit_log(user_id=user_id, action="Interbank transaction",
                         metadata={
                             "amount": amount,
                             "destination": destination_account_number,
                             "wallet_id": wallet_id,
                             "transfer_id": transfer_id,
                         }
        )

        insert_webhook_log("interbank.transaction", {
            "user_id": user_id,
            "type": "interbank transaction",
            "amount": amount,
            "wallet_id": wallet_id
        })

        return transfer_id

    except Exception as e:
        logger.error(f"exception occurred in insert interbank transfer: {e}", exc_info=True)
        raise


def update_interbank_status(transfer_id, mon_ref, status):
    try:
        with conn:
            with conn.cursor() as cursor:
                cursor.execute("""
                    UPDATE interbank_transfers SET monnify_reference = %s, status = %s WHERE transfer_id = %s
                    RETURNING user_id
                """, (mon_ref, status, transfer_id))

                row = cursor.fetchone()

                if not row:
                    logger.warning(f"No interbank transfer found for transfer_id={transfer_id}")
                    raise NotFoundError("Transfer record not found")

                user_id = row[0]

        insert_audit_log(user_id=user_id, action="Interbank transaction update", metadata={
            "status": status,
            "ref": mon_ref
        })

        return True

    except Exception as e:
        logger.error(f"exception occurred in update interbank status: {e}", exc_info=True)
        raise


def get_interbank_by_transfer_id(transfer_id):
    try:
        with conn:
            with conn.cursor() as cursor:
                cursor.execute("""
                    SELECT * FROM interbank_transfers WHERE transfer_id = %s
                """, (transfer_id, ))

                txn = cursor.fetchone()

        if not txn:
            raise NotFoundError("transaction not found")

        return {
            "transfer_id": txn[0],
            "user_id": txn[1],
            "wallet_id": txn[2],
            "amount": txn[3],
            "destination_bank_code": txn[4],
            "destination_account_number": txn[5],
            "beneficiary_name": txn[6],
            "narration": txn[7],
            "monnify_reference": txn[8],
            "status": txn[9],
            "created_at": txn[10],
            "updated_at": txn[11]
        }

    except Exception as e:
        logger.error(f"exception occurred in get interbank with params: {e}", exc_info=True)
        raise