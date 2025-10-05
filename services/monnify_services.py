import os
import base64
from dotenv import load_dotenv
import requests

from error_handling.errors import NotFoundError
from models.audit_logs_model import insert_audit_log
from models.transactions_model import create_transaction
from models.users_model import search_user_with_params
from models.wallets_model import update_wallet_balance_deposit, get_wallet_by_params, update_wallet_balance_debit
from models.webhook_logs_model import insert_webhook_log
from services.auth_services import r
from error_handling.error_handler import logger
from services.email_service import send_transaction_notification
from services.notification_services import send_txn_push

load_dotenv()

MONNIFY_BASE_URL = os.getenv("MONNIFY_URL")
MONNIFY_API_KEY = os.getenv("MONNIFY_API_KEY")
MONNIFY_SECRET_KEY = os.getenv("MONNIFY_SECRET")
MONNIFY_CONTRACT_CODE = os.getenv("CONTRACT_CODE")


def get_auth_token():
    """
    get monnify access token
    :return: token: str
    """
    try:
        token = r.get("monnify_access_token")

        if token:
            return token

        auth_str = f"{MONNIFY_API_KEY}:{MONNIFY_SECRET_KEY}"
        base64_auth = base64.b64encode(auth_str.encode()).decode()

        url = f"{MONNIFY_BASE_URL}/api/v1/auth/login"
        header = {"Content-Type": "application/json", "Authorization": f"Basic {base64_auth}"}

        res = requests.post(url, headers=header)
        res.raise_for_status()

        data = res.json()

        token = data["responseBody"]["accessToken"]
        exp = data["responseBody"]["expiresIn"]

        r.set("monnify_access_token", token, ttl=exp - 60)

        return token

    except Exception as e:
        logger.error(f"error fetching monnify token: {e}", exc_info=True)
        raise


def create_reserved_account(user_id, account_name, email, bvn):
    """
    Create a virtual (reserved) account for the user.
    """
    try:
        token = get_auth_token()

        payload = {
            "accountReference": str(user_id),
            "accountName": account_name,
            "customerEmail": email,
            "bvn": bvn,
            "contractCode": MONNIFY_CONTRACT_CODE,
            "currencyCode": "NGN"
        }

        url = f"{MONNIFY_BASE_URL}/api/v2/bank-transfer/reserved-accounts"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }

        res = requests.post(url, json=payload, headers=headers)
        res.raise_for_status()

        data = res.json()
        return data["responseBody"]

    except Exception as e:
        logger.error(f"Error creating reserved account: {e}", exc_info=True)
        raise


def initiate_interbank_transfer(account, amount, destination_bank_code, destination_account_number,
                                narration, reference):
    """
    Send funds to another bank account via Monnify.
    """
    try:
        wallet = get_wallet_by_params(account_number=account)
        if not wallet:
            raise NotFoundError("sender account does not exist")


        token = get_auth_token()

        payload = {
            "amount": amount,
            "reference": reference,
            "narration": narration,
            "destinationBankCode": destination_bank_code,
            "destinationAccountNumber": destination_account_number,
            "currency": "NGN",
            "sourceAccountNumber": os.getenv("MONNIFY_WALLET_ACCOUNT"),
        }

        url = f"{MONNIFY_BASE_URL}api/v2/disbursements/single"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }

        res = requests.post(url, json=payload, headers=headers)
        res.raise_for_status()

        data = res.json()

        if data["requestSuccessful"]:
            update_wallet_balance_debit(amount, user_id=wallet["user_id"])

        create_transaction(
            wallet_id=wallet["wallet_id"],
            user_id=wallet["user_id"],
            txn_type="credit",
            amount=amount,
            from_account=account,
            to_account=destination_account_number,
            description=narration or "outgoing transfer"
        )

        insert_audit_log(
            user_id=wallet["user_id"],
            action="Incoming transfer",
            metadata={
                "amount": amount,
                "to": destination_account_number,
                "reference": reference
            }
        )

        insert_webhook_log("monnify.incoming_transfer", payload)

        user = search_user_with_params(user_id=wallet["user_id"])
        send_transaction_notification(
            email=user["email"],
            name=user["name"],
            txn_type="credit",
            amount=amount,
            balance=wallet["balance"] + amount
        )

        send_txn_push(wallet["user_id"], "credit", amount, wallet["balance"] + amount)
        return data["responseBody"]

    except Exception as e:
        logger.error(f"Error initiating interbank transfer: {e}", exc_info=True)
        raise


def process_incoming_transfer(payload):
    try:
        account_reference = payload.get("accountReference")
        amount = float(payload.get("amountPaid", 0))
        payment_reference = payload.get("paymentReference")
        transaction_reference = payload.get("transactionReference")
        paid_by = payload.get("customerName")
        narration = payload.get("paymentDescription")

        wallet = get_wallet_by_params(account_number=account_reference)

        if not wallet:
            raise NotFoundError("wallet not found for incoming transfer")

        update_wallet_balance_deposit(amount, wallet["user_id"])

        create_transaction(
            wallet_id=wallet["wallet_id"],
            user_id=wallet["user_id"],
            txn_type="credit",
            amount=amount,
            from_account={"name": paid_by},
            to_account=account_reference,
            description=narration or "Wallet funding"
        )

        insert_webhook_log("monnify.incoming_transfer", payload)

        user = search_user_with_params(user_id=wallet["user_id"])
        send_transaction_notification(
            email=user["email"],
            name=user["name"],
            txn_type="credit",
            amount=amount,
            balance=wallet["balance"] + amount
        )
        send_txn_push(wallet["user_id"], "credit", amount, wallet["balance"] + amount)

        insert_audit_log(
            user_id=wallet["user_id"],
            action="Incoming transfer",
            metadata={
                "amount": amount,
                "from": paid_by,
                "reference": transaction_reference
            }
        )

        return True

    except Exception as e:
        logger.error(f"exception in process incoming transfer: {e}", exc_info=True)
        raise
