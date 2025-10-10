from dotenv import load_dotenv
from flask import Blueprint, request, jsonify
from flasgger import swag_from
from error_handling.error_handler import logger
from error_handling.errors import ValidationError, UnauthorizedError, NotFoundError, InternalServerError
from models.interbank_models import update_interbank_status, get_interbank_by_transfer_id
from models.wallets_model import update_wallet_balance_deposit
from models.webhook_logs_model import insert_webhook_log
import os
import hmac
import hashlib
import json

load_dotenv()

from services.monnify_services import process_incoming_transfer

webhook_bp = Blueprint("webhook_bp", __name__)

MONNIFY_SECRET_KEY = os.getenv("MONNIFY_SECRET")


@webhook_bp.route("/monnify/webhook", methods=["POST"])
@swag_from({
    'tags': ['Webhooks'],
    'summary': 'Monnify Main Webhook Handler',
    'description': 'Handles various webhook events from Monnify payment gateway including disbursements and transactions',
    'parameters': [
        {
            'name': 'monnify-signature',
            'in': 'header',
            'required': True,
            'type': 'string',
            'description': 'HMAC SHA512 signature for payload verification'
        },
        {
            'name': 'body',
            'in': 'body',
            'required': True,
            'schema': {
                'type': 'object',
                'properties': {
                    'eventType': {
                        'type': 'string',
                        'enum': ['DISBURSEMENT_TRANSFER', 'SUCCESSFUL_TRANSACTION', 'FAILED'],
                        'example': 'SUCCESSFUL_TRANSACTION'
                    },
                    'eventData': {
                        'type': 'object',
                        'properties': {
                            'reference': {'type': 'string'},
                            'transactionStatus': {'type': 'string'},
                            'productReference': {'type': 'string'},
                            'accountReference': {'type': 'string'},
                            'amountPaid': {'type': 'number'}
                        }
                    }
                },
                'required': ['eventType', 'eventData']
            }
        }
    ],
    'responses': {
        200: {
            'description': 'Webhook processed successfully',
            'content': {
                'application/json': {
                    'example': {
                        'status': 'success'
                    }
                }
            }
        },
        400: {'description': 'Validation error - Invalid payload format'},
        401: {'description': 'Unauthorized - Invalid signature'},
        404: {'description': 'Resource not found'},
        500: {'description': 'Internal server error'}
    }
})
def monnify_webhook():
    try:
        payload = request.get_data(as_text=True)
        headers = request.headers
        signature = headers.get("monnify-signature")


        if not signature:
            raise ValidationError("Missing Monnify signature header")

        computed_hash = hmac.new(
            MONNIFY_SECRET_KEY.encode(),
            msg=payload.encode(),
            digestmod=hashlib.sha512
        ).hexdigest()

        if computed_hash != signature:
            logger.warning(f"DEBUG SIGNATURES -> computed: {computed_hash}, received: {signature}")
            raise UnauthorizedError("Invalid Monnify signature")

        data = json.loads(payload)
        event_type = data.get("eventType")
        event_data = data.get("eventData")

        insert_webhook_log(event_type, event_data)

        if event_type == "DISBURSEMENT_TRANSFER":
            mon_ref = event_data.get("reference")
            status = event_data.get("transactionStatus")
            transfer_id = event_data.get("productReference")

            update_interbank_status(transfer_id, mon_ref, status)

        elif event_type == "SUCCESSFUL_TRANSACTION":
            account_ref = event_data.get("accountReference")
            amount = event_data.get("amountPaid")

            logger.info(f"Wallet debited for user: {account_ref} | Amount: {amount}")

        elif event_type == "FAILED":
            transfer_id = event_data.get("productReference")
            txn = get_interbank_by_transfer_id(transfer_id)
            update_wallet_balance_deposit(txn["amount"], txn["user_id"])

        return jsonify({"status": "success"}), 200

    except (UnauthorizedError, ValidationError, NotFoundError) as e:
        raise e

    except Exception as e:
        logger.error(f"Error processing Monnify webhook: {e}", exc_info=True)
        raise InternalServerError


@webhook_bp.route("/monnify/incoming", methods=["POST"])
@swag_from({
    'tags': ['Webhooks'],
    'summary': 'Monnify Incoming Transfer Webhook',
    'description': 'Handles incoming transfer notifications from Monnify payment gateway',
    'parameters': [
        {
            'name': 'monnify-signature',
            'in': 'header',
            'required': True,
            'type': 'string',
            'description': 'HMAC SHA512 signature for payload verification'
        },
        {
            'name': 'body',
            'in': 'body',
            'required': True,
            'schema': {
                'type': 'object',
                'properties': {
                    'eventType': {
                        'type': 'string',
                        'enum': ['SUCCESSFUL_TRANSACTION'],
                        'example': 'SUCCESSFUL_TRANSACTION'
                    },
                    'eventData': {
                        'type': 'object',
                        'properties': {
                            'transactionReference': {'type': 'string'},
                            'paymentReference': {'type': 'string'},
                            'amountPaid': {'type': 'number'},
                            'destinationAccountNumber': {'type': 'string'},
                            'destinationAccountName': {'type': 'string'},
                            'destinationBankName': {'type': 'string'}
                        }
                    }
                },
                'required': ['eventType', 'eventData']
            }
        }
    ],
    'responses': {
        200: {
            'description': 'Webhook processed successfully',
            'content': {
                'application/json': {
                    'example': {
                        'success': True,
                        'message': 'processed'
                    }
                }
            }
        },
        400: {'description': 'Validation error - Invalid payload format'},
        401: {'description': 'Unauthorized - Invalid signature'},
        404: {'description': 'Resource not found'},
        500: {'description': 'Internal server error'}
    }
})
def monnify_incoming_webhook():
    try:
        data = request.get_json()
        logger.info(f"Received Monnify incoming webhook: {data}")

        signature = request.headers.get("monnify-signature")

        if not signature:
            raise ValidationError("Missing Monnify signature header")

        computed_signature = hmac.new(
            MONNIFY_SECRET_KEY.encode("utf-8"),
            msg=request.data,
            digestmod=hashlib.sha512
        ).hexdigest()

        if signature != computed_signature:
            raise UnauthorizedError("Invalid Monnify signature")

        event_type = data.get("eventType")

        if event_type == "SUCCESSFUL_TRANSACTION":
            process_incoming_transfer(data.get("eventData", {}))
            return jsonify({"success": True, "message": "processed"}), 200

        logger.warn(f"Unhandled Monnify event type: {event_type}")
        return jsonify({"success": True, "message": "ignored"}), 200

    except (UnauthorizedError, ValidationError, NotFoundError) as e:
        raise e

    except Exception as e:
        logger.error(f"Exception in Monnify webhook: {e}", exc_info=True)
        raise InternalServerError
