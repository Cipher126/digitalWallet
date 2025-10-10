from flask import Blueprint, request, jsonify
from flasgger import swag_from

from error_handling.error_handler import logger
from error_handling.errors import InsufficientDataError, ValidationError, NotFoundError, InternalServerError, \
    UnauthorizedError, ForbiddenError, LockoutError, InsufficientFundsError
from middleware.auth_middleware import token_required
from middleware.rate_middleware import rate_limiter
from models.wallets_model import get_wallet_by_params
from services.monnify_services import process_outgoing_transfer
from services.wallet_services import set_wallet_pin, change_wallet_pin, transfer_between_wallet, activate_wallet

wallet_bp = Blueprint("wallet", __name__)

@wallet_bp.route('/set-pin', methods=['POST'])
@rate_limiter(capacity=5, refill_rate=0.1)
@token_required(role="user")
@swag_from({
    'tags': ['Wallet Management'],
    'summary': 'Set Wallet PIN',
    'description': 'Set a new PIN for the wallet',
    'security': [{'BearerAuth': []}],
    'parameters': [{
        'name': 'body',
        'in': 'body',
        'required': True,
        'schema': {
            'type': 'object',
            'properties': {
                'pin': {'type': 'string', 'example': '1234'}
            },
            'required': ['pin']
        }
    }],
    'responses': {
        200: {
            'description': 'PIN set successfully',
            'content': {
                'application/json': {
                    'example': {
                        'success': True,
                        'message': 'Wallet PIN set successfully'
                    }
                }
            }
        },
        400: {'description': 'Invalid PIN format'},
        401: {'description': 'Unauthorized'},
        500: {'description': 'Internal server error'}
    }
})
def set_pin(user_id):
    try:
        data = request.get_json()
        pin = data.get("pin")

        if not pin:
            raise InsufficientDataError("provide new wallet pin")

        response, status = set_wallet_pin(pin, user_id)

        return jsonify(response), status

    except (ValidationError, NotFoundError, InsufficientDataError, UnauthorizedError, ForbiddenError) as e:
        raise e

    except Exception as e:
        logger.error(f"exception occurred in set wallet pin: {e}", exc_info=True)
        raise InternalServerError


@wallet_bp.route('/activate', methods=['POST'])
@rate_limiter(capacity=5, refill_rate=0.1)
@token_required(role="user")
@swag_from({
    'tags': ['Wallet Management'],
    'summary': 'Activate Wallet',
    'description': 'Activate wallet using BVN verification',
    'security': [{'BearerAuth': []}],
    'parameters': [{
        'name': 'body',
        'in': 'body',
        'required': True,
        'schema': {
            'type': 'object',
            'properties': {
                'bvn': {'type': 'string', 'example': '22222222222'}
            },
            'required': ['bvn']
        }
    }],
    'responses': {
        200: {
            'description': 'Wallet activated successfully',
            'content': {
                'application/json': {
                    'example': {
                        'success': True,
                        'message': 'Wallet activated successfully'
                    }
                }
            }
        },
        400: {'description': 'Invalid BVN'},
        401: {'description': 'Unauthorized'},
        500: {'description': 'Internal server error'}
    }
})
def activate(user_id):
    try:
        data = request.get_json()
        bvn = data.get("bvn")

        response, status = activate_wallet(user_id, bvn)

        return jsonify(response), status

    except (ValidationError, UnauthorizedError, NotFoundError, ForbiddenError) as e:
        raise e

    except Exception as e:
        logger.error(f"exception occurred in activate wallet: {e}", exc_info=True)
        raise InternalServerError


@wallet_bp.route('/change-pin', methods=['PUT'])
@rate_limiter(capacity=5, refill_rate=0.1)
@token_required(role="user")
@swag_from({
    'tags': ['Wallet Management'],
    'summary': 'Change Wallet PIN',
    'description': 'Change existing wallet PIN to a new PIN',
    'security': [{'BearerAuth': []}],
    'parameters': [{
        'name': 'body',
        'in': 'body',
        'required': True,
        'schema': {
            'type': 'object',
            'properties': {
                'old_pin': {'type': 'string', 'example': '1234'},
                'pin': {'type': 'string', 'example': '5678'}
            },
            'required': ['old_pin', 'pin']
        }
    }],
    'responses': {
        200: {
            'description': 'PIN changed successfully',
            'content': {
                'application/json': {
                    'example': {
                        'success': True,
                        'message': 'Wallet PIN changed successfully'
                    }
                }
            }
        },
        400: {'description': 'Invalid PIN format'},
        401: {'description': 'Unauthorized or incorrect old PIN'},
        500: {'description': 'Internal server error'}
    }
})
def change(user_id):
    try:
        data = request.get_json()
        pin = data.get("pin")
        old_pin = data.get("old_pin")

        if not pin and old_pin:
            raise InsufficientDataError("provide new wallet pin and old pin")

        response, status = change_wallet_pin(pin, old_pin, user_id)

        return jsonify(response), status

    except (ValidationError, NotFoundError, InsufficientDataError, UnauthorizedError, ForbiddenError) as e:
        raise e

    except Exception as e:
        logger.error(f"exception occurred in set wallet pin: {e}", exc_info=True)
        raise InternalServerError


@wallet_bp.route('/transfer/internal', methods=['POST'])
@rate_limiter(capacity=5, refill_rate=0.1)
@token_required(role=["user", "admin"])
@swag_from({
    'tags': ['Wallet Transactions'],
    'summary': 'Internal Wallet Transfer',
    'description': 'Transfer funds between internal wallets',
    'security': [{'BearerAuth': []}],
    'parameters': [{
        'name': 'body',
        'in': 'body',
        'required': True,
        'schema': {
            'type': 'object',
            'properties': {
                'amount': {'type': 'number', 'example': 1000.00},
                'to_account': {'type': 'string', 'example': '1234567890'},
                'from_account': {'type': 'string', 'example': '0987654321'},
                'pin': {'type': 'string', 'example': '1234'}
            },
            'required': ['amount', 'to_account', 'from_account', 'pin']
        }
    }],
    'responses': {
        200: {
            'description': 'Transfer successful',
            'content': {
                'application/json': {
                    'example': {
                        'success': True,
                        'message': 'Transfer successful',
                        'reference': 'TRF123456'
                    }
                }
            }
        },
        400: {'description': 'Invalid transfer details'},
        401: {'description': 'Unauthorized or incorrect PIN'},
        402: {'description': 'Insufficient funds'},
        500: {'description': 'Internal server error'}
    }
})
def transfer(user_id):
    try:
        data = request.get_json()
        amount = float(data.get("amount"))
        to_account = data.get("to_account")
        from_account = data.get("from_account")
        pin = data.get("pin")

        response, status = transfer_between_wallet(amount, to_account, from_account, pin)

        return jsonify(response), status

    except (UnauthorizedError, ValidationError, NotFoundError,
            InsufficientFundsError, LockoutError, ForbiddenError) as e:
        raise e

    except Exception as e:
        logger.error(f"exception occurred in transfer: {e}", exc_info=True)
        raise InternalServerError


@wallet_bp.route('/transfer/external', methods=['POST'])
@rate_limiter(capacity=5, refill_rate=0.1)
@token_required(role=["user", "admin"])
@swag_from({
    'tags': ['Wallet Transactions'],
    'summary': 'External Bank Transfer',
    'description': 'Transfer funds to external bank accounts',
    'security': [{'BearerAuth': []}],
    'parameters': [{
        'name': 'body',
        'in': 'body',
        'required': True,
        'schema': {
            'type': 'object',
            'properties': {
                'amount': {'type': 'number', 'example': 1000.00},
                'bank_code': {'type': 'string', 'example': '058'},
                'destination_account': {'type': 'string', 'example': '0123456789'},
                'narration': {'type': 'string', 'example': 'Payment for services'}
            },
            'required': ['amount', 'bank_code', 'destination_account']
        }
    }],
    'responses': {
        200: {
            'description': 'Transfer initiated successfully',
            'content': {
                'application/json': {
                    'example': {
                        'success': True,
                        'message': 'Transfer initiated',
                        'reference': 'EXT123456'
                    }
                }
            }
        },
        400: {'description': 'Invalid transfer details'},
        401: {'description': 'Unauthorized'},
        402: {'description': 'Insufficient funds'},
        404: {'description': 'Wallet not found'},
        500: {'description': 'Internal server error'}
    }
})
def external(user_id):
    try:
        data = request.get_json()
        amount = data.get("amount")
        bank_code = data.get("bank_code")
        destination_account = data.get("destination_account")
        narration = data.get("narration")

        account_number = get_wallet_by_params(user_id=user_id)["account_number"]

        if not account_number:
            raise NotFoundError("wallet not found")

        response, status = process_outgoing_transfer(
            account_number,
            amount,
            bank_code,
            destination_account,
            narration
        )

        return jsonify(response), status

    except (InsufficientFundsError, NotFoundError) as e:
        raise e

    except Exception as e:
        logger.error(f"Error initiating interbank transfer: {e}", exc_info=True)
        raise