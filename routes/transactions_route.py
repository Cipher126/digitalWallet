from flask import Blueprint, request, jsonify
from flasgger import swag_from

from error_handling.error_handler import logger
from error_handling.errors import InternalServerError, NotFoundError, ValidationError, UnauthorizedError, \
    ForbiddenError, InsufficientDataError
from middleware.auth_middleware import token_required
from middleware.rate_middleware import rate_limiter
from services.transaction_services import view_transaction_history, view_single_transaction

txn_bp = Blueprint("transaction", __name__)


@txn_bp.route('/transaction-history', methods=['GET'])
@rate_limiter(capacity=30, refill_rate=1)
@token_required(role=["user", "admin"])
@swag_from({
    'tags': ['Transactions'],
    'summary': 'View Transaction History',
    'description': 'Retrieve paginated transaction history for a user',
    'security': [{'BearerAuth': []}],
    'parameters': [
        {
            'name': 'limit',
            'in': 'query',
            'required': False,
            'type': 'integer',
            'description': 'Number of transactions to return per page',
            'default': 10
        },
        {
            'name': 'offset',
            'in': 'query',
            'required': False,
            'type': 'integer',
            'description': 'Number of transactions to skip',
            'default': 0
        }
    ],
    'responses': {
        200: {
            'description': 'Transaction history retrieved successfully',
            'content': {
                'application/json': {
                    'example': {
                        'success': True,
                        'transactions': [
                            {
                                'reference': 'TXN123456',
                                'amount': 1000.00,
                                'type': 'credit',
                                'timestamp': '2025-10-10T10:00:00Z',
                                'status': 'completed',
                                'metadata': {
                                    'sender': 'John Doe',
                                    'recipient': 'Jane Smith',
                                    'description': 'Payment for services'
                                }
                            }
                        ],
                        'total_count': 50,
                        'page_size': 10,
                        'current_page': 1
                    }
                }
            }
        },
        401: {'description': 'Unauthorized - Invalid or missing token'},
        403: {'description': 'Forbidden - Insufficient permissions'},
        404: {'description': 'No transactions found'},
        500: {'description': 'Internal server error'}
    }
})
def history(user_id):
    try:
        limit = request.args.get("limit", type=int)
        offset = request.args.get("offset", type=int)

        response, status = view_transaction_history(user_id, limit, offset)

        return jsonify(response), status

    except (NotFoundError, ValidationError, UnauthorizedError, ForbiddenError) as e:
        raise e

    except Exception as e:
        logger.error(f"exception occurred in view transaction history: {e}", exc_info=True)
        raise InternalServerError


@txn_bp.route('/view-single-transaction/<reference>', methods=['GET'])
@rate_limiter(capacity=30, refill_rate=1)
@token_required(role=["user", "admin"])
@swag_from({
    'tags': ['Transactions'],
    'summary': 'View Single Transaction',
    'description': 'Retrieve details of a specific transaction using its reference',
    'security': [{'BearerAuth': []}],
    'parameters': [
        {
            'name': 'reference',
            'in': 'path',
            'required': True,
            'type': 'string',
            'description': 'Transaction reference number'
        }
    ],
    'responses': {
        200: {
            'description': 'Transaction details retrieved successfully',
            'content': {
                'application/json': {
                    'example': {
                        'success': True,
                        'transaction': {
                            'reference': 'TXN123456',
                            'amount': 1000.00,
                            'type': 'credit',
                            'timestamp': '2025-10-10T10:00:00Z',
                            'status': 'completed',
                            'metadata': {
                                'sender': 'John Doe',
                                'recipient': 'Jane Smith',
                                'description': 'Payment for services',
                                'bank_name': 'Example Bank',
                                'account_number': '1234567890'
                            }
                        }
                    }
                }
            }
        },
        401: {'description': 'Unauthorized - Invalid or missing token'},
        403: {'description': 'Forbidden - Insufficient permissions'},
        404: {'description': 'Transaction not found'},
        500: {'description': 'Internal server error'}
    }
})
def single_txn(user_id, reference):
    try:
        response, status = view_single_transaction(ref=reference)

        return jsonify(response), status

    except (NotFoundError, InsufficientDataError, ForbiddenError, UnauthorizedError) as e:
        raise e

    except Exception as e:
        logger.error(f"exception occurred in view single transaction: {e}", exc_info=True)
        raise InternalServerError