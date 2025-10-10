from flask import Blueprint, request, jsonify
from flasgger import swag_from

from error_handling.error_handler import logger
from error_handling.errors import UnauthorizedError, ForbiddenError, ConflictError, InternalServerError, \
    ValidationError, NotFoundError
from middleware.auth_middleware import token_required
from middleware.rate_middleware import rate_limiter
from services.audit_services import view_user_log_history, view_all_log_history
from services.user_services import disable_user, enable_user
from services.wallet_services import deactivate_wallet, activate_wallet, freeze_wallet

admin_bp = Blueprint("admin", __name__)

@admin_bp.route('/deactivate-user/<identifier>', methods=['PUT'])
@rate_limiter(capacity=10, refill_rate=0.5)
@token_required(role="admin")
@swag_from({
    'tags': ['Admin Management'],
    'summary': 'Deactivate User Account',
    'description': 'Deactivate a user account using their identifier (email or username)',
    'security': [{'BearerAuth': []}],
    'parameters': [
        {
            'name': 'identifier',
            'in': 'path',
            'required': True,
            'type': 'string',
            'description': 'User email or username'
        }
    ],
    'responses': {
        200: {
            'description': 'User account deactivated successfully',
            'content': {
                'application/json': {
                    'example': {
                        'success': True,
                        'message': 'User account deactivated successfully'
                    }
                }
            }
        },
        401: {'description': 'Unauthorized - Invalid or missing token'},
        403: {'description': 'Forbidden - Insufficient permissions'},
        409: {'description': 'Conflict - Account already deactivated'},
        500: {'description': 'Internal server error'}
    }
})
def deactivate(user_id, identifier):
    try:
        response, status = disable_user(identifier)

        return jsonify(response), status

    except (UnauthorizedError, ForbiddenError, ConflictError) as e:
        raise e

    except Exception as e:
        logger.error(f"exception occurred in deactivate: {e}", exc_info=True)
        raise InternalServerError


@admin_bp.route('/activate-user/<identifier>', methods=['PUT'])
@rate_limiter(capacity=10, refill_rate=0.5)
@token_required(role="admin")
@swag_from({
    'tags': ['Admin Management'],
    'summary': 'Activate User Account',
    'description': 'Activate a previously deactivated user account',
    'security': [{'BearerAuth': []}],
    'parameters': [
        {
            'name': 'identifier',
            'in': 'path',
            'required': True,
            'type': 'string',
            'description': 'User email or username'
        }
    ],
    'responses': {
        200: {
            'description': 'User account activated successfully',
            'content': {
                'application/json': {
                    'example': {
                        'success': True,
                        'message': 'User account activated successfully'
                    }
                }
            }
        },
        401: {'description': 'Unauthorized - Invalid or missing token'},
        403: {'description': 'Forbidden - Insufficient permissions'},
        409: {'description': 'Conflict - Account already active'},
        500: {'description': 'Internal server error'}
    }
})
def activate(user_id, identifier):
    try:
        response, status = enable_user(identifier)

        return jsonify(response), status

    except (UnauthorizedError, ForbiddenError, ConflictError) as e:
        raise e

    except Exception as e:
        logger.error(f"exception occurred in deactivate: {e}", exc_info=True)
        raise InternalServerError


@admin_bp.route('/freeze-wallet/<identifier>', methods=['PUT'])
@rate_limiter(capacity=10, refill_rate=0.5)
@token_required(role="admin")
@swag_from({
    'tags': ['Admin Management'],
    'summary': 'Freeze User Wallet',
    'description': 'Temporarily freeze a user\'s wallet to prevent transactions',
    'security': [{'BearerAuth': []}],
    'parameters': [
        {
            'name': 'identifier',
            'in': 'path',
            'required': True,
            'type': 'string',
            'description': 'Wallet ID or user identifier'
        }
    ],
    'responses': {
        200: {
            'description': 'Wallet frozen successfully',
            'content': {
                'application/json': {
                    'example': {
                        'success': True,
                        'message': 'Wallet has been frozen'
                    }
                }
            }
        },
        401: {'description': 'Unauthorized - Invalid or missing token'},
        403: {'description': 'Forbidden - Insufficient permissions'},
        409: {'description': 'Conflict - Wallet already frozen'},
        500: {'description': 'Internal server error'}
    }
})
def freeze(user_id, identifier):
    try:
        response, status = deactivate_wallet(identifier)

        return jsonify(response), status

    except (UnauthorizedError, ForbiddenError, ConflictError) as e:
        raise e

    except Exception as e:
        logger.error(f"exception occurred in deactivate: {e}", exc_info=True)
        raise InternalServerError


@admin_bp.route('/unfreeze-wallet/<identifier>', methods=['PUT'])
@rate_limiter(capacity=10, refill_rate=0.5)
@token_required(role="admin")
@swag_from({
    'tags': ['Admin Management'],
    'summary': 'Unfreeze User Wallet',
    'description': 'Unfreeze a previously frozen wallet to enable transactions',
    'security': [{'BearerAuth': []}],
    'parameters': [
        {
            'name': 'identifier',
            'in': 'path',
            'required': True,
            'type': 'string',
            'description': 'Wallet ID or user identifier'
        }
    ],
    'responses': {
        200: {
            'description': 'Wallet unfrozen successfully',
            'content': {
                'application/json': {
                    'example': {
                        'success': True,
                        'message': 'Wallet has been unfrozen'
                    }
                }
            }
        },
        401: {'description': 'Unauthorized - Invalid or missing token'},
        403: {'description': 'Forbidden - Insufficient permissions'},
        409: {'description': 'Conflict - Wallet not frozen'},
        500: {'description': 'Internal server error'}
    }
})
def un_freeze(user_id, identifier):
    try:
        response, status =  freeze_wallet(identifier)

        return jsonify(response), status

    except (UnauthorizedError, ForbiddenError, ConflictError) as e:
        raise e

    except Exception as e:
        logger.error(f"exception occurred in deactivate: {e}", exc_info=True)
        raise InternalServerError


@admin_bp.route('/user_logs/<username>', methods=['GET'])
@rate_limiter(capacity=30, refill_rate=1)
@token_required(role="admin")
@swag_from({
    'tags': ['Admin Monitoring'],
    'summary': 'View User Activity Logs',
    'description': 'Retrieve activity logs for a specific user',
    'security': [{'BearerAuth': []}],
    'parameters': [
        {
            'name': 'username',
            'in': 'path',
            'required': True,
            'type': 'string',
            'description': 'Username of the user'
        },
        {
            'name': 'limit',
            'in': 'query',
            'required': False,
            'type': 'integer',
            'description': 'Number of log entries to return'
        }
    ],
    'responses': {
        200: {
            'description': 'User logs retrieved successfully',
            'content': {
                'application/json': {
                    'example': {
                        'success': True,
                        'logs': [
                            {
                                'timestamp': '2025-10-10T10:00:00Z',
                                'action': 'login',
                                'details': 'User logged in successfully'
                            }
                        ]
                    }
                }
            }
        },
        401: {'description': 'Unauthorized - Invalid or missing token'},
        403: {'description': 'Forbidden - Insufficient permissions'},
        404: {'description': 'User not found'},
        500: {'description': 'Internal server error'}
    }
})
def view_user_activity(user_id, username):
    try:
        limit = request.args.get("limit", type=int)

        response, status = view_user_log_history(username, limit)

        return jsonify(response), status

    except (NotFoundError, ForbiddenError, UnauthorizedError, ValidationError) as e:
        raise e

    except Exception as e:
        logger.error(f"exception occurred in view user activity: {e}", exc_info=True)
        raise InternalServerError


@admin_bp.route('/view_logs', methods=['GET'])
@rate_limiter(capacity=30, refill_rate=1)
@token_required(role="admin")
@swag_from({
    'tags': ['Admin Monitoring'],
    'summary': 'View All System Logs',
    'description': 'Retrieve all system activity logs',
    'security': [{'BearerAuth': []}],
    'parameters': [
        {
            'name': 'limit',
            'in': 'query',
            'required': False,
            'type': 'integer',
            'description': 'Number of log entries to return'
        }
    ],
    'responses': {
        200: {
            'description': 'System logs retrieved successfully',
            'content': {
                'application/json': {
                    'example': {
                        'success': True,
                        'logs': [
                            {
                                'timestamp': '2025-10-10T10:00:00Z',
                                'user': 'johndoe',
                                'action': 'wallet_creation',
                                'details': 'New wallet created'
                            }
                        ]
                    }
                }
            }
        },
        401: {'description': 'Unauthorized - Invalid or missing token'},
        403: {'description': 'Forbidden - Insufficient permissions'},
        500: {'description': 'Internal server error'}
    }
})
def view_activity(user_id):
    try:
        limit = request.args.get("limit", type=int)

        response, status = view_all_log_history(limit)

        return jsonify(response), status

    except (NotFoundError, ForbiddenError, UnauthorizedError, ValidationError) as e:
        raise e

    except Exception as e:
        logger.error(f"exception occurred in view user activity: {e}", exc_info=True)
        raise InternalServerError