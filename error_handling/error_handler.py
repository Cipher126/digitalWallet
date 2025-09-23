import traceback
import logging
import datetime
from flask import request, jsonify
from .errors import AppError
from werkzeug.exceptions import HTTPException

logger = logging.getLogger(__name__)

def format_response(error_code, message, details=None):
    payload = {
        "success": False,
        "error": {
            "code": error_code,
            "message": message,
        },
        "timestamp": datetime.datetime.now(datetime.UTC)
    }

    if details:
        payload["error"]["details"] = details

    req_id = request.headers.get("X-Request-ID")

    if req_id:
        payload["request_id"] = req_id

    return payload

def handle_error(app):
    @app.errorhandler(AppError)
    def handle_app_error(error):
        logger.warning(f"AppError: {error.error_code} | {error.message} | {error.details}")
        res = format_response(error.error_code, error.message, error.details)

        return jsonify(res), error.status_code


    @app.errorhandler(HTTPException)
    def handle_http_exception(error):
        code = getattr(error, "code", 500)
        message = getattr(error, "description", str(error))

        res = format_response("http_error", message)

        return jsonify(res), code

    @app.errorhandler(Exception)
    def handle_unexpected_error(error):
        tb = traceback.format_exc()
        logger.error("Uncaught Exception: %s\n%s", str(error), tb)
        res = format_response("internal_server_error", "An internal server error occurred")

        return jsonify(res), 500